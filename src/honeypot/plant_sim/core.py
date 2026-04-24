"""Deterministische Simulationslogik fuer die Kern-Szenarien von V1."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from honeypot.asset_domain import PlantAlarm, PlantSnapshot
from honeypot.asset_domain.models import AssetStatus, CommunicationState, DataQuality
from honeypot.event_core import EventRecorder

SCENARIO_ALARM_CODES = frozenset(
    {
        "PLANT_CURTAILED",
        "BREAKER_OPEN",
        "COMM_LOSS_INVERTER_BLOCK",
    }
)
SCENARIO_ALARM_DEFINITIONS = {
    "PLANT_CURTAILED": {"category": "process", "severity": "medium"},
    "BREAKER_OPEN": {"category": "site", "severity": "high"},
    "COMM_LOSS_INVERTER_BLOCK": {"category": "communication", "severity": "medium"},
}
PLANT_SIM_COMPONENT = "plant-sim"
PLANT_SIM_PROTOCOL = "internal-sim"
PLANT_SIM_SERVICE = "plant-core"


class PlantSimulationError(ValueError):
    """Signalisiert ungueltige Simulationskommandos oder Startzustaende."""


@dataclass(frozen=True, slots=True)
class SimulationEventContext:
    """Metadaten fuer die Eventspur von `plant_sim`-Schreibpfaden."""

    source_ip: str = "127.0.0.1"
    actor_type: str = "system"
    session_id: str | None = None
    correlation_id: str | None = None
    causation_id: str | None = None
    protocol: str | None = PLANT_SIM_PROTOCOL
    service: str | None = PLANT_SIM_SERVICE


def determine_data_quality(*, status: AssetStatus, communication_state: CommunicationState) -> DataQuality:
    """Leitet Datenqualitaet aus Status und Kommunikationslage ab."""

    if communication_state == "healthy":
        return "good"
    if communication_state == "degraded":
        return "estimated"
    if status in ("offline", "faulted"):
        return "invalid"
    return "stale"


@dataclass(frozen=True, slots=True)
class PlantSimulator:
    """Leitet aus einem Referenzzustand deterministische Szenarien ab."""

    nominal_capacity_kw: float
    baseline_block_power_kw: dict[str, float]
    event_recorder: EventRecorder | None = None
    default_event_context: SimulationEventContext = field(default_factory=SimulationEventContext)

    @classmethod
    def from_snapshot(
        cls,
        snapshot: PlantSnapshot,
        *,
        event_recorder: EventRecorder | None = None,
        default_event_context: SimulationEventContext | None = None,
    ) -> "PlantSimulator":
        """Leitet eine nominale Parkleistung aus dem Referenzzustand ab."""

        baseline_irradiance_factor = min(snapshot.weather_station.irradiance_w_m2, 1000) / 1000
        if baseline_irradiance_factor <= 0:
            raise PlantSimulationError("ein Referenzzustand mit Einstrahlung > 0 W/m2 ist erforderlich")

        baseline_output_kw = max(
            snapshot.total_inverter_power_kw,
            snapshot.revenue_meter.export_power_kw,
            snapshot.site.plant_power_mw * 1000,
        )
        if baseline_output_kw <= 0:
            raise PlantSimulationError("ein Referenzzustand mit positiver Leistung ist erforderlich")

        return cls(
            nominal_capacity_kw=baseline_output_kw / baseline_irradiance_factor,
            baseline_block_power_kw={
                block.asset_id: max(block.block_power_kw, 0.0) for block in snapshot.inverter_blocks
            },
            event_recorder=event_recorder,
            default_event_context=(
                SimulationEventContext() if default_event_context is None else default_event_context
            ),
        )

    def estimate_available_power_kw(
        self,
        snapshot: PlantSnapshot,
        *,
        irradiance_w_m2: int | None = None,
    ) -> float:
        """Schaetzt die verfuegbare Wirkleistung aus der Einstrahlung."""

        irradiance = snapshot.weather_station.irradiance_w_m2 if irradiance_w_m2 is None else irradiance_w_m2
        if irradiance < 0:
            raise PlantSimulationError("Einstrahlung darf nicht negativ sein")

        irradiance_factor = min(irradiance, 1000) / 1000
        return round(self.nominal_capacity_kw * irradiance_factor, 1)

    def simulate_normal_operation(self, snapshot: PlantSnapshot) -> PlantSnapshot:
        """Erzeugt einen gesunden Basiszustand ohne aktive Szenario-Alarme."""

        total_power_kw = self.estimate_available_power_kw(snapshot)
        inverter_blocks = _with_rebalanced_block_power(snapshot, total_power_kw)
        site = snapshot.site.model_copy(
            update={
                "operating_mode": "normal",
                "availability_state": "available",
                "plant_power_mw": round(total_power_kw / 1000, 3),
                "plant_power_limit_pct": 100,
                "breaker_state": "closed",
                "communications_health": "healthy",
            }
        )
        power_plant_controller = snapshot.power_plant_controller.model_copy(
            update={
                "active_power_limit_pct": 100,
            }
        )
        revenue_meter = snapshot.revenue_meter.model_copy(
            update={
                "export_power_kw": total_power_kw,
            }
        )
        grid_interconnect = snapshot.grid_interconnect.model_copy(
            update={
                "breaker_state": "closed",
                "export_path_available": True,
                "grid_acceptance_state": "accepted",
            }
        )
        alarms = _replace_scenario_alarms(snapshot.alarms)
        return _build_snapshot(
            snapshot,
            site=site,
            power_plant_controller=power_plant_controller,
            inverter_blocks=inverter_blocks,
            revenue_meter=revenue_meter,
            grid_interconnect=grid_interconnect,
            alarms=alarms,
        )

    def apply_curtailment(
        self,
        snapshot: PlantSnapshot,
        *,
        active_power_limit_pct: float,
        event_context: SimulationEventContext | None = None,
    ) -> PlantSnapshot:
        """Reduziert die Parkleistung ueber den PPC-Wirkleistungsgrenzwert."""

        if not 0 <= active_power_limit_pct <= 100:
            raise PlantSimulationError("active_power_limit_pct muss im Bereich 0..100 liegen")
        normalized_limit_pct = round(active_power_limit_pct, 1)

        base_snapshot = self.simulate_normal_operation(snapshot)
        total_power_kw = round(
            self.estimate_available_power_kw(base_snapshot) * (normalized_limit_pct / 100),
            1,
        )
        inverter_blocks = _with_rebalanced_block_power(base_snapshot, total_power_kw)
        site = base_snapshot.site.model_copy(
            update={
                "operating_mode": "normal" if normalized_limit_pct == 100 else "curtailed",
                "plant_power_mw": round(total_power_kw / 1000, 3),
                "plant_power_limit_pct": normalized_limit_pct,
            }
        )
        power_plant_controller = base_snapshot.power_plant_controller.model_copy(
            update={
                "active_power_limit_pct": normalized_limit_pct,
            }
        )
        revenue_meter = base_snapshot.revenue_meter.model_copy(
            update={
                "export_power_kw": total_power_kw,
            }
        )
        alarms = _replace_scenario_alarms(
            base_snapshot.alarms,
            "PLANT_CURTAILED" if normalized_limit_pct < 100 else None,
        )
        resulting_snapshot = _build_snapshot(
            base_snapshot,
            site=site,
            power_plant_controller=power_plant_controller,
            inverter_blocks=inverter_blocks,
            revenue_meter=revenue_meter,
            alarms=alarms,
        )
        self._record_snapshot_transition(
            snapshot,
            resulting_snapshot,
            event_type="process.setpoint.curtailment_changed",
            category="process",
            severity="high",
            asset_id=resulting_snapshot.power_plant_controller.asset_id,
            action="set_active_power_limit",
            requested_value=normalized_limit_pct,
            previous_value=snapshot.power_plant_controller.active_power_limit_pct,
            resulting_value=resulting_snapshot.power_plant_controller.active_power_limit_pct,
            resulting_state={
                "active_power_limit_pct": resulting_snapshot.power_plant_controller.active_power_limit_pct,
                "plant_power_mw": resulting_snapshot.site.plant_power_mw,
                "active_alarm_codes": list(resulting_snapshot.active_alarm_codes),
            },
            alarm_code=_present_alarm_code(resulting_snapshot, "PLANT_CURTAILED"),
            tags=("control-path", "ppc", "curtailment"),
            event_context=event_context,
        )
        return resulting_snapshot

    def apply_reactive_power_target(
        self,
        snapshot: PlantSnapshot,
        *,
        reactive_power_target: float,
        event_context: SimulationEventContext | None = None,
    ) -> PlantSnapshot:
        """Aktualisiert das PPC-Blindleistungsziel ohne weitere Anlagenumschaltung."""

        if not -1.0 <= reactive_power_target <= 1.0:
            raise PlantSimulationError("reactive_power_target muss im Bereich -1.0..1.0 liegen")
        normalized_target = round(reactive_power_target, 3)

        resulting_snapshot = _build_snapshot(
            snapshot,
            site=snapshot.site.model_copy(
                update={
                    "reactive_power_setpoint": normalized_target,
                }
            ),
            power_plant_controller=snapshot.power_plant_controller.model_copy(
                update={
                    "reactive_power_target": normalized_target,
                }
            ),
        )
        self._record_snapshot_transition(
            snapshot,
            resulting_snapshot,
            event_type="process.setpoint.reactive_power_target_changed",
            category="process",
            severity="medium",
            asset_id=resulting_snapshot.power_plant_controller.asset_id,
            action="set_reactive_power_target",
            requested_value=normalized_target,
            previous_value=snapshot.power_plant_controller.reactive_power_target,
            resulting_value=resulting_snapshot.power_plant_controller.reactive_power_target,
            resulting_state={
                "reactive_power_target": resulting_snapshot.power_plant_controller.reactive_power_target,
                "plant_power_mw": resulting_snapshot.site.plant_power_mw,
                "active_alarm_codes": list(resulting_snapshot.active_alarm_codes),
            },
            alarm_code=None,
            tags=("control-path", "ppc", "reactive-power"),
            event_context=event_context,
        )
        return resulting_snapshot

    def apply_block_enable_request(
        self,
        snapshot: PlantSnapshot,
        *,
        asset_id: str,
        block_enable_request: bool,
        block_power_limit_pct: float,
        event_context: SimulationEventContext | None = None,
    ) -> PlantSnapshot:
        """Aktualisiert den Enable-Request eines Inverter-Blocks mit sichtbarer Wirkung."""

        previous_block = _require_block(snapshot, asset_id)
        previous_value = 0 if _is_block_disabled(previous_block) else 1
        normalized_enable_request = 1 if block_enable_request else 0
        resulting_snapshot = self._apply_inverter_block_control_state(
            snapshot,
            asset_id=asset_id,
            block_enable_request=block_enable_request,
            block_power_limit_pct=block_power_limit_pct,
        )
        resulting_block = _require_block(resulting_snapshot, asset_id)
        self._record_snapshot_transition(
            snapshot,
            resulting_snapshot,
            event_type="process.setpoint.block_enable_request_changed",
            category="process",
            severity="medium",
            asset_id=asset_id,
            action="set_block_enable_request",
            requested_value=normalized_enable_request,
            previous_value=previous_value,
            resulting_value=normalized_enable_request,
            resulting_state={
                "block_enable_request": normalized_enable_request,
                "block_power_limit_pct": round(block_power_limit_pct, 1),
                "status": resulting_block.status,
                "communication_state": resulting_block.communication_state,
                "availability_pct": resulting_block.availability_pct,
                "block_power_kw": resulting_block.block_power_kw,
                "plant_power_mw": resulting_snapshot.site.plant_power_mw,
            },
            alarm_code=None,
            tags=("control-path", "inverter-block", "enable"),
            event_context=event_context,
        )
        return resulting_snapshot

    def apply_block_power_limit(
        self,
        snapshot: PlantSnapshot,
        *,
        asset_id: str,
        block_enable_request: bool,
        block_power_limit_pct: float,
        event_context: SimulationEventContext | None = None,
    ) -> PlantSnapshot:
        """Aktualisiert die Blockleistungsbegrenzung eines Inverter-Blocks."""

        if not 0 <= block_power_limit_pct <= 100:
            raise PlantSimulationError("block_power_limit_pct muss im Bereich 0..100 liegen")

        previous_block = _require_block(snapshot, asset_id)
        previous_limit_pct = _derived_block_power_limit_pct(
            snapshot=snapshot,
            asset_id=asset_id,
            baseline_block_power_kw=self.baseline_block_power_kw,
        )
        normalized_limit_pct = round(block_power_limit_pct, 1)
        resulting_snapshot = self._apply_inverter_block_control_state(
            snapshot,
            asset_id=asset_id,
            block_enable_request=block_enable_request,
            block_power_limit_pct=normalized_limit_pct,
        )
        resulting_block = _require_block(resulting_snapshot, asset_id)
        self._record_snapshot_transition(
            snapshot,
            resulting_snapshot,
            event_type="process.setpoint.block_power_limit_changed",
            category="process",
            severity="medium",
            asset_id=asset_id,
            action="set_block_power_limit",
            requested_value=normalized_limit_pct,
            previous_value=previous_limit_pct,
            resulting_value=normalized_limit_pct,
            resulting_state={
                "block_enable_request": 1 if block_enable_request else 0,
                "block_power_limit_pct": normalized_limit_pct,
                "status": resulting_block.status,
                "availability_pct": resulting_block.availability_pct,
                "block_power_kw": resulting_block.block_power_kw,
                "plant_power_mw": resulting_snapshot.site.plant_power_mw,
            },
            alarm_code=None,
            tags=("control-path", "inverter-block", "power-limit"),
            event_context=event_context,
        )
        return resulting_snapshot

    def reset_block(
        self,
        snapshot: PlantSnapshot,
        *,
        asset_id: str,
        block_enable_request: bool,
        block_power_limit_pct: float,
        event_context: SimulationEventContext | None = None,
    ) -> PlantSnapshot:
        """Fuehrt einen simulierten Block-Reset mit sichtbarer Wiederherstellung aus."""

        previous_block = _require_block(snapshot, asset_id)
        resulting_snapshot = self._apply_inverter_block_control_state(
            snapshot,
            asset_id=asset_id,
            block_enable_request=block_enable_request,
            block_power_limit_pct=block_power_limit_pct,
            reset_requested=True,
        )
        resulting_block = _require_block(resulting_snapshot, asset_id)
        alarm_code = "COMM_LOSS_INVERTER_BLOCK" if previous_block.communication_state == "lost" else None
        self._record_snapshot_transition(
            snapshot,
            resulting_snapshot,
            event_type="process.control.block_reset_requested",
            category="process",
            severity="medium",
            asset_id=asset_id,
            action="block_reset_request",
            requested_value=1,
            previous_value={
                "status": previous_block.status,
                "communication_state": previous_block.communication_state,
                "quality": previous_block.quality,
            },
            resulting_value="applied",
            resulting_state={
                "block_enable_request": 1 if block_enable_request else 0,
                "block_power_limit_pct": round(block_power_limit_pct, 1),
                "status": resulting_block.status,
                "communication_state": resulting_block.communication_state,
                "quality": resulting_block.quality,
                "availability_pct": resulting_block.availability_pct,
                "block_power_kw": resulting_block.block_power_kw,
                "plant_power_mw": resulting_snapshot.site.plant_power_mw,
                "active_alarm_codes": list(resulting_snapshot.active_alarm_codes),
            },
            alarm_code=alarm_code,
            tags=("control-path", "inverter-block", "reset"),
            event_context=event_context,
        )
        return resulting_snapshot

    def open_breaker(
        self,
        snapshot: PlantSnapshot,
        *,
        event_context: SimulationEventContext | None = None,
    ) -> PlantSnapshot:
        """Simuliert einen offenen Netzuebergabebreaker mit Exportverlust."""

        base_snapshot = self.simulate_normal_operation(snapshot)
        inverter_blocks = tuple(
            block.model_copy(update={"block_power_kw": 0.0}) for block in base_snapshot.inverter_blocks
        )
        site = base_snapshot.site.model_copy(
            update={
                "operating_mode": "faulted",
                "availability_state": "unavailable",
                "plant_power_mw": 0.0,
                "breaker_state": "open",
            }
        )
        revenue_meter = base_snapshot.revenue_meter.model_copy(
            update={
                "export_power_kw": 0.0,
            }
        )
        grid_interconnect = base_snapshot.grid_interconnect.model_copy(
            update={
                "breaker_state": "open",
                "export_path_available": False,
                "grid_acceptance_state": "unavailable",
            }
        )
        alarms = _replace_scenario_alarms(base_snapshot.alarms, "BREAKER_OPEN")
        resulting_snapshot = _build_snapshot(
            base_snapshot,
            site=site,
            inverter_blocks=inverter_blocks,
            revenue_meter=revenue_meter,
            grid_interconnect=grid_interconnect,
            alarms=alarms,
        )
        self._record_snapshot_transition(
            snapshot,
            resulting_snapshot,
            event_type="process.breaker.state_changed",
            category="process",
            severity="high",
            asset_id=resulting_snapshot.grid_interconnect.asset_id,
            action="breaker_open_request",
            requested_value="open",
            previous_value=snapshot.grid_interconnect.breaker_state,
            resulting_value=resulting_snapshot.grid_interconnect.breaker_state,
            resulting_state={
                "breaker_state": resulting_snapshot.grid_interconnect.breaker_state,
                "plant_power_mw": resulting_snapshot.site.plant_power_mw,
                "export_power_kw": resulting_snapshot.revenue_meter.export_power_kw,
                "active_alarm_codes": list(resulting_snapshot.active_alarm_codes),
            },
            alarm_code=_present_alarm_code(resulting_snapshot, "BREAKER_OPEN"),
            tags=("control-path", "grid", "breaker"),
            event_context=event_context,
        )
        return resulting_snapshot

    def _apply_inverter_block_control_state(
        self,
        snapshot: PlantSnapshot,
        *,
        asset_id: str,
        block_enable_request: bool,
        block_power_limit_pct: float,
        reset_requested: bool = False,
    ) -> PlantSnapshot:
        return self._apply_inverter_block_control_matrix(
            snapshot,
            block_control_states={
                asset_id: (block_enable_request, round(block_power_limit_pct, 1)),
            },
            reset_asset_ids=frozenset({asset_id}) if reset_requested else frozenset(),
        )

    def _apply_inverter_block_control_matrix(
        self,
        snapshot: PlantSnapshot,
        *,
        block_control_states: dict[str, tuple[bool, float]],
        reset_asset_ids: frozenset[str] = frozenset(),
    ) -> PlantSnapshot:
        merged_block_control_states = _current_block_control_states(
            snapshot=snapshot,
            baseline_block_power_kw=self.baseline_block_power_kw,
        )
        for control_asset_id, (control_enable_request, control_power_limit_pct) in block_control_states.items():
            if not 0 <= control_power_limit_pct <= 100:
                raise PlantSimulationError("block_power_limit_pct muss im Bereich 0..100 liegen")
            _require_block(snapshot, control_asset_id)
            merged_block_control_states[control_asset_id] = (
                control_enable_request,
                round(control_power_limit_pct, 1),
            )

        effective_total_power_kw = 0.0 if snapshot.site.breaker_state == "open" else round(
            self.estimate_available_power_kw(snapshot) * (snapshot.site.plant_power_limit_pct / 100),
            1,
        )
        weighted_powers = _distribute_power_kw_for_controls(
            snapshot.inverter_blocks,
            total_power_kw=effective_total_power_kw,
            baseline_block_power_kw=self.baseline_block_power_kw,
            block_control_states=merged_block_control_states,
        )

        inverter_blocks = []
        for block in snapshot.inverter_blocks:
            block_enable_request, block_power_limit_pct = merged_block_control_states[block.asset_id]
            target_limit_factor = round(block_power_limit_pct / 100, 3)
            is_reset = block.asset_id in reset_asset_ids
            if is_reset:
                base_block = block.model_copy(
                    update={
                        "status": "online",
                        "communication_state": "healthy",
                    }
                )
            else:
                base_block = block

            block_power_kw = weighted_powers[block.asset_id]
            if not block_enable_request:
                status = "offline"
                communication_state = "degraded"
                availability_pct = 0
            elif _is_block_disabled(base_block):
                status = "online"
                communication_state = "healthy"
                availability_pct = 100 if block_power_kw > 0 else 0
            else:
                status = base_block.status
                communication_state = base_block.communication_state
                availability_pct = 100 if block_power_kw > 0 and status != "offline" else base_block.availability_pct

            if is_reset and block_enable_request:
                availability_pct = 100 if block_power_kw > 0 else 0
            if block_enable_request and block_power_kw == 0 and snapshot.site.breaker_state != "open":
                availability_pct = 0 if target_limit_factor == 0 else availability_pct

            inverter_blocks.append(
                base_block.model_copy(
                    update={
                        "status": status,
                        "communication_state": communication_state,
                        "quality": determine_data_quality(status=status, communication_state=communication_state),
                        "availability_pct": availability_pct,
                        "block_power_kw": block_power_kw,
                    }
                )
            )

        final_blocks = tuple(inverter_blocks)
        if snapshot.site.breaker_state == "open":
            availability_state = "unavailable"
            site_power_mw = 0.0
            export_power_kw = 0.0
            operating_mode = "faulted"
        else:
            available_count = sum(1 for block in final_blocks if block.availability_pct > 0)
            site_power_mw = round(sum(block.block_power_kw for block in final_blocks) / 1000, 3)
            export_power_kw = round(sum(block.block_power_kw for block in final_blocks), 1)
            if available_count == 0:
                availability_state = "unavailable"
            elif any(
                block.status != "online" or block.communication_state != "healthy" or block.availability_pct < 100
                for block in final_blocks
            ):
                availability_state = "partially_available"
            else:
                availability_state = "available"
            if snapshot.site.operating_mode == "maintenance":
                operating_mode = "maintenance"
            elif snapshot.site.plant_power_limit_pct < 100:
                operating_mode = "curtailed"
            else:
                operating_mode = "normal"

        site = snapshot.site.model_copy(
            update={
                "operating_mode": operating_mode,
                "availability_state": availability_state,
                "plant_power_mw": site_power_mw,
                "communications_health": (
                    "degraded"
                    if any(block.communication_state != "healthy" for block in final_blocks)
                    else "healthy"
                ),
            }
        )
        revenue_meter = snapshot.revenue_meter.model_copy(update={"export_power_kw": export_power_kw})
        alarms = _replace_scenario_alarms(
            snapshot.alarms,
            "PLANT_CURTAILED" if snapshot.site.plant_power_limit_pct < 100 else None,
            "BREAKER_OPEN" if snapshot.site.breaker_state == "open" else None,
            "COMM_LOSS_INVERTER_BLOCK" if any(block.communication_state == "lost" for block in final_blocks) else None,
        )
        return _build_snapshot(
            snapshot,
            site=site,
            inverter_blocks=final_blocks,
            revenue_meter=revenue_meter,
            alarms=alarms,
        )

    def close_breaker(
        self,
        snapshot: PlantSnapshot,
        *,
        event_context: SimulationEventContext | None = None,
    ) -> PlantSnapshot:
        """Schliesst den Netzuebergabebreaker und stellt den Normalexport wieder her."""

        resulting_snapshot = self.simulate_normal_operation(snapshot)
        self._record_snapshot_transition(
            snapshot,
            resulting_snapshot,
            event_type="process.breaker.state_changed",
            category="process",
            severity="medium",
            asset_id=resulting_snapshot.grid_interconnect.asset_id,
            action="breaker_close_request",
            requested_value="closed",
            previous_value=snapshot.grid_interconnect.breaker_state,
            resulting_value=resulting_snapshot.grid_interconnect.breaker_state,
            resulting_state={
                "breaker_state": resulting_snapshot.grid_interconnect.breaker_state,
                "plant_power_mw": resulting_snapshot.site.plant_power_mw,
                "export_power_kw": resulting_snapshot.revenue_meter.export_power_kw,
                "active_alarm_codes": list(resulting_snapshot.active_alarm_codes),
            },
            alarm_code=_present_alarm_code(resulting_snapshot, "BREAKER_OPEN"),
            tags=("control-path", "grid", "breaker"),
            event_context=event_context,
        )
        return resulting_snapshot

    def lose_block_communications(
        self,
        snapshot: PlantSnapshot,
        *,
        asset_id: str,
        event_context: SimulationEventContext | None = None,
    ) -> PlantSnapshot:
        """Markiert einen Inverter-Block als Kommunikationsverlust ohne Anlagen-Trip."""

        target_found = False
        inverter_blocks = []
        for block in snapshot.inverter_blocks:
            if block.asset_id != asset_id:
                inverter_blocks.append(block)
                continue

            target_found = True
            inverter_blocks.append(
                block.model_copy(
                    update={
                        "status": "degraded",
                        "communication_state": "lost",
                        "quality": determine_data_quality(status="degraded", communication_state="lost"),
                    }
                )
            )

        if not target_found:
            raise PlantSimulationError(f"unbekannter inverter_block fuer Kommunikationsverlust: {asset_id}")

        site = snapshot.site.model_copy(
            update={
                "availability_state": "partially_available",
                "communications_health": "degraded",
            }
        )
        alarms = _replace_scenario_alarms(
            snapshot.alarms,
            "COMM_LOSS_INVERTER_BLOCK",
        )
        resulting_snapshot = _build_snapshot(
            snapshot,
            site=site,
            inverter_blocks=tuple(inverter_blocks),
            alarms=alarms,
        )
        degraded_block = next(block for block in resulting_snapshot.inverter_blocks if block.asset_id == asset_id)
        previous_block = next(block for block in snapshot.inverter_blocks if block.asset_id == asset_id)
        self._record_snapshot_transition(
            snapshot,
            resulting_snapshot,
            event_type="system.communication.inverter_block_lost",
            category="system",
            severity="medium",
            asset_id=asset_id,
            action="simulate_comm_loss",
            requested_value="lost",
            previous_value=previous_block.communication_state,
            resulting_value=degraded_block.communication_state,
            resulting_state={
                "communication_state": degraded_block.communication_state,
                "quality": degraded_block.quality,
                "site_communications_health": resulting_snapshot.site.communications_health,
                "active_alarm_codes": list(resulting_snapshot.active_alarm_codes),
            },
            alarm_code=_present_alarm_code(resulting_snapshot, "COMM_LOSS_INVERTER_BLOCK"),
            tags=("fault-path", "communications", "inverter-block"),
            event_context=event_context,
        )
        return resulting_snapshot

    def acknowledge_alarm(
        self,
        snapshot: PlantSnapshot,
        *,
        code: str,
        event_context: SimulationEventContext | None = None,
    ) -> PlantSnapshot:
        """Quittiert einen aktiven Alarm, ohne ihn zu loeschen."""

        updated_alarms = []
        target_found = False
        for alarm in snapshot.alarms:
            if alarm.code != code:
                updated_alarms.append(alarm)
                continue

            target_found = True
            if alarm.state == "active_unacknowledged":
                updated_alarms.append(alarm.model_copy(update={"state": "active_acknowledged"}))
                continue
            if alarm.state == "active_acknowledged":
                updated_alarms.append(alarm)
                continue
            raise PlantSimulationError(f"Alarm '{code}' kann im Zustand '{alarm.state}' nicht quittiert werden")

        if not target_found:
            raise PlantSimulationError(f"unbekannter Alarm fuer Quittierung: {code}")

        resulting_snapshot = _build_snapshot(snapshot, alarms=tuple(updated_alarms))
        updated_alarm = resulting_snapshot.alarm_by_code(code)
        if updated_alarm is None:
            raise PlantSimulationError(f"Alarm '{code}' ist nach Quittierung nicht mehr auffindbar")

        self._record_snapshot_transition(
            snapshot,
            resulting_snapshot,
            event_type="alert.alarm_acknowledged",
            category="alert",
            severity=updated_alarm.severity,
            asset_id=_asset_id_for_alarm(resulting_snapshot, code),
            action="acknowledge_alarm",
            requested_value="acknowledge",
            previous_value=snapshot.alarm_by_code(code).state,
            resulting_value=updated_alarm.state,
            resulting_state={
                "alarm_code": updated_alarm.code,
                "alarm_state": updated_alarm.state,
                "active_alarm_count": resulting_snapshot.site.active_alarm_count,
            },
            alarm_code=updated_alarm.code,
            tags=("control-path", "alarm", "acknowledgement"),
            event_context=event_context,
        )
        return resulting_snapshot

    def _record_snapshot_transition(
        self,
        previous_snapshot: PlantSnapshot,
        resulting_snapshot: PlantSnapshot,
        *,
        event_type: str,
        category,
        severity,
        asset_id: str,
        action: str,
        requested_value: Any | None,
        previous_value: Any | None,
        resulting_value: Any | None,
        resulting_state: dict[str, Any],
        alarm_code: str | None,
        tags: tuple[str, ...],
        event_context: SimulationEventContext | None,
    ) -> None:
        if self.event_recorder is None:
            return

        context = self.default_event_context if event_context is None else event_context
        event = self.event_recorder.build_event(
            event_type=event_type,
            category=category,
            severity=severity,
            source_ip=context.source_ip,
            actor_type=context.actor_type,
            component=PLANT_SIM_COMPONENT,
            asset_id=asset_id,
            action=action,
            result="accepted",
            correlation_id=context.correlation_id,
            session_id=context.session_id,
            causation_id=context.causation_id,
            protocol=context.protocol,
            service=context.service,
            requested_value=requested_value,
            previous_value=previous_value,
            resulting_value=resulting_value,
            resulting_state=resulting_state,
            alarm_code=alarm_code,
            tags=tags,
        )
        alert = _build_alert_for_snapshot(
            self.event_recorder,
            event=event,
            previous_snapshot=previous_snapshot,
            resulting_snapshot=resulting_snapshot,
            alarm_code=alarm_code,
        )
        self.event_recorder.record(
            event,
            current_state_updates=_snapshot_state_updates(resulting_snapshot),
            alert=alert,
        )


def _with_rebalanced_block_power(snapshot: PlantSnapshot, total_power_kw: float) -> tuple:
    distribution = _distribute_power_kw(snapshot.inverter_blocks, total_power_kw)
    return tuple(
        block.model_copy(
            update={
                "status": "online",
                "communication_state": "healthy",
                "quality": determine_data_quality(status="online", communication_state="healthy"),
                "availability_pct": 100,
                "block_power_kw": distribution[index],
            }
        )
        for index, block in enumerate(snapshot.inverter_blocks)
    )


def _distribute_power_kw_for_controls(
    blocks: tuple,
    *,
    total_power_kw: float,
    baseline_block_power_kw: dict[str, float],
    block_control_states: dict[str, tuple[bool, float]],
) -> dict[str, float]:
    weights = [max(baseline_block_power_kw.get(block.asset_id, block.block_power_kw), 1.0) for block in blocks]
    total_weight = sum(weights)
    if total_weight <= 0:
        return {block.asset_id: 0.0 for block in blocks}

    distribution: dict[str, float] = {}
    remaining_power_kw = round(total_power_kw, 1)
    for index, block in enumerate(blocks):
        weight = weights[index]
        if index == len(blocks) - 1:
            base_share = round(remaining_power_kw, 1)
        else:
            base_share = round(total_power_kw * (weight / total_weight), 1)
            remaining_power_kw = round(remaining_power_kw - base_share, 1)

        block_enable_request, block_power_limit_pct = block_control_states[block.asset_id]
        if not block_enable_request:
            distribution[block.asset_id] = 0.0
            continue
        distribution[block.asset_id] = round(base_share * (block_power_limit_pct / 100), 1)
    return distribution


def _distribute_power_kw(blocks: tuple, total_power_kw: float) -> tuple[float, ...]:
    if not blocks:
        return ()

    baseline_weights = [max(block.block_power_kw, 0.0) for block in blocks]
    total_weight = sum(baseline_weights)
    if total_weight <= 0:
        baseline_weights = [1.0 for _ in blocks]
        total_weight = float(len(blocks))

    remaining_power_kw = round(total_power_kw, 1)
    distribution: list[float] = []
    for index, weight in enumerate(baseline_weights):
        if index == len(baseline_weights) - 1:
            distribution.append(round(remaining_power_kw, 1))
            continue

        share = round(total_power_kw * (weight / total_weight), 1)
        distribution.append(share)
        remaining_power_kw = round(remaining_power_kw - share, 1)
    return tuple(distribution)


def _replace_scenario_alarms(alarms: tuple[PlantAlarm, ...], *active_alarm_codes: str | None) -> tuple[PlantAlarm, ...]:
    requested_active_codes = {code for code in active_alarm_codes if code is not None}
    updated_alarms: list[PlantAlarm] = []
    seen_scenario_codes: set[str] = set()

    for alarm in alarms:
        if alarm.code not in SCENARIO_ALARM_CODES:
            updated_alarms.append(alarm)
            continue

        seen_scenario_codes.add(alarm.code)
        if alarm.code in requested_active_codes:
            next_state = alarm.state if alarm.state in ("active_unacknowledged", "active_acknowledged") else "active_unacknowledged"
            updated_alarms.append(alarm.model_copy(update={"state": next_state}))
            continue

        if alarm.state in ("active_unacknowledged", "active_acknowledged"):
            updated_alarms.append(alarm.model_copy(update={"state": "cleared"}))
        else:
            updated_alarms.append(alarm)

    for code in requested_active_codes - seen_scenario_codes:
        definition = SCENARIO_ALARM_DEFINITIONS[code]
        updated_alarms.append(
            PlantAlarm(
                code=code,
                category=definition["category"],
                severity=definition["severity"],
                state="active_unacknowledged",
            )
        )

    return tuple(updated_alarms)


def _build_snapshot(
    snapshot: PlantSnapshot,
    *,
    site=None,
    power_plant_controller=None,
    inverter_blocks=None,
    revenue_meter=None,
    grid_interconnect=None,
    alarms: tuple[PlantAlarm, ...] | None = None,
) -> PlantSnapshot:
    final_alarms = snapshot.alarms if alarms is None else alarms
    base_site = snapshot.site if site is None else site
    final_site = base_site.model_copy(update={"active_alarm_count": len(_active_alarms(final_alarms))})
    power_plant_controller_model = snapshot.power_plant_controller if power_plant_controller is None else power_plant_controller
    final_revenue_meter = snapshot.revenue_meter if revenue_meter is None else revenue_meter
    final_grid = snapshot.grid_interconnect if grid_interconnect is None else grid_interconnect
    return PlantSnapshot(
        fixture_name=snapshot.fixture_name,
        start_time=snapshot.start_time,
        observed_at=snapshot.observed_at,
        site=final_site,
        power_plant_controller=power_plant_controller_model.model_copy(
            update={
                "quality": determine_data_quality(
                    status=power_plant_controller_model.status,
                    communication_state=power_plant_controller_model.communication_state,
                )
            }
        ),
        inverter_blocks=snapshot.inverter_blocks if inverter_blocks is None else inverter_blocks,
        weather_station=snapshot.weather_station,
        revenue_meter=final_revenue_meter.model_copy(
            update={
                "quality": determine_data_quality(
                    status=final_revenue_meter.status,
                    communication_state=final_revenue_meter.communication_state,
                )
            }
        ),
        grid_interconnect=final_grid.model_copy(
            update={
                "quality": determine_data_quality(
                    status=final_grid.status,
                    communication_state=final_grid.communication_state,
                )
            }
        ),
        alarms=final_alarms,
    )


def _active_alarms(alarms: tuple[PlantAlarm, ...]) -> tuple[PlantAlarm, ...]:
    return tuple(alarm for alarm in alarms if alarm.is_active)


def _present_alarm_code(snapshot: PlantSnapshot, code: str) -> str | None:
    return code if snapshot.alarm_by_code(code) is not None else None


def _build_alert_for_snapshot(
    recorder: EventRecorder,
    *,
    event,
    previous_snapshot: PlantSnapshot,
    resulting_snapshot: PlantSnapshot,
    alarm_code: str | None,
):
    if alarm_code is None:
        return None

    alarm = resulting_snapshot.alarm_by_code(alarm_code)
    if alarm is None:
        return None

    previous_alarm_state = None
    previous_alarm = previous_snapshot.alarm_by_code(alarm_code)
    if previous_alarm is not None:
        previous_alarm_state = previous_alarm.state

    return recorder.build_alert(
        event=event,
        alarm_code=alarm.code,
        severity=alarm.severity,
        state=alarm.state,
        message=(
            f"Alarm {alarm.code} wechselte von {previous_alarm_state or 'missing'} auf {alarm.state}"
        ),
    )


def _snapshot_state_updates(snapshot: PlantSnapshot) -> dict[str, Any]:
    return {
        "site": snapshot.site.model_dump(mode="json"),
        "power_plant_controller": snapshot.power_plant_controller.model_dump(mode="json"),
        "inverter_blocks": [block.model_dump(mode="json") for block in snapshot.inverter_blocks],
        "weather_station": snapshot.weather_station.model_dump(mode="json"),
        "revenue_meter": snapshot.revenue_meter.model_dump(mode="json"),
        "grid_interconnect": snapshot.grid_interconnect.model_dump(mode="json"),
        "alarms": [alarm.model_dump(mode="json") for alarm in snapshot.alarms],
    }


def _asset_id_for_alarm(snapshot: PlantSnapshot, code: str) -> str:
    if code == "PLANT_CURTAILED":
        return snapshot.power_plant_controller.asset_id
    if code == "BREAKER_OPEN":
        return snapshot.grid_interconnect.asset_id
    if code == "COMM_LOSS_INVERTER_BLOCK":
        for block in snapshot.inverter_blocks:
            if block.communication_state == "lost":
                return block.asset_id
    return snapshot.power_plant_controller.asset_id


def _require_block(snapshot: PlantSnapshot, asset_id: str):
    for block in snapshot.inverter_blocks:
        if block.asset_id == asset_id:
            return block
    raise PlantSimulationError(f"unbekannter inverter_block: {asset_id}")


def _is_block_disabled(block) -> bool:
    return block.status == "offline" and block.availability_pct == 0


def _derived_block_power_limit_pct(
    *,
    snapshot: PlantSnapshot,
    asset_id: str,
    baseline_block_power_kw: dict[str, float],
) -> float:
    block = _require_block(snapshot, asset_id)
    if _is_block_disabled(block):
        return 0.0
    baseline_power_kw = max(baseline_block_power_kw.get(asset_id, block.block_power_kw), 0.0)
    if baseline_power_kw <= 0:
        return 100.0
    global_limit_factor = snapshot.site.plant_power_limit_pct / 100
    if global_limit_factor <= 0:
        return 100.0
    derived_limit_pct = (block.block_power_kw / (baseline_power_kw * global_limit_factor)) * 100
    return round(max(0.0, min(100.0, derived_limit_pct)), 1)


def _current_block_control_states(
    *,
    snapshot: PlantSnapshot,
    baseline_block_power_kw: dict[str, float],
) -> dict[str, tuple[bool, float]]:
    return {
        block.asset_id: (
            not _is_block_disabled(block),
            _derived_block_power_limit_pct(
                snapshot=snapshot,
                asset_id=block.asset_id,
                baseline_block_power_kw=baseline_block_power_kw,
            ),
        )
        for block in snapshot.inverter_blocks
    }
