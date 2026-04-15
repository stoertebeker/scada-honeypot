"""Deterministische Simulationslogik fuer die Kern-Szenarien von V1."""

from __future__ import annotations

from dataclasses import dataclass

from honeypot.asset_domain import PlantAlarm, PlantSnapshot
from honeypot.asset_domain.models import AssetStatus, CommunicationState, DataQuality

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


class PlantSimulationError(ValueError):
    """Signalisiert ungueltige Simulationskommandos oder Startzustaende."""


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

    @classmethod
    def from_snapshot(cls, snapshot: PlantSnapshot) -> "PlantSimulator":
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

        return cls(nominal_capacity_kw=baseline_output_kw / baseline_irradiance_factor)

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

    def apply_curtailment(self, snapshot: PlantSnapshot, *, active_power_limit_pct: int) -> PlantSnapshot:
        """Reduziert die Parkleistung ueber den PPC-Wirkleistungsgrenzwert."""

        if not 0 <= active_power_limit_pct <= 100:
            raise PlantSimulationError("active_power_limit_pct muss im Bereich 0..100 liegen")

        base_snapshot = self.simulate_normal_operation(snapshot)
        total_power_kw = round(
            self.estimate_available_power_kw(base_snapshot) * (active_power_limit_pct / 100),
            1,
        )
        inverter_blocks = _with_rebalanced_block_power(base_snapshot, total_power_kw)
        site = base_snapshot.site.model_copy(
            update={
                "operating_mode": "normal" if active_power_limit_pct == 100 else "curtailed",
                "plant_power_mw": round(total_power_kw / 1000, 3),
                "plant_power_limit_pct": active_power_limit_pct,
            }
        )
        power_plant_controller = base_snapshot.power_plant_controller.model_copy(
            update={
                "active_power_limit_pct": active_power_limit_pct,
            }
        )
        revenue_meter = base_snapshot.revenue_meter.model_copy(
            update={
                "export_power_kw": total_power_kw,
            }
        )
        alarms = _replace_scenario_alarms(
            base_snapshot.alarms,
            "PLANT_CURTAILED" if active_power_limit_pct < 100 else None,
        )
        return _build_snapshot(
            base_snapshot,
            site=site,
            power_plant_controller=power_plant_controller,
            inverter_blocks=inverter_blocks,
            revenue_meter=revenue_meter,
            alarms=alarms,
        )

    def open_breaker(self, snapshot: PlantSnapshot) -> PlantSnapshot:
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
        return _build_snapshot(
            base_snapshot,
            site=site,
            inverter_blocks=inverter_blocks,
            revenue_meter=revenue_meter,
            grid_interconnect=grid_interconnect,
            alarms=alarms,
        )

    def lose_block_communications(self, snapshot: PlantSnapshot, *, asset_id: str) -> PlantSnapshot:
        """Markiert einen Inverter-Block als Kommunikationsverlust ohne Anlagen-Trip."""

        base_snapshot = self.simulate_normal_operation(snapshot)
        target_found = False
        inverter_blocks = []
        for block in base_snapshot.inverter_blocks:
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

        site = base_snapshot.site.model_copy(
            update={
                "availability_state": "partially_available",
                "communications_health": "degraded",
            }
        )
        alarms = _replace_scenario_alarms(
            base_snapshot.alarms,
            "COMM_LOSS_INVERTER_BLOCK",
        )
        return _build_snapshot(
            base_snapshot,
            site=site,
            inverter_blocks=tuple(inverter_blocks),
            alarms=alarms,
        )

    def acknowledge_alarm(self, snapshot: PlantSnapshot, *, code: str) -> PlantSnapshot:
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

        return _build_snapshot(snapshot, alarms=tuple(updated_alarms))


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
