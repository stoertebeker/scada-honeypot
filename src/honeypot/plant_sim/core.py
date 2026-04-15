"""Deterministische Simulationslogik fuer die Kern-Szenarien von V1."""

from __future__ import annotations

from dataclasses import dataclass

from honeypot.asset_domain import PlantSnapshot

SCENARIO_ALARM_CODES = frozenset(
    {
        "PLANT_CURTAILED",
        "BREAKER_OPEN",
        "COMM_LOSS_INVERTER_BLOCK",
    }
)


class PlantSimulationError(ValueError):
    """Signalisiert ungueltige Simulationskommandos oder Startzustaende."""


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
        active_alarm_codes = _replace_scenario_alarm_codes(snapshot.active_alarm_codes)
        return _build_snapshot(
            snapshot,
            site=site,
            power_plant_controller=power_plant_controller,
            inverter_blocks=inverter_blocks,
            revenue_meter=revenue_meter,
            grid_interconnect=grid_interconnect,
            active_alarm_codes=active_alarm_codes,
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
        active_alarm_codes = _replace_scenario_alarm_codes(
            base_snapshot.active_alarm_codes,
            "PLANT_CURTAILED" if active_power_limit_pct < 100 else None,
        )
        return _build_snapshot(
            base_snapshot,
            site=site,
            power_plant_controller=power_plant_controller,
            inverter_blocks=inverter_blocks,
            revenue_meter=revenue_meter,
            active_alarm_codes=active_alarm_codes,
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
        active_alarm_codes = _replace_scenario_alarm_codes(base_snapshot.active_alarm_codes, "BREAKER_OPEN")
        return _build_snapshot(
            base_snapshot,
            site=site,
            inverter_blocks=inverter_blocks,
            revenue_meter=revenue_meter,
            grid_interconnect=grid_interconnect,
            active_alarm_codes=active_alarm_codes,
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
                        "quality": "stale",
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
        active_alarm_codes = _replace_scenario_alarm_codes(
            base_snapshot.active_alarm_codes,
            "COMM_LOSS_INVERTER_BLOCK",
        )
        return _build_snapshot(
            base_snapshot,
            site=site,
            inverter_blocks=tuple(inverter_blocks),
            active_alarm_codes=active_alarm_codes,
        )


def _with_rebalanced_block_power(snapshot: PlantSnapshot, total_power_kw: float) -> tuple:
    distribution = _distribute_power_kw(snapshot.inverter_blocks, total_power_kw)
    return tuple(
        block.model_copy(
            update={
                "status": "online",
                "communication_state": "healthy",
                "quality": "good",
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


def _replace_scenario_alarm_codes(active_alarm_codes: tuple[str, ...], *new_alarm_codes: str | None) -> tuple[str, ...]:
    remaining_codes = [code for code in active_alarm_codes if code not in SCENARIO_ALARM_CODES]
    for code in new_alarm_codes:
        if code is None or code in remaining_codes:
            continue
        remaining_codes.append(code)
    return tuple(remaining_codes)


def _build_snapshot(
    snapshot: PlantSnapshot,
    *,
    site=None,
    power_plant_controller=None,
    inverter_blocks=None,
    revenue_meter=None,
    grid_interconnect=None,
    active_alarm_codes: tuple[str, ...] | None = None,
) -> PlantSnapshot:
    final_alarm_codes = snapshot.active_alarm_codes if active_alarm_codes is None else active_alarm_codes
    base_site = snapshot.site if site is None else site
    final_site = base_site.model_copy(update={"active_alarm_count": len(final_alarm_codes)})
    return PlantSnapshot(
        fixture_name=snapshot.fixture_name,
        start_time=snapshot.start_time,
        site=final_site,
        power_plant_controller=snapshot.power_plant_controller
        if power_plant_controller is None
        else power_plant_controller,
        inverter_blocks=snapshot.inverter_blocks if inverter_blocks is None else inverter_blocks,
        weather_station=snapshot.weather_station,
        revenue_meter=snapshot.revenue_meter if revenue_meter is None else revenue_meter,
        grid_interconnect=snapshot.grid_interconnect if grid_interconnect is None else grid_interconnect,
        active_alarm_codes=final_alarm_codes,
    )
