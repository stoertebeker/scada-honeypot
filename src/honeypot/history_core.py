"""Verdichtete Anlagenhistorie fuer HMI-Trends und Ops-Wartung."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from honeypot.asset_domain import PlantSnapshot
from honeypot.time_core import ensure_utc_datetime


@dataclass(frozen=True, slots=True)
class PlantHistorySample:
    """Ein persistierbarer Verlaufspunkt mit Fokus auf Erzeugungswerte."""

    observed_at: datetime
    plant_power_mw: float
    active_power_limit_pct: float
    irradiance_w_m2: float
    export_power_mw: float
    block_power_kw: tuple[tuple[str, float], ...]
    export_energy_mwh_total: float | None = None

    @classmethod
    def from_snapshot(cls, snapshot: PlantSnapshot) -> "PlantHistorySample":
        return cls(
            observed_at=ensure_utc_datetime(snapshot.observed_at),
            plant_power_mw=snapshot.site.plant_power_mw,
            active_power_limit_pct=snapshot.power_plant_controller.active_power_limit_pct,
            irradiance_w_m2=float(snapshot.weather_station.irradiance_w_m2),
            export_power_mw=snapshot.revenue_meter.export_power_kw / 1000,
            block_power_kw=tuple((block.asset_id, block.block_power_kw) for block in snapshot.inverter_blocks),
            export_energy_mwh_total=snapshot.revenue_meter.export_energy_mwh_total,
        )


def apply_history_sample_to_snapshot(snapshot: PlantSnapshot, sample: PlantHistorySample) -> PlantSnapshot:
    """Richtet den sichtbaren Runtime-Snapshot am letzten Verlaufspunkt aus."""

    observed_at = ensure_utc_datetime(sample.observed_at)
    block_power_by_asset = dict(sample.block_power_kw)
    return snapshot.model_copy(
        update={
            "observed_at": observed_at,
            "site": snapshot.site.model_copy(
                update={
                    "plant_power_mw": sample.plant_power_mw,
                    "plant_power_limit_pct": sample.active_power_limit_pct,
                }
            ),
            "power_plant_controller": snapshot.power_plant_controller.model_copy(
                update={
                    "last_update_ts": observed_at,
                    "active_power_limit_pct": sample.active_power_limit_pct,
                }
            ),
            "inverter_blocks": tuple(
                block.model_copy(
                    update={
                        "last_update_ts": observed_at,
                        "block_power_kw": block_power_by_asset.get(block.asset_id, block.block_power_kw),
                    }
                )
                for block in snapshot.inverter_blocks
            ),
            "weather_station": snapshot.weather_station.model_copy(
                update={
                    "last_update_ts": observed_at,
                    "irradiance_w_m2": round(sample.irradiance_w_m2),
                }
            ),
            "revenue_meter": snapshot.revenue_meter.model_copy(
                update={
                    "last_update_ts": observed_at,
                    "export_power_kw": sample.export_power_mw * 1000,
                    "export_energy_mwh_total": sample.export_energy_mwh_total,
                }
            ),
            "grid_interconnect": snapshot.grid_interconnect.model_copy(update={"last_update_ts": observed_at}),
        }
    )
