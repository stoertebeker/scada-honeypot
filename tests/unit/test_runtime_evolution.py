from __future__ import annotations

from datetime import UTC, datetime, timedelta

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.plant_sim import PlantSimulator
from honeypot.protocol_modbus import ReadOnlyRegisterMap
from honeypot.runtime_evolution import (
    BackgroundPlantEvolutionService,
    TrendHistoryBuffer,
    seed_plant_history_if_empty,
    trend_history_capacity,
)
from honeypot.storage import SQLiteEventStore
from honeypot.time_core import FrozenClock
from honeypot.weather_core import DeterministicDiurnalWeatherProvider


def build_snapshot() -> PlantSnapshot:
    return PlantSnapshot.from_fixture(load_plant_fixture("normal_operation"))


def test_background_evolution_service_advances_observed_at_and_asset_freshness() -> None:
    snapshot = build_snapshot()
    clock = FrozenClock(snapshot.start_time)
    register_map = ReadOnlyRegisterMap(snapshot)
    history = TrendHistoryBuffer(max_samples=8)
    service = BackgroundPlantEvolutionService(
        register_map=register_map,
        history=history,
        clock=clock,
        interval_seconds=5.0,
    )

    first_snapshot = service.evolve_once()
    clock.advance(timedelta(minutes=5))
    second_snapshot = service.evolve_once()

    assert first_snapshot.observed_at == datetime(2026, 4, 1, 10, 0, 1, tzinfo=UTC)
    assert second_snapshot.observed_at == datetime(2026, 4, 1, 10, 5, tzinfo=UTC)
    assert second_snapshot.power_plant_controller.last_update_ts == second_snapshot.observed_at
    assert all(block.last_update_ts == second_snapshot.observed_at for block in second_snapshot.inverter_blocks)
    assert second_snapshot.weather_station.last_update_ts == second_snapshot.observed_at
    assert second_snapshot.revenue_meter.last_update_ts == second_snapshot.observed_at
    assert second_snapshot.grid_interconnect.last_update_ts == second_snapshot.observed_at
    assert tuple(sample.observed_at for sample in history.snapshot()) == (
        datetime(2026, 4, 1, 10, 0, 1, tzinfo=UTC),
        datetime(2026, 4, 1, 10, 5, tzinfo=UTC),
    )


def test_trend_history_capacity_scales_with_window_and_interval() -> None:
    assert trend_history_capacity(window_minutes=180, interval_seconds=5.0) == 2161
    assert trend_history_capacity(window_minutes=1, interval_seconds=60.0) == 2


def test_background_evolution_service_drives_weather_and_power_from_provider() -> None:
    snapshot = build_snapshot()
    clock = FrozenClock(snapshot.start_time)
    register_map = ReadOnlyRegisterMap(snapshot)
    history = TrendHistoryBuffer(max_samples=8)
    service = BackgroundPlantEvolutionService(
        register_map=register_map,
        history=history,
        clock=clock,
        simulator=PlantSimulator.from_snapshot(snapshot),
        weather_provider=DeterministicDiurnalWeatherProvider(),
        timezone="Europe/Berlin",
        weather_latitude=52.52,
        weather_longitude=13.405,
        weather_elevation_m=34,
        interval_seconds=5.0,
    )

    midday_snapshot = service.evolve_once()
    clock.advance(timedelta(hours=10))
    night_snapshot = service.evolve_once()

    assert midday_snapshot.weather_station.quality == "good"
    assert night_snapshot.weather_station.irradiance_w_m2 < midday_snapshot.weather_station.irradiance_w_m2
    assert night_snapshot.site.plant_power_mw < midday_snapshot.site.plant_power_mw
    assert night_snapshot.revenue_meter.export_power_kw < midday_snapshot.revenue_meter.export_power_kw
    assert night_snapshot.revenue_meter.export_energy_mwh_total is not None
    assert night_snapshot.revenue_meter.export_energy_mwh_total > 0
    assert night_snapshot.revenue_meter.grid_voltage_v is not None
    assert night_snapshot.revenue_meter.grid_frequency_hz is not None


def test_seed_plant_history_creates_one_month_generation_history(tmp_path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "history.db")
    clock = FrozenClock(datetime(2026, 4, 27, 12, 0, tzinfo=UTC))

    inserted_count = seed_plant_history_if_empty(
        history_store=store,
        snapshot=snapshot,
        simulator=PlantSimulator.from_snapshot(snapshot),
        clock=clock,
        timezone="Europe/Berlin",
        weather_latitude=53.5511,
        weather_longitude=9.9937,
        weather_elevation_m=15,
    )
    second_count = seed_plant_history_if_empty(
        history_store=store,
        snapshot=snapshot,
        simulator=PlantSimulator.from_snapshot(snapshot),
        clock=clock,
        timezone="Europe/Berlin",
        weather_latitude=53.5511,
        weather_longitude=9.9937,
        weather_elevation_m=15,
    )

    history = store.fetch_plant_history()

    assert inserted_count == 721
    assert second_count == 0
    assert store.count_rows("plant_history") == 721
    assert history[0].observed_at == datetime(2026, 3, 28, 12, 0, tzinfo=UTC)
    assert history[-1].observed_at == clock.now()
    assert history[-1].export_energy_mwh_total is not None
    assert history[-1].export_energy_mwh_total > history[0].export_energy_mwh_total
    assert any(sample.export_power_mw > 0 for sample in history)
    assert all(sample.observed_at >= clock.now() - timedelta(days=30) for sample in history)
