from __future__ import annotations

from datetime import UTC, datetime, timedelta

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.protocol_modbus import ReadOnlyRegisterMap
from honeypot.runtime_evolution import BackgroundPlantEvolutionService, TrendHistoryBuffer, trend_history_capacity
from honeypot.time_core import FrozenClock


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
