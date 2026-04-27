from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.history_core import PlantHistorySample, apply_history_sample_to_snapshot
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
from honeypot.weather_core import DeterministicDiurnalWeatherProvider, PlausibleHistoricalWeatherProvider, WeatherObservation


def build_snapshot() -> PlantSnapshot:
    return PlantSnapshot.from_fixture(load_plant_fixture("normal_operation"))


class RecordingMinuteWeatherProvider:
    provider_name = "deterministic"

    def __init__(self) -> None:
        self.observed_at_values: list[datetime] = []

    def observe(
        self,
        *,
        observed_at: datetime,
        timezone: str,
        latitude: float | None = None,
        longitude: float | None = None,
        elevation_m: float | None = None,
    ) -> WeatherObservation:
        self.observed_at_values.append(observed_at)
        irradiance = 600 + observed_at.minute
        return WeatherObservation(
            provider="deterministic",
            observed_at=observed_at,
            local_time=observed_at,
            quality="good",
            confidence_pct_x10=1000,
            irradiance_w_m2=irradiance,
            ambient_temperature_c=22.0,
            module_temperature_c=round(22.0 + irradiance * 0.015, 1),
            wind_speed_m_s=3.0,
        )


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
        datetime(2026, 4, 1, 10, 0, tzinfo=UTC),
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


def test_background_evolution_uses_stable_minute_weather_values() -> None:
    snapshot = build_snapshot()
    clock = FrozenClock(datetime(2026, 4, 27, 10, 30, 5, tzinfo=UTC))
    register_map = ReadOnlyRegisterMap(snapshot)
    history = TrendHistoryBuffer(max_samples=8)
    weather_provider = RecordingMinuteWeatherProvider()
    service = BackgroundPlantEvolutionService(
        register_map=register_map,
        history=history,
        clock=clock,
        simulator=PlantSimulator.from_snapshot(snapshot),
        weather_provider=weather_provider,
        timezone="Europe/Berlin",
        weather_latitude=53.5511,
        weather_longitude=9.9937,
        weather_elevation_m=15,
    )

    first_snapshot = service.evolve_once()
    clock.advance(timedelta(seconds=20))
    second_snapshot = service.evolve_once()
    clock.advance(timedelta(minutes=1))
    third_snapshot = service.evolve_once()

    assert weather_provider.observed_at_values == [
        datetime(2026, 4, 27, 10, 30, 30, tzinfo=UTC),
        datetime(2026, 4, 27, 10, 30, 30, tzinfo=UTC),
        datetime(2026, 4, 27, 10, 31, 30, tzinfo=UTC),
    ]
    assert first_snapshot.weather_station.irradiance_w_m2 == second_snapshot.weather_station.irradiance_w_m2
    assert first_snapshot.site.plant_power_mw == second_snapshot.site.plant_power_mw
    assert third_snapshot.weather_station.irradiance_w_m2 != second_snapshot.weather_station.irradiance_w_m2
    assert tuple(sample.observed_at for sample in history.snapshot()) == (
        datetime(2026, 4, 27, 10, 30, tzinfo=UTC),
        datetime(2026, 4, 27, 10, 31, tzinfo=UTC),
    )


def test_background_evolution_does_not_latch_history_power_as_inverter_limit() -> None:
    snapshot = build_snapshot()
    simulator = PlantSimulator.from_snapshot(snapshot)
    restored_snapshot = apply_history_sample_to_snapshot(
        snapshot,
        PlantHistorySample(
            observed_at=datetime(2026, 4, 27, 3, 0, tzinfo=UTC),
            plant_power_mw=0.0,
            active_power_limit_pct=100.0,
            irradiance_w_m2=0.0,
            export_power_mw=0.0,
            block_power_kw=tuple((block.asset_id, 0.0) for block in snapshot.inverter_blocks),
            export_energy_mwh_total=120.0,
        ),
    )
    clock = FrozenClock(datetime(2026, 4, 27, 10, 30, tzinfo=UTC))
    register_map = ReadOnlyRegisterMap(restored_snapshot, simulator=simulator)
    service = BackgroundPlantEvolutionService(
        register_map=register_map,
        history=TrendHistoryBuffer(max_samples=8),
        clock=clock,
        simulator=simulator,
        weather_provider=DeterministicDiurnalWeatherProvider(),
        timezone="Europe/Berlin",
        weather_latitude=53.5511,
        weather_longitude=9.9937,
        weather_elevation_m=15,
    )

    evolved_snapshot = service.evolve_once()

    assert evolved_snapshot.weather_station.irradiance_w_m2 > 500
    assert evolved_snapshot.site.plant_power_mw > 3.0
    assert evolved_snapshot.revenue_meter.export_power_kw > 3000
    assert all(block.block_power_kw > 0 for block in evolved_snapshot.inverter_blocks)


def test_background_evolution_preserves_latched_inverter_block_controls() -> None:
    snapshot = build_snapshot()
    simulator = PlantSimulator.from_snapshot(snapshot)
    register_map = ReadOnlyRegisterMap(snapshot, simulator=simulator)
    register_map.set_block_control_state(
        asset_id="invb-02",
        block_enable_request=True,
        block_power_limit_pct=40.0,
    )
    service = BackgroundPlantEvolutionService(
        register_map=register_map,
        history=TrendHistoryBuffer(max_samples=8),
        clock=FrozenClock(datetime(2026, 4, 27, 10, 30, tzinfo=UTC)),
        simulator=simulator,
        weather_provider=DeterministicDiurnalWeatherProvider(),
        timezone="Europe/Berlin",
        weather_latitude=53.5511,
        weather_longitude=9.9937,
        weather_elevation_m=15,
    )

    evolved_snapshot = service.evolve_once()
    limited_block = next(block for block in evolved_snapshot.inverter_blocks if block.asset_id == "invb-02")
    unrestricted_block = next(block for block in evolved_snapshot.inverter_blocks if block.asset_id == "invb-01")

    assert register_map.get_block_control_states()["invb-02"] == (True, 40.0)
    assert limited_block.block_power_kw < unrestricted_block.block_power_kw * 0.5


def test_background_evolution_preserves_dc_disconnect_state() -> None:
    snapshot = build_snapshot()
    simulator = PlantSimulator.from_snapshot(snapshot)
    register_map = ReadOnlyRegisterMap(snapshot, simulator=simulator)
    register_map.set_block_dc_disconnect_state(asset_id="invb-02", dc_disconnect_state="open")
    service = BackgroundPlantEvolutionService(
        register_map=register_map,
        history=TrendHistoryBuffer(max_samples=8),
        clock=FrozenClock(datetime(2026, 4, 27, 10, 30, tzinfo=UTC)),
        simulator=simulator,
        weather_provider=DeterministicDiurnalWeatherProvider(),
        timezone="Europe/Berlin",
        weather_latitude=53.5511,
        weather_longitude=9.9937,
        weather_elevation_m=15,
    )

    evolved_snapshot = service.evolve_once()
    isolated_block = next(block for block in evolved_snapshot.inverter_blocks if block.asset_id == "invb-02")
    active_block = next(block for block in evolved_snapshot.inverter_blocks if block.asset_id == "invb-01")

    assert isolated_block.dc_disconnect_state == "open"
    assert isolated_block.status == "online"
    assert isolated_block.communication_state == "healthy"
    assert isolated_block.block_power_kw == 0.0
    assert active_block.block_power_kw > 0
    assert evolved_snapshot.site.plant_power_mw < snapshot.site.plant_power_mw


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


def test_seed_plant_history_uses_plausible_weather_variation(tmp_path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "history.db")
    clock = FrozenClock(datetime(2026, 4, 27, 12, 0, tzinfo=UTC))

    seed_plant_history_if_empty(
        history_store=store,
        snapshot=snapshot,
        simulator=PlantSimulator.from_snapshot(snapshot),
        clock=clock,
        timezone="Europe/Berlin",
        weather_latitude=53.5511,
        weather_longitude=9.9937,
        weather_elevation_m=15,
        weather_provider=PlausibleHistoricalWeatherProvider(),
    )

    history = store.fetch_plant_history()
    daily_energy_mwh: dict[date, float] = {}
    daily_peak_mw: dict[date, float] = {}
    for sample in history:
        local_date = sample.observed_at.date()
        daily_energy_mwh[local_date] = daily_energy_mwh.get(local_date, 0.0) + sample.export_power_mw
        daily_peak_mw[local_date] = max(daily_peak_mw.get(local_date, 0.0), sample.plant_power_mw)

    complete_daily_energy = tuple(value for value in daily_energy_mwh.values() if value > 0)
    complete_daily_peaks = tuple(value for value in daily_peak_mw.values() if value > 0)

    assert len(complete_daily_energy) >= 25
    assert max(complete_daily_energy) - min(complete_daily_energy) > 10
    assert len({round(value, 1) for value in complete_daily_peaks}) >= 8
