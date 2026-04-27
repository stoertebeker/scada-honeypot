"""Hintergrund-Evolution fuer tickende Snapshot-Zeit und kleine Trendhistorie."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from math import ceil
from threading import Event, Lock, Thread
from typing import Any

from honeypot.asset_domain import PlantSnapshot
from honeypot.history_core import PlantHistorySample
from honeypot.plant_sim import PlantSimulator
from honeypot.protocol_modbus import ReadOnlyRegisterMap
from honeypot.time_core import Clock, SystemClock, ensure_utc_datetime
from honeypot.weather_core import DeterministicDiurnalWeatherProvider, WeatherObservationProvider

PLANT_HISTORY_RETENTION_DAYS = 30
PLANT_HISTORY_SEED_STEP_MINUTES = 60
PLANT_HISTORY_LIVE_SAMPLE_SECONDS = 60


TrendSample = PlantHistorySample


@dataclass(slots=True)
class TrendHistoryBuffer:
    """Kleine In-Memory-Historie fuer sichtbare Mini-Zeitreihen."""

    max_samples: int
    _samples: deque[TrendSample] = field(default_factory=deque, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.max_samples < 2:
            raise ValueError("max_samples muss mindestens 2 sein")
        self._samples = deque(maxlen=self.max_samples)

    def append_snapshot(self, snapshot: PlantSnapshot) -> TrendSample:
        sample = _trend_sample_for_minute(snapshot)
        with self._lock:
            if self._samples and self._samples[-1].observed_at == sample.observed_at:
                self._samples[-1] = sample
            else:
                self._samples.append(sample)
        return sample

    def snapshot(self) -> tuple[TrendSample, ...]:
        with self._lock:
            return tuple(self._samples)


@dataclass(slots=True)
class BackgroundPlantEvolutionService:
    """Fuehrt die gemeinsame Anlagenzeit im Hintergrund fort."""

    register_map: ReadOnlyRegisterMap
    history: TrendHistoryBuffer
    clock: Clock = field(default_factory=SystemClock)
    simulator: PlantSimulator | None = None
    weather_provider: WeatherObservationProvider | None = None
    timezone: str = "UTC"
    weather_latitude: float | None = None
    weather_longitude: float | None = None
    weather_elevation_m: float | None = None
    interval_seconds: float = 5.0
    history_store: Any | None = None
    history_retention_days: int = PLANT_HISTORY_RETENTION_DAYS
    history_live_sample_seconds: int = PLANT_HISTORY_LIVE_SAMPLE_SECONDS
    _stop_event: Event = field(default_factory=Event, init=False, repr=False)
    _wake_event: Event = field(default_factory=Event, init=False, repr=False)
    _thread: Thread | None = field(default=None, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _evolution_count: int = field(default=0, init=False, repr=False)
    _last_persisted_history_at: datetime | None = field(default=None, init=False, repr=False)

    @property
    def evolution_count(self) -> int:
        with self._lock:
            return self._evolution_count

    def start_in_thread(self) -> "BackgroundPlantEvolutionService":
        thread = self._thread
        if thread is not None and thread.is_alive():
            return self

        self.evolve_once()
        self._stop_event.clear()
        self._wake_event.clear()
        self._thread = Thread(
            target=self._run_loop,
            name="plant-evolution",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=max(self.interval_seconds, 0.1) + 1.0)
        self._thread = None

    def wake(self) -> None:
        self._wake_event.set()

    def evolve_once(self) -> PlantSnapshot:
        snapshot = self.register_map.snapshot
        now = ensure_utc_datetime(self.clock.now())
        observed_at = now if now > snapshot.observed_at else ensure_utc_datetime(snapshot.observed_at + timedelta(seconds=1))
        evolved_snapshot = self._evolve_snapshot(snapshot=snapshot, observed_at=observed_at)
        self.register_map.replace_snapshot(evolved_snapshot)
        sample = self.history.append_snapshot(evolved_snapshot)
        self._persist_history_sample(sample)
        with self._lock:
            self._evolution_count += 1
        return evolved_snapshot

    def _evolve_snapshot(self, *, snapshot: PlantSnapshot, observed_at: datetime) -> PlantSnapshot:
        if self.simulator is None or self.weather_provider is None:
            return snapshot.model_copy(
                update={
                    "observed_at": observed_at,
                    "power_plant_controller": snapshot.power_plant_controller.model_copy(update={"last_update_ts": observed_at}),
                    "inverter_blocks": tuple(
                        block.model_copy(update={"last_update_ts": observed_at}) for block in snapshot.inverter_blocks
                    ),
                    "weather_station": snapshot.weather_station.model_copy(update={"last_update_ts": observed_at}),
                    "revenue_meter": snapshot.revenue_meter.model_copy(update={"last_update_ts": observed_at}),
                    "grid_interconnect": snapshot.grid_interconnect.model_copy(update={"last_update_ts": observed_at}),
                }
            )

        measurement_at = _minute_measurement_time(observed_at)
        observation = self.weather_provider.observe(
            observed_at=measurement_at,
            timezone=self.timezone,
            latitude=self.weather_latitude,
            longitude=self.weather_longitude,
            elevation_m=self.weather_elevation_m,
        )
        return self.simulator.evolve_with_weather(
            snapshot,
            observed_at=observed_at,
            weather_observation=observation,
            block_control_states=self.register_map.get_block_control_states(),
        )

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            self._wake_event.wait(timeout=self.interval_seconds)
            self._wake_event.clear()
            if self._stop_event.is_set():
                break
            self.evolve_once()

    def _persist_history_sample(self, sample: TrendSample) -> None:
        if self.history_store is None:
            return

        observed_at = ensure_utc_datetime(sample.observed_at)
        if self._last_persisted_history_at is not None:
            elapsed = (observed_at - self._last_persisted_history_at).total_seconds()
            if elapsed < self.history_live_sample_seconds:
                return

        sample_to_store = self._sample_with_integrated_energy(sample)
        self.history_store.append_plant_history_sample(sample_to_store)
        self.history_store.prune_plant_history(
            before=observed_at - timedelta(days=self.history_retention_days)
        )
        self._last_persisted_history_at = observed_at

    def _sample_with_integrated_energy(self, sample: TrendSample) -> TrendSample:
        if self.history_store is None or sample.export_energy_mwh_total is not None:
            return sample

        latest_history = self.history_store.fetch_plant_history(limit=1)
        if not latest_history:
            return TrendSample(
                observed_at=sample.observed_at,
                plant_power_mw=sample.plant_power_mw,
                active_power_limit_pct=sample.active_power_limit_pct,
                irradiance_w_m2=sample.irradiance_w_m2,
                export_power_mw=sample.export_power_mw,
                block_power_kw=sample.block_power_kw,
                export_energy_mwh_total=0.0,
            )

        latest_sample = latest_history[-1]
        base_total = 0.0 if latest_sample.export_energy_mwh_total is None else latest_sample.export_energy_mwh_total
        interval_hours = max(
            (ensure_utc_datetime(sample.observed_at) - ensure_utc_datetime(latest_sample.observed_at)).total_seconds(),
            0.0,
        ) / 3600
        return TrendSample(
            observed_at=sample.observed_at,
            plant_power_mw=sample.plant_power_mw,
            active_power_limit_pct=sample.active_power_limit_pct,
            irradiance_w_m2=sample.irradiance_w_m2,
            export_power_mw=sample.export_power_mw,
            block_power_kw=sample.block_power_kw,
            export_energy_mwh_total=round(base_total + max(sample.export_power_mw, 0.0) * interval_hours, 4),
        )


def seed_plant_history_if_empty(
    *,
    history_store: Any,
    snapshot: PlantSnapshot,
    simulator: PlantSimulator,
    clock: Clock,
    timezone: str,
    weather_latitude: float | None = None,
    weather_longitude: float | None = None,
    weather_elevation_m: float | None = None,
    retention_days: int = PLANT_HISTORY_RETENTION_DAYS,
    step_minutes: int = PLANT_HISTORY_SEED_STEP_MINUTES,
) -> int:
    """Fuellt einen frischen Store mit einer plausiblen 30-Tage-Erzeugungshistorie."""

    if history_store.count_rows("plant_history") > 0:
        now = ensure_utc_datetime(clock.now())
        history_store.prune_plant_history(before=now - timedelta(days=retention_days))
        return 0

    now = ensure_utc_datetime(clock.now())
    step = timedelta(minutes=step_minutes)
    start = now - timedelta(days=retention_days)
    weather_provider = DeterministicDiurnalWeatherProvider()
    previous_observed_at = start - step
    export_energy_mwh_total = 0.0
    samples: list[TrendSample] = []
    observed_at = start

    while observed_at <= now:
        step_snapshot = _snapshot_for_history_seed(
            snapshot=snapshot,
            observed_at=previous_observed_at,
            export_energy_mwh_total=export_energy_mwh_total,
        )
        observation = weather_provider.observe(
            observed_at=observed_at,
            timezone=timezone,
            latitude=weather_latitude,
            longitude=weather_longitude,
            elevation_m=weather_elevation_m,
        )
        working_snapshot = simulator.evolve_with_weather(
            step_snapshot,
            observed_at=observed_at,
            weather_observation=observation,
        )
        samples.append(TrendSample.from_snapshot(working_snapshot))
        export_energy_mwh_total = working_snapshot.revenue_meter.export_energy_mwh_total or export_energy_mwh_total
        previous_observed_at = observed_at
        observed_at += step

    history_store.append_plant_history_samples(samples)
    history_store.prune_plant_history(before=now - timedelta(days=retention_days))
    return len(samples)


def _snapshot_for_history_seed(
    *,
    snapshot: PlantSnapshot,
    observed_at: datetime,
    export_energy_mwh_total: float,
) -> PlantSnapshot:
    observed_at = ensure_utc_datetime(observed_at)
    return snapshot.model_copy(
        update={
            "observed_at": observed_at,
            "power_plant_controller": snapshot.power_plant_controller.model_copy(update={"last_update_ts": observed_at}),
            "inverter_blocks": tuple(
                block.model_copy(update={"last_update_ts": observed_at}) for block in snapshot.inverter_blocks
            ),
            "weather_station": snapshot.weather_station.model_copy(update={"last_update_ts": observed_at}),
            "revenue_meter": snapshot.revenue_meter.model_copy(
                update={
                    "last_update_ts": observed_at,
                    "export_energy_mwh_total": export_energy_mwh_total,
                }
            ),
            "grid_interconnect": snapshot.grid_interconnect.model_copy(update={"last_update_ts": observed_at}),
        }
    )


def _trend_sample_for_minute(snapshot: PlantSnapshot) -> TrendSample:
    sample = TrendSample.from_snapshot(snapshot)
    return TrendSample(
        observed_at=_minute_bucket(sample.observed_at),
        plant_power_mw=sample.plant_power_mw,
        active_power_limit_pct=sample.active_power_limit_pct,
        irradiance_w_m2=sample.irradiance_w_m2,
        export_power_mw=sample.export_power_mw,
        block_power_kw=sample.block_power_kw,
        export_energy_mwh_total=sample.export_energy_mwh_total,
    )


def _minute_measurement_time(value: datetime) -> datetime:
    bucket = _minute_bucket(value)
    return bucket + timedelta(seconds=30)


def _minute_bucket(value: datetime) -> datetime:
    value = ensure_utc_datetime(value)
    return value.replace(second=0, microsecond=0)


def trend_history_capacity(*, window_minutes: int, interval_seconds: float) -> int:
    """Leitet eine kleine, stabile Ringbuffer-Groesse aus Fenster und Takt ab."""

    return max(2, ceil((window_minutes * 60) / max(interval_seconds, 1.0)) + 1)
