"""Hintergrund-Evolution fuer tickende Snapshot-Zeit und kleine Trendhistorie."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from math import ceil
from threading import Event, Lock, Thread

from honeypot.asset_domain import PlantSnapshot
from honeypot.protocol_modbus import ReadOnlyRegisterMap
from honeypot.time_core import Clock, SystemClock, ensure_utc_datetime


@dataclass(frozen=True, slots=True)
class TrendSample:
    """Verdichteter Verlaufspunkt fuer die HMI-Trendansicht."""

    observed_at: datetime
    plant_power_mw: float
    active_power_limit_pct: float
    irradiance_w_m2: float
    export_power_mw: float
    block_power_kw: tuple[tuple[str, float], ...]


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
        sample = TrendSample(
            observed_at=snapshot.observed_at,
            plant_power_mw=snapshot.site.plant_power_mw,
            active_power_limit_pct=snapshot.power_plant_controller.active_power_limit_pct,
            irradiance_w_m2=float(snapshot.weather_station.irradiance_w_m2),
            export_power_mw=snapshot.revenue_meter.export_power_kw / 1000,
            block_power_kw=tuple((block.asset_id, block.block_power_kw) for block in snapshot.inverter_blocks),
        )
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
    interval_seconds: float = 5.0
    _stop_event: Event = field(default_factory=Event, init=False, repr=False)
    _wake_event: Event = field(default_factory=Event, init=False, repr=False)
    _thread: Thread | None = field(default=None, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _evolution_count: int = field(default=0, init=False, repr=False)

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
        evolved_snapshot = snapshot.model_copy(
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
        self.register_map.replace_snapshot(evolved_snapshot)
        self.history.append_snapshot(evolved_snapshot)
        with self._lock:
            self._evolution_count += 1
        return evolved_snapshot

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            self._wake_event.wait(timeout=self.interval_seconds)
            self._wake_event.clear()
            if self._stop_event.is_set():
                break
            self.evolve_once()


def trend_history_capacity(*, window_minutes: int, interval_seconds: float) -> int:
    """Leitet eine kleine, stabile Ringbuffer-Groesse aus Fenster und Takt ab."""

    return max(2, ceil((window_minutes * 60) / max(interval_seconds, 1.0)) + 1)
