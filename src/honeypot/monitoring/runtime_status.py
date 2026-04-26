"""Lokaler Status-Writer fuer pre-exposure Monitoring ohne HTTP-Debugpfad."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Any, Mapping, Protocol

from honeypot.exporter_runner import BackgroundOutboxRunnerService, OutboxDrainResult
from honeypot.exporter_sdk import HoneypotExporter
from honeypot.storage import SQLiteEventStore
from honeypot.time_core import Clock, SystemClock, ensure_utc_datetime


class AddressableService(Protocol):
    """Minimaler Vertrag fuer lokale Dienste mit bindbarer Adresse."""

    @property
    def address(self) -> tuple[str, int]:
        """Liefert die aktuelle Bind-Adresse."""


def _iso_timestamp(value) -> str:
    return ensure_utc_datetime(value).isoformat().replace("+00:00", "Z")


def _serialize_drain_result(result: OutboxDrainResult | None) -> dict[str, int] | None:
    if result is None:
        return None
    return {
        "leased_count": result.leased_count,
        "delivered_count": result.delivered_count,
        "retried_count": result.retried_count,
        "failed_count": result.failed_count,
    }


@dataclass(slots=True)
class RuntimeStatusWriter:
    """Schreibt einen lokalen Heartbeat ueber Runtime, Alerts und Exportpfade."""

    site_code: str
    fixture_name: str
    path: Path
    event_store: SQLiteEventStore
    modbus_service: AddressableService
    hmi_service: AddressableService
    exporters: Mapping[str, HoneypotExporter]
    ops_service: AddressableService | None = None
    outbox_runner_service: BackgroundOutboxRunnerService | None = None
    clock: Clock = field(default_factory=SystemClock)

    def render_payload(self, *, running: bool) -> dict[str, Any]:
        alerts = self.event_store.fetch_alerts()
        outbox_entries = self.event_store.fetch_outbox_entries()

        alert_state_counts = Counter(alert.state for alert in alerts)
        outbox_status_counts = Counter(entry.status for entry in outbox_entries)
        outbox_target_status_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for entry in outbox_entries:
            outbox_target_status_counts[entry.target_type][entry.status] += 1

        exporter_health: dict[str, dict[str, str | None]] = {}
        for target_type, exporter in self.exporters.items():
            try:
                health = exporter.health()
                exporter_health[target_type] = {
                    "exporter_id": exporter.exporter_id,
                    "status": health.status,
                    "detail": health.detail,
                }
            except Exception as exc:  # pragma: no cover - defensiv fuer spaetere Exporter
                exporter_health[target_type] = {
                    "exporter_id": exporter.exporter_id,
                    "status": "unavailable",
                    "detail": f"health_check_failed:{exc.__class__.__name__}",
                }

        modbus_host, modbus_port = self.modbus_service.address
        hmi_host, hmi_port = self.hmi_service.address
        ops_payload: dict[str, Any] | None = None
        if self.ops_service is not None:
            ops_host, ops_port = self.ops_service.address
            ops_payload = {
                "bind_host": ops_host,
                "port": ops_port,
                "dashboard_url": f"http://{ops_host}:{ops_port}/",
            }
        return {
            "generated_at": _iso_timestamp(self.clock.now()),
            "site_code": self.site_code,
            "fixture_name": self.fixture_name,
            "runtime": {
                "running": running,
                "modbus": {
                    "bind_host": modbus_host,
                    "port": modbus_port,
                },
                "hmi": {
                    "bind_host": hmi_host,
                    "port": hmi_port,
                    "overview_url": f"http://{hmi_host}:{hmi_port}/overview",
                },
                "ops": ops_payload,
                "outbox_runner": {
                    "enabled": self.outbox_runner_service is not None,
                    "drain_count": 0 if self.outbox_runner_service is None else self.outbox_runner_service.drain_count,
                    "last_result": (
                        None
                        if self.outbox_runner_service is None
                        else _serialize_drain_result(self.outbox_runner_service.last_result)
                    ),
                },
            },
            "store": {
                "current_state_rows": self.event_store.count_rows("current_state"),
                "event_rows": self.event_store.count_rows("event_log"),
                "alert_rows": self.event_store.count_rows("alert_log"),
                "outbox_rows": self.event_store.count_rows("outbox"),
            },
            "alerts": {
                "active_count": sum(1 for alert in alerts if alert.state.startswith("active")),
                "state_counts": dict(sorted(alert_state_counts.items())),
            },
            "outbox": {
                "status_counts": dict(sorted(outbox_status_counts.items())),
                "target_status_counts": {
                    target_type: dict(sorted(status_counts.items()))
                    for target_type, status_counts in sorted(outbox_target_status_counts.items())
                },
            },
            "exporters": exporter_health,
        }

    def write_status(self, *, running: bool) -> dict[str, Any]:
        payload = self.render_payload(running=running)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.path.with_name(f"{self.path.name}.tmp")
        temp_path.write_text(
            json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temp_path.replace(self.path)
        return payload


@dataclass(slots=True)
class BackgroundRuntimeStatusService:
    """Fuehrt den Status-Writer im Hintergrund fuer pre-exposure Monitoring aus."""

    writer: RuntimeStatusWriter
    interval_seconds: float = 5.0
    _stop_event: Event = field(default_factory=Event, init=False, repr=False)
    _wake_event: Event = field(default_factory=Event, init=False, repr=False)
    _thread: Thread | None = field(default=None, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _last_error: str | None = field(default=None, init=False, repr=False)
    _write_count: int = field(default=0, init=False, repr=False)

    @property
    def last_error(self) -> str | None:
        with self._lock:
            return self._last_error

    @property
    def write_count(self) -> int:
        with self._lock:
            return self._write_count

    def start_in_thread(self) -> "BackgroundRuntimeStatusService":
        thread = self._thread
        if thread is not None and thread.is_alive():
            return self

        self._write_once(running=True)
        self._stop_event.clear()
        self._wake_event.clear()
        self._thread = Thread(
            target=self._run_loop,
            name="runtime-status-writer",
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
        self._write_once(running=False)

    def wake(self) -> None:
        self._wake_event.set()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            self._wake_event.wait(timeout=self.interval_seconds)
            self._wake_event.clear()
            if self._stop_event.is_set():
                break
            self._write_once(running=True)

    def _write_once(self, *, running: bool) -> None:
        try:
            self.writer.write_status(running=running)
        except Exception as exc:
            with self._lock:
                self._last_error = f"{exc.__class__.__name__}: {exc}"
            if self._thread is None:
                raise
            return
        with self._lock:
            self._last_error = None
            self._write_count += 1
