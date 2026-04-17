"""Leichter Outbox-Runner fuer lokale Exporter-Pfade."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from threading import Event, Lock, Thread
from typing import Sequence

from honeypot.event_core.models import AlertRecord, EventRecord
from honeypot.exporter_sdk import HoneypotExporter
from honeypot.storage import SQLiteEventStore
from honeypot.time_core import Clock, SystemClock, ensure_utc_datetime


@dataclass(frozen=True, slots=True)
class OutboxDrainResult:
    """Kurzer Laufbericht fuer Tests und spaetere Telemetrie."""

    leased_count: int
    delivered_count: int
    retried_count: int
    failed_count: int


@dataclass(slots=True)
class OutboxRunner:
    """Leased faellige Outbox-Eintraege und uebergibt sie an Exporter."""

    store: SQLiteEventStore
    exporters: dict[str, HoneypotExporter]
    batch_size: int = 50
    retry_backoff_seconds: int = 30
    clock: Clock = field(default_factory=SystemClock)

    def drain_once(self) -> OutboxDrainResult:
        now = ensure_utc_datetime(self.clock.now())
        leased_entries = self.store.lease_outbox_entries(limit=self.batch_size, not_before=now)
        if not leased_entries:
            return OutboxDrainResult(leased_count=0, delivered_count=0, retried_count=0, failed_count=0)

        delivered_count = 0
        retried_count = 0
        failed_count = 0
        grouped: dict[tuple[str, str], list] = {}
        for entry in leased_entries:
            grouped.setdefault((entry.target_type, entry.payload_kind), []).append(entry)

        for (target_type, payload_kind), entries in grouped.items():
            exporter = self.exporters.get(target_type)
            outbox_ids = [entry.outbox_id for entry in entries if entry.outbox_id is not None]
            if exporter is None:
                self.store.mark_outbox_failed(outbox_ids, last_error=f"Kein Exporter registriert fuer {target_type}")
                failed_count += len(outbox_ids)
                continue

            payloads = self._resolve_payloads(payload_kind=payload_kind, payload_refs=[entry.payload_ref for entry in entries])
            if payloads is None:
                self.store.mark_outbox_failed(
                    outbox_ids,
                    last_error=f"Payload-Aufloesung fuer {payload_kind} fehlgeschlagen",
                )
                failed_count += len(outbox_ids)
                continue

            capabilities = exporter.capabilities()
            if payload_kind == "event" and not capabilities.supports_events:
                self.store.mark_outbox_failed(outbox_ids, last_error=f"Exporter {target_type} unterstuetzt keine Events")
                failed_count += len(outbox_ids)
                continue
            if payload_kind == "alert" and not capabilities.supports_alerts:
                self.store.mark_outbox_failed(outbox_ids, last_error=f"Exporter {target_type} unterstuetzt keine Alerts")
                failed_count += len(outbox_ids)
                continue

            delivery = (
                exporter.deliver_event_batch(payloads)
                if payload_kind == "event"
                else exporter.deliver_alert_batch(payloads)
            )
            if delivery.status == "delivered":
                self.store.mark_outbox_delivered(outbox_ids)
                delivered_count += len(outbox_ids)
                continue

            self.store.requeue_outbox_entries(
                outbox_ids,
                next_attempt_at=now + timedelta(seconds=delivery.retry_after_seconds or self.retry_backoff_seconds),
                last_error=delivery.detail or f"Exporter {target_type} bat um Retry",
            )
            retried_count += len(outbox_ids)

        return OutboxDrainResult(
            leased_count=len(leased_entries),
            delivered_count=delivered_count,
            retried_count=retried_count,
            failed_count=failed_count,
        )

    def _resolve_payloads(
        self,
        *,
        payload_kind: str,
        payload_refs: Sequence[str],
    ) -> tuple[EventRecord, ...] | tuple[AlertRecord, ...] | None:
        if payload_kind == "event":
            events = []
            for payload_ref in payload_refs:
                event = self.store.fetch_event(payload_ref)
                if event is None:
                    return None
                events.append(event)
            return tuple(events)

        if payload_kind == "alert":
            alerts = []
            for payload_ref in payload_refs:
                alert = self.store.fetch_alert(payload_ref)
                if alert is None:
                    return None
                alerts.append(alert)
            return tuple(alerts)

        return None


@dataclass(slots=True)
class BackgroundOutboxRunnerService:
    """Fuehrt den Outbox-Drain im Hintergrund fuer die lokale Runtime aus."""

    runner: OutboxRunner
    drain_interval_seconds: float = 1.0
    _stop_event: Event = field(default_factory=Event, init=False, repr=False)
    _wake_event: Event = field(default_factory=Event, init=False, repr=False)
    _thread: Thread | None = field(default=None, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _last_result: OutboxDrainResult | None = field(default=None, init=False, repr=False)
    _drain_count: int = field(default=0, init=False, repr=False)

    @property
    def last_result(self) -> OutboxDrainResult | None:
        with self._lock:
            return self._last_result

    @property
    def drain_count(self) -> int:
        with self._lock:
            return self._drain_count

    def start_in_thread(self) -> "BackgroundOutboxRunnerService":
        thread = self._thread
        if thread is not None and thread.is_alive():
            return self

        self._stop_event.clear()
        self._wake_event.clear()
        self._thread = Thread(
            target=self._run_loop,
            name="outbox-runner",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=max(self.drain_interval_seconds, 0.1) + 1.0)
        self._thread = None

    def wake(self) -> None:
        self._wake_event.set()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            result = self.runner.drain_once()
            with self._lock:
                self._last_result = result
                self._drain_count += 1
            if self._stop_event.is_set():
                break
            self._wake_event.wait(timeout=self.drain_interval_seconds)
            self._wake_event.clear()
