"""Recorder fuer normalisierte Events, Alerts und Outbox-Auftraege."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Mapping, Sequence
from uuid import uuid4

from honeypot.event_core.models import (
    AlertRecord,
    AlertSeverity,
    AlertState,
    EventCategory,
    EventRecord,
    EventSeverity,
    RecordedArtifacts,
)
from honeypot.storage import JsonlEventArchive, SQLiteEventStore
from honeypot.time_core import Clock, SystemClock


def _prefixed_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


@dataclass(slots=True)
class EventRecorder:
    """Baut normalisierte Kern-Events und persistiert sie lokal."""

    store: SQLiteEventStore
    clock: Clock = field(default_factory=SystemClock)
    archive: JsonlEventArchive | None = None

    def build_event(
        self,
        *,
        event_type: str,
        category: EventCategory,
        severity: EventSeverity,
        source_ip: str,
        actor_type: str,
        component: str,
        asset_id: str,
        action: str,
        result: str,
        timestamp: datetime | None = None,
        event_id: str | None = None,
        correlation_id: str | None = None,
        session_id: str | None = None,
        causation_id: str | None = None,
        protocol: str | None = None,
        service: str | None = None,
        endpoint_or_register: str | None = None,
        requested_value: Any | None = None,
        previous_value: Any | None = None,
        resulting_value: Any | None = None,
        resulting_state: Any | None = None,
        alarm_code: str | None = None,
        error_code: str | None = None,
        message: str | None = None,
        tags: Sequence[str] | None = None,
    ) -> EventRecord:
        """Erzeugt ein lokal normalisiertes Event nach V1-Vertrag."""

        event_timestamp = self.clock.now() if timestamp is None else timestamp
        return EventRecord(
            timestamp=event_timestamp,
            event_id=_prefixed_id("evt") if event_id is None else event_id,
            correlation_id=_prefixed_id("corr") if correlation_id is None else correlation_id,
            event_type=event_type,
            category=category,
            severity=severity,
            source_ip=source_ip,
            actor_type=actor_type,
            component=component,
            asset_id=asset_id,
            action=action,
            result=result,
            session_id=session_id,
            causation_id=causation_id,
            protocol=protocol,
            service=service,
            endpoint_or_register=endpoint_or_register,
            requested_value=requested_value,
            previous_value=previous_value,
            resulting_value=resulting_value,
            resulting_state=resulting_state,
            alarm_code=alarm_code,
            error_code=error_code,
            message=message,
            tags=() if tags is None else tuple(tags),
        )

    def build_alert(
        self,
        *,
        event: EventRecord,
        alarm_code: str,
        severity: AlertSeverity,
        state: AlertState,
        message: str | None = None,
        created_at: datetime | None = None,
    ) -> AlertRecord:
        """Leitet einen Alert aus einem vorhandenen Event ab."""

        alert_timestamp = self.clock.now() if created_at is None else created_at
        return AlertRecord(
            alert_id=_prefixed_id("alt"),
            event_id=event.event_id,
            correlation_id=event.correlation_id,
            alarm_code=alarm_code,
            severity=severity,
            state=state,
            component=event.component,
            asset_id=event.asset_id,
            message=message,
            created_at=alert_timestamp,
        )

    def record(
        self,
        event: EventRecord,
        *,
        current_state_updates: Mapping[str, Any] | None = None,
        alert: AlertRecord | None = None,
        outbox_targets: Sequence[str] = (),
    ) -> RecordedArtifacts:
        """Persistiert Event, optional State-Updates, Alert und Outbox-Auftraege."""

        self.store.append_event(event)
        if self.archive is not None:
            # Das JSONL-Archiv bleibt ein best-effort Analyseartefakt; SQLite ist die Primärwahrheit.
            self.archive.append_event(event)
        if current_state_updates:
            updated_at = event.timestamp
            for state_key, state_payload in current_state_updates.items():
                self.store.upsert_current_state(state_key, state_payload, updated_at=updated_at)

        if alert is not None:
            self.store.append_alert(alert)
            outbox_entries = self.store.enqueue_alert_targets(
                alert,
                target_types=tuple(outbox_targets),
                next_attempt_at=alert.created_at + timedelta(seconds=0),
            )
            return RecordedArtifacts(event=event, alert=alert, outbox_entries=outbox_entries)

        return RecordedArtifacts(event=event)
