"""Kanonische Event-, Alert- und Outbox-Modelle fuer V1."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from honeypot.time_core import ensure_utc_datetime

EventCategory = Literal["transport", "auth", "protocol", "hmi", "process", "alert", "system"]
EventSeverity = Literal["debug", "info", "low", "medium", "high", "critical"]
AlertSeverity = Literal["low", "medium", "high", "critical"]
AlertState = Literal["inactive", "active_unacknowledged", "active_acknowledged", "cleared"]
OutboxStatus = Literal["pending", "leased", "delivered", "failed"]
OutboxPayloadKind = Literal["event", "alert"]


def _normalize_required_string(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("muss ein String sein")
    normalized = value.strip()
    if not normalized:
        raise ValueError("darf nicht leer sein")
    return normalized


def _normalize_optional_string(value: object) -> str | None:
    if value is None:
        return None
    return _normalize_required_string(value)


class EventRecord(BaseModel):
    """Normalisiertes Kern-Event nach dem kanonischen V1-Vertrag."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    timestamp: datetime
    event_id: str
    correlation_id: str
    event_type: str
    category: EventCategory
    severity: EventSeverity
    source_ip: str
    actor_type: str
    component: str
    asset_id: str
    action: str
    result: str
    session_id: str | None = None
    causation_id: str | None = None
    protocol: str | None = None
    service: str | None = None
    endpoint_or_register: str | None = None
    requested_value: Any | None = None
    previous_value: Any | None = None
    resulting_value: Any | None = None
    resulting_state: Any | None = None
    alarm_code: str | None = None
    error_code: str | None = None
    message: str | None = None
    tags: tuple[str, ...] = ()

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return ensure_utc_datetime(value)

    @field_validator(
        "event_id",
        "correlation_id",
        "event_type",
        "source_ip",
        "actor_type",
        "component",
        "asset_id",
        "action",
        "result",
        mode="before",
    )
    @classmethod
    def validate_required_strings(cls, value: object) -> str:
        return _normalize_required_string(value)

    @field_validator(
        "session_id",
        "causation_id",
        "protocol",
        "service",
        "endpoint_or_register",
        "alarm_code",
        "error_code",
        "message",
        mode="before",
    )
    @classmethod
    def validate_optional_strings(cls, value: object) -> str | None:
        return _normalize_optional_string(value)

    @field_validator("tags", mode="before")
    @classmethod
    def validate_tags(cls, value: object) -> tuple[str, ...]:
        if value in (None, "", ()):
            return ()
        if not isinstance(value, (list, tuple)):
            raise TypeError("tags muessen eine Liste oder ein Tupel sein")
        return tuple(_normalize_required_string(item) for item in value)


class AlertRecord(BaseModel):
    """Abgeleiteter Alert fuer `alert_log` und Outbox."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    alert_id: str
    event_id: str
    correlation_id: str
    alarm_code: str
    severity: AlertSeverity
    state: AlertState
    component: str
    asset_id: str
    message: str | None = None
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return ensure_utc_datetime(value)

    @field_validator(
        "alert_id",
        "event_id",
        "correlation_id",
        "alarm_code",
        "component",
        "asset_id",
        mode="before",
    )
    @classmethod
    def validate_required_strings(cls, value: object) -> str:
        return _normalize_required_string(value)

    @field_validator("message", mode="before")
    @classmethod
    def validate_message(cls, value: object) -> str | None:
        return _normalize_optional_string(value)


class OutboxEntry(BaseModel):
    """Auslieferungsauftrag fuer spaetere Exporter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outbox_id: int | None = None
    target_type: str
    payload_kind: OutboxPayloadKind
    payload_ref: str
    status: OutboxStatus = "pending"
    retry_count: int = Field(default=0, ge=0)
    next_attempt_at: datetime
    last_error: str | None = None
    created_at: datetime

    @field_validator("next_attempt_at", "created_at")
    @classmethod
    def validate_timestamps(cls, value: datetime) -> datetime:
        return ensure_utc_datetime(value)

    @field_validator("target_type", "payload_ref", mode="before")
    @classmethod
    def validate_required_strings(cls, value: object) -> str:
        return _normalize_required_string(value)

    @field_validator("last_error", mode="before")
    @classmethod
    def validate_last_error(cls, value: object) -> str | None:
        return _normalize_optional_string(value)


class RecordedArtifacts(BaseModel):
    """Rueckgabe eines Recorder-Durchlaufs fuer Tests und spaetere Integration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event: EventRecord
    alert: AlertRecord | None = None
    alerts: tuple[AlertRecord, ...] = ()
    outbox_entries: tuple[OutboxEntry, ...] = ()
