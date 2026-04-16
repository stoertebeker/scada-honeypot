"""Lokaler SQLite-Wahrheitskern fuer Events, Alerts, State und Outbox."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from honeypot.event_core.models import AlertRecord, EventRecord, OutboxEntry
from honeypot.time_core import ensure_utc_datetime


def _normalize_required_text(value: str, *, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} darf nicht leer sein")
    return normalized


def _iso_timestamp(value: datetime) -> str:
    return ensure_utc_datetime(value).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _json_blob(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


class SQLiteEventStore:
    """SQLite-Persistenz fuer `current_state`, `event_log`, `alert_log` und `outbox`."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL;")
        connection.execute("PRAGMA foreign_keys=ON;")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS current_state (
                    state_key TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS event_log (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    actor_type TEXT NOT NULL,
                    component TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    session_id TEXT,
                    causation_id TEXT,
                    protocol TEXT,
                    service TEXT,
                    endpoint_or_register TEXT,
                    requested_value_json TEXT,
                    previous_value_json TEXT,
                    resulting_value_json TEXT,
                    resulting_state_json TEXT,
                    alarm_code TEXT,
                    error_code TEXT,
                    message TEXT,
                    tags_json TEXT NOT NULL,
                    raw_event_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alert_log (
                    alert_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL REFERENCES event_log(event_id),
                    correlation_id TEXT NOT NULL,
                    alarm_code TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    state TEXT NOT NULL,
                    component TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    message TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS outbox (
                    outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_type TEXT NOT NULL,
                    payload_kind TEXT NOT NULL,
                    payload_ref TEXT NOT NULL,
                    status TEXT NOT NULL,
                    retry_count INTEGER NOT NULL,
                    next_attempt_at TEXT NOT NULL,
                    last_error TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_outbox_status_next_attempt
                ON outbox(status, next_attempt_at);
                """
            )

    def journal_mode(self) -> str:
        with self._connect() as connection:
            row = connection.execute("PRAGMA journal_mode;").fetchone()
        return str(row[0])

    def append_event(self, event: EventRecord) -> None:
        payload = event.model_dump(mode="json")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO event_log (
                    event_id, timestamp, correlation_id, event_type, category, severity,
                    source_ip, actor_type, component, asset_id, action, result,
                    session_id, causation_id, protocol, service, endpoint_or_register,
                    requested_value_json, previous_value_json, resulting_value_json,
                    resulting_state_json, alarm_code, error_code, message, tags_json, raw_event_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    _iso_timestamp(event.timestamp),
                    event.correlation_id,
                    event.event_type,
                    event.category,
                    event.severity,
                    event.source_ip,
                    event.actor_type,
                    event.component,
                    event.asset_id,
                    event.action,
                    event.result,
                    event.session_id,
                    event.causation_id,
                    event.protocol,
                    event.service,
                    event.endpoint_or_register,
                    _json_blob(event.requested_value) if event.requested_value is not None else None,
                    _json_blob(event.previous_value) if event.previous_value is not None else None,
                    _json_blob(event.resulting_value) if event.resulting_value is not None else None,
                    _json_blob(event.resulting_state) if event.resulting_state is not None else None,
                    event.alarm_code,
                    event.error_code,
                    event.message,
                    _json_blob(list(event.tags)),
                    _json_blob(payload),
                ),
            )

    def append_alert(self, alert: AlertRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO alert_log (
                    alert_id, event_id, correlation_id, alarm_code, severity, state,
                    component, asset_id, message, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.event_id,
                    alert.correlation_id,
                    alert.alarm_code,
                    alert.severity,
                    alert.state,
                    alert.component,
                    alert.asset_id,
                    alert.message,
                    _iso_timestamp(alert.created_at),
                ),
            )

    def enqueue_alert_targets(
        self,
        alert: AlertRecord,
        *,
        target_types: Sequence[str],
        next_attempt_at: datetime,
    ) -> tuple[OutboxEntry, ...]:
        if not target_types:
            return ()

        created_at = alert.created_at
        entries: list[OutboxEntry] = []
        with self._connect() as connection:
            for target_type in target_types:
                normalized_target_type = _normalize_required_text(target_type, field_name="target_type")
                cursor = connection.execute(
                    """
                    INSERT INTO outbox (
                        target_type, payload_kind, payload_ref, status, retry_count,
                        next_attempt_at, last_error, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        normalized_target_type,
                        "alert",
                        alert.alert_id,
                        "pending",
                        0,
                        _iso_timestamp(next_attempt_at),
                        None,
                        _iso_timestamp(created_at),
                    ),
                )
                entries.append(
                    OutboxEntry(
                        outbox_id=int(cursor.lastrowid),
                        target_type=normalized_target_type,
                        payload_kind="alert",
                        payload_ref=alert.alert_id,
                        status="pending",
                        retry_count=0,
                        next_attempt_at=next_attempt_at,
                        last_error=None,
                        created_at=created_at,
                    )
                )
        return tuple(entries)

    def upsert_current_state(self, state_key: str, state_payload: Any, *, updated_at: datetime) -> None:
        normalized_state_key = _normalize_required_text(state_key, field_name="state_key")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO current_state (state_key, state_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(state_key) DO UPDATE SET
                    state_json = excluded.state_json,
                    updated_at = excluded.updated_at
                """,
                (
                    normalized_state_key,
                    _json_blob(state_payload),
                    _iso_timestamp(updated_at),
                ),
            )

    def count_rows(self, table_name: str) -> int:
        if table_name not in {"current_state", "event_log", "alert_log", "outbox"}:
            raise ValueError(f"ungueltiger Tabellenname: {table_name}")
        with self._connect() as connection:
            row = connection.execute(f"SELECT COUNT(*) AS row_count FROM {table_name}").fetchone()
        return int(row["row_count"])

    def fetch_events(self) -> tuple[EventRecord, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT raw_event_json
                FROM event_log
                ORDER BY timestamp, event_id
                """
            ).fetchall()

        return tuple(EventRecord.model_validate(json.loads(str(row["raw_event_json"]))) for row in rows)

    def fetch_alerts(self) -> tuple[AlertRecord, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT alert_id, event_id, correlation_id, alarm_code, severity, state,
                       component, asset_id, message, created_at
                FROM alert_log
                ORDER BY created_at, alert_id
                """
            ).fetchall()

        return tuple(
            AlertRecord(
                alert_id=str(row["alert_id"]),
                event_id=str(row["event_id"]),
                correlation_id=str(row["correlation_id"]),
                alarm_code=str(row["alarm_code"]),
                severity=row["severity"],
                state=row["state"],
                component=str(row["component"]),
                asset_id=str(row["asset_id"]),
                message=row["message"],
                created_at=_parse_timestamp(str(row["created_at"])),
            )
            for row in rows
        )

    def fetch_current_state(self, state_key: str) -> Any | None:
        normalized_state_key = _normalize_required_text(state_key, field_name="state_key")
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT state_json
                FROM current_state
                WHERE state_key = ?
                """,
                (normalized_state_key,),
            ).fetchone()

        if row is None:
            return None
        return json.loads(str(row["state_json"]))

    def fetch_outbox_entries(self) -> tuple[OutboxEntry, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT outbox_id, target_type, payload_kind, payload_ref, status,
                       retry_count, next_attempt_at, last_error, created_at
                FROM outbox
                ORDER BY outbox_id
                """
            ).fetchall()

        return tuple(
            OutboxEntry(
                outbox_id=int(row["outbox_id"]),
                target_type=str(row["target_type"]),
                payload_kind=row["payload_kind"],
                payload_ref=str(row["payload_ref"]),
                status=row["status"],
                retry_count=int(row["retry_count"]),
                next_attempt_at=_parse_timestamp(str(row["next_attempt_at"])),
                last_error=row["last_error"],
                created_at=_parse_timestamp(str(row["created_at"])),
            )
            for row in rows
        )
