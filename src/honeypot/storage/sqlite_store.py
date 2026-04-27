"""Lokaler SQLite-Wahrheitskern fuer Events, Alerts, State und Outbox."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from honeypot.event_core.models import AlertRecord, EventRecord, OutboxEntry
from honeypot.history_core import PlantHistorySample
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


@dataclass(frozen=True, slots=True)
class LoginCampaignRecord:
    campaign_id: str
    source_ip: str
    user_agent: str
    endpoint: str
    first_seen: datetime
    last_seen: datetime
    attempt_count: int


@dataclass(frozen=True, slots=True)
class CredentialCountRecord:
    scope_type: str
    scope_id: str
    value_type: str
    credential_value: str
    credential_fingerprint: str
    count: int
    first_seen: datetime
    last_seen: datetime


@dataclass(frozen=True, slots=True)
class LoginCredentialStats:
    campaign_count: int
    all_time_unique_usernames: int
    all_time_unique_passwords: int
    all_time_dropped_unique_passwords: int


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

                CREATE TABLE IF NOT EXISTS ops_settings (
                    setting_key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS plant_history (
                    observed_at TEXT PRIMARY KEY,
                    plant_power_mw REAL NOT NULL,
                    active_power_limit_pct REAL NOT NULL,
                    irradiance_w_m2 REAL NOT NULL,
                    export_power_mw REAL NOT NULL,
                    export_energy_mwh_total REAL,
                    block_power_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS login_campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    source_ip TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS login_credential_counts (
                    scope_type TEXT NOT NULL,
                    scope_id TEXT NOT NULL,
                    value_type TEXT NOT NULL,
                    credential_value TEXT NOT NULL,
                    credential_fingerprint TEXT NOT NULL,
                    count INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY (scope_type, scope_id, value_type, credential_value)
                );

                CREATE TABLE IF NOT EXISTS login_capture_stats (
                    stat_key TEXT PRIMARY KEY,
                    stat_value INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_outbox_status_next_attempt
                ON outbox(status, next_attempt_at);

                CREATE INDEX IF NOT EXISTS idx_plant_history_observed_at
                ON plant_history(observed_at);

                CREATE INDEX IF NOT EXISTS idx_login_campaigns_last_seen
                ON login_campaigns(last_seen);

                CREATE INDEX IF NOT EXISTS idx_login_credential_top
                ON login_credential_counts(scope_type, scope_id, value_type, count DESC, last_seen DESC);
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
        if table_name not in {
            "current_state",
            "event_log",
            "alert_log",
            "outbox",
            "ops_settings",
            "plant_history",
            "login_campaigns",
            "login_credential_counts",
            "login_capture_stats",
        }:
            raise ValueError(f"ungueltiger Tabellenname: {table_name}")
        with self._connect() as connection:
            row = connection.execute(f"SELECT COUNT(*) AS row_count FROM {table_name}").fetchone()
        return int(row["row_count"])

    def record_login_credential_attempt(
        self,
        *,
        campaign_id: str,
        source_ip: str,
        user_agent: str,
        endpoint: str,
        username: str,
        password: str | None,
        observed_at: datetime,
        max_unique_passwords: int,
        max_credential_length: int,
        capture_password: bool,
    ) -> None:
        normalized_campaign_id = _normalize_required_text(campaign_id, field_name="campaign_id")
        normalized_source_ip = _normalize_required_text(source_ip, field_name="source_ip")
        normalized_endpoint = _normalize_required_text(endpoint, field_name="endpoint")
        normalized_user_agent = _sanitize_credential_value(user_agent, max_length=max_credential_length)
        normalized_username = _sanitize_credential_value(username, max_length=max_credential_length)
        normalized_password = (
            None
            if password is None
            else _sanitize_credential_value(password, max_length=max_credential_length)
        )
        if max_unique_passwords < 0:
            raise ValueError("max_unique_passwords muss groesser oder gleich 0 sein")
        timestamp = _iso_timestamp(observed_at)

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO login_campaigns (
                    campaign_id, source_ip, user_agent, endpoint, first_seen, last_seen, attempt_count
                ) VALUES (?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(campaign_id) DO UPDATE SET
                    source_ip = excluded.source_ip,
                    user_agent = excluded.user_agent,
                    endpoint = excluded.endpoint,
                    first_seen = CASE
                        WHEN excluded.first_seen < first_seen THEN excluded.first_seen
                        ELSE first_seen
                    END,
                    last_seen = CASE
                        WHEN excluded.last_seen > last_seen THEN excluded.last_seen
                        ELSE last_seen
                    END,
                    attempt_count = attempt_count + 1
                """,
                (
                    normalized_campaign_id,
                    normalized_source_ip,
                    normalized_user_agent,
                    normalized_endpoint,
                    timestamp,
                    timestamp,
                ),
            )
            _upsert_credential_count(
                connection,
                scope_type="all_time",
                scope_id="all",
                value_type="username",
                credential_value=normalized_username,
                observed_at=timestamp,
            )
            _upsert_credential_count(
                connection,
                scope_type="campaign",
                scope_id=normalized_campaign_id,
                value_type="username",
                credential_value=normalized_username,
                observed_at=timestamp,
            )
            if capture_password and normalized_password is not None:
                global_password_exists = _credential_exists(
                    connection,
                    scope_type="all_time",
                    scope_id="all",
                    value_type="password",
                    credential_value=normalized_password,
                )
                unique_password_count = _all_time_unique_password_count(connection)
                if global_password_exists or unique_password_count < max_unique_passwords:
                    _upsert_credential_count(
                        connection,
                        scope_type="all_time",
                        scope_id="all",
                        value_type="password",
                        credential_value=normalized_password,
                        observed_at=timestamp,
                    )
                    if not global_password_exists:
                        _set_login_capture_stat(
                            connection,
                            stat_key="all_time_unique_passwords",
                            stat_value=unique_password_count + 1,
                            updated_at=timestamp,
                        )
                    _upsert_credential_count(
                        connection,
                        scope_type="campaign",
                        scope_id=normalized_campaign_id,
                        value_type="password",
                        credential_value=normalized_password,
                        observed_at=timestamp,
                    )
                else:
                    _increment_login_capture_stat(
                        connection,
                        stat_key="all_time_dropped_unique_passwords",
                        delta=1,
                        updated_at=timestamp,
                    )

    def fetch_login_campaigns(self, *, limit: int = 100) -> tuple[LoginCampaignRecord, ...]:
        if limit <= 0:
            raise ValueError("limit muss groesser als 0 sein")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT campaign_id, source_ip, user_agent, endpoint, first_seen, last_seen, attempt_count
                FROM login_campaigns
                ORDER BY last_seen DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return tuple(_login_campaign_from_row(row) for row in rows)

    def fetch_login_campaign(self, campaign_id: str) -> LoginCampaignRecord | None:
        normalized_campaign_id = _normalize_required_text(campaign_id, field_name="campaign_id")
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT campaign_id, source_ip, user_agent, endpoint, first_seen, last_seen, attempt_count
                FROM login_campaigns
                WHERE campaign_id = ?
                """,
                (normalized_campaign_id,),
            ).fetchone()
        if row is None:
            return None
        return _login_campaign_from_row(row)

    def fetch_login_credential_top(
        self,
        *,
        value_type: str,
        scope_type: str = "all_time",
        scope_id: str = "all",
        limit: int = 100,
    ) -> tuple[CredentialCountRecord, ...]:
        if value_type not in {"username", "password"}:
            raise ValueError("value_type muss username oder password sein")
        if scope_type not in {"all_time", "campaign"}:
            raise ValueError("scope_type muss all_time oder campaign sein")
        if limit <= 0:
            raise ValueError("limit muss groesser als 0 sein")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT scope_type, scope_id, value_type, credential_value, credential_fingerprint,
                       count, first_seen, last_seen
                FROM login_credential_counts
                WHERE scope_type = ?
                  AND scope_id = ?
                  AND value_type = ?
                ORDER BY count DESC, last_seen DESC, credential_value ASC
                LIMIT ?
                """,
                (scope_type, scope_id, value_type, limit),
            ).fetchall()
        return tuple(_credential_count_from_row(row) for row in rows)

    def iter_login_credential_export(
        self,
        *,
        value_type: str,
        scope_type: str = "all_time",
        scope_id: str = "all",
    ) -> Iterator[CredentialCountRecord]:
        if value_type not in {"username", "password"}:
            raise ValueError("value_type muss username oder password sein")
        if scope_type not in {"all_time", "campaign"}:
            raise ValueError("scope_type muss all_time oder campaign sein")
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT scope_type, scope_id, value_type, credential_value, credential_fingerprint,
                       count, first_seen, last_seen
                FROM login_credential_counts
                WHERE scope_type = ?
                  AND scope_id = ?
                  AND value_type = ?
                ORDER BY count DESC, last_seen DESC, credential_value ASC
                """,
                (scope_type, scope_id, value_type),
            )
            for row in rows:
                yield _credential_count_from_row(row)
        finally:
            connection.close()

    def login_credential_stats(self) -> LoginCredentialStats:
        with self._connect() as connection:
            campaign_count = int(
                connection.execute("SELECT COUNT(*) AS row_count FROM login_campaigns").fetchone()["row_count"]
            )
            username_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) AS row_count
                    FROM login_credential_counts
                    WHERE scope_type = 'all_time'
                      AND scope_id = 'all'
                      AND value_type = 'username'
                    """
                ).fetchone()["row_count"]
            )
            password_count = _all_time_unique_password_count(connection)
            row = connection.execute(
                """
                SELECT stat_value
                FROM login_capture_stats
                WHERE stat_key = 'all_time_dropped_unique_passwords'
                """
            ).fetchone()
        return LoginCredentialStats(
            campaign_count=campaign_count,
            all_time_unique_usernames=username_count,
            all_time_unique_passwords=password_count,
            all_time_dropped_unique_passwords=0 if row is None else int(row["stat_value"]),
        )

    def append_plant_history_sample(self, sample: PlantHistorySample) -> None:
        self.append_plant_history_samples((sample,))

    def append_plant_history_samples(self, samples: Sequence[PlantHistorySample]) -> None:
        if not samples:
            return
        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO plant_history (
                    observed_at, plant_power_mw, active_power_limit_pct, irradiance_w_m2,
                    export_power_mw, export_energy_mwh_total, block_power_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(observed_at) DO UPDATE SET
                    plant_power_mw = excluded.plant_power_mw,
                    active_power_limit_pct = excluded.active_power_limit_pct,
                    irradiance_w_m2 = excluded.irradiance_w_m2,
                    export_power_mw = excluded.export_power_mw,
                    export_energy_mwh_total = excluded.export_energy_mwh_total,
                    block_power_json = excluded.block_power_json
                """,
                tuple(_plant_history_params(sample) for sample in samples),
            )

    def fetch_plant_history(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
    ) -> tuple[PlantHistorySample, ...]:
        if limit is not None and limit <= 0:
            raise ValueError("limit muss groesser als 0 sein")

        clauses: list[str] = []
        params: list[Any] = []
        if since is not None:
            clauses.append("observed_at >= ?")
            params.append(_iso_timestamp(since))
        if until is not None:
            clauses.append("observed_at <= ?")
            params.append(_iso_timestamp(until))
        where = "" if not clauses else f"WHERE {' AND '.join(clauses)}"

        with self._connect() as connection:
            if limit is None:
                rows = connection.execute(
                    f"""
                    SELECT observed_at, plant_power_mw, active_power_limit_pct, irradiance_w_m2,
                           export_power_mw, export_energy_mwh_total, block_power_json
                    FROM plant_history
                    {where}
                    ORDER BY observed_at
                    """,
                    tuple(params),
                ).fetchall()
            else:
                rows = connection.execute(
                    f"""
                    SELECT observed_at, plant_power_mw, active_power_limit_pct, irradiance_w_m2,
                           export_power_mw, export_energy_mwh_total, block_power_json
                    FROM (
                        SELECT observed_at, plant_power_mw, active_power_limit_pct, irradiance_w_m2,
                               export_power_mw, export_energy_mwh_total, block_power_json
                        FROM plant_history
                        {where}
                        ORDER BY observed_at DESC
                        LIMIT ?
                    )
                    ORDER BY observed_at
                    """,
                    tuple(params + [limit]),
                ).fetchall()

        return tuple(_plant_history_sample_from_row(row) for row in rows)

    def prune_plant_history(self, *, before: datetime) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM plant_history
                WHERE observed_at < ?
                """,
                (_iso_timestamp(before),),
            )
            return cursor.rowcount

    def delete_plant_history(self) -> int:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM plant_history")
            return cursor.rowcount

    def fetch_ops_settings(self) -> dict[str, Any]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT setting_key, value_json
                FROM ops_settings
                ORDER BY setting_key
                """
            ).fetchall()

        return {str(row["setting_key"]): json.loads(str(row["value_json"])) for row in rows}

    def upsert_ops_settings(self, settings: dict[str, Any], *, updated_at: datetime) -> None:
        if not settings:
            return
        timestamp = _iso_timestamp(updated_at)
        with self._connect() as connection:
            for setting_key, value in settings.items():
                normalized_setting_key = _normalize_required_text(setting_key, field_name="setting_key")
                connection.execute(
                    """
                    INSERT INTO ops_settings (setting_key, value_json, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(setting_key) DO UPDATE SET
                        value_json = excluded.value_json,
                        updated_at = excluded.updated_at
                    """,
                    (
                        normalized_setting_key,
                        _json_blob(value),
                        timestamp,
                    ),
                )

    def fetch_events(self) -> tuple[EventRecord, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT raw_event_json
                FROM event_log
                ORDER BY rowid
                """
            ).fetchall()

        return tuple(EventRecord.model_validate(json.loads(str(row["raw_event_json"]))) for row in rows)

    def fetch_event(self, event_id: str) -> EventRecord | None:
        normalized_event_id = _normalize_required_text(event_id, field_name="event_id")
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT raw_event_json
                FROM event_log
                WHERE event_id = ?
                """,
                (normalized_event_id,),
            ).fetchone()

        if row is None:
            return None
        return EventRecord.model_validate(json.loads(str(row["raw_event_json"])))

    def fetch_alerts(self) -> tuple[AlertRecord, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT alert_id, event_id, correlation_id, alarm_code, severity, state,
                       component, asset_id, message, created_at
                FROM alert_log
                ORDER BY created_at, rowid
                """
            ).fetchall()

        return tuple(
            _alert_from_row(row)
            for row in rows
        )

    def fetch_alert(self, alert_id: str) -> AlertRecord | None:
        normalized_alert_id = _normalize_required_text(alert_id, field_name="alert_id")
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT alert_id, event_id, correlation_id, alarm_code, severity, state,
                       component, asset_id, message, created_at
                FROM alert_log
                WHERE alert_id = ?
                """,
                (normalized_alert_id,),
            ).fetchone()

        if row is None:
            return None
        return _alert_from_row(row)

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

        return tuple(_outbox_entry_from_row(row) for row in rows)

    def lease_outbox_entries(
        self,
        *,
        limit: int,
        not_before: datetime,
    ) -> tuple[OutboxEntry, ...]:
        if limit <= 0:
            raise ValueError("limit muss groesser als 0 sein")

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT outbox_id, target_type, payload_kind, payload_ref, status,
                       retry_count, next_attempt_at, last_error, created_at
                FROM outbox
                WHERE status = 'pending'
                  AND next_attempt_at <= ?
                ORDER BY outbox_id
                LIMIT ?
                """,
                (_iso_timestamp(not_before), limit),
            ).fetchall()
            if not rows:
                return ()

            outbox_ids = [int(row["outbox_id"]) for row in rows]
            placeholders = ", ".join("?" for _ in outbox_ids)
            connection.execute(
                f"""
                UPDATE outbox
                SET status = 'leased'
                WHERE outbox_id IN ({placeholders})
                """,
                outbox_ids,
            )

        leased_entries = []
        for row in rows:
            leased_entries.append(
                _outbox_entry_from_row(
                    {
                        **dict(row),
                        "status": "leased",
                    }
                )
            )
        return tuple(leased_entries)

    def mark_outbox_delivered(self, outbox_ids: Sequence[int]) -> None:
        if not outbox_ids:
            return
        placeholders = ", ".join("?" for _ in outbox_ids)
        with self._connect() as connection:
            connection.execute(
                f"""
                UPDATE outbox
                SET status = 'delivered',
                    last_error = NULL
                WHERE outbox_id IN ({placeholders})
                """,
                tuple(outbox_ids),
            )

    def requeue_outbox_entries(
        self,
        outbox_ids: Sequence[int],
        *,
        next_attempt_at: datetime,
        last_error: str,
    ) -> None:
        if not outbox_ids:
            return
        placeholders = ", ".join("?" for _ in outbox_ids)
        normalized_error = _normalize_required_text(last_error, field_name="last_error")
        with self._connect() as connection:
            connection.execute(
                f"""
                UPDATE outbox
                SET status = 'pending',
                    retry_count = retry_count + 1,
                    next_attempt_at = ?,
                    last_error = ?
                WHERE outbox_id IN ({placeholders})
                """,
                (_iso_timestamp(next_attempt_at), normalized_error, *outbox_ids),
            )

    def mark_outbox_failed(self, outbox_ids: Sequence[int], *, last_error: str) -> None:
        if not outbox_ids:
            return
        placeholders = ", ".join("?" for _ in outbox_ids)
        normalized_error = _normalize_required_text(last_error, field_name="last_error")
        with self._connect() as connection:
            connection.execute(
                f"""
                UPDATE outbox
                SET status = 'failed',
                    retry_count = retry_count + 1,
                    last_error = ?
                WHERE outbox_id IN ({placeholders})
                """,
                (normalized_error, *outbox_ids),
            )


def _alert_from_row(row: sqlite3.Row) -> AlertRecord:
    return AlertRecord(
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


def _plant_history_params(sample: PlantHistorySample) -> tuple[Any, ...]:
    return (
        _iso_timestamp(sample.observed_at),
        sample.plant_power_mw,
        sample.active_power_limit_pct,
        sample.irradiance_w_m2,
        sample.export_power_mw,
        sample.export_energy_mwh_total,
        _json_blob(tuple(sample.block_power_kw)),
    )


def _plant_history_sample_from_row(row: sqlite3.Row) -> PlantHistorySample:
    block_power = json.loads(str(row["block_power_json"]))
    return PlantHistorySample(
        observed_at=_parse_timestamp(str(row["observed_at"])),
        plant_power_mw=float(row["plant_power_mw"]),
        active_power_limit_pct=float(row["active_power_limit_pct"]),
        irradiance_w_m2=float(row["irradiance_w_m2"]),
        export_power_mw=float(row["export_power_mw"]),
        export_energy_mwh_total=(
            None if row["export_energy_mwh_total"] is None else float(row["export_energy_mwh_total"])
        ),
        block_power_kw=tuple((str(asset_id), float(power_kw)) for asset_id, power_kw in block_power),
    )


def _login_campaign_from_row(row: sqlite3.Row) -> LoginCampaignRecord:
    return LoginCampaignRecord(
        campaign_id=str(row["campaign_id"]),
        source_ip=str(row["source_ip"]),
        user_agent=str(row["user_agent"]),
        endpoint=str(row["endpoint"]),
        first_seen=_parse_timestamp(str(row["first_seen"])),
        last_seen=_parse_timestamp(str(row["last_seen"])),
        attempt_count=int(row["attempt_count"]),
    )


def _credential_count_from_row(row: sqlite3.Row) -> CredentialCountRecord:
    return CredentialCountRecord(
        scope_type=str(row["scope_type"]),
        scope_id=str(row["scope_id"]),
        value_type=str(row["value_type"]),
        credential_value=str(row["credential_value"]),
        credential_fingerprint=str(row["credential_fingerprint"]),
        count=int(row["count"]),
        first_seen=_parse_timestamp(str(row["first_seen"])),
        last_seen=_parse_timestamp(str(row["last_seen"])),
    )


def _sanitize_credential_value(value: str, *, max_length: int) -> str:
    if max_length <= 0:
        raise ValueError("max_credential_length muss groesser als 0 sein")
    normalized = "".join(char if char.isprintable() and char not in "\r\n\t" else "?" for char in value)
    return normalized[:max_length]


def _credential_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _upsert_credential_count(
    connection: sqlite3.Connection,
    *,
    scope_type: str,
    scope_id: str,
    value_type: str,
    credential_value: str,
    observed_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO login_credential_counts (
            scope_type, scope_id, value_type, credential_value, credential_fingerprint,
            count, first_seen, last_seen
        ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(scope_type, scope_id, value_type, credential_value) DO UPDATE SET
            count = count + 1,
            first_seen = CASE
                WHEN excluded.first_seen < first_seen THEN excluded.first_seen
                ELSE first_seen
            END,
            last_seen = CASE
                WHEN excluded.last_seen > last_seen THEN excluded.last_seen
                ELSE last_seen
            END
        """,
        (
            scope_type,
            scope_id,
            value_type,
            credential_value,
            _credential_fingerprint(credential_value),
            observed_at,
            observed_at,
        ),
    )


def _credential_exists(
    connection: sqlite3.Connection,
    *,
    scope_type: str,
    scope_id: str,
    value_type: str,
    credential_value: str,
) -> bool:
    row = connection.execute(
        """
        SELECT 1
        FROM login_credential_counts
        WHERE scope_type = ?
          AND scope_id = ?
          AND value_type = ?
          AND credential_value = ?
        LIMIT 1
        """,
        (scope_type, scope_id, value_type, credential_value),
    ).fetchone()
    return row is not None


def _all_time_unique_password_count(connection: sqlite3.Connection) -> int:
    stat_value = _login_capture_stat(connection, stat_key="all_time_unique_passwords")
    if stat_value is not None:
        return stat_value
    row = connection.execute(
        """
        SELECT COUNT(*) AS row_count
        FROM login_credential_counts
        WHERE scope_type = 'all_time'
          AND scope_id = 'all'
          AND value_type = 'password'
        """
    ).fetchone()
    return int(row["row_count"])


def _login_capture_stat(connection: sqlite3.Connection, *, stat_key: str) -> int | None:
    row = connection.execute(
        """
        SELECT stat_value
        FROM login_capture_stats
        WHERE stat_key = ?
        """,
        (stat_key,),
    ).fetchone()
    if row is None:
        return None
    return int(row["stat_value"])


def _set_login_capture_stat(
    connection: sqlite3.Connection,
    *,
    stat_key: str,
    stat_value: int,
    updated_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO login_capture_stats (stat_key, stat_value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(stat_key) DO UPDATE SET
            stat_value = excluded.stat_value,
            updated_at = excluded.updated_at
        """,
        (stat_key, stat_value, updated_at),
    )


def _increment_login_capture_stat(
    connection: sqlite3.Connection,
    *,
    stat_key: str,
    delta: int,
    updated_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO login_capture_stats (stat_key, stat_value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(stat_key) DO UPDATE SET
            stat_value = stat_value + excluded.stat_value,
            updated_at = excluded.updated_at
        """,
        (stat_key, delta, updated_at),
    )


def _outbox_entry_from_row(row: sqlite3.Row | dict[str, Any]) -> OutboxEntry:
    return OutboxEntry(
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
