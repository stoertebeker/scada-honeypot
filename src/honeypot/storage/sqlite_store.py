"""Lokaler SQLite-Wahrheitskern fuer Events, Alerts, State und Outbox."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
import shutil
from threading import RLock
from typing import Any, Sequence

from honeypot.event_core.models import AlertRecord, EventRecord, OutboxEntry
from honeypot.history_core import PlantHistorySample
from honeypot.storage.retention import SQLiteRetentionPolicy
from honeypot.time_core import ensure_utc_datetime

_SOURCE_ACTIVITY_SORT_COLUMNS = {
    "source_ip": "source_ip",
    "events": "event_count",
    "rejected": "rejected_count",
    "sessions": "session_count",
    "first_seen": "first_seen",
    "last_seen": "last_seen",
    "top_type": "top_event_type",
    "top_endpoint": "top_endpoint",
}
_SOURCE_ACTIVITY_SORT_DIRECTIONS = {"asc", "desc"}
_SOURCE_ACTIVITY_DERIVED_SORTS = {"top_type", "top_endpoint"}


def _filesystem_free_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free


def _utc_now() -> datetime:
    return datetime.now(UTC)


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


def _ensure_plant_history_operating_mode_column(connection: sqlite3.Connection) -> None:
    columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(plant_history)").fetchall()
    }
    if "operating_mode" not in columns:
        connection.execute("ALTER TABLE plant_history ADD COLUMN operating_mode TEXT NOT NULL DEFAULT 'normal'")


def _normalize_operating_mode(value: object) -> str:
    normalized = str(value or "normal").strip().lower()
    if normalized in {"normal", "curtailed", "maintenance", "faulted"}:
        return normalized
    return "normal"


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


@dataclass(frozen=True, slots=True)
class EventPage:
    events: tuple[EventRecord, ...]
    next_before_rowid: int | None


@dataclass(frozen=True, slots=True)
class EventActivitySummary:
    total_events: int
    total_alerts: int
    active_alerts: int
    unique_sources: int
    rejected_events: int
    last_event_at: datetime | None


@dataclass(frozen=True, slots=True)
class SourceActivityRecord:
    source_ip: str
    event_count: int
    rejected_count: int
    session_count: int
    first_seen: datetime
    last_seen: datetime
    top_event_type: str
    top_endpoint: str


class SQLiteEventStore:
    """SQLite-Persistenz fuer `current_state`, `event_log`, `alert_log` und `outbox`."""

    def __init__(
        self,
        path: str | Path,
        *,
        retention_policy: SQLiteRetentionPolicy | None = None,
        free_bytes_provider: Callable[[Path], int] = _filesystem_free_bytes,
        now_provider: Callable[[], datetime] = _utc_now,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.retention_policy = SQLiteRetentionPolicy() if retention_policy is None else retention_policy
        self._free_bytes_provider = free_bytes_provider
        self._now_provider = now_provider
        self._retention_lock = RLock()
        self._writes_since_sweep = 0
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL;")
        connection.execute("PRAGMA foreign_keys=ON;")
        page_size = int(connection.execute("PRAGMA page_size;").fetchone()[0])
        wal_budget = min(64 * 1024 * 1024, max(page_size, self.retention_policy.max_database_bytes // 8))
        shared_memory_budget = min(
            1024 * 1024,
            max(page_size, self.retention_policy.max_database_bytes // 64),
        )
        database_budget = max(
            page_size,
            self.retention_policy.max_database_bytes - wal_budget - shared_memory_budget,
        )
        connection.execute(f"PRAGMA max_page_count={max(1, database_budget // page_size)};")
        connection.execute(f"PRAGMA journal_size_limit={wal_budget};")
        connection.execute(f"PRAGMA wal_autocheckpoint={max(1, wal_budget // page_size)};")
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
                    operating_mode TEXT NOT NULL DEFAULT 'normal',
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

                CREATE TABLE IF NOT EXISTS evidence_retention_stats (
                    stat_key TEXT PRIMARY KEY,
                    stat_value INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_outbox_status_next_attempt
                ON outbox(status, next_attempt_at);

                CREATE INDEX IF NOT EXISTS idx_event_log_event_type
                ON event_log(event_type);

                CREATE INDEX IF NOT EXISTS idx_event_log_source_ip
                ON event_log(source_ip);

                CREATE INDEX IF NOT EXISTS idx_event_log_result
                ON event_log(result);

                CREATE INDEX IF NOT EXISTS idx_event_log_source_type
                ON event_log(source_ip, event_type);

                CREATE INDEX IF NOT EXISTS idx_event_log_source_endpoint
                ON event_log(source_ip, endpoint_or_register);

                CREATE INDEX IF NOT EXISTS idx_alert_log_state
                ON alert_log(state);

                CREATE INDEX IF NOT EXISTS idx_alert_log_created_at
                ON alert_log(created_at);

                CREATE INDEX IF NOT EXISTS idx_alert_log_rule_context
                ON alert_log(alarm_code, severity, component, asset_id, message, created_at);

                CREATE INDEX IF NOT EXISTS idx_plant_history_observed_at
                ON plant_history(observed_at);

                CREATE INDEX IF NOT EXISTS idx_login_campaigns_last_seen
                ON login_campaigns(last_seen);

                CREATE INDEX IF NOT EXISTS idx_login_credential_top
                ON login_credential_counts(scope_type, scope_id, value_type, count DESC, last_seen DESC);
                """
            )
            _ensure_plant_history_operating_mode_column(connection)
        self.enforce_retention()

    def journal_mode(self) -> str:
        with self._connect() as connection:
            row = connection.execute("PRAGMA journal_mode;").fetchone()
        return str(row[0])

    def append_event(self, event: EventRecord) -> bool:
        payload = event.model_dump(mode="json")
        serialized_payload = _json_blob(payload)
        estimated_write_bytes = len(serialized_payload.encode("utf-8")) + 64 * 1024
        with self._retention_lock:
            health_event = event.category == "system" and event.actor_type == "system"
            try:
                has_capacity = self._has_write_capacity(
                    use_health_reserve=health_event,
                    estimated_write_bytes=estimated_write_bytes,
                )
            except (OSError, sqlite3.Error):
                has_capacity = False
            if not has_capacity:
                try:
                    with self._connect() as connection:
                        _increment_retention_stat(
                            connection,
                            stat_key="events_dropped",
                            delta=1,
                            updated_at=_iso_timestamp(self._now_provider()),
                        )
                except sqlite3.Error:
                    pass
                return False
            try:
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
                            serialized_payload,
                        ),
                    )
                    _increment_retention_stat(
                        connection,
                        stat_key="events_retained",
                        delta=1,
                        updated_at=_iso_timestamp(self._now_provider()),
                    )
            except sqlite3.OperationalError as exc:
                if not _is_storage_exhaustion_error(exc):
                    raise
                try:
                    with self._connect() as connection:
                        _increment_retention_stat(
                            connection,
                            stat_key="events_dropped",
                            delta=1,
                            updated_at=_iso_timestamp(self._now_provider()),
                        )
                except sqlite3.Error:
                    pass
                return False
            self._after_evidence_write_locked(observed_at=event.timestamp)
            with self._connect() as connection:
                return connection.execute(
                    "SELECT 1 FROM event_log WHERE event_id = ?",
                    (event.event_id,),
                ).fetchone() is not None

    def append_alert(self, alert: AlertRecord) -> None:
        self.append_alert_with_targets(
            alert,
            target_types=(),
            next_attempt_at=alert.created_at,
        )

    def append_alert_with_targets(
        self,
        alert: AlertRecord,
        *,
        target_types: Sequence[str],
        next_attempt_at: datetime,
    ) -> tuple[OutboxEntry, ...] | None:
        """Persistiert Alert und Outbox atomar, sofern sein Event noch vorhanden ist."""

        with self._retention_lock, self._connect() as connection:
            event_exists = connection.execute(
                "SELECT 1 FROM event_log WHERE event_id = ?",
                (alert.event_id,),
            ).fetchone() is not None
            if not event_exists:
                return None
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
            return _enqueue_alert_targets(
                connection,
                alert=alert,
                target_types=target_types,
                next_attempt_at=next_attempt_at,
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

        with self._connect() as connection:
            return _enqueue_alert_targets(
                connection,
                alert=alert,
                target_types=target_types,
                next_attempt_at=next_attempt_at,
            )

    def upsert_current_state(self, state_key: str, state_payload: Any, *, updated_at: datetime) -> bool:
        normalized_state_key = _normalize_required_text(state_key, field_name="state_key")
        try:
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
        except sqlite3.OperationalError as exc:
            if not _is_storage_exhaustion_error(exc):
                raise
            return False
        return True

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
            "evidence_retention_stats",
        }:
            raise ValueError(f"ungueltiger Tabellenname: {table_name}")
        with self._connect() as connection:
            row = connection.execute(f"SELECT COUNT(*) AS row_count FROM {table_name}").fetchone()
        return int(row["row_count"])

    def enforce_retention(self, *, reference_time: datetime | None = None) -> None:
        """Entfernt alte/ueberzaehlige Belege und begrenzt WAL-Wachstum."""

        with self._retention_lock:
            retention_now = self._now_provider() if reference_time is None else reference_time
            cutoff = _iso_timestamp(
                retention_now - timedelta(days=self.retention_policy.max_age_days)
            )
            updated_at = _iso_timestamp(retention_now)
            with self._connect() as connection:
                outbox_pruned = _prune_outbox(
                    connection,
                    cutoff=cutoff,
                    max_rows=self.retention_policy.max_outbox_rows,
                )
                alerts_pruned, dependent_outbox_pruned = _prune_alerts(
                    connection,
                    cutoff=cutoff,
                    max_rows=self.retention_policy.max_alert_rows,
                )
                events_pruned, dependent_alerts_pruned, event_outbox_pruned = _prune_events(
                    connection,
                    cutoff=cutoff,
                    max_rows=self.retention_policy.max_event_rows,
                    max_rows_per_source=self.retention_policy.max_event_rows_per_source,
                )
                campaigns_pruned, campaign_credentials_pruned = _prune_campaigns(
                    connection,
                    cutoff=cutoff,
                    max_rows=self.retention_policy.max_campaign_rows,
                    max_rows_per_source=self.retention_policy.max_campaign_rows_per_source,
                )
                credentials_pruned = _prune_credentials(
                    connection,
                    cutoff=cutoff,
                    max_rows=self.retention_policy.max_credential_rows,
                )
                _increment_retention_stat(
                    connection,
                    stat_key="outbox_pruned",
                    delta=outbox_pruned + dependent_outbox_pruned + event_outbox_pruned,
                    updated_at=updated_at,
                )
                _increment_retention_stat(
                    connection,
                    stat_key="alerts_pruned",
                    delta=alerts_pruned + dependent_alerts_pruned,
                    updated_at=updated_at,
                )
                _increment_retention_stat(
                    connection,
                    stat_key="events_pruned",
                    delta=events_pruned,
                    updated_at=updated_at,
                )
                _increment_retention_stat(
                    connection,
                    stat_key="campaigns_pruned",
                    delta=campaigns_pruned,
                    updated_at=updated_at,
                )
                _increment_retention_stat(
                    connection,
                    stat_key="credentials_pruned",
                    delta=campaign_credentials_pruned + credentials_pruned,
                    updated_at=updated_at,
                )
            self._writes_since_sweep = 0
            with self._connect() as connection:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE);")

    def evidence_retention_status(self) -> dict[str, Any]:
        with self._connect() as connection:
            counters = {
                str(row["stat_key"]): int(row["stat_value"])
                for row in connection.execute(
                    "SELECT stat_key, stat_value FROM evidence_retention_stats ORDER BY stat_key"
                ).fetchall()
            }
            retained_rows = {
                table_name: int(
                    connection.execute(
                        f"SELECT COUNT(*) AS row_count FROM {table_name}"
                    ).fetchone()["row_count"]
                )
                for table_name in (
                    "event_log",
                    "alert_log",
                    "outbox",
                    "login_campaigns",
                    "login_credential_counts",
                )
            }
        for counter_name in (
            "events_retained",
            "events_dropped",
            "events_pruned",
            "alerts_pruned",
            "outbox_pruned",
            "campaigns_dropped",
            "campaigns_pruned",
            "usernames_dropped",
            "credentials_pruned",
        ):
            counters.setdefault(counter_name, 0)
        return {
            "retained_rows": retained_rows,
            "database_bytes": self._database_bytes(),
            "database_used_bytes": self._database_used_bytes(),
            "free_bytes": self._free_bytes_provider(self.path.parent),
            "max_database_bytes": self.retention_policy.max_database_bytes,
            "min_free_bytes": self.retention_policy.min_free_bytes,
            "reserved_health_bytes": self.retention_policy.reserved_health_bytes,
            "counters": counters,
        }

    def _after_evidence_write_locked(self, *, observed_at: datetime) -> None:
        self._writes_since_sweep += 1
        if self._writes_since_sweep >= self.retention_policy.sweep_interval_writes:
            self.enforce_retention(reference_time=observed_at)

    def _has_write_capacity(
        self,
        *,
        use_health_reserve: bool,
        estimated_write_bytes: int = 0,
    ) -> bool:
        reserve = 0 if use_health_reserve else self.retention_policy.reserved_health_bytes
        if (
            self._free_bytes_provider(self.path.parent) - estimated_write_bytes
            < self.retention_policy.min_free_bytes + reserve
        ):
            return False
        byte_limit = self.retention_policy.max_database_bytes - reserve
        if self._database_used_bytes() + estimated_write_bytes <= byte_limit:
            return True

        batch_size = max(1, min(100, self.retention_policy.sweep_interval_writes))
        for _ in range(16):
            pruned = self._prune_byte_pressure_batch_locked(batch_size=batch_size)
            if not pruned:
                return False
            if self._database_used_bytes() + estimated_write_bytes <= byte_limit:
                return True
        return False

    def _database_bytes(self) -> int:
        candidates = (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
        )
        return sum(candidate.stat().st_size for candidate in candidates if candidate.exists())

    def _database_used_bytes(self) -> int:
        with self._connect() as connection:
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
            freelist_count = int(connection.execute("PRAGMA freelist_count").fetchone()[0])
        auxiliary_paths = (Path(f"{self.path}-wal"), Path(f"{self.path}-shm"))
        auxiliary_bytes = sum(path.stat().st_size for path in auxiliary_paths if path.exists())
        return max(0, page_count - freelist_count) * page_size + auxiliary_bytes

    def _prune_byte_pressure_batch_locked(self, *, batch_size: int) -> bool:
        updated_at = _iso_timestamp(self._now_provider())
        with self._connect() as connection:
            pruned = _prune_oldest_evidence_batch(connection, batch_size=batch_size)
            for stat_key, delta in pruned.items():
                _increment_retention_stat(
                    connection,
                    stat_key=stat_key,
                    delta=delta,
                    updated_at=updated_at,
                )
        if not any(pruned.values()):
            return False
        with self._connect() as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        return True

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

        with self._retention_lock:
            try:
                has_capacity = self._has_write_capacity(
                    use_health_reserve=False,
                    estimated_write_bytes=64 * 1024,
                )
            except (OSError, sqlite3.Error):
                has_capacity = False
            if not has_capacity:
                try:
                    with self._connect() as connection:
                        _increment_retention_stat(
                            connection,
                            stat_key="campaigns_dropped",
                            delta=1,
                            updated_at=timestamp,
                        )
                        _increment_retention_stat(
                            connection,
                            stat_key="usernames_dropped",
                            delta=1,
                            updated_at=timestamp,
                        )
                except sqlite3.Error:
                    pass
                return

            with self._connect() as connection:
                campaign_exists = connection.execute(
                    "SELECT 1 FROM login_campaigns WHERE campaign_id = ?",
                    (normalized_campaign_id,),
                ).fetchone() is not None
                if not campaign_exists:
                    global_campaign_count = int(
                        connection.execute("SELECT COUNT(*) FROM login_campaigns").fetchone()[0]
                    )
                    source_campaign_count = int(
                        connection.execute(
                            "SELECT COUNT(*) FROM login_campaigns WHERE source_ip = ?",
                            (normalized_source_ip,),
                        ).fetchone()[0]
                    )
                    if (
                        global_campaign_count >= self.retention_policy.max_campaign_rows
                        or source_campaign_count >= self.retention_policy.max_campaign_rows_per_source
                    ):
                        _increment_retention_stat(
                            connection,
                            stat_key="campaigns_dropped",
                            delta=1,
                            updated_at=timestamp,
                        )
                        _increment_retention_stat(
                            connection,
                            stat_key="usernames_dropped",
                            delta=1,
                            updated_at=timestamp,
                        )
                        return

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

                global_username_exists = _credential_exists(
                    connection,
                    scope_type="all_time",
                    scope_id="all",
                    value_type="username",
                    credential_value=normalized_username,
                )
                global_username_count = _credential_scope_count(
                    connection,
                    scope_type="all_time",
                    scope_id="all",
                    value_type="username",
                )
                source_username_exists = _source_username_exists(
                    connection,
                    source_ip=normalized_source_ip,
                    credential_value=normalized_username,
                )
                source_username_count = _source_unique_username_count(
                    connection,
                    source_ip=normalized_source_ip,
                )
                username_allowed = (
                    (global_username_exists or global_username_count < self.retention_policy.max_unique_usernames)
                    and (
                        source_username_exists
                        or source_username_count < self.retention_policy.max_unique_usernames_per_source
                    )
                )
                if username_allowed:
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
                else:
                    _increment_retention_stat(
                        connection,
                        stat_key="usernames_dropped",
                        delta=1,
                        updated_at=timestamp,
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
            self._after_evidence_write_locked(observed_at=observed_at)

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
                    observed_at, operating_mode, plant_power_mw, active_power_limit_pct, irradiance_w_m2,
                    export_power_mw, export_energy_mwh_total, block_power_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(observed_at) DO UPDATE SET
                    operating_mode = excluded.operating_mode,
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
                    SELECT observed_at, operating_mode, plant_power_mw, active_power_limit_pct, irradiance_w_m2,
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
                    SELECT observed_at, operating_mode, plant_power_mw, active_power_limit_pct, irradiance_w_m2,
                           export_power_mw, export_energy_mwh_total, block_power_json
                    FROM (
                        SELECT observed_at, operating_mode, plant_power_mw, active_power_limit_pct, irradiance_w_m2,
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

    def fetch_events_page(
        self,
        *,
        limit: int,
        before_rowid: int | None = None,
        event_type: str | None = None,
        source_ips: Sequence[str] = (),
        excluded_source_ips: Sequence[str] = (),
        result: str | None = None,
    ) -> EventPage:
        if limit <= 0:
            raise ValueError("limit muss groesser als 0 sein")
        if before_rowid is not None and before_rowid <= 0:
            raise ValueError("before_rowid muss groesser als 0 sein")

        clauses: list[str] = []
        params: list[Any] = []
        if before_rowid is not None:
            clauses.append("rowid < ?")
            params.append(before_rowid)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        _append_in_clause(
            clauses,
            params,
            column="source_ip",
            values=source_ips,
            negated=False,
        )
        _append_in_clause(
            clauses,
            params,
            column="source_ip",
            values=excluded_source_ips,
            negated=True,
        )
        if result:
            clauses.append("result = ?")
            params.append(result)

        where = "" if not clauses else f"WHERE {' AND '.join(clauses)}"
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT rowid, raw_event_json
                FROM event_log
                {where}
                ORDER BY rowid DESC
                LIMIT ?
                """,
                tuple(params + [limit + 1]),
            ).fetchall()

        page_rows = rows[:limit]
        next_before_rowid = int(page_rows[-1]["rowid"]) if len(rows) > limit and page_rows else None
        return EventPage(
            events=tuple(EventRecord.model_validate(json.loads(str(row["raw_event_json"]))) for row in page_rows),
            next_before_rowid=next_before_rowid,
        )

    def fetch_activity_summary(self) -> EventActivitySummary:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM event_log) AS total_events,
                    (SELECT COUNT(*) FROM alert_log) AS total_alerts,
                    (SELECT COUNT(*) FROM alert_log WHERE state LIKE 'active%') AS active_alerts,
                    (SELECT COUNT(DISTINCT source_ip) FROM event_log) AS unique_sources,
                    (SELECT COUNT(*) FROM event_log WHERE result = 'rejected') AS rejected_events,
                    (SELECT timestamp FROM event_log ORDER BY rowid DESC LIMIT 1) AS last_event_at
                """
            ).fetchone()

        last_event_at = row["last_event_at"]
        return EventActivitySummary(
            total_events=int(row["total_events"]),
            total_alerts=int(row["total_alerts"]),
            active_alerts=int(row["active_alerts"]),
            unique_sources=int(row["unique_sources"]),
            rejected_events=int(row["rejected_events"]),
            last_event_at=None if last_event_at is None else _parse_timestamp(str(last_event_at)),
        )

    def fetch_source_activity(
        self,
        *,
        limit: int,
        sort: str = "last_seen",
        direction: str = "desc",
    ) -> tuple[SourceActivityRecord, ...]:
        if limit <= 0:
            raise ValueError("limit muss groesser als 0 sein")
        sort_key = sort.strip().lower()
        if sort_key in _SOURCE_ACTIVITY_DERIVED_SORTS:
            rows = self._fetch_source_activity_with_derived_sort(
                limit=limit,
                sort=sort_key,
                direction=direction,
            )
        else:
            rows = self._fetch_source_activity_with_base_sort(
                limit=limit,
                sort=sort_key,
                direction=direction,
            )

        return tuple(_source_activity_from_row(row) for row in rows)

    def _fetch_source_activity_with_base_sort(
        self,
        *,
        limit: int,
        sort: str,
        direction: str,
    ) -> tuple[sqlite3.Row, ...]:
        grouped_order_by = _source_activity_order_by(sort=sort, direction=direction, table_alias="grouped")
        ranked_order_by = _source_activity_order_by(sort=sort, direction=direction, table_alias="ranked")
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                WITH grouped AS (
                    SELECT
                        source_ip,
                        COUNT(*) AS event_count,
                        SUM(CASE WHEN result = 'rejected' THEN 1 ELSE 0 END) AS rejected_count,
                        COUNT(DISTINCT NULLIF(session_id, '')) AS session_count,
                        MIN(timestamp) AS first_seen,
                        MAX(timestamp) AS last_seen
                    FROM event_log
                    GROUP BY source_ip
                )
                SELECT
                    ranked.source_ip,
                    ranked.event_count,
                    ranked.rejected_count,
                    ranked.session_count,
                    ranked.first_seen,
                    ranked.last_seen,
                    (
                        SELECT event_type
                        FROM event_log AS type_events
                        WHERE type_events.source_ip = ranked.source_ip
                        GROUP BY event_type
                        ORDER BY COUNT(*) DESC, MIN(rowid) ASC
                        LIMIT 1
                    ) AS top_event_type,
                    (
                        SELECT COALESCE(endpoint_or_register, '')
                        FROM event_log AS endpoint_events
                        WHERE endpoint_events.source_ip = ranked.source_ip
                        GROUP BY COALESCE(endpoint_or_register, '')
                        ORDER BY COUNT(*) DESC, MIN(rowid) ASC
                        LIMIT 1
                    ) AS top_endpoint
                FROM (
                    SELECT *
                    FROM grouped
                    ORDER BY {grouped_order_by}
                    LIMIT ?
                ) AS ranked
                ORDER BY {ranked_order_by}
                """,
                (limit,),
            ).fetchall()
        return tuple(rows)

    def _fetch_source_activity_with_derived_sort(
        self,
        *,
        limit: int,
        sort: str,
        direction: str,
    ) -> tuple[sqlite3.Row, ...]:
        order_by = _source_activity_order_by(sort=sort, direction=direction, table_alias="grouped")
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                WITH grouped AS (
                    SELECT
                        source_ip,
                        COUNT(*) AS event_count,
                        SUM(CASE WHEN result = 'rejected' THEN 1 ELSE 0 END) AS rejected_count,
                        COUNT(DISTINCT NULLIF(session_id, '')) AS session_count,
                        MIN(timestamp) AS first_seen,
                        MAX(timestamp) AS last_seen
                    FROM event_log
                    GROUP BY source_ip
                )
                SELECT
                    grouped.source_ip,
                    grouped.event_count,
                    grouped.rejected_count,
                    grouped.session_count,
                    grouped.first_seen,
                    grouped.last_seen,
                    (
                        SELECT event_type
                        FROM event_log AS type_events
                        WHERE type_events.source_ip = grouped.source_ip
                        GROUP BY event_type
                        ORDER BY COUNT(*) DESC, MIN(rowid) ASC
                        LIMIT 1
                    ) AS top_event_type,
                    (
                        SELECT COALESCE(endpoint_or_register, '')
                        FROM event_log AS endpoint_events
                        WHERE endpoint_events.source_ip = grouped.source_ip
                        GROUP BY COALESCE(endpoint_or_register, '')
                        ORDER BY COUNT(*) DESC, MIN(rowid) ASC
                        LIMIT 1
                    ) AS top_endpoint
                FROM grouped
                ORDER BY {order_by}
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return tuple(rows)

    def fetch_top_sources(self, *, limit: int) -> tuple[SourceActivityRecord, ...]:
        return self.fetch_source_activity(limit=limit, sort="events", direction="desc")

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

    def fetch_recent_alerts(self, *, limit: int) -> tuple[AlertRecord, ...]:
        if limit <= 0:
            raise ValueError("limit muss groesser als 0 sein")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT alert_id, event_id, correlation_id, alarm_code, severity, state,
                       component, asset_id, message, created_at
                FROM alert_log
                ORDER BY created_at DESC, rowid DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return tuple(_alert_from_row(row) for row in rows)

    def fetch_rule_alert_context(self, *, alarm_codes: Sequence[str]) -> tuple[AlertRecord, ...]:
        normalized_alarm_codes = tuple(
            dict.fromkeys(
                _normalize_required_text(alarm_code, field_name="alarm_code")
                for alarm_code in alarm_codes
            )
        )
        if not normalized_alarm_codes:
            return ()

        placeholders = ", ".join("?" for _ in normalized_alarm_codes)
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT alert_id, event_id, correlation_id, alarm_code, severity, state,
                       component, asset_id, message, created_at
                FROM (
                    SELECT alert_id, event_id, correlation_id, alarm_code, severity, state,
                           component, asset_id, message, created_at,
                           ROW_NUMBER() OVER (
                               PARTITION BY alarm_code, severity, component, asset_id, COALESCE(message, '')
                               ORDER BY created_at DESC, rowid DESC
                           ) AS rank
                    FROM alert_log
                    WHERE alarm_code IN ({placeholders})
                )
                WHERE rank = 1
                ORDER BY created_at, alert_id
                """,
                normalized_alarm_codes,
            ).fetchall()

        return tuple(_alert_from_row(row) for row in rows)

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


def _increment_retention_stat(
    connection: sqlite3.Connection,
    *,
    stat_key: str,
    delta: int,
    updated_at: str,
) -> None:
    if delta <= 0:
        return
    connection.execute(
        """
        INSERT INTO evidence_retention_stats (stat_key, stat_value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(stat_key) DO UPDATE SET
            stat_value = stat_value + excluded.stat_value,
            updated_at = excluded.updated_at
        """,
        (stat_key, delta, updated_at),
    )


def _enqueue_alert_targets(
    connection: sqlite3.Connection,
    *,
    alert: AlertRecord,
    target_types: Sequence[str],
    next_attempt_at: datetime,
) -> tuple[OutboxEntry, ...]:
    created_at = alert.created_at
    entries: list[OutboxEntry] = []
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


def _is_storage_exhaustion_error(exc: sqlite3.OperationalError) -> bool:
    message = str(exc).lower()
    return any(
        marker in message
        for marker in (
            "database or disk is full",
            "database full",
            "disk i/o error",
        )
    )


def _prune_oldest_evidence_batch(
    connection: sqlite3.Connection,
    *,
    batch_size: int,
) -> dict[str, int]:
    outbox_pruned = connection.execute(
        """
        DELETE FROM outbox
        WHERE outbox_id IN (
            SELECT outbox_id FROM outbox ORDER BY outbox_id ASC LIMIT ?
        )
        """,
        (batch_size,),
    ).rowcount

    connection.execute(
        "CREATE TEMP TABLE IF NOT EXISTS retention_alert_ids (alert_id TEXT PRIMARY KEY)"
    )
    connection.execute("DELETE FROM retention_alert_ids")
    connection.execute(
        """
        INSERT OR IGNORE INTO retention_alert_ids
        SELECT alert_id FROM alert_log ORDER BY created_at ASC, rowid ASC LIMIT ?
        """,
        (batch_size,),
    )
    alert_count = int(connection.execute("SELECT COUNT(*) FROM retention_alert_ids").fetchone()[0])
    outbox_pruned += connection.execute(
        "DELETE FROM outbox WHERE payload_ref IN (SELECT alert_id FROM retention_alert_ids)"
    ).rowcount
    connection.execute(
        "DELETE FROM alert_log WHERE alert_id IN (SELECT alert_id FROM retention_alert_ids)"
    )

    connection.execute(
        "CREATE TEMP TABLE IF NOT EXISTS retention_event_ids (event_id TEXT PRIMARY KEY)"
    )
    connection.execute("DELETE FROM retention_event_ids")
    connection.execute(
        """
        INSERT OR IGNORE INTO retention_event_ids
        SELECT event_id FROM event_log ORDER BY rowid ASC LIMIT ?
        """,
        (batch_size,),
    )
    event_count = int(connection.execute("SELECT COUNT(*) FROM retention_event_ids").fetchone()[0])
    outbox_pruned += connection.execute(
        """
        DELETE FROM outbox
        WHERE payload_ref IN (
            SELECT alert_id FROM alert_log
            WHERE event_id IN (SELECT event_id FROM retention_event_ids)
        )
        """
    ).rowcount
    dependent_alerts = connection.execute(
        "DELETE FROM alert_log WHERE event_id IN (SELECT event_id FROM retention_event_ids)"
    ).rowcount
    connection.execute(
        "DELETE FROM event_log WHERE event_id IN (SELECT event_id FROM retention_event_ids)"
    )

    connection.execute(
        "CREATE TEMP TABLE IF NOT EXISTS retention_campaign_ids (campaign_id TEXT PRIMARY KEY)"
    )
    connection.execute("DELETE FROM retention_campaign_ids")
    connection.execute(
        """
        INSERT OR IGNORE INTO retention_campaign_ids
        SELECT campaign_id
        FROM login_campaigns
        ORDER BY last_seen ASC, rowid ASC
        LIMIT ?
        """,
        (batch_size,),
    )
    campaign_count = int(connection.execute("SELECT COUNT(*) FROM retention_campaign_ids").fetchone()[0])
    campaign_credentials = connection.execute(
        """
        DELETE FROM login_credential_counts
        WHERE scope_type = 'campaign'
          AND scope_id IN (SELECT campaign_id FROM retention_campaign_ids)
        """
    ).rowcount
    connection.execute(
        "DELETE FROM login_campaigns WHERE campaign_id IN (SELECT campaign_id FROM retention_campaign_ids)"
    )
    credentials_pruned = connection.execute(
        """
        DELETE FROM login_credential_counts
        WHERE rowid IN (
            SELECT rowid
            FROM login_credential_counts
            ORDER BY last_seen ASC, rowid ASC
            LIMIT ?
        )
        """,
        (batch_size,),
    ).rowcount

    return {
        "outbox_pruned": outbox_pruned,
        "alerts_pruned": alert_count + dependent_alerts,
        "events_pruned": event_count,
        "campaigns_pruned": campaign_count,
        "credentials_pruned": campaign_credentials + credentials_pruned,
    }


def _prune_outbox(connection: sqlite3.Connection, *, cutoff: str, max_rows: int) -> int:
    expired = connection.execute(
        "DELETE FROM outbox WHERE created_at < ?",
        (cutoff,),
    ).rowcount
    overflow = connection.execute(
        """
        DELETE FROM outbox
        WHERE outbox_id IN (
            SELECT outbox_id
            FROM outbox
            ORDER BY outbox_id DESC
            LIMIT -1 OFFSET ?
        )
        """,
        (max_rows,),
    ).rowcount
    return expired + overflow


def _prune_alerts(
    connection: sqlite3.Connection,
    *,
    cutoff: str,
    max_rows: int,
) -> tuple[int, int]:
    connection.execute(
        "CREATE TEMP TABLE IF NOT EXISTS retention_alert_ids (alert_id TEXT PRIMARY KEY)"
    )
    connection.execute("DELETE FROM retention_alert_ids")
    connection.execute(
        "INSERT OR IGNORE INTO retention_alert_ids SELECT alert_id FROM alert_log WHERE created_at < ?",
        (cutoff,),
    )
    connection.execute(
        """
        INSERT OR IGNORE INTO retention_alert_ids
        SELECT alert_id FROM alert_log ORDER BY rowid DESC LIMIT -1 OFFSET ?
        """,
        (max_rows,),
    )
    alert_count = int(connection.execute("SELECT COUNT(*) FROM retention_alert_ids").fetchone()[0])
    dependent_outbox = connection.execute(
        "DELETE FROM outbox WHERE payload_ref IN (SELECT alert_id FROM retention_alert_ids)"
    ).rowcount
    connection.execute(
        "DELETE FROM alert_log WHERE alert_id IN (SELECT alert_id FROM retention_alert_ids)"
    )
    return alert_count, dependent_outbox


def _prune_events(
    connection: sqlite3.Connection,
    *,
    cutoff: str,
    max_rows: int,
    max_rows_per_source: int,
) -> tuple[int, int, int]:
    connection.execute(
        "CREATE TEMP TABLE IF NOT EXISTS retention_event_ids (event_id TEXT PRIMARY KEY)"
    )
    connection.execute("DELETE FROM retention_event_ids")
    connection.execute(
        "INSERT OR IGNORE INTO retention_event_ids SELECT event_id FROM event_log WHERE timestamp < ?",
        (cutoff,),
    )
    connection.execute(
        """
        INSERT OR IGNORE INTO retention_event_ids
        SELECT event_id FROM event_log ORDER BY rowid DESC LIMIT -1 OFFSET ?
        """,
        (max_rows,),
    )
    connection.execute(
        """
        INSERT OR IGNORE INTO retention_event_ids
        SELECT event_id
        FROM (
            SELECT event_id,
                   ROW_NUMBER() OVER (PARTITION BY source_ip ORDER BY rowid DESC) AS source_rank
            FROM event_log
        )
        WHERE source_rank > ?
        """,
        (max_rows_per_source,),
    )
    event_count = int(connection.execute("SELECT COUNT(*) FROM retention_event_ids").fetchone()[0])
    dependent_outbox = connection.execute(
        """
        DELETE FROM outbox
        WHERE payload_ref IN (
            SELECT alert_id FROM alert_log
            WHERE event_id IN (SELECT event_id FROM retention_event_ids)
        )
        """
    ).rowcount
    dependent_alerts = connection.execute(
        "DELETE FROM alert_log WHERE event_id IN (SELECT event_id FROM retention_event_ids)"
    ).rowcount
    connection.execute(
        "DELETE FROM event_log WHERE event_id IN (SELECT event_id FROM retention_event_ids)"
    )
    return event_count, dependent_alerts, dependent_outbox


def _prune_campaigns(
    connection: sqlite3.Connection,
    *,
    cutoff: str,
    max_rows: int,
    max_rows_per_source: int,
) -> tuple[int, int]:
    connection.execute(
        "CREATE TEMP TABLE IF NOT EXISTS retention_campaign_ids (campaign_id TEXT PRIMARY KEY)"
    )
    connection.execute("DELETE FROM retention_campaign_ids")
    connection.execute(
        """
        INSERT OR IGNORE INTO retention_campaign_ids
        SELECT campaign_id FROM login_campaigns WHERE last_seen < ?
        """,
        (cutoff,),
    )
    connection.execute(
        """
        INSERT OR IGNORE INTO retention_campaign_ids
        SELECT campaign_id FROM login_campaigns ORDER BY last_seen DESC, rowid DESC LIMIT -1 OFFSET ?
        """,
        (max_rows,),
    )
    connection.execute(
        """
        INSERT OR IGNORE INTO retention_campaign_ids
        SELECT campaign_id
        FROM (
            SELECT campaign_id,
                   ROW_NUMBER() OVER (
                       PARTITION BY source_ip ORDER BY last_seen DESC, rowid DESC
                   ) AS source_rank
            FROM login_campaigns
        )
        WHERE source_rank > ?
        """,
        (max_rows_per_source,),
    )
    campaign_count = int(connection.execute("SELECT COUNT(*) FROM retention_campaign_ids").fetchone()[0])
    credential_count = connection.execute(
        """
        DELETE FROM login_credential_counts
        WHERE scope_type = 'campaign'
          AND scope_id IN (SELECT campaign_id FROM retention_campaign_ids)
        """
    ).rowcount
    connection.execute(
        "DELETE FROM login_campaigns WHERE campaign_id IN (SELECT campaign_id FROM retention_campaign_ids)"
    )
    return campaign_count, credential_count


def _prune_credentials(connection: sqlite3.Connection, *, cutoff: str, max_rows: int) -> int:
    expired = connection.execute(
        "DELETE FROM login_credential_counts WHERE last_seen < ?",
        (cutoff,),
    ).rowcount
    overflow = connection.execute(
        """
        DELETE FROM login_credential_counts
        WHERE rowid IN (
            SELECT rowid
            FROM login_credential_counts
            ORDER BY last_seen DESC, rowid DESC
            LIMIT -1 OFFSET ?
        )
        """,
        (max_rows,),
    ).rowcount
    return expired + overflow


def _credential_scope_count(
    connection: sqlite3.Connection,
    *,
    scope_type: str,
    scope_id: str,
    value_type: str,
) -> int:
    return int(
        connection.execute(
            """
            SELECT COUNT(*)
            FROM login_credential_counts
            WHERE scope_type = ? AND scope_id = ? AND value_type = ?
            """,
            (scope_type, scope_id, value_type),
        ).fetchone()[0]
    )


def _source_username_exists(
    connection: sqlite3.Connection,
    *,
    source_ip: str,
    credential_value: str,
) -> bool:
    return connection.execute(
        """
        SELECT 1
        FROM login_credential_counts AS credentials
        JOIN login_campaigns AS campaigns
          ON credentials.scope_type = 'campaign'
         AND credentials.scope_id = campaigns.campaign_id
        WHERE campaigns.source_ip = ?
          AND credentials.value_type = 'username'
          AND credentials.credential_value = ?
        LIMIT 1
        """,
        (source_ip, credential_value),
    ).fetchone() is not None


def _source_unique_username_count(connection: sqlite3.Connection, *, source_ip: str) -> int:
    return int(
        connection.execute(
            """
            SELECT COUNT(DISTINCT credentials.credential_value)
            FROM login_credential_counts AS credentials
            JOIN login_campaigns AS campaigns
              ON credentials.scope_type = 'campaign'
             AND credentials.scope_id = campaigns.campaign_id
            WHERE campaigns.source_ip = ?
              AND credentials.value_type = 'username'
            """,
            (source_ip,),
        ).fetchone()[0]
    )


def _append_in_clause(
    clauses: list[str],
    params: list[Any],
    *,
    column: str,
    values: Sequence[str],
    negated: bool,
) -> None:
    normalized_values = tuple(sorted({value.strip() for value in values if value.strip()}))
    if not normalized_values:
        return
    placeholders = ", ".join("?" for _ in normalized_values)
    operator = "NOT IN" if negated else "IN"
    clauses.append(f"{column} {operator} ({placeholders})")
    params.extend(normalized_values)


def _source_activity_order_by(*, sort: str, direction: str, table_alias: str) -> str:
    sort_key = sort.strip().lower()
    sort_column = _SOURCE_ACTIVITY_SORT_COLUMNS.get(sort_key)
    if sort_column is None:
        raise ValueError("source activity sort is not supported")

    normalized_direction = direction.strip().lower()
    if normalized_direction not in _SOURCE_ACTIVITY_SORT_DIRECTIONS:
        raise ValueError("source activity sort direction is not supported")

    sort_expression = (
        sort_column
        if sort_key in _SOURCE_ACTIVITY_DERIVED_SORTS
        else f"{table_alias}.{sort_column}"
    )
    if sort_key == "source_ip":
        return f"{sort_expression} {normalized_direction.upper()}"
    return f"{sort_expression} {normalized_direction.upper()}, {table_alias}.source_ip ASC"


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


def _source_activity_from_row(row: sqlite3.Row) -> SourceActivityRecord:
    return SourceActivityRecord(
        source_ip=str(row["source_ip"]),
        event_count=int(row["event_count"]),
        rejected_count=int(row["rejected_count"]),
        session_count=int(row["session_count"]),
        first_seen=_parse_timestamp(str(row["first_seen"])),
        last_seen=_parse_timestamp(str(row["last_seen"])),
        top_event_type=str(row["top_event_type"] or ""),
        top_endpoint=str(row["top_endpoint"] or ""),
    )


def _plant_history_params(sample: PlantHistorySample) -> tuple[Any, ...]:
    return (
        _iso_timestamp(sample.observed_at),
        sample.operating_mode,
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
        operating_mode=_normalize_operating_mode(row["operating_mode"]),
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
