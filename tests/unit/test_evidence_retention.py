from datetime import UTC, datetime, timedelta
import gzip
import importlib
import sqlite3

from honeypot.event_core import EventRecorder
from honeypot.storage import (
    JsonlEventArchive,
    JsonlRetentionPolicy,
    SQLiteEventStore,
    SQLiteRetentionPolicy,
)
from honeypot.time_core import FrozenClock


MIB = 1024 * 1024


def _policy(**overrides: int) -> SQLiteRetentionPolicy:
    values = {
        "max_age_days": 30,
        "max_event_rows": 3,
        "max_event_rows_per_source": 2,
        "max_alert_rows": 3,
        "max_outbox_rows": 3,
        "max_campaign_rows": 2,
        "max_campaign_rows_per_source": 1,
        "max_credential_rows": 12,
        "max_unique_usernames": 2,
        "max_unique_usernames_per_source": 1,
        "max_database_bytes": 32 * MIB,
        "reserved_health_bytes": MIB,
        "min_free_bytes": 0,
        "sweep_interval_writes": 1,
    }
    values.update(overrides)
    return SQLiteRetentionPolicy(**values)


def _event(recorder: EventRecorder, *, index: int, source_ip: str, category: str = "hmi"):
    return recorder.build_event(
        event_type="hmi.page.overview_viewed" if category == "hmi" else "system.storage.health",
        category=category,
        severity="low" if category == "hmi" else "high",
        source_ip=source_ip,
        actor_type="remote_client" if category == "hmi" else "system",
        component="hmi-web" if category == "hmi" else "storage",
        asset_id="hmi-web" if category == "hmi" else "evidence-store",
        action=f"record_{index}",
        result="served",
        event_id=f"evt_{category}_{index}",
        correlation_id=f"corr_{category}_{index}",
    )


def test_sqlite_retention_bounds_global_and_per_source_rows_across_restart(tmp_path) -> None:
    now = datetime(2026, 8, 14, 10, 0, tzinfo=UTC)
    db_path = tmp_path / "events.db"
    store = SQLiteEventStore(db_path, retention_policy=_policy(), now_provider=lambda: now)
    recorder = EventRecorder(store=store, clock=FrozenClock(now))

    for index in range(3):
        recorder.record(_event(recorder, index=index, source_ip="203.0.113.10"))
    for index in range(3, 5):
        recorder.record(_event(recorder, index=index, source_ip="198.51.100.20"))

    reopened = SQLiteEventStore(db_path, retention_policy=_policy(), now_provider=lambda: now)
    events = reopened.fetch_events()

    assert len(events) == 3
    assert sum(event.source_ip == "203.0.113.10" for event in events) <= 2
    assert sum(event.source_ip == "198.51.100.20" for event in events) <= 2
    assert reopened.evidence_retention_status()["counters"]["events_pruned"] >= 2


def test_sqlite_retention_prunes_expired_evidence_on_restart(tmp_path) -> None:
    initial_now = datetime(2026, 8, 1, 10, 0, tzinfo=UTC)
    db_path = tmp_path / "events.db"
    initial_policy = _policy(max_age_days=30, max_event_rows=10, max_event_rows_per_source=10)
    store = SQLiteEventStore(db_path, retention_policy=initial_policy, now_provider=lambda: initial_now)
    recorder = EventRecorder(store=store, clock=FrozenClock(initial_now))
    recorder.record(_event(recorder, index=1, source_ip="203.0.113.10"))

    reopened = SQLiteEventStore(
        db_path,
        retention_policy=_policy(max_age_days=1, max_event_rows=10, max_event_rows_per_source=10),
        now_provider=lambda: initial_now + timedelta(days=2),
    )

    assert reopened.fetch_events() == ()
    assert reopened.evidence_retention_status()["counters"]["events_pruned"] == 1


def test_sqlite_event_retention_deletes_events_and_dependents_in_batches(
    monkeypatch,
    tmp_path,
) -> None:
    sqlite_store = importlib.import_module("honeypot.storage.sqlite_store")
    monkeypatch.setattr(sqlite_store, "_EVENT_RETENTION_DELETE_BATCH_SIZE", 2)
    now = datetime(2026, 8, 14, 10, 0, tzinfo=UTC)
    db_path = tmp_path / "events.db"
    store = SQLiteEventStore(
        db_path,
        retention_policy=_policy(
            max_event_rows=2,
            max_event_rows_per_source=2,
            max_alert_rows=10,
            max_outbox_rows=10,
            sweep_interval_writes=100,
        ),
        now_provider=lambda: now,
    )
    recorder = EventRecorder(store=store, clock=FrozenClock(now))
    events = tuple(
        _event(recorder, index=index, source_ip="203.0.113.10") for index in range(7)
    )
    for event in events:
        assert recorder.record(event).persisted is True
    for event in (events[0], events[3]):
        alert = recorder.build_alert(
            event=event,
            alarm_code=f"RETENTION_BATCH_{event.event_id}",
            severity="high",
            state="active_unacknowledged",
        )
        assert store.append_alert_with_targets(
            alert,
            target_types=("webhook",),
            next_attempt_at=now,
        ) is not None

    store.enforce_retention(reference_time=now)

    assert {event.event_id for event in store.fetch_events()} == {
        events[5].event_id,
        events[6].event_id,
    }
    assert store.count_rows("alert_log") == 0
    assert store.count_rows("outbox") == 0
    counters = store.evidence_retention_status()["counters"]
    assert counters["events_pruned"] == 5
    assert counters["alerts_pruned"] == 2
    assert counters["outbox_pruned"] == 2
    with sqlite3.connect(db_path) as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_pruned_parent_event_cannot_create_orphan_alert_or_outbox(tmp_path) -> None:
    now = datetime(2026, 8, 14, 10, 0, tzinfo=UTC)
    store = SQLiteEventStore(
        tmp_path / "events.db",
        retention_policy=_policy(
            max_event_rows=1,
            max_event_rows_per_source=1,
            sweep_interval_writes=1,
        ),
        now_provider=lambda: now,
    )
    recorder = EventRecorder(store=store, clock=FrozenClock(now))
    first_event = _event(recorder, index=1, source_ip="203.0.113.10")
    recorder.record(first_event)
    recorder.record(_event(recorder, index=2, source_ip="203.0.113.10"))
    alert = recorder.build_alert(
        event=first_event,
        alarm_code="RETENTION_TEST",
        severity="high",
        state="active_unacknowledged",
    )

    result = store.append_alert_with_targets(
        alert,
        target_types=("webhook",),
        next_attempt_at=now,
    )

    assert result is None
    assert store.count_rows("alert_log") == 0
    assert store.count_rows("outbox") == 0


def test_campaign_and_username_cardinality_is_bounded_globally_and_per_source(tmp_path) -> None:
    now = datetime(2026, 8, 14, 10, 0, tzinfo=UTC)
    store = SQLiteEventStore(tmp_path / "events.db", retention_policy=_policy(), now_provider=lambda: now)

    attempts = (
        ("camp-a-1", "203.0.113.10", "alice"),
        ("camp-a-2", "203.0.113.10", "bob"),
        ("camp-b-1", "198.51.100.20", "carol"),
        ("camp-c-1", "192.0.2.30", "dave"),
    )
    for campaign_id, source_ip, username in attempts:
        store.record_login_credential_attempt(
            campaign_id=campaign_id,
            source_ip=source_ip,
            user_agent="retention-test",
            endpoint="/service/login",
            username=username,
            password=None,
            observed_at=now,
            max_unique_passwords=0,
            max_credential_length=128,
            capture_password=False,
        )

    stats = store.login_credential_stats()
    counters = store.evidence_retention_status()["counters"]

    assert stats.campaign_count == 2
    assert stats.all_time_unique_usernames == 2
    assert counters["campaigns_dropped"] == 2
    assert counters["usernames_dropped"] == 2


def test_free_space_watermark_preserves_reserved_system_event_budget(tmp_path) -> None:
    now = datetime(2026, 8, 14, 10, 0, tzinfo=UTC)
    available = {"bytes": 150 * MIB}
    policy = _policy(
        max_database_bytes=256 * MIB,
        min_free_bytes=100 * MIB,
        reserved_health_bytes=50 * MIB,
    )
    store = SQLiteEventStore(
        tmp_path / "events.db",
        retention_policy=policy,
        now_provider=lambda: now,
        free_bytes_provider=lambda _path: available["bytes"],
    )
    recorder = EventRecorder(store=store, clock=FrozenClock(now))

    attacker_result = recorder.record(_event(recorder, index=1, source_ip="203.0.113.10"))
    health_result = recorder.record(
        _event(recorder, index=2, source_ip="127.0.0.1", category="system")
    )
    available["bytes"] = 99 * MIB
    exhausted_result = recorder.record(
        _event(recorder, index=3, source_ip="127.0.0.1", category="system")
    )

    assert attacker_result.persisted is False
    assert health_result.persisted is True
    assert exhausted_result.persisted is False
    assert store.evidence_retention_status()["counters"]["events_dropped"] == 2


def test_sqlite_byte_budget_evicts_oldest_evidence_and_reuses_pages(tmp_path) -> None:
    now = datetime(2026, 8, 14, 10, 0, tzinfo=UTC)
    byte_limit = 512 * 1024
    store = SQLiteEventStore(
        tmp_path / "events.db",
        retention_policy=_policy(
            max_event_rows=100,
            max_event_rows_per_source=100,
            max_database_bytes=byte_limit,
            reserved_health_bytes=64 * 1024,
        ),
        now_provider=lambda: now,
    )
    recorder = EventRecorder(store=store, clock=FrozenClock(now))
    for index in range(20):
        event = _event(recorder, index=index, source_ip="203.0.113.10").model_copy(
            update={"message": "x" * 32_000}
        )
        assert recorder.record(event).persisted is True

    status = store.evidence_retention_status()

    assert status["database_bytes"] <= byte_limit
    assert status["counters"]["events_pruned"] >= 1
    assert store.fetch_event("evt_hmi_19") is not None
    assert store.count_rows("event_log") < 20


def test_jsonl_archive_rotates_compresses_and_bounds_total_bytes(tmp_path) -> None:
    now = datetime(2026, 8, 14, 10, 0, tzinfo=UTC)
    archive_path = tmp_path / "events.jsonl"
    archive = JsonlEventArchive(
        archive_path,
        retention_policy=JsonlRetentionPolicy(
            max_file_bytes=700,
            max_total_bytes=2_200,
            max_age_days=30,
            min_free_bytes=0,
        ),
        now_provider=lambda: now,
    )
    store = SQLiteEventStore(
        tmp_path / "events.db",
        retention_policy=_policy(max_event_rows=20, max_event_rows_per_source=20),
        now_provider=lambda: now,
    )
    recorder = EventRecorder(store=store, archive=archive, clock=FrozenClock(now))

    for index in range(10):
        recorder.record(_event(recorder, index=index, source_ip="203.0.113.10"))

    compressed = sorted(tmp_path.glob("events.*.jsonl.gz"))
    status = archive.retention_status()

    assert compressed
    with gzip.open(compressed[-1], "rt", encoding="utf-8") as handle:
        assert handle.readline().startswith("{")
    assert status["retained_bytes"] <= 2_200
    assert status["rotations"] >= 1


def test_jsonl_archive_reports_enospc_without_breaking_sqlite_truth(tmp_path) -> None:
    now = datetime(2026, 8, 14, 10, 0, tzinfo=UTC)
    archive = JsonlEventArchive(
        tmp_path / "events.jsonl",
        retention_policy=JsonlRetentionPolicy(
            max_file_bytes=1_024,
            max_total_bytes=4_096,
            max_age_days=30,
            min_free_bytes=100,
        ),
        free_bytes_provider=lambda _path: 99,
        now_provider=lambda: now,
    )
    store = SQLiteEventStore(
        tmp_path / "events.db",
        retention_policy=_policy(max_event_rows=10, max_event_rows_per_source=10),
        now_provider=lambda: now,
    )
    recorder = EventRecorder(store=store, archive=archive, clock=FrozenClock(now))

    result = recorder.record(
        _event(recorder, index=1, source_ip="203.0.113.10"),
        current_state_updates={"site": {"breaker_state": "closed"}},
    )

    assert result.persisted is True
    assert store.count_rows("event_log") == 1
    assert archive.retention_status()["dropped_events"] == 1
    assert not (tmp_path / "events.jsonl").exists()


def test_sqlite_enospc_is_reported_as_unpersisted_without_crashing(monkeypatch, tmp_path) -> None:
    now = datetime(2026, 8, 14, 10, 0, tzinfo=UTC)
    store = SQLiteEventStore(
        tmp_path / "events.db",
        retention_policy=_policy(),
        now_provider=lambda: now,
    )
    recorder = EventRecorder(store=store, clock=FrozenClock(now))

    def raise_enospc():
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(store, "_connect", raise_enospc)

    result = recorder.record(
        _event(recorder, index=1, source_ip="203.0.113.10"),
        current_state_updates={"site": {"breaker_state": "closed"}},
    )

    assert result.persisted is False
