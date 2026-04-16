from datetime import UTC, datetime

from honeypot.event_core import EventRecorder
from honeypot.storage import SQLiteEventStore
from honeypot.time_core import FrozenClock


def build_recorder(tmp_path):
    clock = FrozenClock(datetime(2026, 4, 16, 9, 30, tzinfo=UTC))
    store = SQLiteEventStore(tmp_path / "tmp" / "honeypot-events.db")
    return EventRecorder(store=store, clock=clock)


def test_build_event_normalizes_required_contract_fields(tmp_path) -> None:
    recorder = build_recorder(tmp_path)

    event = recorder.build_event(
        event_type=" process.breaker.changed ",
        category="process",
        severity="high",
        source_ip=" 203.0.113.24 ",
        actor_type=" remote_client ",
        component=" plant-sim ",
        asset_id=" grid-01 ",
        action=" breaker_open_request ",
        result=" accepted ",
        protocol=" internal-sim ",
        service=" plant-core ",
        endpoint_or_register=" breaker/open ",
        tags=(" control-path ", " breaker "),
    )

    assert event.timestamp == datetime(2026, 4, 16, 9, 30, tzinfo=UTC)
    assert event.event_id.startswith("evt_")
    assert event.correlation_id.startswith("corr_")
    assert event.event_type == "process.breaker.changed"
    assert event.component == "plant-sim"
    assert event.asset_id == "grid-01"
    assert event.tags == ("control-path", "breaker")


def test_build_event_reuses_supplied_correlation_chain(tmp_path) -> None:
    recorder = build_recorder(tmp_path)

    first_event = recorder.build_event(
        event_type="process.curtailment.changed",
        category="process",
        severity="high",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="ppc-01",
        action="set_active_power_limit",
        result="accepted",
    )
    second_event = recorder.build_event(
        event_type="process.power.fell",
        category="process",
        severity="high",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="site-01",
        action="recalculate_power",
        result="accepted",
        correlation_id=first_event.correlation_id,
        causation_id=first_event.event_id,
    )

    assert second_event.correlation_id == first_event.correlation_id
    assert second_event.causation_id == first_event.event_id


def test_recorder_persists_event_state_alert_and_outbox_in_wal_store(tmp_path) -> None:
    recorder = build_recorder(tmp_path)
    event = recorder.build_event(
        event_type="alert.breaker.open",
        category="alert",
        severity="high",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="grid-01",
        action="breaker_open_request",
        result="accepted",
        alarm_code="BREAKER_OPEN",
        resulting_state={"breaker_state": "open", "plant_power_mw": 0.0},
    )
    alert = recorder.build_alert(
        event=event,
        alarm_code="BREAKER_OPEN",
        severity="high",
        state="active_unacknowledged",
        message="Breaker open erkannt",
    )

    recorded = recorder.record(
        event,
        current_state_updates={"site": {"breaker_state": "open", "active_alarm_count": 1}},
        alert=alert,
        outbox_targets=("webhook", "email"),
    )

    assert recorder.store.journal_mode().lower() == "wal"
    assert recorder.store.count_rows("event_log") == 1
    assert recorder.store.count_rows("current_state") == 1
    assert recorder.store.count_rows("alert_log") == 1
    assert recorder.store.count_rows("outbox") == 2
    assert recorded.alert is not None
    assert {entry.target_type for entry in recorded.outbox_entries} == {"webhook", "email"}
    assert all(entry.status == "pending" for entry in recorded.outbox_entries)


def test_record_without_outbox_targets_still_persists_local_truth(tmp_path) -> None:
    recorder = build_recorder(tmp_path)
    event = recorder.build_event(
        event_type="process.curtailment.changed",
        category="process",
        severity="high",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="ppc-01",
        action="set_active_power_limit",
        result="accepted",
    )

    recorded = recorder.record(event, current_state_updates={"ppc": {"active_power_limit_pct": 50}})

    assert recorded.alert is None
    assert recorded.outbox_entries == ()
    assert recorder.store.count_rows("event_log") == 1
    assert recorder.store.count_rows("current_state") == 1
    assert recorder.store.count_rows("outbox") == 0
