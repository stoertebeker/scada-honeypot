import json
from datetime import UTC, datetime

from honeypot.event_core import EventRecorder
from honeypot.rule_engine import (
    COMM_LOSS_ALERT_CODE,
    DEFAULT_CAPACITY_MW,
    GRID_PATH_UNAVAILABLE_ALERT_CODE,
    LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE,
    MULTI_BLOCK_UNAVAILABLE_ALERT_CODE,
    RuleEngine,
    SETPOINT_ALERT_CODE,
    SITE_AGGREGATE_ASSET_ID,
)
from honeypot.storage import JsonlEventArchive, SQLiteEventStore
from honeypot.time_core import FrozenClock


def build_recorder(tmp_path, *, archive_path=None, rule_engine=None):
    clock = FrozenClock(datetime(2026, 4, 16, 9, 30, tzinfo=UTC))
    store = SQLiteEventStore(tmp_path / "tmp" / "honeypot-events.db")
    archive = None if archive_path is None else JsonlEventArchive(archive_path)
    return EventRecorder(store=store, clock=clock, archive=archive, rule_engine=rule_engine)


def build_low_output_state(
    *,
    plant_power_mw: float,
    irradiance_w_m2: int = 892,
    plant_power_limit_pct: float = 100,
    breaker_state: str = "closed",
    export_path_available: bool = True,
    alarms=(),
):
    return {
        "site": {
            "plant_power_mw": plant_power_mw,
            "plant_power_limit_pct": plant_power_limit_pct,
            "breaker_state": breaker_state,
        },
        "weather_station": {
            "irradiance_w_m2": irradiance_w_m2,
        },
        "grid_interconnect": {
            "export_path_available": export_path_available,
        },
        "alarms": list(alarms),
    }


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


def test_fetch_events_preserves_insert_order_for_identical_timestamps(tmp_path) -> None:
    recorder = build_recorder(tmp_path)
    first_event = recorder.build_event(
        event_type="process.setpoint.block_enable_request_changed",
        category="process",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="invb-02",
        action="set_block_enable_request",
        result="accepted",
        requested_value=0,
    )
    second_event = recorder.build_event(
        event_type="protocol.modbus.single_register_write",
        category="protocol",
        severity="info",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="protocol-modbus",
        asset_id="invb-02",
        action="write_single_register",
        result="accepted",
        requested_value={"register_start": 40200},
    )

    recorder.record(first_event)
    recorder.record(second_event)

    events = recorder.store.fetch_events()

    assert [event.event_id for event in events] == [first_event.event_id, second_event.event_id]


def test_fetch_alerts_preserves_insert_order_for_identical_timestamps(tmp_path) -> None:
    recorder = build_recorder(tmp_path)
    first_event = recorder.build_event(
        event_type="process.breaker.state_changed",
        category="process",
        severity="high",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="grid-01",
        action="breaker_open_request",
        result="accepted",
    )
    second_event = recorder.build_event(
        event_type="process.breaker.state_changed",
        category="process",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="grid-01",
        action="breaker_close_request",
        result="accepted",
    )
    first_alert = recorder.build_alert(
        event=first_event,
        alarm_code="GRID_PATH_UNAVAILABLE",
        severity="critical",
        state="active_unacknowledged",
        message="Exportpfad nicht verfuegbar auf grid-01",
    )
    second_alert = recorder.build_alert(
        event=second_event,
        alarm_code="GRID_PATH_UNAVAILABLE",
        severity="critical",
        state="cleared",
        message="Exportpfad nicht verfuegbar auf grid-01",
    )

    recorder.record(first_event, alert=first_alert)
    recorder.record(second_event, alert=second_alert)

    alerts = recorder.store.fetch_alerts()

    assert [alert.alert_id for alert in alerts] == [first_alert.alert_id, second_alert.alert_id]


def test_record_derives_rule_based_alert_and_outbox_when_configured(tmp_path) -> None:
    recorder = build_recorder(tmp_path, rule_engine=RuleEngine.default_v1())
    event = recorder.build_event(
        event_type="process.setpoint.reactive_power_target_changed",
        category="process",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="ppc-01",
        action="set_reactive_power_target",
        result="accepted",
        resulting_state={"reactive_power_target": 0.25},
        tags=("control-path", "ppc", "reactive-power"),
    )

    recorded = recorder.record(event, outbox_targets=("webhook",))
    alerts = recorder.store.fetch_alerts()
    outbox_entries = recorder.store.fetch_outbox_entries()

    assert recorded.alert is not None
    assert recorded.alerts == alerts
    assert recorded.alert.alarm_code == SETPOINT_ALERT_CODE
    assert recorded.alert.severity == "high"
    assert recorded.alert.message == "Erfolgreiche Setpoint-Aenderung: set_reactive_power_target auf ppc-01"
    assert len(alerts) == 1
    assert len(outbox_entries) == 1
    assert outbox_entries[0].target_type == "webhook"


def test_record_keeps_explicit_process_alert_and_dedupes_matching_rule_alert(tmp_path) -> None:
    recorder = build_recorder(tmp_path, rule_engine=RuleEngine.default_v1())
    event = recorder.build_event(
        event_type="process.breaker.state_changed",
        category="process",
        severity="high",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="grid-01",
        action="breaker_open_request",
        result="accepted",
        alarm_code="BREAKER_OPEN",
        resulting_value="open",
        resulting_state={"breaker_state": "open", "plant_power_mw": 0.0},
        tags=("control-path", "grid", "breaker"),
    )
    explicit_alert = recorder.build_alert(
        event=event,
        alarm_code="BREAKER_OPEN",
        severity="high",
        state="active_unacknowledged",
        message="Breaker open erkannt",
    )

    recorded = recorder.record(event, alert=explicit_alert, outbox_targets=("webhook",))
    alerts = recorder.store.fetch_alerts()

    assert len(recorded.alerts) == 1
    assert recorded.alert is not None
    assert recorded.alert.message == "Breaker open erkannt"
    assert len(alerts) == 1
    assert alerts[0].alarm_code == "BREAKER_OPEN"


def test_record_suppresses_duplicate_rule_alert_while_matching_alert_is_active(tmp_path) -> None:
    recorder = build_recorder(tmp_path, rule_engine=RuleEngine.default_v1())
    first_event = recorder.build_event(
        event_type="process.setpoint.reactive_power_target_changed",
        category="process",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="ppc-01",
        action="set_reactive_power_target",
        result="accepted",
        resulting_state={"reactive_power_target": 0.25},
        tags=("control-path", "ppc", "reactive-power"),
    )
    second_event = first_event.model_copy(
        update={
            "event_id": "evt_rule_repeat",
            "correlation_id": "corr_rule_repeat",
        }
    )

    first_record = recorder.record(first_event, outbox_targets=("webhook",))
    second_record = recorder.record(second_event, outbox_targets=("webhook",))
    alerts = recorder.store.fetch_alerts()
    outbox_entries = recorder.store.fetch_outbox_entries()

    assert first_record.alert is not None
    assert len(first_record.alerts) == 1
    assert second_record.alert is None
    assert second_record.alerts == ()
    assert len(alerts) == 1
    assert len(outbox_entries) == 1
    assert alerts[0].alarm_code == SETPOINT_ALERT_CODE


def test_record_allows_rule_alert_again_after_matching_alert_was_cleared(tmp_path) -> None:
    recorder = build_recorder(tmp_path, rule_engine=RuleEngine.default_v1())
    event = recorder.build_event(
        event_type="process.setpoint.reactive_power_target_changed",
        category="process",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="ppc-01",
        action="set_reactive_power_target",
        result="accepted",
        resulting_state={"reactive_power_target": 0.25},
        tags=("control-path", "ppc", "reactive-power"),
    )

    first_record = recorder.record(event, outbox_targets=("webhook",))
    first_alert = recorder.store.fetch_alerts()[0]
    cleared_event = event.model_copy(
        update={
            "event_id": "evt_rule_cleared",
            "correlation_id": "corr_rule_cleared",
        }
    )
    cleared_alert = first_alert.model_copy(
        update={
            "alert_id": "alt_rule_cleared",
            "event_id": cleared_event.event_id,
            "correlation_id": cleared_event.correlation_id,
            "state": "cleared",
            "created_at": cleared_event.timestamp,
        }
    )
    recorder.record(cleared_event, alert=cleared_alert)

    second_event = event.model_copy(
        update={
            "event_id": "evt_rule_after_clear",
            "correlation_id": "corr_rule_after_clear",
        }
    )
    second_record = recorder.record(second_event, outbox_targets=("webhook",))
    alerts = recorder.store.fetch_alerts()
    outbox_entries = recorder.store.fetch_outbox_entries()

    assert first_record.alert is not None
    assert second_record.alert is not None
    assert len(second_record.alerts) == 1
    assert len(alerts) == 3
    assert second_record.alert.alarm_code == SETPOINT_ALERT_CODE
    assert second_record.alert.state == "active_unacknowledged"
    assert len(outbox_entries) == 2


def test_record_derives_multi_block_follow_up_alert_and_outbox_on_second_comm_loss(tmp_path) -> None:
    recorder = build_recorder(tmp_path, rule_engine=RuleEngine.default_v1())
    first_event = recorder.build_event(
        event_type="system.communication.inverter_block_lost",
        category="system",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="invb-01",
        action="simulate_comm_loss",
        result="accepted",
        resulting_value="lost",
        tags=("fault-path", "communications", "inverter-block"),
    )
    second_event = first_event.model_copy(
        update={
            "event_id": "evt_comm_loss_02",
            "correlation_id": "corr_comm_loss_02",
            "asset_id": "invb-02",
        }
    )

    first_record = recorder.record(first_event, outbox_targets=("webhook",))
    second_record = recorder.record(second_event, outbox_targets=("webhook",))
    alerts = recorder.store.fetch_alerts()
    outbox_entries = recorder.store.fetch_outbox_entries()

    assert len(first_record.alerts) == 1
    assert first_record.alert is not None
    assert first_record.alert.alarm_code == COMM_LOSS_ALERT_CODE
    assert len(second_record.alerts) == 2
    assert {alert.alarm_code for alert in second_record.alerts} == {
        COMM_LOSS_ALERT_CODE,
        MULTI_BLOCK_UNAVAILABLE_ALERT_CODE,
    }
    aggregate_alert = next(alert for alert in second_record.alerts if alert.alarm_code == MULTI_BLOCK_UNAVAILABLE_ALERT_CODE)
    assert aggregate_alert.asset_id == SITE_AGGREGATE_ASSET_ID
    assert aggregate_alert.severity == "critical"
    assert len(alerts) == 3
    assert len(outbox_entries) == 3


def test_record_derives_grid_path_follow_up_alert_and_clears_it_after_breaker_close(tmp_path) -> None:
    recorder = build_recorder(tmp_path, rule_engine=RuleEngine.default_v1())
    open_event = recorder.build_event(
        event_type="process.breaker.state_changed",
        category="process",
        severity="high",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="grid-01",
        action="breaker_open_request",
        result="accepted",
        alarm_code="BREAKER_OPEN",
        resulting_value="open",
        resulting_state={"breaker_state": "open", "plant_power_mw": 0.0},
        tags=("control-path", "grid", "breaker"),
    )
    close_event = open_event.model_copy(
        update={
            "event_id": "evt_grid_close",
            "correlation_id": "corr_grid_close",
            "action": "breaker_close_request",
            "resulting_value": "closed",
            "resulting_state": {"breaker_state": "closed", "plant_power_mw": 5.8},
        }
    )

    open_record = recorder.record(
        open_event,
        current_state_updates={
            "grid_interconnect": {
                "breaker_state": "open",
                "export_path_available": False,
                "grid_acceptance_state": "unavailable",
            }
        },
        outbox_targets=("webhook",),
    )
    close_record = recorder.record(
        close_event,
        current_state_updates={
            "grid_interconnect": {
                "breaker_state": "closed",
                "export_path_available": True,
                "grid_acceptance_state": "accepted",
            }
        },
        outbox_targets=("webhook",),
    )
    alerts = recorder.store.fetch_alerts()
    outbox_entries = recorder.store.fetch_outbox_entries()

    assert {alert.alarm_code for alert in open_record.alerts} == {"BREAKER_OPEN", GRID_PATH_UNAVAILABLE_ALERT_CODE}
    grid_path_open = next(alert for alert in open_record.alerts if alert.alarm_code == GRID_PATH_UNAVAILABLE_ALERT_CODE)
    grid_path_cleared = next(alert for alert in close_record.alerts if alert.alarm_code == GRID_PATH_UNAVAILABLE_ALERT_CODE)
    assert grid_path_open.state == "active_unacknowledged"
    assert grid_path_cleared.state == "cleared"
    assert grid_path_cleared.asset_id == "grid-01"
    assert len(alerts) == 3
    assert len(outbox_entries) == 3


def test_record_re_raises_grid_path_follow_up_after_cleared_history(tmp_path) -> None:
    recorder = build_recorder(tmp_path, rule_engine=RuleEngine.default_v1())
    open_state = {
        "grid_interconnect": {
            "breaker_state": "open",
            "export_path_available": False,
            "grid_acceptance_state": "unavailable",
        }
    }
    closed_state = {
        "grid_interconnect": {
            "breaker_state": "closed",
            "export_path_available": True,
            "grid_acceptance_state": "accepted",
        }
    }

    first_open_event = recorder.build_event(
        event_type="process.breaker.state_changed",
        category="process",
        severity="high",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="grid-01",
        action="breaker_open_request",
        result="accepted",
        event_id="evt_grid_open_first",
        correlation_id="corr_grid_open_first",
        alarm_code="BREAKER_OPEN",
        resulting_value="open",
        tags=("control-path", "grid", "breaker"),
    )
    close_event = first_open_event.model_copy(
        update={
            "event_id": "evt_grid_close",
            "correlation_id": "corr_grid_close",
            "action": "breaker_close_request",
            "resulting_value": "closed",
        }
    )
    second_open_event = first_open_event.model_copy(
        update={
            "event_id": "evt_grid_open_second",
            "correlation_id": "corr_grid_open_second",
        }
    )

    recorder.record(first_open_event, current_state_updates=open_state, outbox_targets=("webhook",))
    recorder.record(close_event, current_state_updates=closed_state, outbox_targets=("webhook",))
    second_open_record = recorder.record(second_open_event, current_state_updates=open_state, outbox_targets=("webhook",))

    grid_path_alerts = tuple(alert for alert in second_open_record.alerts if alert.alarm_code == GRID_PATH_UNAVAILABLE_ALERT_CODE)

    assert len(grid_path_alerts) == 1
    assert grid_path_alerts[0].state == "active_unacknowledged"


def test_record_derives_low_output_follow_up_alert_without_breaker_or_curtailment(tmp_path) -> None:
    recorder = build_recorder(
        tmp_path,
        rule_engine=RuleEngine.default_v1(capacity_mw=DEFAULT_CAPACITY_MW, low_output_threshold_pct=35),
    )
    event = recorder.build_event(
        event_type="process.setpoint.block_enable_request_changed",
        category="process",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="invb-02",
        action="set_block_enable_request",
        result="accepted",
        resulting_value=0,
        tags=("control-path", "inverter-block", "enable"),
    )

    recorded = recorder.record(
        event,
        current_state_updates=build_low_output_state(plant_power_mw=1.9),
        outbox_targets=("webhook",),
    )
    alerts = recorder.store.fetch_alerts()
    outbox_entries = recorder.store.fetch_outbox_entries()

    low_output_alert = next(alert for alert in recorded.alerts if alert.alarm_code == LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE)

    assert {alert.alarm_code for alert in recorded.alerts} == {
        SETPOINT_ALERT_CODE,
        LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE,
    }
    assert low_output_alert.state == "active_unacknowledged"
    assert len(alerts) == 2
    assert len(outbox_entries) == 2


def test_record_clears_low_output_follow_up_after_site_recovers(tmp_path) -> None:
    recorder = build_recorder(
        tmp_path,
        rule_engine=RuleEngine.default_v1(capacity_mw=DEFAULT_CAPACITY_MW, low_output_threshold_pct=35),
    )
    first_event = recorder.build_event(
        event_type="process.setpoint.block_enable_request_changed",
        category="process",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="invb-02",
        action="set_block_enable_request",
        result="accepted",
        event_id="evt_low_output_active",
        correlation_id="corr_low_output_active",
        resulting_value=0,
        tags=("control-path", "inverter-block", "enable"),
    )
    cleared_event = first_event.model_copy(
        update={
            "event_id": "evt_low_output_cleared",
            "correlation_id": "corr_low_output_cleared",
            "event_type": "process.control.block_reset_requested",
            "action": "block_reset_request",
            "resulting_value": "applied",
        }
    )

    recorder.record(first_event, current_state_updates=build_low_output_state(plant_power_mw=1.9), outbox_targets=("webhook",))
    cleared_record = recorder.record(
        cleared_event,
        current_state_updates=build_low_output_state(plant_power_mw=5.8),
        outbox_targets=("webhook",),
    )
    alerts = recorder.store.fetch_alerts()

    low_output_alerts = tuple(alert for alert in alerts if alert.alarm_code == LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE)

    assert len(cleared_record.alerts) == 1
    assert cleared_record.alert is not None
    assert cleared_record.alert.alarm_code == LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE
    assert cleared_record.alert.state == "cleared"
    assert len(low_output_alerts) == 2


def test_record_suppresses_duplicate_multi_block_follow_up_while_aggregate_alert_is_active(tmp_path) -> None:
    recorder = build_recorder(tmp_path, rule_engine=RuleEngine.default_v1())

    for index, asset_id in enumerate(("invb-01", "invb-02"), start=1):
        event = recorder.build_event(
            event_type="system.communication.inverter_block_lost",
            category="system",
            severity="medium",
            source_ip="203.0.113.24",
            actor_type="remote_client",
            component="plant-sim",
            asset_id=asset_id,
            action="simulate_comm_loss",
            result="accepted",
            event_id=f"evt_comm_loss_seed_{index}",
            correlation_id=f"corr_comm_loss_seed_{index}",
            resulting_value="lost",
            tags=("fault-path", "communications", "inverter-block"),
        )
        recorder.record(event, outbox_targets=("webhook",))

    third_event = recorder.build_event(
        event_type="system.communication.inverter_block_lost",
        category="system",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="invb-03",
        action="simulate_comm_loss",
        result="accepted",
        event_id="evt_comm_loss_03",
        correlation_id="corr_comm_loss_03",
        resulting_value="lost",
        tags=("fault-path", "communications", "inverter-block"),
    )

    third_record = recorder.record(third_event, outbox_targets=("webhook",))
    alerts = recorder.store.fetch_alerts()
    outbox_entries = recorder.store.fetch_outbox_entries()

    assert len(third_record.alerts) == 1
    assert third_record.alert is not None
    assert third_record.alert.alarm_code == COMM_LOSS_ALERT_CODE
    assert len(alerts) == 4
    assert len(outbox_entries) == 4


def test_record_writes_event_to_jsonl_archive_when_enabled(tmp_path) -> None:
    archive_path = tmp_path / "logs" / "events.jsonl"
    recorder = build_recorder(tmp_path, archive_path=archive_path)
    event = recorder.build_event(
        event_type="protocol.modbus.holding_registers_read",
        category="protocol",
        severity="info",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="protocol-modbus",
        asset_id="ppc-01",
        action="read_holding_registers",
        result="accepted",
        requested_value={"register_start": 40001, "register_count": 8},
    )

    recorder.record(event)

    archive_lines = archive_path.read_text(encoding="utf-8").splitlines()
    archived_event = json.loads(archive_lines[0])

    assert len(archive_lines) == 1
    assert archived_event["event_id"] == event.event_id
    assert archived_event["correlation_id"] == event.correlation_id
    assert archived_event["event_type"] == "protocol.modbus.holding_registers_read"
    assert archived_event["requested_value"] == {"register_count": 8, "register_start": 40001}
    assert recorder.store.count_rows("event_log") == 1


def test_archive_write_failure_does_not_block_sqlite_truth(tmp_path) -> None:
    archive_dir = tmp_path / "logs"
    archive_dir.mkdir(parents=True)
    recorder = build_recorder(tmp_path, archive_path=archive_dir)
    event = recorder.build_event(
        event_type="process.breaker.state_changed",
        category="process",
        severity="high",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="grid-01",
        action="breaker_open_request",
        result="accepted",
    )

    recorder.record(event)

    assert recorder.store.count_rows("event_log") == 1
    assert recorder.archive is not None
    assert recorder.archive.last_error is not None
