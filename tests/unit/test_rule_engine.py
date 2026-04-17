from datetime import UTC, datetime

import pytest

from honeypot.event_core.models import EventRecord
from honeypot.rule_engine import (
    LOGIN_FAILURE_THRESHOLD,
    REPEATED_LOGIN_FAILURE_ALERT_CODE,
    RuleContext,
    RuleEngine,
    SETPOINT_ALERT_CODE,
    SuccessfulSetpointChangeRule,
)


def build_event(
    *,
    event_type: str = "process.setpoint.reactive_power_target_changed",
    category: str = "process",
    action: str = "set_reactive_power_target",
    result: str = "accepted",
    alarm_code: str | None = None,
    source_ip: str = "203.0.113.24",
    asset_id: str = "ppc-01",
    requested_value=None,
    resulting_value=None,
    tags: tuple[str, ...] = ("control-path", "ppc", "reactive-power"),
) -> EventRecord:
    return EventRecord(
        timestamp=datetime(2026, 4, 16, 9, 30, tzinfo=UTC),
        event_id="evt_rule_test",
        correlation_id="corr_rule_test",
        event_type=event_type,
        category=category,
        severity="medium",
        source_ip=source_ip,
        actor_type="remote_client",
        component="plant-sim",
        asset_id=asset_id,
        action=action,
        result=result,
        protocol="modbus-tcp",
        service="holding-registers",
        requested_value=requested_value,
        resulting_value=resulting_value,
        tags=tags,
        alarm_code=alarm_code,
    )


def test_rule_engine_registers_rules_once_and_rejects_duplicate_ids() -> None:
    engine = RuleEngine()
    engine.register(SuccessfulSetpointChangeRule())

    with pytest.raises(ValueError, match="Rule-ID"):
        engine.register(SuccessfulSetpointChangeRule())

    assert engine.rule_ids == ("successful_setpoint_change",)


def test_successful_setpoint_rule_derives_alert_for_accepted_setpoint_event() -> None:
    engine = RuleEngine.default_v1()

    derived_alerts = engine.evaluate(build_event(), context=RuleContext(current_state={"ppc": {"active_power_limit_pct": 100}}))

    assert len(derived_alerts) == 1
    assert derived_alerts[0].alarm_code == SETPOINT_ALERT_CODE
    assert derived_alerts[0].severity == "high"
    assert derived_alerts[0].state == "active_unacknowledged"
    assert derived_alerts[0].message == "Erfolgreiche Setpoint-Aenderung: set_reactive_power_target auf ppc-01"


def test_successful_setpoint_rule_skips_existing_alarm_and_non_processwirk_paths() -> None:
    engine = RuleEngine.default_v1()

    plant_mode_alerts = engine.evaluate(
        build_event(
            event_type="process.setpoint.plant_mode_request_changed",
            action="set_plant_mode_request",
            tags=("control-path", "ppc", "plant-mode"),
        )
    )
    alarm_backed_alerts = engine.evaluate(
        build_event(
            event_type="process.setpoint.curtailment_changed",
            action="set_active_power_limit",
            alarm_code="PLANT_CURTAILED",
            tags=("control-path", "ppc", "curtailment"),
        )
    )

    assert plant_mode_alerts == ()
    assert alarm_backed_alerts == ()


def test_rule_engine_respects_minimum_severity_gate() -> None:
    engine = RuleEngine.default_v1(min_severity="critical")

    derived_alerts = engine.evaluate(build_event())

    assert derived_alerts == ()


def test_default_v1_registers_documented_initial_rules() -> None:
    engine = RuleEngine.default_v1()

    assert engine.rule_ids == (
        "repeated_service_login_failure",
        "successful_setpoint_change",
        "breaker_open",
        "inverter_comm_loss",
    )


def test_breaker_open_rule_derives_alert_for_accepted_open_event() -> None:
    engine = RuleEngine.default_v1()

    derived_alerts = engine.evaluate(
        build_event(
            event_type="process.breaker.state_changed",
            action="breaker_open_request",
            asset_id="grid-01",
            alarm_code="BREAKER_OPEN",
            resulting_value="open",
            tags=("control-path", "grid", "breaker"),
        )
    )

    assert len(derived_alerts) == 1
    assert derived_alerts[0].alarm_code == "BREAKER_OPEN"
    assert derived_alerts[0].severity == "high"


def test_inverter_comm_loss_rule_derives_alert_for_lost_block_event() -> None:
    engine = RuleEngine.default_v1()

    derived_alerts = engine.evaluate(
        build_event(
            event_type="system.communication.inverter_block_lost",
            category="system",
            action="simulate_comm_loss",
            asset_id="invb-02",
            alarm_code="COMM_LOSS_INVERTER_BLOCK",
            resulting_value="lost",
            tags=("fault-path", "communications", "inverter-block"),
        )
    )

    assert len(derived_alerts) == 1
    assert derived_alerts[0].alarm_code == "COMM_LOSS_INVERTER_BLOCK"
    assert derived_alerts[0].severity == "medium"


def test_repeated_login_failure_rule_triggers_on_threshold_and_resets_on_success() -> None:
    engine = RuleEngine.default_v1()
    failure_event = build_event(
        event_type="hmi.auth.service_login_attempt",
        category="auth",
        action="login",
        result="failure",
        source_ip="198.51.100.42",
        asset_id="hmi-web",
        requested_value={"username": "field.service"},
        tags=("auth", "service", "web"),
    )

    first = engine.evaluate(failure_event)
    second = engine.evaluate(failure_event.model_copy(update={"event_id": "evt_rule_test_2"}))
    third = engine.evaluate(failure_event.model_copy(update={"event_id": "evt_rule_test_3"}))

    success_event = build_event(
        event_type="hmi.auth.service_login_attempt",
        category="auth",
        action="login",
        result="success",
        source_ip="198.51.100.42",
        asset_id="hmi-web",
        requested_value={"username": "field.service"},
        tags=("auth", "service", "web"),
    )
    assert first == ()
    assert second == ()
    assert LOGIN_FAILURE_THRESHOLD == 3
    assert len(third) == 1
    assert third[0].alarm_code == REPEATED_LOGIN_FAILURE_ALERT_CODE
    assert third[0].severity == "medium"
    assert "field.service" in third[0].message
    assert engine.evaluate(success_event) == ()
    post_reset = engine.evaluate(failure_event.model_copy(update={"event_id": "evt_rule_test_4"}))
    assert post_reset == ()
