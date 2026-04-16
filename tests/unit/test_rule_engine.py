from datetime import UTC, datetime

import pytest

from honeypot.event_core.models import EventRecord
from honeypot.rule_engine import RuleContext, RuleEngine, SETPOINT_ALERT_CODE, SuccessfulSetpointChangeRule


def build_event(
    *,
    event_type: str = "process.setpoint.reactive_power_target_changed",
    action: str = "set_reactive_power_target",
    result: str = "accepted",
    alarm_code: str | None = None,
    tags: tuple[str, ...] = ("control-path", "ppc", "reactive-power"),
) -> EventRecord:
    return EventRecord(
        timestamp=datetime(2026, 4, 16, 9, 30, tzinfo=UTC),
        event_id="evt_rule_test",
        correlation_id="corr_rule_test",
        event_type=event_type,
        category="process",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="ppc-01",
        action=action,
        result=result,
        protocol="modbus-tcp",
        service="holding-registers",
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
