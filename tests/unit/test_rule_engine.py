from datetime import UTC, datetime

import pytest

from honeypot.event_core.models import AlertRecord, EventRecord
from honeypot.rule_engine import (
    COMM_LOSS_ALERT_CODE,
    DEFAULT_CAPACITY_MW,
    GRID_PATH_UNAVAILABLE_ALERT_CODE,
    LOGIN_FAILURE_THRESHOLD,
    LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE,
    MULTI_BLOCK_UNAVAILABLE_ALERT_CODE,
    REPEATED_LOGIN_FAILURE_ALERT_CODE,
    RuleContext,
    RuleEngine,
    SETPOINT_ALERT_CODE,
    SITE_AGGREGATE_ASSET_ID,
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


def build_low_output_state(
    *,
    plant_power_mw: float,
    irradiance_w_m2: int = 892,
    plant_power_limit_pct: float = 100,
    breaker_state: str = "closed",
    export_path_available: bool = True,
    alarms: tuple[dict[str, str], ...] = (),
) -> dict[str, object]:
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
        "alarms": alarms,
    }


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
        "grid_path_unavailable",
        "low_site_output_unexpected",
        "inverter_comm_loss",
        "multi_block_unavailable",
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


def test_grid_path_unavailable_rule_derives_follow_up_alert_for_breaker_open() -> None:
    engine = RuleEngine.default_v1()

    derived_alerts = engine.evaluate(
        build_event(
            event_type="process.breaker.state_changed",
            action="breaker_open_request",
            asset_id="grid-01",
            alarm_code="BREAKER_OPEN",
            resulting_value="open",
            tags=("control-path", "grid", "breaker"),
        ),
        context=RuleContext(
            current_state={
                "grid_interconnect": {
                    "breaker_state": "open",
                    "export_path_available": False,
                    "grid_acceptance_state": "unavailable",
                }
            }
        ),
    )

    assert len(derived_alerts) == 2
    follow_up_alert = next(alert for alert in derived_alerts if alert.alarm_code == GRID_PATH_UNAVAILABLE_ALERT_CODE)
    assert follow_up_alert.severity == "critical"
    assert follow_up_alert.state == "active_unacknowledged"
    assert follow_up_alert.asset_id == "grid-01"
    assert follow_up_alert.message == "Exportpfad nicht verfuegbar auf grid-01"


def test_grid_path_unavailable_rule_clears_follow_up_alert_after_breaker_close() -> None:
    engine = RuleEngine.default_v1()
    existing_alert = AlertRecord(
        alert_id="alt_grid_path_active",
        event_id="evt_existing_grid_path",
        correlation_id="corr_existing_grid_path",
        alarm_code=GRID_PATH_UNAVAILABLE_ALERT_CODE,
        severity="critical",
        state="active_unacknowledged",
        component="plant-sim",
        asset_id="grid-01",
        message="Exportpfad nicht verfuegbar auf grid-01",
        created_at=datetime(2026, 4, 16, 9, 29, tzinfo=UTC),
    )

    derived_alerts = engine.evaluate(
        build_event(
            event_type="process.breaker.state_changed",
            action="breaker_close_request",
            asset_id="grid-01",
            alarm_code="BREAKER_OPEN",
            resulting_value="closed",
            tags=("control-path", "grid", "breaker"),
        ),
        context=RuleContext(
            current_state={
                "grid_interconnect": {
                    "breaker_state": "closed",
                    "export_path_available": True,
                    "grid_acceptance_state": "accepted",
                }
            },
            alert_history=(existing_alert,),
        ),
    )

    assert len(derived_alerts) == 1
    assert derived_alerts[0].alarm_code == GRID_PATH_UNAVAILABLE_ALERT_CODE
    assert derived_alerts[0].severity == "critical"
    assert derived_alerts[0].state == "cleared"


def test_grid_path_unavailable_rule_allows_re_raise_after_clear() -> None:
    engine = RuleEngine.default_v1()
    cleared_alert = AlertRecord(
        alert_id="alt_grid_path_cleared",
        event_id="evt_existing_grid_path",
        correlation_id="corr_existing_grid_path",
        alarm_code=GRID_PATH_UNAVAILABLE_ALERT_CODE,
        severity="critical",
        state="cleared",
        component="plant-sim",
        asset_id="grid-01",
        message="Exportpfad nicht verfuegbar auf grid-01",
        created_at=datetime(2026, 4, 16, 9, 29, tzinfo=UTC),
    )

    derived_alerts = engine.evaluate(
        build_event(
            event_type="process.breaker.state_changed",
            action="breaker_open_request",
            asset_id="grid-01",
            alarm_code="BREAKER_OPEN",
            resulting_value="open",
            tags=("control-path", "grid", "breaker"),
        ),
        context=RuleContext(
            current_state={
                "grid_interconnect": {
                    "breaker_state": "open",
                    "export_path_available": False,
                    "grid_acceptance_state": "unavailable",
                }
            },
            alert_history=(cleared_alert,),
        ),
    )

    assert {alert.alarm_code for alert in derived_alerts} == {"BREAKER_OPEN", GRID_PATH_UNAVAILABLE_ALERT_CODE}


def test_low_site_output_rule_derives_follow_up_alert_for_large_shortfall() -> None:
    engine = RuleEngine.default_v1(capacity_mw=DEFAULT_CAPACITY_MW, low_output_threshold_pct=35)

    derived_alerts = engine.evaluate(
        build_event(
            event_type="process.setpoint.block_enable_request_changed",
            action="set_block_enable_request",
            asset_id="invb-02",
            resulting_value=0,
            tags=("control-path", "inverter-block", "enable"),
        ),
        context=RuleContext(current_state=build_low_output_state(plant_power_mw=1.9)),
    )

    low_output_alert = next(
        alert for alert in derived_alerts if alert.alarm_code == LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE
    )

    assert {alert.alarm_code for alert in derived_alerts} == {
        SETPOINT_ALERT_CODE,
        LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE,
    }
    assert low_output_alert.severity == "high"
    assert low_output_alert.asset_id == SITE_AGGREGATE_ASSET_ID
    assert low_output_alert.message == "Parkleistung deutlich unter erwarteter Verfuegbarkeit"


def test_low_site_output_rule_skips_breaker_and_curtailment_states() -> None:
    engine = RuleEngine.default_v1(capacity_mw=DEFAULT_CAPACITY_MW, low_output_threshold_pct=35)

    breaker_alerts = engine.evaluate(
        build_event(
            event_type="process.breaker.state_changed",
            action="breaker_open_request",
            asset_id="grid-01",
            resulting_value="open",
            tags=("control-path", "grid", "breaker"),
        ),
        context=RuleContext(
            current_state=build_low_output_state(
                plant_power_mw=0.0,
                breaker_state="open",
                export_path_available=False,
            )
        ),
    )
    curtailed_alerts = engine.evaluate(
        build_event(
            event_type="process.setpoint.curtailment_changed",
            action="set_active_power_limit",
            asset_id="ppc-01",
            resulting_value=60,
            tags=("control-path", "ppc", "curtailment"),
        ),
        context=RuleContext(
            current_state=build_low_output_state(
                plant_power_mw=3.48,
                plant_power_limit_pct=60,
                alarms=(
                    {"code": "PLANT_CURTAILED", "state": "active_unacknowledged"},
                ),
            )
        ),
    )

    assert not any(alert.alarm_code == LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE for alert in breaker_alerts)
    assert not any(alert.alarm_code == LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE for alert in curtailed_alerts)


def test_low_site_output_rule_clears_follow_up_alert_after_recovery() -> None:
    engine = RuleEngine.default_v1(capacity_mw=DEFAULT_CAPACITY_MW, low_output_threshold_pct=35)
    existing_alert = AlertRecord(
        alert_id="alt_low_output_active",
        event_id="evt_low_output_active",
        correlation_id="corr_low_output_active",
        alarm_code=LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE,
        severity="high",
        state="active_unacknowledged",
        component="plant-sim",
        asset_id=SITE_AGGREGATE_ASSET_ID,
        message="Parkleistung deutlich unter erwarteter Verfuegbarkeit",
        created_at=datetime(2026, 4, 16, 9, 29, tzinfo=UTC),
    )

    derived_alerts = engine.evaluate(
        build_event(
            event_type="process.control.block_reset_requested",
            action="block_reset_request",
            asset_id="invb-02",
            resulting_value="applied",
            tags=("control-path", "inverter-block", "reset"),
        ),
        context=RuleContext(
            current_state=build_low_output_state(plant_power_mw=5.8),
            alert_history=(existing_alert,),
        ),
    )

    assert len(derived_alerts) == 1
    assert derived_alerts[0].alarm_code == LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE
    assert derived_alerts[0].state == "cleared"


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
    assert derived_alerts[0].alarm_code == COMM_LOSS_ALERT_CODE
    assert derived_alerts[0].severity == "medium"


def test_multi_block_unavailable_rule_derives_critical_follow_up_on_second_distinct_loss() -> None:
    engine = RuleEngine.default_v1()
    first_loss_alert = AlertRecord(
        alert_id="alt_comm_loss_01",
        event_id="evt_existing_loss",
        correlation_id="corr_existing_loss",
        alarm_code=COMM_LOSS_ALERT_CODE,
        severity="medium",
        state="active_unacknowledged",
        component="plant-sim",
        asset_id="invb-01",
        message="Kommunikationsverlust fuer Inverter-Block invb-01",
        created_at=datetime(2026, 4, 16, 9, 29, tzinfo=UTC),
    )

    derived_alerts = engine.evaluate(
        build_event(
            event_type="system.communication.inverter_block_lost",
            category="system",
            action="simulate_comm_loss",
            asset_id="invb-02",
            alarm_code=COMM_LOSS_ALERT_CODE,
            resulting_value="lost",
            tags=("fault-path", "communications", "inverter-block"),
        ),
        context=RuleContext(alert_history=(first_loss_alert,)),
    )

    assert len(derived_alerts) == 2
    assert {alert.alarm_code for alert in derived_alerts} == {
        COMM_LOSS_ALERT_CODE,
        MULTI_BLOCK_UNAVAILABLE_ALERT_CODE,
    }
    aggregate_alert = next(alert for alert in derived_alerts if alert.alarm_code == MULTI_BLOCK_UNAVAILABLE_ALERT_CODE)
    assert aggregate_alert.severity == "critical"
    assert aggregate_alert.asset_id == SITE_AGGREGATE_ASSET_ID
    assert aggregate_alert.message == "Mehrere Inverter-Bloecke gleichzeitig nicht verfuegbar"


def test_multi_block_unavailable_rule_is_suppressed_while_matching_aggregate_alert_is_active() -> None:
    engine = RuleEngine.default_v1()
    active_alerts = (
        AlertRecord(
            alert_id="alt_comm_loss_01",
            event_id="evt_existing_loss",
            correlation_id="corr_existing_loss",
            alarm_code=COMM_LOSS_ALERT_CODE,
            severity="medium",
            state="active_unacknowledged",
            component="plant-sim",
            asset_id="invb-01",
            message="Kommunikationsverlust fuer Inverter-Block invb-01",
            created_at=datetime(2026, 4, 16, 9, 29, tzinfo=UTC),
        ),
        AlertRecord(
            alert_id="alt_multi_block_active",
            event_id="evt_existing_multi",
            correlation_id="corr_existing_multi",
            alarm_code=MULTI_BLOCK_UNAVAILABLE_ALERT_CODE,
            severity="critical",
            state="active_unacknowledged",
            component="plant-sim",
            asset_id=SITE_AGGREGATE_ASSET_ID,
            message="Mehrere Inverter-Bloecke gleichzeitig nicht verfuegbar",
            created_at=datetime(2026, 4, 16, 9, 30, tzinfo=UTC),
        ),
    )

    derived_alerts = engine.evaluate(
        build_event(
            event_type="system.communication.inverter_block_lost",
            category="system",
            action="simulate_comm_loss",
            asset_id="invb-03",
            alarm_code=COMM_LOSS_ALERT_CODE,
            resulting_value="lost",
            tags=("fault-path", "communications", "inverter-block"),
        ),
        context=RuleContext(alert_history=active_alerts),
    )

    assert len(derived_alerts) == 1
    assert derived_alerts[0].alarm_code == COMM_LOSS_ALERT_CODE


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


def test_repeated_login_failure_rule_clears_matching_active_alert_on_success() -> None:
    engine = RuleEngine.default_v1()
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
    existing_alert = AlertRecord(
        alert_id="alt_repeated_login_active",
        event_id="evt_repeated_login_active",
        correlation_id="corr_repeated_login_active",
        alarm_code=REPEATED_LOGIN_FAILURE_ALERT_CODE,
        severity="medium",
        state="active_unacknowledged",
        component="plant-sim",
        asset_id="hmi-web",
        message="Wiederholte Login-Fehlschlaege fuer field.service von 198.51.100.42",
        created_at=datetime(2026, 4, 16, 9, 29, tzinfo=UTC),
    )

    derived_alerts = engine.evaluate(
        success_event,
        context=RuleContext(
            alert_history=(existing_alert,),
        ),
    )

    assert len(derived_alerts) == 1
    assert derived_alerts[0].alarm_code == REPEATED_LOGIN_FAILURE_ALERT_CODE
    assert derived_alerts[0].severity == "medium"
    assert derived_alerts[0].state == "cleared"


def test_rule_engine_suppresses_matching_active_alert_from_history() -> None:
    engine = RuleEngine.default_v1()
    event = build_event()
    existing_alert = AlertRecord(
        alert_id="alt_rule_test",
        event_id="evt_existing",
        correlation_id="corr_existing",
        alarm_code=SETPOINT_ALERT_CODE,
        severity="high",
        state="active_acknowledged",
        component=event.component,
        asset_id=event.asset_id,
        message="Erfolgreiche Setpoint-Aenderung: set_reactive_power_target auf ppc-01",
        created_at=datetime(2026, 4, 16, 9, 29, tzinfo=UTC),
    )

    derived_alerts = engine.evaluate(
        event,
        context=RuleContext(
            current_state={"ppc": {"active_power_limit_pct": 100}},
            alert_history=(existing_alert,),
        ),
    )

    assert derived_alerts == ()


def test_rule_engine_allows_alert_again_after_matching_history_was_cleared() -> None:
    engine = RuleEngine.default_v1()
    event = build_event()
    cleared_alert = AlertRecord(
        alert_id="alt_rule_test_cleared",
        event_id="evt_existing",
        correlation_id="corr_existing",
        alarm_code=SETPOINT_ALERT_CODE,
        severity="high",
        state="cleared",
        component=event.component,
        asset_id=event.asset_id,
        message="Erfolgreiche Setpoint-Aenderung: set_reactive_power_target auf ppc-01",
        created_at=datetime(2026, 4, 16, 9, 29, tzinfo=UTC),
    )

    derived_alerts = engine.evaluate(
        event,
        context=RuleContext(
            current_state={"ppc": {"active_power_limit_pct": 100}},
            alert_history=(cleared_alert,),
        ),
    )

    assert len(derived_alerts) == 1
    assert derived_alerts[0].alarm_code == SETPOINT_ALERT_CODE
