import pytest

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.event_core import EventRecorder
from honeypot.plant_sim import PlantSimulator, SimulationEventContext, determine_data_quality
from honeypot.storage import SQLiteEventStore
from honeypot.time_core import FrozenClock


def build_snapshot() -> PlantSnapshot:
    return PlantSnapshot.from_fixture(load_plant_fixture("normal_operation"))


def build_recording_simulator(snapshot: PlantSnapshot, tmp_path) -> tuple[PlantSimulator, SQLiteEventStore]:
    store = SQLiteEventStore(tmp_path / "tmp" / "plant-sim-events.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    simulator = PlantSimulator.from_snapshot(snapshot, event_recorder=recorder)
    return simulator, store


def test_estimate_available_power_scales_with_irradiance() -> None:
    snapshot = build_snapshot()
    simulator = PlantSimulator.from_snapshot(snapshot)

    low_output_kw = simulator.estimate_available_power_kw(snapshot, irradiance_w_m2=420)
    baseline_output_kw = simulator.estimate_available_power_kw(snapshot)
    high_output_kw = simulator.estimate_available_power_kw(snapshot, irradiance_w_m2=1000)

    assert low_output_kw < baseline_output_kw < high_output_kw
    assert baseline_output_kw == pytest.approx(5800.0)


def test_apply_curtailment_reduces_power_and_sets_alarm() -> None:
    snapshot = build_snapshot()
    simulator = PlantSimulator.from_snapshot(snapshot)

    curtailed_snapshot = simulator.apply_curtailment(snapshot, active_power_limit_pct=60)

    assert curtailed_snapshot.site.operating_mode == "curtailed"
    assert curtailed_snapshot.site.plant_power_limit_pct == 60
    assert curtailed_snapshot.power_plant_controller.active_power_limit_pct == 60
    assert curtailed_snapshot.site.plant_power_mw == pytest.approx(3.48)
    assert curtailed_snapshot.revenue_meter.export_power_kw == pytest.approx(3480.0)
    assert curtailed_snapshot.active_alarm_codes == ("PLANT_CURTAILED",)


def test_open_breaker_zeroes_export_and_sets_fault_alarm() -> None:
    snapshot = build_snapshot()
    simulator = PlantSimulator.from_snapshot(snapshot)

    breaker_open_snapshot = simulator.open_breaker(snapshot)

    assert breaker_open_snapshot.site.breaker_state == "open"
    assert breaker_open_snapshot.site.operating_mode == "faulted"
    assert breaker_open_snapshot.site.availability_state == "unavailable"
    assert breaker_open_snapshot.grid_interconnect.export_path_available is False
    assert breaker_open_snapshot.revenue_meter.export_power_kw == pytest.approx(0.0)
    assert breaker_open_snapshot.site.plant_power_mw == pytest.approx(0.0)
    assert breaker_open_snapshot.active_alarm_codes == ("BREAKER_OPEN",)


def test_close_breaker_restores_export_and_clears_fault_alarm() -> None:
    snapshot = build_snapshot()
    simulator = PlantSimulator.from_snapshot(snapshot)

    breaker_open_snapshot = simulator.open_breaker(snapshot)
    restored_snapshot = simulator.close_breaker(breaker_open_snapshot)

    assert restored_snapshot.site.breaker_state == "closed"
    assert restored_snapshot.site.operating_mode == "normal"
    assert restored_snapshot.grid_interconnect.export_path_available is True
    assert restored_snapshot.revenue_meter.export_power_kw == pytest.approx(5800.0)
    assert restored_snapshot.site.plant_power_mw == pytest.approx(5.8)
    assert restored_snapshot.alarm_by_code("BREAKER_OPEN").state == "cleared"
    assert restored_snapshot.active_alarm_codes == ()


def test_comm_loss_marks_target_block_stale_without_zeroing_site_power() -> None:
    snapshot = build_snapshot()
    simulator = PlantSimulator.from_snapshot(snapshot)

    degraded_snapshot = simulator.lose_block_communications(snapshot, asset_id="invb-02")

    degraded_block = next(block for block in degraded_snapshot.inverter_blocks if block.asset_id == "invb-02")
    assert degraded_block.status == "degraded"
    assert degraded_block.communication_state == "lost"
    assert degraded_block.quality == "stale"
    assert degraded_snapshot.site.communications_health == "degraded"
    assert degraded_snapshot.site.availability_state == "partially_available"
    assert degraded_snapshot.revenue_meter.export_power_kw == pytest.approx(snapshot.revenue_meter.export_power_kw)
    assert degraded_snapshot.active_alarm_codes == ("COMM_LOSS_INVERTER_BLOCK",)


def test_sequential_comm_loss_preserves_prior_lost_blocks() -> None:
    snapshot = build_snapshot()
    simulator = PlantSimulator.from_snapshot(snapshot)

    first_loss_snapshot = simulator.lose_block_communications(snapshot, asset_id="invb-01")
    second_loss_snapshot = simulator.lose_block_communications(first_loss_snapshot, asset_id="invb-02")

    first_lost_block = next(block for block in second_loss_snapshot.inverter_blocks if block.asset_id == "invb-01")
    second_lost_block = next(block for block in second_loss_snapshot.inverter_blocks if block.asset_id == "invb-02")
    remaining_block = next(block for block in second_loss_snapshot.inverter_blocks if block.asset_id == "invb-03")

    assert first_lost_block.communication_state == "lost"
    assert first_lost_block.quality == "stale"
    assert second_lost_block.communication_state == "lost"
    assert second_lost_block.quality == "stale"
    assert remaining_block.communication_state == "healthy"
    assert second_loss_snapshot.site.communications_health == "degraded"
    assert second_loss_snapshot.active_alarm_codes == ("COMM_LOSS_INVERTER_BLOCK",)


def test_block_enable_request_zeroes_target_block_and_reduces_site_power() -> None:
    snapshot = build_snapshot()
    simulator = PlantSimulator.from_snapshot(snapshot)

    disabled_snapshot = simulator.apply_block_enable_request(
        snapshot,
        asset_id="invb-02",
        block_enable_request=False,
        block_power_limit_pct=100,
    )

    disabled_block = next(block for block in disabled_snapshot.inverter_blocks if block.asset_id == "invb-02")
    assert disabled_block.status == "offline"
    assert disabled_block.availability_pct == 0
    assert disabled_block.block_power_kw == pytest.approx(0.0)
    assert disabled_snapshot.site.availability_state == "partially_available"
    assert disabled_snapshot.site.plant_power_mw == pytest.approx(3.88)
    assert disabled_snapshot.revenue_meter.export_power_kw == pytest.approx(3880.0)


def test_sequential_block_enable_requests_preserve_prior_disabled_blocks() -> None:
    snapshot = build_snapshot()
    simulator = PlantSimulator.from_snapshot(snapshot)

    first_disabled_snapshot = simulator.apply_block_enable_request(
        snapshot,
        asset_id="invb-01",
        block_enable_request=False,
        block_power_limit_pct=100,
    )
    second_disabled_snapshot = simulator.apply_block_enable_request(
        first_disabled_snapshot,
        asset_id="invb-02",
        block_enable_request=False,
        block_power_limit_pct=100,
    )

    first_disabled_block = next(block for block in second_disabled_snapshot.inverter_blocks if block.asset_id == "invb-01")
    second_disabled_block = next(block for block in second_disabled_snapshot.inverter_blocks if block.asset_id == "invb-02")
    remaining_block = next(block for block in second_disabled_snapshot.inverter_blocks if block.asset_id == "invb-03")

    assert first_disabled_block.status == "offline"
    assert first_disabled_block.block_power_kw == pytest.approx(0.0)
    assert second_disabled_block.status == "offline"
    assert second_disabled_block.block_power_kw == pytest.approx(0.0)
    assert remaining_block.block_power_kw > 1900
    assert second_disabled_snapshot.site.plant_power_mw < 2.0
    assert second_disabled_snapshot.site.availability_state == "partially_available"


def test_block_reset_restores_comm_loss_block_without_forcing_plant_mode() -> None:
    snapshot = build_snapshot()
    simulator = PlantSimulator.from_snapshot(snapshot)

    degraded_snapshot = simulator.lose_block_communications(snapshot, asset_id="invb-02")
    reset_snapshot = simulator.reset_block(
        degraded_snapshot,
        asset_id="invb-02",
        block_enable_request=True,
        block_power_limit_pct=50,
    )

    reset_block = next(block for block in reset_snapshot.inverter_blocks if block.asset_id == "invb-02")
    assert reset_block.status == "online"
    assert reset_block.communication_state == "healthy"
    assert reset_block.block_power_kw == pytest.approx(960.0)
    assert reset_snapshot.site.operating_mode == "normal"
    assert reset_snapshot.alarm_by_code("COMM_LOSS_INVERTER_BLOCK").state == "cleared"


def test_acknowledge_alarm_keeps_alarm_active_until_condition_clears() -> None:
    snapshot = build_snapshot()
    simulator = PlantSimulator.from_snapshot(snapshot)

    curtailed_snapshot = simulator.apply_curtailment(snapshot, active_power_limit_pct=60)
    acknowledged_snapshot = simulator.acknowledge_alarm(curtailed_snapshot, code="PLANT_CURTAILED")
    cleared_snapshot = simulator.simulate_normal_operation(acknowledged_snapshot)

    assert acknowledged_snapshot.alarm_by_code("PLANT_CURTAILED").state == "active_acknowledged"
    assert acknowledged_snapshot.site.active_alarm_count == 1
    assert cleared_snapshot.alarm_by_code("PLANT_CURTAILED").state == "cleared"
    assert cleared_snapshot.site.active_alarm_count == 0
    assert cleared_snapshot.active_alarm_codes == ()


def test_determine_data_quality_covers_all_v1_quality_states() -> None:
    assert determine_data_quality(status="online", communication_state="healthy") == "good"
    assert determine_data_quality(status="degraded", communication_state="degraded") == "estimated"
    assert determine_data_quality(status="degraded", communication_state="lost") == "stale"
    assert determine_data_quality(status="offline", communication_state="lost") == "invalid"


def test_apply_curtailment_records_event_state_and_alert(tmp_path) -> None:
    snapshot = build_snapshot()
    simulator, store = build_recording_simulator(snapshot, tmp_path)

    simulator.apply_curtailment(
        snapshot,
        active_power_limit_pct=60,
        event_context=SimulationEventContext(
            source_ip="203.0.113.24",
            actor_type="remote_client",
            correlation_id="corr_fixed_curtailment",
            protocol="modbus-tcp",
            service="holding-registers",
            session_id="sess_curtailment",
        ),
    )

    events = store.fetch_events()
    alerts = store.fetch_alerts()
    site_state = store.fetch_current_state("site")

    assert len(events) == 1
    assert len(alerts) == 1
    assert events[0].event_type == "process.setpoint.curtailment_changed"
    assert events[0].correlation_id == "corr_fixed_curtailment"
    assert events[0].source_ip == "203.0.113.24"
    assert events[0].actor_type == "remote_client"
    assert events[0].asset_id == "ppc-01"
    assert events[0].requested_value == 60
    assert events[0].previous_value == 100
    assert events[0].resulting_value == 60
    assert events[0].resulting_state["plant_power_mw"] == pytest.approx(3.48)
    assert events[0].alarm_code == "PLANT_CURTAILED"
    assert site_state["plant_power_limit_pct"] == 60
    assert site_state["active_alarm_count"] == 1
    assert alerts[0].alarm_code == "PLANT_CURTAILED"
    assert alerts[0].state == "active_unacknowledged"


def test_open_breaker_records_fault_event_and_zeroed_state(tmp_path) -> None:
    snapshot = build_snapshot()
    simulator, store = build_recording_simulator(snapshot, tmp_path)

    simulator.open_breaker(snapshot)

    events = store.fetch_events()
    alerts = store.fetch_alerts()
    grid_state = store.fetch_current_state("grid_interconnect")

    assert len(events) == 1
    assert len(alerts) == 1
    assert events[0].event_type == "process.breaker.state_changed"
    assert events[0].asset_id == "grid-01"
    assert events[0].previous_value == "closed"
    assert events[0].resulting_value == "open"
    assert events[0].alarm_code == "BREAKER_OPEN"
    assert grid_state["breaker_state"] == "open"
    assert grid_state["export_path_available"] is False
    assert alerts[0].alarm_code == "BREAKER_OPEN"
    assert alerts[0].state == "active_unacknowledged"


def test_close_breaker_records_cleared_alert_state(tmp_path) -> None:
    snapshot = build_snapshot()
    simulator, store = build_recording_simulator(snapshot, tmp_path)

    breaker_open_snapshot = simulator.open_breaker(snapshot)
    simulator.close_breaker(breaker_open_snapshot)

    events = store.fetch_events()
    alerts = store.fetch_alerts()
    grid_state = store.fetch_current_state("grid_interconnect")
    close_event = next(event for event in events if event.action == "breaker_close_request")
    cleared_alert = next(alert for alert in alerts if alert.state == "cleared")

    assert len(events) == 2
    assert len(alerts) == 2
    assert close_event.event_type == "process.breaker.state_changed"
    assert close_event.previous_value == "open"
    assert close_event.resulting_value == "closed"
    assert close_event.alarm_code == "BREAKER_OPEN"
    assert grid_state["breaker_state"] == "closed"
    assert grid_state["export_path_available"] is True
    assert cleared_alert.alarm_code == "BREAKER_OPEN"


def test_comm_loss_records_system_event_and_degraded_block_state(tmp_path) -> None:
    snapshot = build_snapshot()
    simulator, store = build_recording_simulator(snapshot, tmp_path)

    simulator.lose_block_communications(snapshot, asset_id="invb-02")

    events = store.fetch_events()
    alerts = store.fetch_alerts()
    site_state = store.fetch_current_state("site")
    inverter_states = store.fetch_current_state("inverter_blocks")
    degraded_block = next(block for block in inverter_states if block["asset_id"] == "invb-02")

    assert len(events) == 1
    assert len(alerts) == 1
    assert events[0].event_type == "system.communication.inverter_block_lost"
    assert events[0].asset_id == "invb-02"
    assert events[0].actor_type == "system"
    assert events[0].resulting_state["communication_state"] == "lost"
    assert degraded_block["communication_state"] == "lost"
    assert degraded_block["quality"] == "stale"
    assert site_state["communications_health"] == "degraded"
    assert alerts[0].alarm_code == "COMM_LOSS_INVERTER_BLOCK"
    assert alerts[0].state == "active_unacknowledged"


def test_block_power_limit_and_reset_record_process_events(tmp_path) -> None:
    snapshot = build_snapshot()
    simulator, store = build_recording_simulator(snapshot, tmp_path)

    limited_snapshot = simulator.apply_block_power_limit(
        snapshot,
        asset_id="invb-02",
        block_enable_request=True,
        block_power_limit_pct=50,
    )
    degraded_snapshot = simulator.lose_block_communications(limited_snapshot, asset_id="invb-02")
    simulator.reset_block(
        degraded_snapshot,
        asset_id="invb-02",
        block_enable_request=True,
        block_power_limit_pct=50,
    )

    events = store.fetch_events()
    alerts = store.fetch_alerts()
    block_state = next(block for block in store.fetch_current_state("inverter_blocks") if block["asset_id"] == "invb-02")
    power_limit_event = next(event for event in events if event.action == "set_block_power_limit")
    reset_event = next(event for event in events if event.action == "block_reset_request")
    cleared_alert = next(alert for alert in alerts if alert.alarm_code == "COMM_LOSS_INVERTER_BLOCK" and alert.state == "cleared")

    assert power_limit_event.resulting_value == 50
    assert power_limit_event.resulting_state["block_power_kw"] == pytest.approx(960.0)
    assert reset_event.resulting_state["communication_state"] == "healthy"
    assert block_state["block_power_kw"] == pytest.approx(960.0)
    assert cleared_alert.state == "cleared"
