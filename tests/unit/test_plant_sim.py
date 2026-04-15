import pytest

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.plant_sim import PlantSimulator


def build_snapshot() -> PlantSnapshot:
    return PlantSnapshot.from_fixture(load_plant_fixture("normal_operation"))


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
    assert degraded_snapshot.revenue_meter.export_power_kw == pytest.approx(5800.0)
    assert degraded_snapshot.active_alarm_codes == ("COMM_LOSS_INVERTER_BLOCK",)
