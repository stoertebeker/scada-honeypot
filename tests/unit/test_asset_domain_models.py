from datetime import UTC, datetime

import pytest

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture


def test_plant_snapshot_maps_normal_operation_fixture() -> None:
    fixture = load_plant_fixture("normal_operation")

    snapshot = PlantSnapshot.from_fixture(fixture)

    assert snapshot.fixture_name == "normal_operation"
    assert snapshot.start_time == datetime(2026, 4, 1, 10, 0, tzinfo=UTC)
    assert snapshot.site.plant_power_mw == pytest.approx(5.8)
    assert snapshot.site.breaker_state == "closed"
    assert snapshot.power_plant_controller.active_power_limit_pct == 100
    assert snapshot.power_plant_controller.control_authority == "remote_scada"
    assert tuple(block.asset_id for block in snapshot.inverter_blocks) == ("invb-01", "invb-02", "invb-03")
    assert snapshot.total_inverter_power_kw == pytest.approx(5800.0)
    assert snapshot.weather_station.module_temperature_c == pytest.approx(31.5)
    assert snapshot.weather_station.wind_speed_m_s == pytest.approx(4.2)
    assert snapshot.revenue_meter.export_power_kw == pytest.approx(5790.0)
    assert snapshot.grid_interconnect.export_path_available is True
    assert snapshot.active_alarm_codes == ()
