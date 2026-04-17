import pytest

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.plant_sim import PlantSimulator
from honeypot.protocol_modbus import ILLEGAL_DATA_ADDRESS, ILLEGAL_DATA_VALUE, ModbusRegisterError, ReadOnlyRegisterMap


def build_snapshot() -> PlantSnapshot:
    return PlantSnapshot.from_fixture(load_plant_fixture("normal_operation"))


def test_unit_1_identity_block_maps_documented_values() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    result = register_map.read_holding_registers(unit_id=1, start_offset=0, quantity=8)

    assert result.asset_id == "ppc-01"
    assert result.values[:4] == (100, 1001, 1, 0)
    assert result.values[4:] == (28784, 25389, 12337, 8224)


def test_unit_1_status_block_maps_core_runtime_values() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    result = register_map.read_holding_registers(unit_id=1, start_offset=99, quantity=12)

    assert result.values[0] == 0
    assert result.values[1] == 0
    assert result.values[2] == 0
    assert result.values[3] == 1
    assert result.values[4:6] == (0, 5800)
    assert result.values[9] == 0
    assert result.values[10] == 0
    assert result.values[11] == 0


def test_unit_1_setpoint_block_maps_latched_runtime_values() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    result = register_map.read_holding_registers(unit_id=1, start_offset=199, quantity=3)

    assert result.values == (1000, 0, 0)


def test_unit_11_and_13_identity_and_status_blocks_distinguish_inverter_blocks() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    unit_11_identity = register_map.read_holding_registers(unit_id=11, start_offset=0, quantity=8)
    unit_11_status = register_map.read_holding_registers(unit_id=11, start_offset=99, quantity=12)
    unit_13_identity = register_map.read_holding_registers(unit_id=13, start_offset=0, quantity=8)
    unit_13_status = register_map.read_holding_registers(unit_id=13, start_offset=99, quantity=12)

    assert unit_11_identity.asset_id == "invb-01"
    assert unit_11_identity.values[:4] == (100, 1101, 11, 1)
    assert unit_11_status.values == (0, 0, 0, 1000, 0, 1935, 0, 0, 0, 0, 0, 0)
    assert unit_13_identity.asset_id == "invb-03"
    assert unit_13_identity.values[:4] == (100, 1101, 13, 3)
    assert unit_13_status.values == (0, 0, 0, 1000, 0, 1945, 0, 0, 0, 0, 0, 0)


def test_unit_12_setpoint_block_defaults_to_enabled_and_unlimited() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    result = register_map.read_holding_registers(unit_id=12, start_offset=199, quantity=3)

    assert result.values == (1, 1000, 0)


def test_unit_12_comm_loss_sets_local_alarm_count_and_alarm_block() -> None:
    snapshot = build_snapshot()
    comm_loss_snapshot = PlantSimulator.from_snapshot(snapshot).lose_block_communications(snapshot, asset_id="invb-02")
    register_map = ReadOnlyRegisterMap(comm_loss_snapshot)

    affected_status = register_map.read_holding_registers(unit_id=12, start_offset=99, quantity=12)
    affected_alarm = register_map.read_holding_registers(unit_id=12, start_offset=299, quantity=6)
    unaffected_alarm = register_map.read_holding_registers(unit_id=11, start_offset=299, quantity=6)

    assert affected_status.values[0:4] == (2, 2, 2, 1000)
    assert affected_status.values[11] == 1
    assert affected_alarm.values == (100, 2, 1, 0, 0, 0)
    assert unaffected_alarm.values == (0, 0, 0, 0, 0, 0)


def test_unit_21_identity_status_and_alarm_blocks_map_weather_station_values() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    identity_result = register_map.read_holding_registers(unit_id=21, start_offset=0, quantity=8)
    status_result = register_map.read_holding_registers(unit_id=21, start_offset=99, quantity=8)
    alarm_result = register_map.read_holding_registers(unit_id=21, start_offset=299, quantity=3)

    assert identity_result.asset_id == "wx-01"
    assert identity_result.values[:4] == (100, 1201, 21, 0)
    assert status_result.values == (0, 0, 0, 840, 315, 220, 42, 1000)
    assert alarm_result.values == (0, 0, 0)


def test_unit_31_identity_status_and_alarm_blocks_map_revenue_meter_values() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    identity_result = register_map.read_holding_registers(unit_id=31, start_offset=0, quantity=8)
    status_result = register_map.read_holding_registers(unit_id=31, start_offset=99, quantity=11)
    alarm_result = register_map.read_holding_registers(unit_id=31, start_offset=299, quantity=4)

    assert identity_result.asset_id == "meter-01"
    assert identity_result.values[:4] == (100, 1301, 31, 0)
    assert status_result.values == (0, 0, 0, 0, 5790, 0, 0, 0, 0, 990, 1)
    assert alarm_result.values == (0, 0, 0, 0)


def test_unit_41_identity_and_status_blocks_map_grid_values() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    identity_result = register_map.read_holding_registers(unit_id=41, start_offset=0, quantity=8)
    status_result = register_map.read_holding_registers(unit_id=41, start_offset=99, quantity=5)
    alarm_result = register_map.read_holding_registers(unit_id=41, start_offset=299, quantity=4)

    assert identity_result.asset_id == "grid-01"
    assert identity_result.values[:4] == (100, 1401, 41, 0)
    assert status_result.values == (0, 0, 0, 1, 0)
    assert alarm_result.values == (0, 0, 0, 0)


def test_reserved_registers_within_active_blocks_read_as_zero() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    result = register_map.read_holding_registers(unit_id=1, start_offset=8, quantity=4)

    assert result.values == (0, 0, 0, 0)


def test_access_outside_active_blocks_is_rejected() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    with pytest.raises(ModbusRegisterError) as exc_info:
        register_map.read_holding_registers(unit_id=1, start_offset=49, quantity=1)

    assert exc_info.value.exception_code == ILLEGAL_DATA_ADDRESS


def test_fc06_write_updates_curtailment_snapshot_and_register_reads() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    write_result = register_map.write_single_register(unit_id=1, start_offset=199, value=555)
    setpoint_result = register_map.read_holding_registers(unit_id=1, start_offset=199, quantity=3)
    plant_power_result = register_map.read_holding_registers(unit_id=1, start_offset=103, quantity=2)
    alarm_result = register_map.read_holding_registers(unit_id=1, start_offset=299, quantity=3)

    assert write_result.register_address == 40200
    assert write_result.previous_value == 1000
    assert write_result.resulting_value == 555
    assert write_result.resulting_state["active_alarm_codes"] == ["PLANT_CURTAILED"]
    assert register_map.snapshot.power_plant_controller.active_power_limit_pct == pytest.approx(55.5)
    assert setpoint_result.values == (555, 0, 1)
    assert plant_power_result.values == (0, 3219)
    assert alarm_result.values == (110, 2, 1)


def test_fc06_rejects_values_above_documented_range() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    with pytest.raises(ModbusRegisterError) as exc_info:
        register_map.write_single_register(unit_id=1, start_offset=199, value=1500)

    assert exc_info.value.exception_code == ILLEGAL_DATA_VALUE


def test_fc16_updates_active_and_reactive_setpoints_across_the_ppc_block() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    write_result = register_map.write_multiple_registers(unit_id=1, start_offset=199, values=(555, 250))
    setpoint_result = register_map.read_holding_registers(unit_id=1, start_offset=199, quantity=3)
    status_result = register_map.read_holding_registers(unit_id=1, start_offset=109, quantity=1)

    assert write_result.start_register_address == 40200
    assert write_result.quantity == 2
    assert write_result.previous_values == (1000, 0)
    assert write_result.resulting_values == (555, 250)
    assert write_result.resulting_state["plant_mode_request"] == 1
    assert register_map.snapshot.power_plant_controller.active_power_limit_pct == pytest.approx(55.5)
    assert register_map.snapshot.power_plant_controller.reactive_power_target == pytest.approx(0.25)
    assert setpoint_result.values == (555, 250, 1)
    assert status_result.values == (250,)


def test_fc16_can_latch_plant_mode_request_without_forcing_actual_operating_mode() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    write_result = register_map.write_multiple_registers(unit_id=1, start_offset=201, values=(2,))
    setpoint_result = register_map.read_holding_registers(unit_id=1, start_offset=199, quantity=3)
    operating_mode_result = register_map.read_holding_registers(unit_id=1, start_offset=99, quantity=1)

    assert write_result.previous_values == (0,)
    assert write_result.resulting_values == (2,)
    assert write_result.resulting_state["plant_mode_request"] == 2
    assert write_result.resulting_state["operating_mode"] == "normal"
    assert setpoint_result.values == (1000, 0, 2)
    assert operating_mode_result.values == (0,)


def test_fc16_rejects_invalid_plant_mode_request_values() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    with pytest.raises(ModbusRegisterError) as exc_info:
        register_map.write_multiple_registers(unit_id=1, start_offset=201, values=(3,))

    assert exc_info.value.exception_code == ILLEGAL_DATA_VALUE


def test_unit_12_fc06_disable_and_reenable_updates_block_state() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    disable_result = register_map.write_single_register(unit_id=12, start_offset=199, value=0)
    disabled_setpoints = register_map.read_holding_registers(unit_id=12, start_offset=199, quantity=3)
    disabled_status = register_map.read_holding_registers(unit_id=12, start_offset=99, quantity=12)
    reenable_result = register_map.write_single_register(unit_id=12, start_offset=199, value=1)
    reenabled_setpoints = register_map.read_holding_registers(unit_id=12, start_offset=199, quantity=3)
    reenabled_status = register_map.read_holding_registers(unit_id=12, start_offset=99, quantity=12)

    assert disable_result.register_address == 40200
    assert disable_result.previous_value == 1
    assert disable_result.resulting_value == 0
    assert disable_result.resulting_state["status"] == "offline"
    assert disable_result.resulting_state["block_power_kw"] == pytest.approx(0.0)
    assert disabled_setpoints.values == (0, 1000, 0)
    assert disabled_status.values[0:4] == (1, 1, 1, 0)
    assert disabled_status.values[5] == 0
    assert reenable_result.previous_value == 0
    assert reenable_result.resulting_value == 1
    assert reenable_result.resulting_state["status"] == "online"
    assert reenabled_setpoints.values == (1, 1000, 0)
    assert reenabled_status.values[0:4] == (0, 0, 0, 1000)
    assert reenabled_status.values[5] == 1920


def test_unit_12_fc16_updates_power_limit_and_reset_clears_comm_loss() -> None:
    snapshot = build_snapshot()
    comm_loss_snapshot = PlantSimulator.from_snapshot(snapshot).lose_block_communications(snapshot, asset_id="invb-02")
    register_map = ReadOnlyRegisterMap(comm_loss_snapshot)

    limit_result = register_map.write_multiple_registers(unit_id=12, start_offset=200, values=(500,))
    limited_setpoints = register_map.read_holding_registers(unit_id=12, start_offset=199, quantity=3)
    limited_status = register_map.read_holding_registers(unit_id=12, start_offset=99, quantity=12)
    reset_result = register_map.write_multiple_registers(unit_id=12, start_offset=201, values=(1,))
    reset_setpoints = register_map.read_holding_registers(unit_id=12, start_offset=199, quantity=3)
    reset_status = register_map.read_holding_registers(unit_id=12, start_offset=99, quantity=12)
    reset_alarm = register_map.read_holding_registers(unit_id=12, start_offset=299, quantity=6)

    assert limit_result.start_register_address == 40201
    assert limit_result.previous_values == (1000,)
    assert limit_result.resulting_values == (500,)
    assert limit_result.resulting_state["block_power_limit_pct"] == pytest.approx(50.0)
    assert limited_setpoints.values == (1, 500, 0)
    assert limited_status.values[5] == 960
    assert reset_result.start_register_address == 40202
    assert reset_result.previous_values == (0,)
    assert reset_result.resulting_values == (0,)
    assert reset_result.resulting_state["communication_state"] == "healthy"
    assert reset_setpoints.values == (1, 500, 0)
    assert reset_status.values[0:4] == (0, 0, 0, 1000)
    assert reset_status.values[5] == 960
    assert reset_alarm.values == (0, 0, 0, 0, 0, 0)


def test_unit_12_rejects_invalid_inverter_write_values() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    with pytest.raises(ModbusRegisterError) as enable_exc:
        register_map.write_single_register(unit_id=12, start_offset=199, value=2)
    with pytest.raises(ModbusRegisterError) as limit_exc:
        register_map.write_single_register(unit_id=12, start_offset=200, value=1001)
    with pytest.raises(ModbusRegisterError) as reset_exc:
        register_map.write_multiple_registers(unit_id=12, start_offset=201, values=(2,))

    assert enable_exc.value.exception_code == ILLEGAL_DATA_VALUE
    assert limit_exc.value.exception_code == ILLEGAL_DATA_VALUE
    assert reset_exc.value.exception_code == ILLEGAL_DATA_VALUE


def test_unit_21_rejects_any_write_in_read_only_slice() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    with pytest.raises(ModbusRegisterError) as fc06_exc:
        register_map.write_single_register(unit_id=21, start_offset=199, value=1)
    with pytest.raises(ModbusRegisterError) as fc16_exc:
        register_map.write_multiple_registers(unit_id=21, start_offset=199, values=(1,))

    assert fc06_exc.value.exception_code == ILLEGAL_DATA_ADDRESS
    assert fc16_exc.value.exception_code == ILLEGAL_DATA_ADDRESS


def test_unit_31_rejects_any_write_in_read_only_slice() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    with pytest.raises(ModbusRegisterError) as fc06_exc:
        register_map.write_single_register(unit_id=31, start_offset=199, value=1)
    with pytest.raises(ModbusRegisterError) as fc16_exc:
        register_map.write_multiple_registers(unit_id=31, start_offset=199, values=(1,))

    assert fc06_exc.value.exception_code == ILLEGAL_DATA_ADDRESS
    assert fc16_exc.value.exception_code == ILLEGAL_DATA_ADDRESS


def test_unit_41_fc06_pulse_requests_open_and_close_breaker() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    open_result = register_map.write_single_register(unit_id=41, start_offset=199, value=1)
    open_status_result = register_map.read_holding_registers(unit_id=41, start_offset=101, quantity=3)
    open_alarm_result = register_map.read_holding_registers(unit_id=41, start_offset=299, quantity=4)
    pulse_result = register_map.read_holding_registers(unit_id=41, start_offset=199, quantity=2)
    close_result = register_map.write_single_register(unit_id=41, start_offset=200, value=1)
    close_status_result = register_map.read_holding_registers(unit_id=41, start_offset=101, quantity=3)
    close_alarm_result = register_map.read_holding_registers(unit_id=41, start_offset=299, quantity=4)

    assert open_result.register_address == 40200
    assert open_result.previous_value == 0
    assert open_result.resulting_value == 0
    assert open_result.asset_id == "grid-01"
    assert open_result.resulting_state["breaker_state"] == "open"
    assert open_status_result.values == (1, 0, 2)
    assert open_alarm_result.values == (120, 3, 1, 1)
    assert pulse_result.values == (0, 0)

    assert close_result.register_address == 40201
    assert close_result.previous_value == 0
    assert close_result.resulting_value == 0
    assert close_result.asset_id == "grid-01"
    assert close_result.resulting_state["breaker_state"] == "closed"
    assert close_status_result.values == (0, 1, 0)
    assert close_alarm_result.values == (0, 0, 3, 0)


def test_unit_41_fc16_rejects_conflicting_breaker_requests() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    with pytest.raises(ModbusRegisterError) as exc_info:
        register_map.write_multiple_registers(unit_id=41, start_offset=199, values=(1, 1))

    assert exc_info.value.exception_code == ILLEGAL_DATA_VALUE
