import pytest

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.protocol_modbus import ILLEGAL_DATA_ADDRESS, ModbusRegisterError, ReadOnlyRegisterMap


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


def test_reserved_registers_within_active_blocks_read_as_zero() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    result = register_map.read_holding_registers(unit_id=1, start_offset=8, quantity=4)

    assert result.values == (0, 0, 0, 0)


def test_access_outside_active_blocks_is_rejected() -> None:
    register_map = ReadOnlyRegisterMap(build_snapshot())

    with pytest.raises(ModbusRegisterError) as exc_info:
        register_map.read_holding_registers(unit_id=1, start_offset=49, quantity=1)

    assert exc_info.value.exception_code == ILLEGAL_DATA_ADDRESS
