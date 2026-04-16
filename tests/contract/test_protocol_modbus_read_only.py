from __future__ import annotations

import socket
from pathlib import Path
from struct import pack, unpack

import pytest

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.event_core import EventRecorder
from honeypot.plant_sim import PlantSimulator
from honeypot.protocol_modbus import (
    ILLEGAL_DATA_ADDRESS,
    ILLEGAL_DATA_VALUE,
    ILLEGAL_FUNCTION,
    READ_HOLDING_REGISTERS,
    READ_INPUT_REGISTERS,
    ReadOnlyModbusTcpService,
    ReadOnlyRegisterMap,
    WRITE_MULTIPLE_REGISTERS,
    WRITE_SINGLE_REGISTER,
)
from honeypot.storage import SQLiteEventStore
from honeypot.time_core import FrozenClock


def build_snapshot() -> PlantSnapshot:
    return PlantSnapshot.from_fixture(load_plant_fixture("normal_operation"))


@pytest.fixture
def running_service(tmp_path: Path):
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "tmp" / "modbus-events.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    service = ReadOnlyModbusTcpService(
        register_map=ReadOnlyRegisterMap(snapshot, event_recorder=recorder),
        bind_host="127.0.0.1",
        port=0,
        event_recorder=recorder,
    ).start_in_thread()
    yield service, store
    service.stop()


def test_fc03_returns_identity_block_with_correct_mbap_header(running_service) -> None:
    service, store = running_service
    response = send_request(
        service.address,
        transaction_id=0x1234,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 0, 8),
    )

    transaction_id, protocol_id, unit_id, pdu = parse_response(response)
    byte_count = pdu[1]
    registers = unpack(f">{byte_count // 2}H", pdu[2:])
    events = store.fetch_events()

    assert transaction_id == 0x1234
    assert protocol_id == 0
    assert unit_id == 1
    assert pdu[0] == READ_HOLDING_REGISTERS
    assert registers == (100, 1001, 1, 0, 28784, 25389, 12337, 8224)
    assert len(events) == 1
    assert events[0].event_type == "protocol.modbus.holding_registers_read"
    assert events[0].requested_value["register_start"] == 40001
    assert events[0].requested_value["register_count"] == 8


def test_reserved_identity_registers_read_as_zero(running_service) -> None:
    service, _ = running_service
    response = send_request(
        service.address,
        transaction_id=2,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 8, 4),
    )

    _, _, _, pdu = parse_response(response)
    assert unpack(">4H", pdu[2:]) == (0, 0, 0, 0)


def test_unknown_gap_returns_illegal_data_address(running_service) -> None:
    service, store = running_service
    response = send_request(
        service.address,
        transaction_id=3,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 49, 1),
    )

    _, _, _, pdu = parse_response(response)
    events = store.fetch_events()

    assert pdu == bytes([READ_HOLDING_REGISTERS | 0x80, ILLEGAL_DATA_ADDRESS])
    assert events[-1].result == "rejected"
    assert events[-1].error_code == "modbus_exception_02"


def test_fc04_is_disabled_by_default_and_returns_illegal_function(running_service) -> None:
    service, _ = running_service
    response = send_request(
        service.address,
        transaction_id=4,
        unit_id=1,
        function_code=READ_INPUT_REGISTERS,
        body=pack(">HH", 0, 1),
    )

    _, _, _, pdu = parse_response(response)
    assert pdu == bytes([READ_INPUT_REGISTERS | 0x80, ILLEGAL_FUNCTION])


def test_fc06_updates_active_power_limit_and_subsequent_reads_reflect_curtailment(running_service) -> None:
    service, store = running_service

    write_response = send_request(
        service.address,
        transaction_id=5,
        unit_id=1,
        function_code=WRITE_SINGLE_REGISTER,
        body=pack(">HH", 199, 555),
    )
    setpoint_response = send_request(
        service.address,
        transaction_id=6,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 199, 3),
    )
    power_response = send_request(
        service.address,
        transaction_id=7,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 103, 2),
    )
    alarm_response = send_request(
        service.address,
        transaction_id=8,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 299, 3),
    )

    _, _, _, write_pdu = parse_response(write_response)
    _, _, _, setpoint_pdu = parse_response(setpoint_response)
    _, _, _, power_pdu = parse_response(power_response)
    _, _, _, alarm_pdu = parse_response(alarm_response)

    events = store.fetch_events()
    alerts = store.fetch_alerts()
    site_state = store.fetch_current_state("site")
    ppc_state = store.fetch_current_state("power_plant_controller")
    protocol_event = next(event for event in events if event.event_type == "protocol.modbus.single_register_write")
    process_event = next(event for event in events if event.event_type == "process.setpoint.curtailment_changed")

    assert unpack(">BHH", write_pdu) == (WRITE_SINGLE_REGISTER, 199, 555)
    assert unpack(">3H", setpoint_pdu[2:]) == (555, 0, 1)
    assert unpack(">2H", power_pdu[2:]) == (0, 3219)
    assert unpack(">3H", alarm_pdu[2:]) == (110, 2, 1)
    assert protocol_event.correlation_id == process_event.correlation_id
    assert protocol_event.requested_value["register_start"] == 40200
    assert protocol_event.requested_value["register_value"] == 555
    assert protocol_event.previous_value == 1000
    assert protocol_event.resulting_value == 555
    assert process_event.requested_value == pytest.approx(55.5)
    assert process_event.resulting_state["plant_power_mw"] == pytest.approx(3.219)
    assert site_state["plant_power_limit_pct"] == pytest.approx(55.5)
    assert ppc_state["active_power_limit_pct"] == pytest.approx(55.5)
    assert len(alerts) == 1
    assert alerts[0].alarm_code == "PLANT_CURTAILED"


def test_fc06_rejects_values_outside_documented_range(running_service) -> None:
    service, store = running_service

    response = send_request(
        service.address,
        transaction_id=9,
        unit_id=1,
        function_code=WRITE_SINGLE_REGISTER,
        body=pack(">HH", 199, 1500),
    )
    readback = send_request(
        service.address,
        transaction_id=10,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 199, 1),
    )

    _, _, _, pdu = parse_response(response)
    _, _, _, readback_pdu = parse_response(readback)
    events = store.fetch_events()
    rejected_event = next(
        event
        for event in events
        if event.action == "fc06" and event.result == "rejected" and event.requested_value["register_value"] == 1500
    )

    assert pdu == bytes([WRITE_SINGLE_REGISTER | 0x80, ILLEGAL_DATA_VALUE])
    assert unpack(">H", readback_pdu[2:])[0] == 1000
    assert rejected_event.error_code == "modbus_exception_03"


def test_fc16_updates_ppc_setpoints_and_keeps_process_events_correlated(running_service) -> None:
    service, store = running_service

    write_response = send_request(
        service.address,
        transaction_id=11,
        unit_id=1,
        function_code=WRITE_MULTIPLE_REGISTERS,
        body=fc16_body(199, 555, 250),
    )
    setpoint_response = send_request(
        service.address,
        transaction_id=12,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 199, 3),
    )
    reactive_status_response = send_request(
        service.address,
        transaction_id=13,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 109, 1),
    )

    _, _, _, write_pdu = parse_response(write_response)
    _, _, _, setpoint_pdu = parse_response(setpoint_response)
    _, _, _, reactive_status_pdu = parse_response(reactive_status_response)

    events = store.fetch_events()
    alerts = store.fetch_alerts()
    ppc_state = store.fetch_current_state("power_plant_controller")
    protocol_event = next(event for event in events if event.event_type == "protocol.modbus.multiple_register_write")
    curtailment_event = next(event for event in events if event.event_type == "process.setpoint.curtailment_changed")
    reactive_event = next(event for event in events if event.event_type == "process.setpoint.reactive_power_target_changed")

    assert unpack(">BHH", write_pdu) == (WRITE_MULTIPLE_REGISTERS, 199, 2)
    assert unpack(">3H", setpoint_pdu[2:]) == (555, 250, 1)
    assert unpack(">H", reactive_status_pdu[2:])[0] == 250
    assert protocol_event.requested_value["register_start"] == 40200
    assert protocol_event.requested_value["register_values"] == [555, 250]
    assert protocol_event.previous_value == [1000, 0]
    assert protocol_event.resulting_value == [555, 250]
    assert protocol_event.correlation_id == curtailment_event.correlation_id == reactive_event.correlation_id
    assert ppc_state["active_power_limit_pct"] == pytest.approx(55.5)
    assert ppc_state["reactive_power_target"] == pytest.approx(0.25)
    assert len(alerts) == 1
    assert alerts[0].alarm_code == "PLANT_CURTAILED"


def test_fc16_can_latch_plant_mode_request_and_rejects_invalid_values(running_service) -> None:
    service, store = running_service

    accepted_response = send_request(
        service.address,
        transaction_id=14,
        unit_id=1,
        function_code=WRITE_MULTIPLE_REGISTERS,
        body=fc16_body(201, 2),
    )
    readback_response = send_request(
        service.address,
        transaction_id=15,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 199, 3),
    )
    rejected_response = send_request(
        service.address,
        transaction_id=16,
        unit_id=1,
        function_code=WRITE_MULTIPLE_REGISTERS,
        body=fc16_body(201, 3),
    )

    _, _, _, accepted_pdu = parse_response(accepted_response)
    _, _, _, readback_pdu = parse_response(readback_response)
    _, _, _, rejected_pdu = parse_response(rejected_response)

    events = store.fetch_events()
    protocol_event = next(
        event
        for event in events
        if event.event_type == "protocol.modbus.multiple_register_write"
        and event.requested_value["register_start"] == 40202
    )
    mode_request_event = next(event for event in events if event.event_type == "process.setpoint.plant_mode_request_changed")
    rejected_event = next(
        event
        for event in events
        if event.action == "fc16" and event.result == "rejected" and event.requested_value["register_values"] == [3]
    )

    assert unpack(">BHH", accepted_pdu) == (WRITE_MULTIPLE_REGISTERS, 201, 1)
    assert unpack(">3H", readback_pdu[2:]) == (1000, 0, 2)
    assert protocol_event.correlation_id == mode_request_event.correlation_id
    assert mode_request_event.resulting_state["plant_mode_request"] == 2
    assert mode_request_event.resulting_state["operating_mode"] == "normal"
    assert rejected_pdu == bytes([WRITE_MULTIPLE_REGISTERS | 0x80, ILLEGAL_DATA_VALUE])
    assert rejected_event.error_code == "modbus_exception_03"


def test_unit_11_and_13_fc03_return_distinct_inverter_identity_and_status(running_service) -> None:
    service, store = running_service

    unit_11_identity_response = send_request(
        service.address,
        transaction_id=39,
        unit_id=11,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 0, 8),
    )
    unit_11_status_response = send_request(
        service.address,
        transaction_id=40,
        unit_id=11,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 99, 12),
    )
    unit_13_identity_response = send_request(
        service.address,
        transaction_id=41,
        unit_id=13,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 0, 8),
    )
    unit_13_status_response = send_request(
        service.address,
        transaction_id=42,
        unit_id=13,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 99, 12),
    )

    unit_11_tx, unit_11_protocol, unit_11_unit, unit_11_identity_pdu = parse_response(unit_11_identity_response)
    _, _, _, unit_11_status_pdu = parse_response(unit_11_status_response)
    unit_13_tx, unit_13_protocol, unit_13_unit, unit_13_identity_pdu = parse_response(unit_13_identity_response)
    _, _, _, unit_13_status_pdu = parse_response(unit_13_status_response)
    events = store.fetch_events()

    assert unit_11_tx == 39
    assert unit_11_protocol == 0
    assert unit_11_unit == 11
    assert unpack(">8H", unit_11_identity_pdu[2:])[:4] == (100, 1101, 11, 1)
    assert unpack(">12H", unit_11_status_pdu[2:]) == (0, 0, 0, 1000, 0, 1935, 0, 0, 0, 0, 0, 0)
    assert unit_13_tx == 41
    assert unit_13_protocol == 0
    assert unit_13_unit == 13
    assert unpack(">8H", unit_13_identity_pdu[2:])[:4] == (100, 1101, 13, 3)
    assert unpack(">12H", unit_13_status_pdu[2:]) == (0, 0, 0, 1000, 0, 1945, 0, 0, 0, 0, 0, 0)
    assert any(event.asset_id == "invb-01" and event.requested_value["register_start"] == 40001 for event in events)
    assert any(event.asset_id == "invb-03" and event.requested_value["register_start"] == 40100 for event in events)


def test_unit_12_fc06_rejects_write_to_current_read_only_slice(running_service) -> None:
    service, store = running_service

    rejected_response = send_request(
        service.address,
        transaction_id=43,
        unit_id=12,
        function_code=WRITE_SINGLE_REGISTER,
        body=pack(">HH", 199, 1),
    )
    readback_response = send_request(
        service.address,
        transaction_id=44,
        unit_id=12,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 99, 12),
    )

    _, _, _, rejected_pdu = parse_response(rejected_response)
    _, _, _, readback_pdu = parse_response(readback_response)
    events = store.fetch_events()
    rejected_event = next(
        event
        for event in events
        if event.action == "fc06"
        and event.result == "rejected"
        and event.asset_id == "invb-02"
        and event.requested_value["register_start"] == 40200
    )

    assert rejected_pdu == bytes([WRITE_SINGLE_REGISTER | 0x80, ILLEGAL_DATA_ADDRESS])
    assert unpack(">12H", readback_pdu[2:]) == (0, 0, 0, 1000, 0, 1920, 0, 0, 0, 0, 0, 0)
    assert rejected_event.error_code == "modbus_exception_02"


def test_unit_12_reflects_comm_loss_in_status_and_alarm_block(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    comm_loss_snapshot = PlantSimulator.from_snapshot(snapshot).lose_block_communications(snapshot, asset_id="invb-02")
    store = SQLiteEventStore(tmp_path / "tmp" / "inverter-comm-loss.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(comm_loss_snapshot.start_time))
    service = ReadOnlyModbusTcpService(
        register_map=ReadOnlyRegisterMap(comm_loss_snapshot, event_recorder=recorder),
        bind_host="127.0.0.1",
        port=0,
        event_recorder=recorder,
    ).start_in_thread()

    try:
        status_response = send_request(
            service.address,
            transaction_id=45,
            unit_id=12,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 99, 12),
        )
        alarm_response = send_request(
            service.address,
            transaction_id=46,
            unit_id=12,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 299, 6),
        )
        unaffected_alarm_response = send_request(
            service.address,
            transaction_id=47,
            unit_id=11,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 299, 6),
        )
    finally:
        service.stop()

    _, _, _, status_pdu = parse_response(status_response)
    _, _, _, alarm_pdu = parse_response(alarm_response)
    _, _, _, unaffected_alarm_pdu = parse_response(unaffected_alarm_response)

    assert unpack(">12H", status_pdu[2:]) == (2, 2, 2, 1000, 0, 1920, 0, 0, 0, 0, 0, 1)
    assert unpack(">6H", alarm_pdu[2:]) == (100, 2, 1, 0, 0, 0)
    assert unpack(">6H", unaffected_alarm_pdu[2:]) == (0, 0, 0, 0, 0, 0)


def test_unit_21_fc03_returns_weather_station_identity_and_status(running_service) -> None:
    service, store = running_service

    identity_response = send_request(
        service.address,
        transaction_id=17,
        unit_id=21,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 0, 8),
    )
    status_response = send_request(
        service.address,
        transaction_id=18,
        unit_id=21,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 99, 8),
    )

    identity_tx, identity_protocol, identity_unit, identity_pdu = parse_response(identity_response)
    _, _, _, status_pdu = parse_response(status_response)
    identity_registers = unpack(">8H", identity_pdu[2:])
    status_registers = unpack(">8H", status_pdu[2:])
    events = store.fetch_events()

    assert identity_tx == 17
    assert identity_protocol == 0
    assert identity_unit == 21
    assert identity_pdu[0] == READ_HOLDING_REGISTERS
    assert identity_registers[:4] == (100, 1201, 21, 0)
    assert status_registers == (0, 0, 0, 840, 315, 220, 42, 1000)
    assert any(event.requested_value["register_start"] == 40001 for event in events)
    assert any(event.requested_value["register_start"] == 40100 for event in events)


def test_unit_21_fc06_rejects_write_to_read_only_slice(running_service) -> None:
    service, store = running_service

    rejected_response = send_request(
        service.address,
        transaction_id=19,
        unit_id=21,
        function_code=WRITE_SINGLE_REGISTER,
        body=pack(">HH", 199, 1),
    )
    readback_response = send_request(
        service.address,
        transaction_id=20,
        unit_id=21,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 102, 5),
    )

    _, _, _, rejected_pdu = parse_response(rejected_response)
    _, _, _, readback_pdu = parse_response(readback_response)
    events = store.fetch_events()
    rejected_event = next(
        event
        for event in events
        if event.action == "fc06"
        and event.result == "rejected"
        and event.asset_id == "wx-01"
        and event.requested_value["register_start"] == 40200
    )

    assert rejected_pdu == bytes([WRITE_SINGLE_REGISTER | 0x80, ILLEGAL_DATA_ADDRESS])
    assert unpack(">5H", readback_pdu[2:]) == (840, 315, 220, 42, 1000)
    assert rejected_event.error_code == "modbus_exception_02"


def test_unit_31_fc03_returns_revenue_meter_identity_and_status(running_service) -> None:
    service, store = running_service

    identity_response = send_request(
        service.address,
        transaction_id=21,
        unit_id=31,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 0, 8),
    )
    status_response = send_request(
        service.address,
        transaction_id=22,
        unit_id=31,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 99, 11),
    )

    identity_tx, identity_protocol, identity_unit, identity_pdu = parse_response(identity_response)
    _, _, _, status_pdu = parse_response(status_response)
    identity_registers = unpack(">8H", identity_pdu[2:])
    status_registers = unpack(">11H", status_pdu[2:])
    events = store.fetch_events()

    assert identity_tx == 21
    assert identity_protocol == 0
    assert identity_unit == 31
    assert identity_pdu[0] == READ_HOLDING_REGISTERS
    assert identity_registers[:4] == (100, 1301, 31, 0)
    assert status_registers == (0, 0, 0, 0, 5790, 0, 0, 0, 0, 990, 1)
    assert any(event.requested_value["register_start"] == 40001 for event in events)
    assert any(event.requested_value["register_start"] == 40100 for event in events)


def test_unit_31_fc06_rejects_write_to_read_only_slice(running_service) -> None:
    service, store = running_service

    rejected_response = send_request(
        service.address,
        transaction_id=23,
        unit_id=31,
        function_code=WRITE_SINGLE_REGISTER,
        body=pack(">HH", 199, 1),
    )
    readback_response = send_request(
        service.address,
        transaction_id=24,
        unit_id=31,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 102, 8),
    )

    _, _, _, rejected_pdu = parse_response(rejected_response)
    _, _, _, readback_pdu = parse_response(readback_response)
    events = store.fetch_events()
    rejected_event = next(
        event
        for event in events
        if event.action == "fc06"
        and event.result == "rejected"
        and event.asset_id == "meter-01"
        and event.requested_value["register_start"] == 40200
    )

    assert rejected_pdu == bytes([WRITE_SINGLE_REGISTER | 0x80, ILLEGAL_DATA_ADDRESS])
    assert unpack(">8H", readback_pdu[2:]) == (0, 5790, 0, 0, 0, 0, 990, 1)
    assert rejected_event.error_code == "modbus_exception_02"


def test_unit_41_fc03_returns_grid_identity_and_status(running_service) -> None:
    service, store = running_service

    identity_response = send_request(
        service.address,
        transaction_id=25,
        unit_id=41,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 0, 8),
    )
    status_response = send_request(
        service.address,
        transaction_id=26,
        unit_id=41,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 99, 5),
    )

    identity_tx, identity_protocol, identity_unit, identity_pdu = parse_response(identity_response)
    _, _, _, status_pdu = parse_response(status_response)
    identity_registers = unpack(">8H", identity_pdu[2:])
    status_registers = unpack(">5H", status_pdu[2:])
    events = store.fetch_events()

    assert identity_tx == 25
    assert identity_protocol == 0
    assert identity_unit == 41
    assert identity_pdu[0] == READ_HOLDING_REGISTERS
    assert identity_registers[:4] == (100, 1401, 41, 0)
    assert status_registers == (0, 0, 0, 1, 0)
    assert any(event.requested_value["register_start"] == 40001 for event in events)
    assert any(event.requested_value["register_start"] == 40100 for event in events)


def test_unit_31_reflects_breaker_open_effects_triggered_by_unit_41(running_service) -> None:
    service, store = running_service

    open_response = send_request(
        service.address,
        transaction_id=27,
        unit_id=41,
        function_code=WRITE_SINGLE_REGISTER,
        body=pack(">HH", 199, 1),
    )
    meter_status_response = send_request(
        service.address,
        transaction_id=28,
        unit_id=31,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 102, 8),
    )
    meter_alarm_response = send_request(
        service.address,
        transaction_id=29,
        unit_id=31,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 299, 4),
    )

    _, _, _, open_pdu = parse_response(open_response)
    _, _, _, meter_status_pdu = parse_response(meter_status_response)
    _, _, _, meter_alarm_pdu = parse_response(meter_alarm_response)
    alerts = store.fetch_alerts()
    breaker_alert = next(
        alert for alert in alerts if alert.alarm_code == "BREAKER_OPEN" and alert.state == "active_unacknowledged"
    )

    assert unpack(">BHH", open_pdu) == (WRITE_SINGLE_REGISTER, 199, 1)
    assert unpack(">8H", meter_status_pdu[2:]) == (0, 0, 0, 0, 0, 0, 990, 0)
    assert unpack(">4H", meter_alarm_pdu[2:]) == (120, 3, 1, 0)
    assert breaker_alert.asset_id == "grid-01"


def test_unit_41_fc06_opens_and_closes_breaker_with_self_clearing_pulses(running_service) -> None:
    service, store = running_service

    open_response = send_request(
        service.address,
        transaction_id=30,
        unit_id=41,
        function_code=WRITE_SINGLE_REGISTER,
        body=pack(">HH", 199, 1),
    )
    open_status_response = send_request(
        service.address,
        transaction_id=31,
        unit_id=41,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 101, 3),
    )
    open_alarm_response = send_request(
        service.address,
        transaction_id=32,
        unit_id=41,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 299, 4),
    )
    pulse_readback_response = send_request(
        service.address,
        transaction_id=33,
        unit_id=41,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 199, 2),
    )
    close_response = send_request(
        service.address,
        transaction_id=34,
        unit_id=41,
        function_code=WRITE_SINGLE_REGISTER,
        body=pack(">HH", 200, 1),
    )
    close_status_response = send_request(
        service.address,
        transaction_id=35,
        unit_id=41,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 101, 3),
    )
    close_alarm_response = send_request(
        service.address,
        transaction_id=36,
        unit_id=41,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 299, 4),
    )

    _, _, _, open_pdu = parse_response(open_response)
    _, _, _, open_status_pdu = parse_response(open_status_response)
    _, _, _, open_alarm_pdu = parse_response(open_alarm_response)
    _, _, _, pulse_readback_pdu = parse_response(pulse_readback_response)
    _, _, _, close_pdu = parse_response(close_response)
    _, _, _, close_status_pdu = parse_response(close_status_response)
    _, _, _, close_alarm_pdu = parse_response(close_alarm_response)

    events = store.fetch_events()
    alerts = store.fetch_alerts()
    grid_state = store.fetch_current_state("grid_interconnect")
    active_breaker_alert = next(alert for alert in alerts if alert.alarm_code == "BREAKER_OPEN" and alert.state == "active_unacknowledged")
    cleared_breaker_alert = next(alert for alert in alerts if alert.alarm_code == "BREAKER_OPEN" and alert.state == "cleared")
    protocol_open_event = next(
        event
        for event in events
        if event.event_type == "protocol.modbus.single_register_write"
        and event.requested_value["register_start"] == 40200
    )
    protocol_close_event = next(
        event
        for event in events
        if event.event_type == "protocol.modbus.single_register_write"
        and event.requested_value["register_start"] == 40201
    )
    process_open_event = next(event for event in events if event.action == "breaker_open_request")
    process_close_event = next(event for event in events if event.action == "breaker_close_request")

    assert unpack(">BHH", open_pdu) == (WRITE_SINGLE_REGISTER, 199, 1)
    assert unpack(">3H", open_status_pdu[2:]) == (1, 0, 2)
    assert unpack(">4H", open_alarm_pdu[2:]) == (120, 3, 1, 1)
    assert unpack(">2H", pulse_readback_pdu[2:]) == (0, 0)
    assert unpack(">BHH", close_pdu) == (WRITE_SINGLE_REGISTER, 200, 1)
    assert unpack(">3H", close_status_pdu[2:]) == (0, 1, 0)
    assert unpack(">4H", close_alarm_pdu[2:]) == (0, 0, 3, 0)
    assert protocol_open_event.previous_value == 0
    assert protocol_open_event.resulting_value == 0
    assert protocol_close_event.previous_value == 0
    assert protocol_close_event.resulting_value == 0
    assert protocol_open_event.correlation_id == process_open_event.correlation_id
    assert protocol_close_event.correlation_id == process_close_event.correlation_id
    assert grid_state["breaker_state"] == "closed"
    assert grid_state["export_path_available"] is True
    assert active_breaker_alert.asset_id == "grid-01"
    assert cleared_breaker_alert.asset_id == "grid-01"


def test_unit_41_fc16_rejects_conflicting_breaker_pulses(running_service) -> None:
    service, store = running_service

    rejected_response = send_request(
        service.address,
        transaction_id=37,
        unit_id=41,
        function_code=WRITE_MULTIPLE_REGISTERS,
        body=fc16_body(199, 1, 1),
    )
    status_response = send_request(
        service.address,
        transaction_id=38,
        unit_id=41,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 101, 3),
    )

    _, _, _, rejected_pdu = parse_response(rejected_response)
    _, _, _, status_pdu = parse_response(status_response)
    events = store.fetch_events()
    rejected_event = next(
        event
        for event in events
        if event.action == "fc16"
        and event.result == "rejected"
        and event.requested_value["register_start"] == 40200
        and event.requested_value["register_values"] == [1, 1]
    )

    assert rejected_pdu == bytes([WRITE_MULTIPLE_REGISTERS | 0x80, ILLEGAL_DATA_VALUE])
    assert unpack(">3H", status_pdu[2:]) == (0, 1, 0)
    assert rejected_event.error_code == "modbus_exception_03"


def send_request(
    address: tuple[str, int],
    *,
    transaction_id: int,
    unit_id: int,
    function_code: int,
    body: bytes,
) -> bytes:
    pdu = bytes([function_code]) + body
    adu = pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id) + pdu
    with socket.create_connection(address, timeout=5) as connection:
        connection.sendall(adu)
        header = recv_exact(connection, 7)
        _, _, length, _ = unpack(">HHHB", header)
        payload = recv_exact(connection, length - 1)
    return header + payload


def fc16_body(start_offset: int, *values: int) -> bytes:
    return pack(">HHB", start_offset, len(values), len(values) * 2) + b"".join(pack(">H", value) for value in values)


def parse_response(response: bytes) -> tuple[int, int, int, bytes]:
    transaction_id, protocol_id, length, unit_id = unpack(">HHHB", response[:7])
    assert len(response[7:]) == length - 1
    return transaction_id, protocol_id, unit_id, response[7:]


def recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("Socket geschlossen, bevor die Antwort komplett war")
        chunks.extend(chunk)
    return bytes(chunks)
