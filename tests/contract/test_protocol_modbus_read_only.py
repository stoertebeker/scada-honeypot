from __future__ import annotations

import socket
from pathlib import Path
from struct import pack, unpack
from time import monotonic, sleep

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
        body=pack(">HH", 0, 18),
    )

    transaction_id, protocol_id, unit_id, pdu = parse_response(response)
    byte_count = pdu[1]
    registers = unpack(f">{byte_count // 2}H", pdu[2:])
    events = store.fetch_events()

    assert transaction_id == 0x1234
    assert protocol_id == 0
    assert unit_id == 1
    assert pdu[0] == READ_HOLDING_REGISTERS
    assert registers[:4] == (124, 4103, 1, 1)
    assert decode_ascii_registers(registers[4:8]) == "PPC-A01"
    assert registers[8:18] == (7100, 7112, 213, 3, 7, 4, 1182, 51026, 1001, 7)
    assert len(events) == 1
    assert events[0].event_type == "protocol.modbus.holding_registers_read"
    assert events[0].requested_value["register_start"] == 40001
    assert events[0].requested_value["register_count"] == 18


def test_reserved_identity_registers_read_as_zero(running_service) -> None:
    service, _ = running_service
    response = send_request(
        service.address,
        transaction_id=2,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 18, 4),
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
    unit_11_identity = unpack(">8H", unit_11_identity_pdu[2:])
    assert unit_11_identity[:4] == (124, 4211, 11, 1)
    assert decode_ascii_registers(unit_11_identity[4:8]) == "INV-B01"
    assert unpack(">12H", unit_11_status_pdu[2:]) == (0, 0, 0, 1000, 0, 1935, 0, 0, 0, 0, 0, 0)
    assert unit_13_tx == 41
    assert unit_13_protocol == 0
    assert unit_13_unit == 13
    unit_13_identity = unpack(">8H", unit_13_identity_pdu[2:])
    assert unit_13_identity[:4] == (124, 4211, 13, 3)
    assert decode_ascii_registers(unit_13_identity[4:8]) == "INV-B03"
    assert unpack(">12H", unit_13_status_pdu[2:]) == (0, 0, 0, 1000, 0, 1945, 0, 0, 0, 0, 0, 0)
    assert any(event.asset_id == "invb-01" and event.requested_value["register_start"] == 40001 for event in events)
    assert any(event.asset_id == "invb-03" and event.requested_value["register_start"] == 40100 for event in events)


def test_unit_12_fc06_can_disable_and_reenable_block(running_service) -> None:
    service, store = running_service

    disable_response = send_request(
        service.address,
        transaction_id=43,
        unit_id=12,
        function_code=WRITE_SINGLE_REGISTER,
        body=pack(">HH", 199, 0),
    )
    disabled_setpoint_response = send_request(
        service.address,
        transaction_id=44,
        unit_id=12,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 199, 3),
    )
    disabled_status_response = send_request(
        service.address,
        transaction_id=45,
        unit_id=12,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 99, 12),
    )
    enable_response = send_request(
        service.address,
        transaction_id=46,
        unit_id=12,
        function_code=WRITE_SINGLE_REGISTER,
        body=pack(">HH", 199, 1),
    )

    _, _, _, disable_pdu = parse_response(disable_response)
    _, _, _, disabled_setpoint_pdu = parse_response(disabled_setpoint_response)
    _, _, _, disabled_status_pdu = parse_response(disabled_status_response)
    _, _, _, enable_pdu = parse_response(enable_response)
    events = store.fetch_events()
    disable_protocol_event = next(
        event
        for event in events
        if event.event_type == "protocol.modbus.single_register_write"
        and event.asset_id == "invb-02"
        and event.requested_value["register_start"] == 40200
    )
    disable_process_event = next(event for event in events if event.action == "set_block_enable_request" and event.requested_value == 0)
    enable_process_event = next(
        event
        for event in events
        if event.action == "set_block_enable_request" and event.requested_value == 1
    )

    assert unpack(">BHH", disable_pdu) == (WRITE_SINGLE_REGISTER, 199, 0)
    assert unpack(">3H", disabled_setpoint_pdu[2:]) == (0, 1000, 0)
    assert unpack(">12H", disabled_status_pdu[2:]) == (1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1)
    assert unpack(">BHH", enable_pdu) == (WRITE_SINGLE_REGISTER, 199, 1)
    assert disable_protocol_event.previous_value == 1
    assert disable_protocol_event.resulting_value == 0
    assert disable_protocol_event.correlation_id == disable_process_event.correlation_id
    assert enable_process_event.resulting_state["status"] == "online"


def test_unit_12_fc06_can_open_and_close_dc_disconnect(running_service) -> None:
    service, store = running_service

    open_response = send_request(
        service.address,
        transaction_id=47,
        unit_id=12,
        function_code=WRITE_SINGLE_REGISTER,
        body=pack(">HH", 202, 1),
    )
    isolated_setpoint_response = send_request(
        service.address,
        transaction_id=48,
        unit_id=12,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 199, 4),
    )
    isolated_status_response = send_request(
        service.address,
        transaction_id=49,
        unit_id=12,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 99, 13),
    )
    close_response = send_request(
        service.address,
        transaction_id=50,
        unit_id=12,
        function_code=WRITE_SINGLE_REGISTER,
        body=pack(">HH", 202, 0),
    )
    restored_setpoint_response = send_request(
        service.address,
        transaction_id=51,
        unit_id=12,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 199, 4),
    )

    _, _, _, open_pdu = parse_response(open_response)
    _, _, _, isolated_setpoint_pdu = parse_response(isolated_setpoint_response)
    _, _, _, isolated_status_pdu = parse_response(isolated_status_response)
    _, _, _, close_pdu = parse_response(close_response)
    _, _, _, restored_setpoint_pdu = parse_response(restored_setpoint_response)
    events = store.fetch_events()
    open_protocol_event = next(
        event
        for event in events
        if event.event_type == "protocol.modbus.single_register_write"
        and event.asset_id == "invb-02"
        and event.requested_value["register_start"] == 40203
        and event.requested_value["register_value"] == 1
    )
    open_process_event = next(
        event
        for event in events
        if event.event_type == "process.control.block_dc_disconnect_changed"
        and event.asset_id == "invb-02"
        and event.requested_value == "open"
    )

    assert unpack(">BHH", open_pdu) == (WRITE_SINGLE_REGISTER, 202, 1)
    assert unpack(">4H", isolated_setpoint_pdu[2:]) == (1, 1000, 0, 1)
    assert unpack(">13H", isolated_status_pdu[2:]) == (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1)
    assert unpack(">BHH", close_pdu) == (WRITE_SINGLE_REGISTER, 202, 0)
    assert unpack(">4H", restored_setpoint_pdu[2:]) == (1, 1000, 0, 0)
    assert open_protocol_event.previous_value == 0
    assert open_protocol_event.resulting_value == 1
    assert open_protocol_event.correlation_id == open_process_event.correlation_id
    assert open_process_event.protocol == "modbus-tcp"
    assert open_process_event.resulting_state["dc_disconnect_state"] == "open"
    assert open_process_event.resulting_state["block_power_kw"] == pytest.approx(0.0)


def test_unit_12_fc16_updates_block_limit_and_reset_clears_comm_loss(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    comm_loss_snapshot = PlantSimulator.from_snapshot(snapshot).lose_block_communications(snapshot, asset_id="invb-02")
    store = SQLiteEventStore(tmp_path / "tmp" / "inverter-control.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(comm_loss_snapshot.start_time))
    service = ReadOnlyModbusTcpService(
        register_map=ReadOnlyRegisterMap(comm_loss_snapshot, event_recorder=recorder),
        bind_host="127.0.0.1",
        port=0,
        event_recorder=recorder,
    ).start_in_thread()

    try:
        limit_response = send_request(
            service.address,
            transaction_id=47,
            unit_id=12,
            function_code=WRITE_MULTIPLE_REGISTERS,
            body=pack(">HHBH", 200, 1, 2, 500),
        )
        setpoint_response = send_request(
            service.address,
            transaction_id=48,
            unit_id=12,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 199, 3),
        )
        status_response = send_request(
            service.address,
            transaction_id=49,
            unit_id=12,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 99, 12),
        )
        reset_response = send_request(
            service.address,
            transaction_id=50,
            unit_id=12,
            function_code=WRITE_MULTIPLE_REGISTERS,
            body=pack(">HHBH", 201, 1, 2, 1),
        )
        alarm_response = send_request(
            service.address,
            transaction_id=51,
            unit_id=12,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 299, 6),
        )
    finally:
        service.stop()

    _, _, _, limit_pdu = parse_response(limit_response)
    _, _, _, setpoint_pdu = parse_response(setpoint_response)
    _, _, _, status_pdu = parse_response(status_response)
    _, _, _, reset_pdu = parse_response(reset_response)
    _, _, _, alarm_pdu = parse_response(alarm_response)
    events = store.fetch_events()
    alerts = store.fetch_alerts()
    protocol_limit_event = next(
        event
        for event in events
        if event.event_type == "protocol.modbus.multiple_register_write"
        and event.requested_value["register_start"] == 40201
    )
    process_limit_event = next(event for event in events if event.action == "set_block_power_limit")
    process_reset_event = next(event for event in events if event.action == "block_reset_request")
    cleared_alert = next(alert for alert in alerts if alert.alarm_code == "COMM_LOSS_INVERTER_BLOCK" and alert.state == "cleared")

    assert unpack(">BHH", limit_pdu) == (WRITE_MULTIPLE_REGISTERS, 200, 1)
    assert unpack(">3H", setpoint_pdu[2:]) == (1, 500, 0)
    assert unpack(">12H", status_pdu[2:]) == (2, 2, 2, 1000, 0, 960, 0, 0, 0, 0, 0, 1)
    assert unpack(">BHH", reset_pdu) == (WRITE_MULTIPLE_REGISTERS, 201, 1)
    assert unpack(">6H", alarm_pdu[2:]) == (0, 0, 0, 0, 0, 0)
    assert protocol_limit_event.correlation_id == process_limit_event.correlation_id
    assert process_reset_event.resulting_state["communication_state"] == "healthy"
    assert cleared_alert.asset_id == "invb-02"


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
    assert identity_registers[:4] == (124, 4307, 21, 1)
    assert decode_ascii_registers(identity_registers[4:8]) == "MET-A01"
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
    assert identity_registers[:4] == (124, 4419, 31, 1)
    assert decode_ascii_registers(identity_registers[4:8]) == "MTR-R01"
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
    assert identity_registers[:4] == (124, 4523, 41, 1)
    assert decode_ascii_registers(identity_registers[4:8]) == "GRD-T01"
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


def test_partial_modbus_header_times_out_without_blocking_service(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "tmp" / "partial-frame-timeout.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    service = ReadOnlyModbusTcpService(
        register_map=ReadOnlyRegisterMap(snapshot, event_recorder=recorder),
        bind_host="127.0.0.1",
        port=0,
        event_recorder=recorder,
        request_timeout_seconds=0.1,
    ).start_in_thread()

    try:
        with socket.create_connection(service.address, timeout=1) as connection:
            connection.settimeout(1)
            connection.sendall(b"\x12\x34")
            assert_connection_closed(connection)

        response = send_request(
            service.address,
            transaction_id=0x1235,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 1),
        )
    finally:
        service.stop()

    _, _, _, pdu = parse_response(response)
    assert pdu[0] == READ_HOLDING_REGISTERS


def test_modbus_per_source_limit_rejects_excess_without_blocking_valid_traffic(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "tmp" / "bounded-connections.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    service = ReadOnlyModbusTcpService(
        register_map=ReadOnlyRegisterMap(snapshot, event_recorder=recorder),
        bind_host="127.0.0.1",
        port=0,
        event_recorder=recorder,
        request_timeout_seconds=2.0,
        max_connections=3,
        max_connections_per_source=2,
    ).start_in_thread()
    held_connections: list[socket.socket] = []

    try:
        first_connection = socket.create_connection(service.address, timeout=1)
        first_connection.settimeout(1)
        first_connection.sendall(b"\x12")
        held_connections.append(first_connection)
        wait_for(lambda: service.active_connections == 1)

        response = send_request(
            service.address,
            transaction_id=0x1236,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 1),
        )
        _, _, _, pdu = parse_response(response)
        assert pdu[0] == READ_HOLDING_REGISTERS

        second_connection = socket.create_connection(service.address, timeout=1)
        second_connection.settimeout(1)
        second_connection.sendall(b"\x34")
        held_connections.append(second_connection)
        wait_for(lambda: service.active_connections == 2)

        per_source_excess = socket.create_connection(
            service.address,
            timeout=1,
            source_address=("127.0.0.1", 0),
        )
        per_source_excess.settimeout(1)
        try:
            assert_connection_closed(per_source_excess)
        finally:
            per_source_excess.close()
        wait_for(lambda: service.rejected_connections == 1)

        assert service.active_connections == 2
        assert service.active_connections_by_source == {"127.0.0.1": 2}
    finally:
        for connection in held_connections:
            connection.close()
        service.stop()


def test_modbus_global_connection_limit_rejects_excess(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    service = ReadOnlyModbusTcpService(
        register_map=ReadOnlyRegisterMap(snapshot),
        bind_host="127.0.0.1",
        port=0,
        request_timeout_seconds=2.0,
        max_connections=2,
        max_connections_per_source=3,
    ).start_in_thread()
    held_connections: list[socket.socket] = []

    try:
        for partial_header in (b"\x12", b"\x34"):
            connection = socket.create_connection(service.address, timeout=1)
            connection.settimeout(1)
            connection.sendall(partial_header)
            held_connections.append(connection)
        wait_for(lambda: service.active_connections == 2)

        excess = socket.create_connection(service.address, timeout=1)
        excess.settimeout(1)
        try:
            assert_connection_closed(excess)
        finally:
            excess.close()

        wait_for(lambda: service.rejected_connections == 1)
        assert service.active_connections == 2
    finally:
        for connection in held_connections:
            connection.close()
        service.stop()


def test_default_modbus_limit_caps_original_64_partial_connection_poc(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    service = ReadOnlyModbusTcpService(
        register_map=ReadOnlyRegisterMap(snapshot),
        bind_host="127.0.0.1",
        port=0,
        request_timeout_seconds=5.0,
    ).start_in_thread()
    held_connections: list[socket.socket] = []

    try:
        for attempt in range(64):
            connection = socket.create_connection(service.address, timeout=1)
            connection.settimeout(1)
            connection.sendall(b"\x12")
            if attempt < service.max_connections_per_source:
                held_connections.append(connection)
            else:
                assert_connection_closed(connection)
                connection.close()

        wait_for(lambda: service.rejected_connections == 56)
        assert service.active_connections == service.max_connections_per_source == 8

        held_connections.pop().close()
        wait_for(lambda: service.active_connections == 7)
        response = send_request(
            service.address,
            transaction_id=0x1237,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 1),
        )
        _, _, _, pdu = parse_response(response)
        assert pdu[0] == READ_HOLDING_REGISTERS
    finally:
        for connection in held_connections:
            connection.close()
        service.stop()


@pytest.mark.parametrize("length", (0, 1, 255, 65535))
def test_modbus_rejects_mbap_lengths_outside_supported_adu_range(running_service, length: int) -> None:
    service, _ = running_service

    with socket.create_connection(service.address, timeout=1) as connection:
        connection.settimeout(1)
        connection.sendall(pack(">HHHB", 0x2233, 0, length, 1))
        assert_connection_closed(connection)


def test_modbus_accepts_maximum_supported_mbap_length_before_rejecting_function(running_service) -> None:
    service, _ = running_service
    pdu = bytes([0x7F]) + bytes(252)

    with socket.create_connection(service.address, timeout=1) as connection:
        connection.sendall(pack(">HHHB", 0x2234, 0, 254, 1) + pdu)
        response_header = recv_exact(connection, 7)
        _, _, response_length, _ = unpack(">HHHB", response_header)
        response_pdu = recv_exact(connection, response_length - 1)

    assert response_pdu == bytes([0xFF, ILLEGAL_FUNCTION])


def test_modbus_proxy_protocol_preserves_source_attribution(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "tmp" / "proxy-source.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    service = ReadOnlyModbusTcpService(
        register_map=ReadOnlyRegisterMap(snapshot, event_recorder=recorder),
        bind_host="127.0.0.1",
        port=0,
        event_recorder=recorder,
        proxy_protocol_enabled=True,
    ).start_in_thread()
    pdu = bytes([READ_HOLDING_REGISTERS]) + pack(">HH", 0, 1)
    adu = pack(">HHHB", 0x3344, 0, len(pdu) + 1, 1) + pdu

    try:
        with socket.create_connection(service.address, timeout=1) as connection:
            connection.sendall(b"PROXY TCP4 203.0.113.42 192.0.2.10 51000 1502\r")
            connection.sendall(b"\n" + adu)
            response_header = recv_exact(connection, 7)
            _, _, response_length, _ = unpack(">HHHB", response_header)
            response_pdu = recv_exact(connection, response_length - 1)
    finally:
        service.stop()

    events = store.fetch_events()
    assert response_pdu[0] == READ_HOLDING_REGISTERS
    assert events[-1].source_ip == "203.0.113.42"


@pytest.mark.parametrize(
    "proxy_header",
    (
        b"",
        b"PROXY UNKNOWN\r\n",
        b"PROXY TCP4 999.0.0.1 192.0.2.10 51000 1502\r\n",
        b"PROXY TCP6 203.0.113.42 192.0.2.10 51000 1502\r\n",
        b"PROXY TCP4 203.0.113.42 192.0.2.10 051000 1502\r\n",
    ),
)
def test_modbus_proxy_protocol_rejects_missing_or_invalid_metadata(tmp_path: Path, proxy_header: bytes) -> None:
    snapshot = build_snapshot()
    service = ReadOnlyModbusTcpService(
        register_map=ReadOnlyRegisterMap(snapshot),
        bind_host="127.0.0.1",
        port=0,
        request_timeout_seconds=0.1,
        proxy_protocol_enabled=True,
    ).start_in_thread()
    pdu = bytes([READ_HOLDING_REGISTERS]) + pack(">HH", 0, 1)
    adu = pack(">HHHB", 0x3345, 0, len(pdu) + 1, 1) + pdu

    try:
        with socket.create_connection(service.address, timeout=1) as connection:
            connection.settimeout(1)
            connection.sendall(proxy_header + adu)
            assert_connection_closed(connection)
    finally:
        service.stop()


def test_modbus_proxy_protocol_rejects_header_over_107_bytes(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    service = ReadOnlyModbusTcpService(
        register_map=ReadOnlyRegisterMap(snapshot),
        bind_host="127.0.0.1",
        port=0,
        proxy_protocol_enabled=True,
    ).start_in_thread()

    try:
        with socket.create_connection(service.address, timeout=1) as connection:
            connection.settimeout(1)
            connection.sendall(b"PROXY " + (b"A" * 102) + b"\r\n")
            assert_connection_closed(connection)
    finally:
        service.stop()


def test_modbus_proxy_protocol_does_not_accept_nested_source_spoofing(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "tmp" / "proxy-spoof.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    service = ReadOnlyModbusTcpService(
        register_map=ReadOnlyRegisterMap(snapshot, event_recorder=recorder),
        bind_host="127.0.0.1",
        port=0,
        event_recorder=recorder,
        proxy_protocol_enabled=True,
    ).start_in_thread()
    outer_proxy = b"PROXY TCP4 203.0.113.42 192.0.2.10 51000 1502\r\n"
    forged_inner_proxy = b"PROXY TCP4 198.51.100.77 192.0.2.10 52000 1502\r\n"

    try:
        with socket.create_connection(service.address, timeout=1) as connection:
            connection.settimeout(1)
            connection.sendall(outer_proxy + forged_inner_proxy)
            assert_connection_closed(connection)
    finally:
        service.stop()

    assert store.fetch_events() == ()


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


def assert_connection_closed(connection: socket.socket) -> None:
    try:
        assert connection.recv(1) == b""
    except ConnectionResetError:
        return


def wait_for(predicate, *, timeout: float = 1.0) -> None:
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        if predicate():
            return
        sleep(0.01)
    raise AssertionError("Bedingung wurde nicht rechtzeitig erfuellt")


def decode_ascii_registers(registers: tuple[int, ...]) -> str:
    raw = b"".join(pack(">H", value) for value in registers)
    return raw.decode("ascii").strip()
