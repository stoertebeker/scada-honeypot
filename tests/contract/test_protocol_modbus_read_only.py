from __future__ import annotations

import socket
from pathlib import Path
from struct import pack, unpack

import pytest

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.event_core import EventRecorder
from honeypot.protocol_modbus import (
    ILLEGAL_DATA_ADDRESS,
    ILLEGAL_DATA_VALUE,
    ILLEGAL_FUNCTION,
    READ_HOLDING_REGISTERS,
    READ_INPUT_REGISTERS,
    ReadOnlyModbusTcpService,
    ReadOnlyRegisterMap,
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
