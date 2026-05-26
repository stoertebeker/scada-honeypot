from __future__ import annotations

import socket
from pathlib import Path
from struct import pack, unpack

import pytest

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.event_core import EventRecorder
from honeypot.protocol_modbus import (
    ILLEGAL_DATA_ADDRESS,
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
    store = SQLiteEventStore(tmp_path / "tmp" / "fingerprint-events.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    service = ReadOnlyModbusTcpService(
        register_map=ReadOnlyRegisterMap(snapshot, event_recorder=recorder),
        bind_host="127.0.0.1",
        port=0,
        event_recorder=recorder,
    ).start_in_thread()
    yield service, store
    service.stop()


def test_modbus_function_code_matrix_is_intentional(running_service) -> None:
    service, store = running_service

    fc03_response = send_request(
        service.address,
        transaction_id=1,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 0, 4),
    )
    fc06_response = send_request(
        service.address,
        transaction_id=2,
        unit_id=1,
        function_code=WRITE_SINGLE_REGISTER,
        body=pack(">HH", 199, 900),
    )
    fc16_response = send_request(
        service.address,
        transaction_id=3,
        unit_id=1,
        function_code=WRITE_MULTIPLE_REGISTERS,
        body=fc16_body(200, 100),
    )
    fc04_response = send_request(
        service.address,
        transaction_id=4,
        unit_id=1,
        function_code=READ_INPUT_REGISTERS,
        body=pack(">HH", 0, 1),
    )
    unsupported_response = send_request(
        service.address,
        transaction_id=5,
        unit_id=1,
        function_code=0x2B,
        body=b"\x0e",
    )

    _, _, _, fc03_pdu = parse_response(fc03_response)
    _, _, _, fc06_pdu = parse_response(fc06_response)
    _, _, _, fc16_pdu = parse_response(fc16_response)
    _, _, _, fc04_pdu = parse_response(fc04_response)
    _, _, _, unsupported_pdu = parse_response(unsupported_response)
    rejected_events = [
        event
        for event in store.fetch_events()
        if event.event_type == "protocol.modbus.request_rejected"
    ]

    assert fc03_pdu[0] == READ_HOLDING_REGISTERS
    assert unpack(">BHH", fc06_pdu) == (WRITE_SINGLE_REGISTER, 199, 900)
    assert unpack(">BHH", fc16_pdu) == (WRITE_MULTIPLE_REGISTERS, 200, 1)
    assert fc04_pdu == bytes([READ_INPUT_REGISTERS | 0x80, ILLEGAL_FUNCTION])
    assert unsupported_pdu == bytes([0x2B | 0x80, ILLEGAL_FUNCTION])
    assert [event.requested_value["function_code"] for event in rejected_events] == [READ_INPUT_REGISTERS, 0x2B]


def test_identity_blocks_are_consistent_across_units(running_service) -> None:
    service, _ = running_service
    expected_identity = {
        1: (100, 1001, 1, 0, "ppc-01"),
        11: (100, 1101, 11, 1, "invb-01"),
        12: (100, 1101, 12, 2, "invb-02"),
        13: (100, 1101, 13, 3, "invb-03"),
        21: (100, 1201, 21, 0, "wx-01"),
        31: (100, 1301, 31, 0, "meter-01"),
        41: (100, 1401, 41, 0, "grid-01"),
    }

    observed_tags: set[str] = set()
    for transaction_id, (unit_id, expected) in enumerate(expected_identity.items(), start=10):
        response = send_request(
            service.address,
            transaction_id=transaction_id,
            unit_id=unit_id,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 8),
        )
        _, _, response_unit, pdu = parse_response(response)
        registers = unpack(">8H", pdu[2:])
        profile_version, device_class, identity_unit, instance, tag = expected

        assert response_unit == unit_id
        assert pdu[0] == READ_HOLDING_REGISTERS
        assert registers[:4] == (profile_version, device_class, identity_unit, instance)
        assert decode_ascii_registers(registers[4:]) == tag
        assert tag not in observed_tags
        observed_tags.add(tag)


def test_write_readback_has_visible_process_effect_and_event_trail(running_service) -> None:
    service, store = running_service

    write_response = send_request(
        service.address,
        transaction_id=30,
        unit_id=1,
        function_code=WRITE_SINGLE_REGISTER,
        body=pack(">HH", 199, 555),
    )
    setpoint_response = send_request(
        service.address,
        transaction_id=31,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 199, 1),
    )
    power_response = send_request(
        service.address,
        transaction_id=32,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 103, 2),
    )

    _, _, _, write_pdu = parse_response(write_response)
    _, _, _, setpoint_pdu = parse_response(setpoint_response)
    _, _, _, power_pdu = parse_response(power_response)
    events = store.fetch_events()
    site_state = store.fetch_current_state("site")
    protocol_event = next(event for event in events if event.event_type == "protocol.modbus.single_register_write")
    process_event = next(event for event in events if event.event_type == "process.setpoint.curtailment_changed")

    assert unpack(">BHH", write_pdu) == (WRITE_SINGLE_REGISTER, 199, 555)
    assert unpack(">H", setpoint_pdu[2:])[0] == 555
    assert unpack(">2H", power_pdu[2:]) == (0, 3219)
    assert service.register_map.snapshot.power_plant_controller.active_power_limit_pct == pytest.approx(55.5)
    assert service.register_map.snapshot.site.plant_power_mw == pytest.approx(3.219)
    assert site_state["plant_power_limit_pct"] == pytest.approx(55.5)
    assert protocol_event.correlation_id == process_event.correlation_id
    assert process_event.resulting_state["plant_power_mw"] == pytest.approx(3.219)


def test_unknown_registers_and_units_are_quiet_modbus_exceptions(running_service) -> None:
    service, store = running_service

    unknown_unit_response = send_request(
        service.address,
        transaction_id=40,
        unit_id=99,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 0, 1),
    )
    gap_response = send_request(
        service.address,
        transaction_id=41,
        unit_id=1,
        function_code=READ_HOLDING_REGISTERS,
        body=pack(">HH", 49, 1),
    )

    _, _, unknown_response_unit, unknown_pdu = parse_response(unknown_unit_response)
    _, _, gap_response_unit, gap_pdu = parse_response(gap_response)
    rejected_events = [event for event in store.fetch_events() if event.result == "rejected"]

    assert unknown_response_unit == 99
    assert unknown_pdu == bytes([READ_HOLDING_REGISTERS | 0x80, ILLEGAL_DATA_ADDRESS])
    assert gap_response_unit == 1
    assert gap_pdu == bytes([READ_HOLDING_REGISTERS | 0x80, ILLEGAL_DATA_ADDRESS])
    assert [(event.asset_id, event.error_code) for event in rejected_events] == [
        ("unit-99", "modbus_exception_02"),
        ("ppc-01", "modbus_exception_02"),
    ]
    assert all(event.severity == "low" for event in rejected_events)


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
    return pack(">HHB", start_offset, len(values), len(values) * 2) + b"".join(
        pack(">H", value) for value in values
    )


def parse_response(response: bytes) -> tuple[int, int, int, bytes]:
    transaction_id, protocol_id, length, unit_id = unpack(">HHHB", response[:7])
    assert protocol_id == 0
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


def decode_ascii_registers(registers: tuple[int, ...]) -> str:
    raw = b"".join(pack(">H", value) for value in registers)
    return raw.decode("ascii").strip()
