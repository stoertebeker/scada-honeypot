from __future__ import annotations

import socket
from collections.abc import Callable
from pathlib import Path
from struct import pack, unpack

import pytest

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.event_core import EventRecorder
from honeypot.protocol_modbus import (
    READ_HOLDING_REGISTERS,
    ReadOnlyModbusTcpService,
    ReadOnlyRegisterMap,
)
from honeypot.storage import SQLiteEventStore
from honeypot.time_core import FrozenClock


def build_snapshot() -> PlantSnapshot:
    return PlantSnapshot.from_fixture(load_plant_fixture("normal_operation"))


def test_default_modbus_timing_profile_does_not_delay_responses(tmp_path: Path) -> None:
    delays: list[float] = []
    service = build_service(tmp_path, response_delay=delays.append).start_in_thread()
    try:
        response = send_request(
            service.address,
            transaction_id=1,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 1),
        )
    finally:
        service.stop()

    _, _, _, pdu = parse_response(response)
    assert pdu[0] == READ_HOLDING_REGISTERS
    assert delays == []


def test_modbus_timing_profile_applies_bounded_deterministic_delay(tmp_path: Path) -> None:
    delays: list[float] = []
    service = build_service(
        tmp_path,
        response_delay_min_ms=12,
        response_delay_max_ms=18,
        response_delay=delays.append,
    ).start_in_thread()
    try:
        first_response = send_request(
            service.address,
            transaction_id=7,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 1),
        )
        second_response = send_request(
            service.address,
            transaction_id=8,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 1),
        )
    finally:
        service.stop()

    _, _, _, first_pdu = parse_response(first_response)
    _, _, _, second_pdu = parse_response(second_response)
    assert first_pdu[0] == READ_HOLDING_REGISTERS
    assert second_pdu[0] == READ_HOLDING_REGISTERS
    assert len(delays) == 2
    assert all(0.012 <= delay <= 0.018 for delay in delays)
    assert delays == [pytest.approx(0.012), pytest.approx(0.015)]


def test_fixed_modbus_timing_profile_applies_exact_delay_to_exception_response(tmp_path: Path) -> None:
    delays: list[float] = []
    service = build_service(
        tmp_path,
        response_delay_min_ms=25,
        response_delay_max_ms=25,
        response_delay=delays.append,
    ).start_in_thread()
    try:
        response = send_request(
            service.address,
            transaction_id=3,
            unit_id=1,
            function_code=0x2B,
            body=b"\x0e",
        )
    finally:
        service.stop()

    _, _, _, pdu = parse_response(response)
    assert pdu == bytes([0x2B | 0x80, 1])
    assert delays == [pytest.approx(0.025)]


def build_service(
    tmp_path: Path,
    *,
    response_delay_min_ms: int = 0,
    response_delay_max_ms: int = 0,
    response_delay: Callable[[float], None],
) -> ReadOnlyModbusTcpService:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "tmp" / "timing-events.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    return ReadOnlyModbusTcpService(
        register_map=ReadOnlyRegisterMap(snapshot, event_recorder=recorder),
        bind_host="127.0.0.1",
        port=0,
        event_recorder=recorder,
        response_delay_min_ms=response_delay_min_ms,
        response_delay_max_ms=response_delay_max_ms,
        response_delay=response_delay,
    )


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
