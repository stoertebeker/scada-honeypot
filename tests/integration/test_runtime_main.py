from __future__ import annotations

import socket
from pathlib import Path
from struct import pack, unpack

from honeypot.main import build_local_runtime
from honeypot.protocol_modbus import READ_HOLDING_REGISTERS


def test_build_local_runtime_starts_local_modbus_listener_and_serves_fixture(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-01",
                f"EVENT_STORE_PATH={event_store_path}",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0)
    try:
        runtime.start()
        host, port = runtime.modbus_service.address
        response = send_request(
            (host, port),
            transaction_id=0x4321,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 8),
        )
    finally:
        runtime.stop()

    transaction_id, protocol_id, unit_id, pdu = parse_response(response)
    byte_count = pdu[1]
    registers = unpack(f">{byte_count // 2}H", pdu[2:])
    events = runtime.event_store.fetch_events()

    assert runtime.config.site_code == "runtime-test-01"
    assert runtime.snapshot.fixture_name == "normal_operation"
    assert transaction_id == 0x4321
    assert protocol_id == 0
    assert unit_id == 1
    assert registers == (100, 1001, 1, 0, 28784, 25389, 12337, 8224)
    assert len(events) == 1
    assert events[0].event_type == "protocol.modbus.holding_registers_read"
    assert events[0].requested_value["register_start"] == 40001


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
