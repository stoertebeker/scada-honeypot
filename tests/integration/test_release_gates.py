from __future__ import annotations

import socket
from pathlib import Path
from struct import pack, unpack

import httpx

from honeypot.exporter_runner import WebhookExporter
from honeypot.main import build_local_runtime
from honeypot.protocol_modbus import READ_HOLDING_REGISTERS


def write_env(tmp_path: Path, *lines: str) -> Path:
    env_file = tmp_path / ".env"
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return env_file


def send_modbus_request(
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


def recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("Socket geschlossen, bevor die Antwort komplett war")
        chunks.extend(chunk)
    return bytes(chunks)


def test_release_gate_http_headers_and_error_pages_are_quiet(tmp_path: Path) -> None:
    env_file = write_env(
        tmp_path,
        f"EVENT_STORE_PATH={tmp_path / 'events' / 'honeypot.db'}",
    )
    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    try:
        runtime.start()
        hmi_address = runtime.hmi_service.address
        with httpx.Client(
            base_url=f"http://{hmi_address[0]}:{hmi_address[1]}",
            timeout=5.0,
            trust_env=False,
        ) as client:
            overview = client.get("/overview")
            unauthorized = client.get("/service/panel")
            missing = client.get("/not-present")
    finally:
        runtime.stop()

    for response in (overview, unauthorized, missing):
        header_names = {name.lower() for name in response.headers}
        assert "server" not in header_names
        assert "date" not in header_names
        assert "fastapi" not in response.text
        assert "starlette" not in response.text
        assert "traceback" not in response.text.lower()

    assert overview.status_code == 200
    assert unauthorized.status_code == 401
    assert "Authentication Required" in unauthorized.text
    assert missing.status_code == 404
    assert "Page Unavailable" in missing.text


def test_release_gate_disabled_service_login_returns_quiet_403(tmp_path: Path) -> None:
    env_file = write_env(
        tmp_path,
        "ENABLE_SERVICE_LOGIN=0",
        f"EVENT_STORE_PATH={tmp_path / 'events' / 'honeypot.db'}",
    )
    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    try:
        runtime.start()
        hmi_address = runtime.hmi_service.address
        response = httpx.get(
            f"http://{hmi_address[0]}:{hmi_address[1]}/service/login",
            timeout=5.0,
            trust_env=False,
        )
    finally:
        runtime.stop()

    header_names = {name.lower() for name in response.headers}
    assert response.status_code == 403
    assert "server" not in header_names
    assert "date" not in header_names
    assert "Access Denied" in response.text
    assert "FastAPI" not in response.text


def test_release_gate_exporter_failure_stays_internal_and_clients_remain_stable(tmp_path: Path) -> None:
    env_file = write_env(
        tmp_path,
        "WEBHOOK_EXPORTER_ENABLED=1",
        "WEBHOOK_EXPORTER_URL=https://example.invalid/hook",
        "OUTBOX_RETRY_BACKOFF_SECONDS=45",
        f"EVENT_STORE_PATH={tmp_path / 'events' / 'honeypot.db'}",
    )
    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    assert runtime.outbox_runner is not None

    def failing_handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(503, json={"accepted": False})

    runtime.outbox_runner.exporters["webhook"] = WebhookExporter(
        url="https://example.invalid/hook",
        retry_after_seconds=45,
        transport=httpx.MockTransport(failing_handler),
    )

    event = runtime.event_recorder.build_event(
        event_type="process.breaker.state_changed",
        category="process",
        severity="high",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="grid-01",
        action="breaker_open_request",
        result="accepted",
        alarm_code="BREAKER_OPEN",
        resulting_value="open",
        tags=("control-path", "grid", "breaker"),
    )
    alert = runtime.event_recorder.build_alert(
        event=event,
        alarm_code="BREAKER_OPEN",
        severity="high",
        state="active_unacknowledged",
        message="Breaker open erkannt",
    )
    runtime.event_recorder.record(event, alert=alert, outbox_targets=("webhook",))

    try:
        runtime.start()
        hmi_address = runtime.hmi_service.address
        modbus_address = runtime.modbus_service.address
        drain_result = runtime.outbox_runner.drain_once()
        overview = httpx.get(
            f"http://{hmi_address[0]}:{hmi_address[1]}/overview",
            timeout=5.0,
            trust_env=False,
        )
        modbus_response = send_modbus_request(
            modbus_address,
            transaction_id=0x5544,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 8),
        )
    finally:
        runtime.stop()

    outbox_entries = runtime.event_store.fetch_outbox_entries()
    transaction_id, protocol_id, _, _ = unpack(">HHHB", modbus_response[:7])

    assert drain_result.retried_count == 1
    assert outbox_entries[0].status == "pending"
    assert outbox_entries[0].retry_count == 1
    assert outbox_entries[0].last_error == "Webhook antwortete mit HTTP 503"
    assert overview.status_code == 200
    assert "Plant Overview" in overview.text
    assert "Webhook" not in overview.text
    assert transaction_id == 0x5544
    assert protocol_id == 0
