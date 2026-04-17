from __future__ import annotations

import socket
from pathlib import Path
from struct import pack, unpack
from time import monotonic, sleep

import httpx

from honeypot.exporter_runner import SmtpExporter, TelegramExporter
from honeypot.hmi_web.app import SERVICE_LOGIN_PASSWORD, SERVICE_LOGIN_USERNAME
from honeypot.main import build_local_runtime
from honeypot.protocol_modbus import READ_HOLDING_REGISTERS


def test_build_local_runtime_starts_local_services_and_serves_shared_truth(tmp_path: Path) -> None:
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

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    modbus_address: tuple[str, int] | None = None
    hmi_address: tuple[str, int] | None = None
    try:
        runtime.start()
        modbus_address = runtime.modbus_service.address
        hmi_address = runtime.hmi_service.address
        response = send_request(
            modbus_address,
            transaction_id=0x4321,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 8),
        )
        overview_response = httpx.get(
            f"http://{hmi_address[0]}:{hmi_address[1]}/overview",
            timeout=5.0,
            trust_env=False,
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
    assert overview_response.status_code == 200
    assert "Plant Overview" in overview_response.text
    assert "5.80 MW" in overview_response.text
    assert len(events) == 2
    assert events[0].event_type == "protocol.modbus.holding_registers_read"
    assert events[0].requested_value["register_start"] == 40001
    assert events[1].event_type == "hmi.page.overview_viewed"
    assert events[1].service == "web-hmi"
    assert events[1].endpoint_or_register == "/overview"
    assert events[1].requested_value == {"http_method": "GET", "http_path": "/overview"}
    assert events[1].resulting_value == {"http_status": 200}
    assert events[1].session_id is not None
    assert modbus_address is not None
    assert hmi_address is not None
    assert_port_closed(modbus_address)
    assert_port_closed(hmi_address)


def test_build_local_runtime_serves_service_control_writes_on_local_hmi(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-02",
                f"EVENT_STORE_PATH={event_store_path}",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    hmi_address: tuple[str, int] | None = None
    try:
        runtime.start()
        hmi_address = runtime.hmi_service.address
        with httpx.Client(
            base_url=f"http://{hmi_address[0]}:{hmi_address[1]}",
            timeout=5.0,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            login_response = client.post(
                "/service/login",
                data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            )
            limit_response = client.post(
                "/service/panel/power-limit",
                data={"active_power_limit_pct": "55.5"},
            )
            limit_panel_response = client.get(limit_response.headers["location"])
            reactive_response = client.post(
                "/service/panel/reactive-power",
                data={"reactive_power_target_pct": "25.0"},
            )
            reactive_panel_response = client.get(reactive_response.headers["location"])
            plant_mode_response = client.post(
                "/service/panel/plant-mode",
                data={"plant_mode_request": "2"},
            )
            plant_mode_panel_response = client.get(plant_mode_response.headers["location"])
            block_response = client.post(
                "/service/panel/inverter-block",
                data={
                    "asset_id": "invb-02",
                    "block_enable_request": "0",
                    "block_power_limit_pct": "65.5",
                },
            )
            block_panel_response = client.get(block_response.headers["location"])
            breaker_response = client.post(
                "/service/panel/breaker",
                data={"breaker_action": "open"},
            )
            breaker_panel_response = client.get(breaker_response.headers["location"])
        events = runtime.event_store.fetch_events()
    finally:
        runtime.stop()

    control_events = [event for event in events if event.event_type == "hmi.action.service_control_submitted"]
    process_events = [
        event
        for event in events
        if event.event_type
        in {
            "process.setpoint.curtailment_changed",
            "process.setpoint.reactive_power_target_changed",
            "process.setpoint.plant_mode_request_changed",
            "process.setpoint.block_enable_request_changed",
            "process.setpoint.block_power_limit_changed",
            "process.breaker.state_changed",
        }
    ]

    assert login_response.status_code == 303
    assert limit_response.status_code == 303
    assert limit_panel_response.status_code == 200
    assert "Active power limit updated successfully." in limit_panel_response.text
    assert "55.5 %" in limit_panel_response.text
    assert reactive_response.status_code == 303
    assert reactive_panel_response.status_code == 200
    assert "Reactive power target updated successfully." in reactive_panel_response.text
    assert plant_mode_response.status_code == 303
    assert plant_mode_panel_response.status_code == 200
    assert "Plant mode request updated successfully." in plant_mode_panel_response.text
    assert block_response.status_code == 303
    assert block_panel_response.status_code == 200
    assert "Inverter block control updated successfully." in block_panel_response.text
    assert breaker_response.status_code == 303
    assert breaker_panel_response.status_code == 200
    assert "Breaker open request accepted." in breaker_panel_response.text
    assert runtime.modbus_service.register_map.snapshot.site.plant_power_mw == 0.0
    assert runtime.modbus_service.register_map.snapshot.site.reactive_power_setpoint == 0.25
    assert runtime.modbus_service.register_map.read_holding_registers(unit_id=1, start_offset=201, quantity=1).values == (2,)
    assert runtime.modbus_service.register_map.read_holding_registers(unit_id=12, start_offset=199, quantity=2).values == (0, 655)
    assert runtime.modbus_service.register_map.snapshot.grid_interconnect.breaker_state == "open"
    assert len(control_events) == 5
    assert len(process_events) == 6
    assert hmi_address is not None
    assert_port_closed(hmi_address)


def test_build_local_runtime_drains_webhook_outbox_in_background(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-03",
                f"EVENT_STORE_PATH={event_store_path}",
                "WEBHOOK_EXPORTER_ENABLED=1",
                "WEBHOOK_EXPORTER_URL=https://example.invalid/hook",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    assert runtime.outbox_runner is not None
    assert runtime.outbox_runner_service is not None
    runtime.outbox_runner_service.drain_interval_seconds = 0.05
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["json"] = request.content.decode("utf-8")
        return httpx.Response(202, json={"accepted": True})

    runtime.outbox_runner.exporters["webhook"] = runtime.outbox_runner.exporters["webhook"].__class__(
        url="https://example.invalid/hook",
        transport=httpx.MockTransport(handler),
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
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and outbox_entries[0].status == "delivered":
                break
            sleep(0.05)
    finally:
        runtime.stop()

    outbox_entries = runtime.event_store.fetch_outbox_entries()

    assert outbox_entries[0].status == "delivered"
    assert runtime.outbox_runner_service.drain_count >= 1
    assert "BREAKER_OPEN" in captured["json"]


def test_build_local_runtime_drains_telegram_outbox_in_background(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-04",
                f"EVENT_STORE_PATH={event_store_path}",
                "TELEGRAM_EXPORTER_ENABLED=1",
                "TELEGRAM_BOT_TOKEN=token-123",
                "TELEGRAM_CHAT_ID=chat-99",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    assert runtime.outbox_runner is not None
    assert runtime.outbox_runner_service is not None
    runtime.outbox_runner_service.drain_interval_seconds = 0.05
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["json"] = request.content.decode("utf-8")
        return httpx.Response(200, json={"ok": True})

    runtime.outbox_runner.exporters["telegram"] = TelegramExporter(
        bot_token="token-123",
        chat_id="chat-99",
        transport=httpx.MockTransport(handler),
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
    runtime.event_recorder.record(event, alert=alert, outbox_targets=("telegram",))

    try:
        runtime.start()
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and outbox_entries[0].status == "delivered":
                break
            sleep(0.05)
    finally:
        runtime.stop()

    outbox_entries = runtime.event_store.fetch_outbox_entries()

    assert outbox_entries[0].status == "delivered"
    assert runtime.outbox_runner_service.drain_count >= 1
    assert captured["path"] == "/bottoken-123/sendMessage"
    assert "BREAKER_OPEN" in captured["json"]


def test_build_local_runtime_drains_smtp_outbox_in_background(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-05",
                f"EVENT_STORE_PATH={event_store_path}",
                "SMTP_EXPORTER_ENABLED=1",
                "SMTP_HOST=mail.example.invalid",
                "SMTP_PORT=2525",
                "SMTP_FROM=alerts@example.invalid",
                "SMTP_TO=soc@example.invalid",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    assert runtime.outbox_runner is not None
    assert runtime.outbox_runner_service is not None
    runtime.outbox_runner_service.drain_interval_seconds = 0.05
    captured = {}

    class FakeSmtpClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            del exc_type, exc, tb

        def send_message(self, message):
            captured["from"] = message["From"]
            captured["to"] = message["To"]
            captured["subject"] = message["Subject"]
            captured["body"] = message.get_content()
            return {}

    runtime.outbox_runner.exporters["smtp"] = SmtpExporter(
        host="mail.example.invalid",
        port=2525,
        mail_from="alerts@example.invalid",
        rcpt_to="soc@example.invalid",
        client_factory=lambda host, port, timeout: FakeSmtpClient(),
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
    runtime.event_recorder.record(event, alert=alert, outbox_targets=("smtp",))

    try:
        runtime.start()
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and outbox_entries[0].status == "delivered":
                break
            sleep(0.05)
    finally:
        runtime.stop()

    outbox_entries = runtime.event_store.fetch_outbox_entries()

    assert outbox_entries[0].status == "delivered"
    assert runtime.outbox_runner_service.drain_count >= 1
    assert captured["from"] == "alerts@example.invalid"
    assert captured["to"] == "soc@example.invalid"
    assert "BREAKER_OPEN" in captured["body"]


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


def assert_port_closed(address: tuple[str, int]) -> None:
    try:
        with socket.create_connection(address, timeout=0.5):
            raise AssertionError(f"Port {address[0]}:{address[1]} ist nach runtime.stop() noch offen")
    except OSError:
        return
