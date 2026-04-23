from __future__ import annotations

import socket
from pathlib import Path
from struct import pack, unpack
from time import monotonic, sleep

import httpx

from honeypot.exporter_runner import SmtpExporter, TelegramExporter
from honeypot.hmi_web.app import SERVICE_LOGIN_PASSWORD, SERVICE_LOGIN_USERNAME
from honeypot.main import build_local_runtime, cli
from honeypot.protocol_modbus import READ_HOLDING_REGISTERS
from honeypot.rule_engine import (
    GRID_PATH_UNAVAILABLE_ALERT_CODE,
    LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE,
    MULTI_BLOCK_UNAVAILABLE_ALERT_CODE,
)


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


def test_cli_reset_runtime_clears_local_artifacts_and_supports_clean_restart(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    archive_path = tmp_path / "logs" / "events.jsonl"
    status_path = tmp_path / "logs" / "runtime-status.json"
    pcap_path = tmp_path / "pcap" / "session.pcapng"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-reset-01",
                f"EVENT_STORE_PATH={event_store_path}",
                "JSONL_ARCHIVE_ENABLED=1",
                f"JSONL_ARCHIVE_PATH={archive_path}",
                "RUNTIME_STATUS_ENABLED=1",
                f"RUNTIME_STATUS_PATH={status_path}",
                f"PCAP_CAPTURE_PATH={pcap_path}",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
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

    runtime.start()
    try:
        runtime.event_recorder.record(event, alert=alert, outbox_targets=("webhook",))
        wait_for(lambda: status_path.is_file())
        pcap_path.parent.mkdir(parents=True, exist_ok=True)
        pcap_path.write_bytes(b"pcap")
        wal_path = Path(f"{event_store_path}-wal")
        shm_path = Path(f"{event_store_path}-shm")
        wal_path.write_bytes(b"wal")
        shm_path.write_bytes(b"shm")
    finally:
        runtime.stop()

    assert event_store_path.exists()
    assert archive_path.exists()
    assert status_path.exists()
    assert pcap_path.exists()
    assert Path(f"{event_store_path}-wal").exists()
    assert Path(f"{event_store_path}-shm").exists()

    assert cli(["--env-file", str(env_file), "--reset-runtime"]) == 0

    assert event_store_path.exists() is False
    assert archive_path.exists() is False
    assert status_path.exists() is False
    assert pcap_path.exists() is False
    assert Path(f"{event_store_path}-wal").exists() is False
    assert Path(f"{event_store_path}-shm").exists() is False

    fresh_runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    try:
        fresh_runtime.start()
        overview_response = httpx.get(
            f"http://{fresh_runtime.hmi_service.address[0]}:{fresh_runtime.hmi_service.address[1]}/overview",
            timeout=5.0,
            trust_env=False,
        )
    finally:
        fresh_runtime.stop()

    assert fresh_runtime.snapshot.fixture_name == "normal_operation"
    assert fresh_runtime.event_store.count_rows("event_log") == 1
    assert fresh_runtime.event_store.count_rows("alert_log") == 0
    assert fresh_runtime.event_store.count_rows("outbox") == 0
    assert overview_response.status_code == 200


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


def test_build_local_runtime_drains_telegram_multi_block_follow_up_in_background(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-12",
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
    captured_payloads: list[str] = []
    captured_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_paths.append(request.url.path)
        captured_payloads.append(request.content.decode("utf-8"))
        return httpx.Response(200, json={"ok": True})

    runtime.outbox_runner.exporters["telegram"] = TelegramExporter(
        bot_token="token-123",
        chat_id="chat-99",
        transport=httpx.MockTransport(handler),
    )

    first_event = runtime.event_recorder.build_event(
        event_type="system.communication.inverter_block_lost",
        category="system",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="invb-01",
        action="simulate_comm_loss",
        result="accepted",
        resulting_value="lost",
        tags=("fault-path", "communications", "inverter-block"),
    )
    second_event = first_event.model_copy(
        update={
            "event_id": "evt_runtime_multi_block_telegram_02",
            "correlation_id": "corr_runtime_multi_block_telegram_02",
            "asset_id": "invb-02",
        }
    )

    runtime.event_recorder.record(
        first_event,
        current_state_updates={"inverter_blocks": _build_inverter_blocks_state("invb-01")},
        outbox_targets=("telegram",),
    )
    runtime.event_recorder.record(
        second_event,
        current_state_updates={"inverter_blocks": _build_inverter_blocks_state("invb-01", "invb-02")},
        outbox_targets=("telegram",),
    )

    try:
        runtime.start()
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and all(entry.status == "delivered" for entry in outbox_entries):
                break
            sleep(0.05)
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()

    assert all(entry.status == "delivered" for entry in outbox_entries)
    assert runtime.outbox_runner_service.drain_count >= 1
    assert all(path == "/bottoken-123/sendMessage" for path in captured_paths)
    assert any(MULTI_BLOCK_UNAVAILABLE_ALERT_CODE in payload for payload in captured_payloads)
    assert any(
        alert.alarm_code == MULTI_BLOCK_UNAVAILABLE_ALERT_CODE and alert.asset_id == "site" and alert.state != "cleared"
        for alert in alerts
    )


def test_build_local_runtime_drains_smtp_multi_block_follow_up_in_background(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-09",
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

    first_event = runtime.event_recorder.build_event(
        event_type="system.communication.inverter_block_lost",
        category="system",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="invb-01",
        action="simulate_comm_loss",
        result="accepted",
        resulting_value="lost",
        tags=("fault-path", "communications", "inverter-block"),
    )
    second_event = first_event.model_copy(
        update={
            "event_id": "evt_runtime_multi_block_smtp_02",
            "correlation_id": "corr_runtime_multi_block_smtp_02",
            "asset_id": "invb-02",
        }
    )

    runtime.event_recorder.record(
        first_event,
        current_state_updates={"inverter_blocks": _build_inverter_blocks_state("invb-01")},
        outbox_targets=("smtp",),
    )
    runtime.event_recorder.record(
        second_event,
        current_state_updates={"inverter_blocks": _build_inverter_blocks_state("invb-01", "invb-02")},
        outbox_targets=("smtp",),
    )

    try:
        runtime.start()
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and all(entry.status == "delivered" for entry in outbox_entries):
                break
            sleep(0.05)
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()

    assert all(entry.status == "delivered" for entry in outbox_entries)
    assert runtime.outbox_runner_service.drain_count >= 1
    assert captured["from"] == "alerts@example.invalid"
    assert captured["to"] == "soc@example.invalid"
    assert MULTI_BLOCK_UNAVAILABLE_ALERT_CODE in captured["body"]
    assert any(
        alert.alarm_code == MULTI_BLOCK_UNAVAILABLE_ALERT_CODE and alert.asset_id == "site" and alert.state != "cleared"
        for alert in alerts
    )


def test_build_local_runtime_drains_smtp_grid_path_follow_up_in_background(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-10",
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
        resulting_value="open",
        tags=("control-path", "grid", "breaker"),
    )

    runtime.event_recorder.record(
        event,
        current_state_updates={
            "grid_interconnect": {
                "breaker_state": "open",
                "export_path_available": False,
                "grid_acceptance_state": "unavailable",
            }
        },
        outbox_targets=("smtp",),
    )

    try:
        runtime.start()
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and all(entry.status == "delivered" for entry in outbox_entries):
                break
            sleep(0.05)
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()

    assert all(entry.status == "delivered" for entry in outbox_entries)
    assert runtime.outbox_runner_service.drain_count >= 1
    assert captured["from"] == "alerts@example.invalid"
    assert captured["to"] == "soc@example.invalid"
    assert GRID_PATH_UNAVAILABLE_ALERT_CODE in captured["body"]
    assert any(
        alert.alarm_code == GRID_PATH_UNAVAILABLE_ALERT_CODE and alert.asset_id == "grid-01" and alert.state != "cleared"
        for alert in alerts
    )


def test_build_local_runtime_drains_smtp_low_output_follow_up_in_background(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-11",
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
        event_type="system.site.low_output_observed",
        category="system",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="system",
        component="plant-sim",
        asset_id="site",
        action="observe_site_output",
        result="observed",
        resulting_value=1.9,
        tags=("diagnostics", "site-output"),
    )

    runtime.event_recorder.record(
        event,
        current_state_updates={
            "site": {
                "plant_power_mw": 1.9,
                "plant_power_limit_pct": 100,
                "breaker_state": "closed",
            },
            "weather_station": {
                "irradiance_w_m2": 892,
            },
            "grid_interconnect": {
                "export_path_available": True,
            },
            "alarms": [],
        },
        outbox_targets=("smtp",),
    )

    try:
        runtime.start()
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and all(entry.status == "delivered" for entry in outbox_entries):
                break
            sleep(0.05)
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()

    assert all(entry.status == "delivered" for entry in outbox_entries)
    assert runtime.outbox_runner_service.drain_count >= 1
    assert captured["from"] == "alerts@example.invalid"
    assert captured["to"] == "soc@example.invalid"
    assert LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE in captured["body"]
    assert any(
        alert.alarm_code == LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE and alert.asset_id == "site" and alert.state != "cleared"
        for alert in alerts
    )


def test_build_local_runtime_drains_webhook_multi_block_follow_up_in_background(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-06",
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
    captured_payloads: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_payloads.append(request.content.decode("utf-8"))
        return httpx.Response(202, json={"accepted": True})

    runtime.outbox_runner.exporters["webhook"] = runtime.outbox_runner.exporters["webhook"].__class__(
        url="https://example.invalid/hook",
        transport=httpx.MockTransport(handler),
    )

    first_event = runtime.event_recorder.build_event(
        event_type="system.communication.inverter_block_lost",
        category="system",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="invb-01",
        action="simulate_comm_loss",
        result="accepted",
        resulting_value="lost",
        tags=("fault-path", "communications", "inverter-block"),
    )
    second_event = first_event.model_copy(
        update={
            "event_id": "evt_runtime_multi_block_02",
            "correlation_id": "corr_runtime_multi_block_02",
            "asset_id": "invb-02",
        }
    )

    runtime.event_recorder.record(
        first_event,
        current_state_updates={"inverter_blocks": _build_inverter_blocks_state("invb-01")},
        outbox_targets=("webhook",),
    )
    runtime.event_recorder.record(
        second_event,
        current_state_updates={"inverter_blocks": _build_inverter_blocks_state("invb-01", "invb-02")},
        outbox_targets=("webhook",),
    )

    try:
        runtime.start()
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and all(entry.status == "delivered" for entry in outbox_entries):
                break
            sleep(0.05)
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()

    assert all(entry.status == "delivered" for entry in outbox_entries)
    assert runtime.outbox_runner_service.drain_count >= 1
    assert any(MULTI_BLOCK_UNAVAILABLE_ALERT_CODE in payload for payload in captured_payloads)
    assert any(
        alert.alarm_code == MULTI_BLOCK_UNAVAILABLE_ALERT_CODE and alert.asset_id == "site" and alert.state != "cleared"
        for alert in alerts
    )


def test_build_local_runtime_drains_webhook_grid_path_follow_up_in_background(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-07",
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
    captured_payloads: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_payloads.append(request.content.decode("utf-8"))
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
        resulting_value="open",
        tags=("control-path", "grid", "breaker"),
    )

    runtime.event_recorder.record(
        event,
        current_state_updates={
            "grid_interconnect": {
                "breaker_state": "open",
                "export_path_available": False,
                "grid_acceptance_state": "unavailable",
            }
        },
        outbox_targets=("webhook",),
    )

    try:
        runtime.start()
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and all(entry.status == "delivered" for entry in outbox_entries):
                break
            sleep(0.05)
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()

    assert all(entry.status == "delivered" for entry in outbox_entries)
    assert runtime.outbox_runner_service.drain_count >= 1
    assert any(GRID_PATH_UNAVAILABLE_ALERT_CODE in payload for payload in captured_payloads)
    assert any(
        alert.alarm_code == GRID_PATH_UNAVAILABLE_ALERT_CODE and alert.asset_id == "grid-01" and alert.state != "cleared"
        for alert in alerts
    )


def test_build_local_runtime_drains_webhook_low_output_follow_up_in_background(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-08",
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
    captured_payloads: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_payloads.append(request.content.decode("utf-8"))
        return httpx.Response(202, json={"accepted": True})

    runtime.outbox_runner.exporters["webhook"] = runtime.outbox_runner.exporters["webhook"].__class__(
        url="https://example.invalid/hook",
        transport=httpx.MockTransport(handler),
    )

    event = runtime.event_recorder.build_event(
        event_type="system.site.low_output_observed",
        category="system",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="system",
        component="plant-sim",
        asset_id="site",
        action="observe_site_output",
        result="observed",
        resulting_value=1.9,
        tags=("diagnostics", "site-output"),
    )

    runtime.event_recorder.record(
        event,
        current_state_updates={
            "site": {
                "plant_power_mw": 1.9,
                "plant_power_limit_pct": 100,
                "breaker_state": "closed",
            },
            "weather_station": {
                "irradiance_w_m2": 892,
            },
            "grid_interconnect": {
                "export_path_available": True,
            },
            "alarms": [],
        },
        outbox_targets=("webhook",),
    )

    try:
        runtime.start()
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and all(entry.status == "delivered" for entry in outbox_entries):
                break
            sleep(0.05)
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()

    assert all(entry.status == "delivered" for entry in outbox_entries)
    assert runtime.outbox_runner_service.drain_count >= 1
    assert any(LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE in payload for payload in captured_payloads)
    assert any(
        alert.alarm_code == LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE and alert.asset_id == "site" and alert.state != "cleared"
        for alert in alerts
    )


def test_build_local_runtime_drains_telegram_grid_path_follow_up_in_background(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-13",
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
    captured_payloads: list[str] = []
    captured_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_paths.append(request.url.path)
        captured_payloads.append(request.content.decode("utf-8"))
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
        resulting_value="open",
        tags=("control-path", "grid", "breaker"),
    )

    runtime.event_recorder.record(
        event,
        current_state_updates={
            "grid_interconnect": {
                "breaker_state": "open",
                "export_path_available": False,
                "grid_acceptance_state": "unavailable",
            }
        },
        outbox_targets=("telegram",),
    )

    try:
        runtime.start()
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and all(entry.status == "delivered" for entry in outbox_entries):
                break
            sleep(0.05)
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()

    assert all(entry.status == "delivered" for entry in outbox_entries)
    assert runtime.outbox_runner_service.drain_count >= 1
    assert all(path == "/bottoken-123/sendMessage" for path in captured_paths)
    assert any(GRID_PATH_UNAVAILABLE_ALERT_CODE in payload for payload in captured_payloads)
    assert any(
        alert.alarm_code == GRID_PATH_UNAVAILABLE_ALERT_CODE and alert.asset_id == "grid-01" and alert.state != "cleared"
        for alert in alerts
    )


def test_build_local_runtime_drains_telegram_low_output_follow_up_in_background(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-14",
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
    captured_payloads: list[str] = []
    captured_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_paths.append(request.url.path)
        captured_payloads.append(request.content.decode("utf-8"))
        return httpx.Response(200, json={"ok": True})

    runtime.outbox_runner.exporters["telegram"] = TelegramExporter(
        bot_token="token-123",
        chat_id="chat-99",
        transport=httpx.MockTransport(handler),
    )

    event = runtime.event_recorder.build_event(
        event_type="system.site.low_output_observed",
        category="system",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="system",
        component="plant-sim",
        asset_id="site",
        action="observe_site_output",
        result="observed",
        resulting_value=1.9,
        tags=("diagnostics", "site-output"),
    )

    runtime.event_recorder.record(
        event,
        current_state_updates={
            "site": {
                "plant_power_mw": 1.9,
                "plant_power_limit_pct": 100,
                "breaker_state": "closed",
            },
            "weather_station": {
                "irradiance_w_m2": 892,
            },
            "grid_interconnect": {
                "export_path_available": True,
            },
            "alarms": [],
        },
        outbox_targets=("telegram",),
    )

    try:
        runtime.start()
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and all(entry.status == "delivered" for entry in outbox_entries):
                break
            sleep(0.05)
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()

    assert all(entry.status == "delivered" for entry in outbox_entries)
    assert runtime.outbox_runner_service.drain_count >= 1
    assert all(path == "/bottoken-123/sendMessage" for path in captured_paths)
    assert any(LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE in payload for payload in captured_payloads)
    assert any(
        alert.alarm_code == LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE and alert.asset_id == "site" and alert.state != "cleared"
        for alert in alerts
    )


def test_build_local_runtime_drains_low_output_follow_up_to_all_exporters_in_background(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-15",
                f"EVENT_STORE_PATH={event_store_path}",
                "WEBHOOK_EXPORTER_ENABLED=1",
                "WEBHOOK_EXPORTER_URL=https://example.invalid/hook",
                "SMTP_EXPORTER_ENABLED=1",
                "SMTP_HOST=mail.example.invalid",
                "SMTP_PORT=2525",
                "SMTP_FROM=alerts@example.invalid",
                "SMTP_TO=soc@example.invalid",
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
    webhook_payloads: list[str] = []
    telegram_payloads: list[str] = []
    smtp_payloads: list[str] = []

    def webhook_handler(request: httpx.Request) -> httpx.Response:
        webhook_payloads.append(request.content.decode("utf-8"))
        return httpx.Response(202, json={"accepted": True})

    def telegram_handler(request: httpx.Request) -> httpx.Response:
        telegram_payloads.append(request.content.decode("utf-8"))
        return httpx.Response(200, json={"ok": True})

    class FakeSmtpClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            del exc_type, exc, tb

        def send_message(self, message):
            smtp_payloads.append(message.get_content())
            return {}

    runtime.outbox_runner.exporters["webhook"] = runtime.outbox_runner.exporters["webhook"].__class__(
        url="https://example.invalid/hook",
        transport=httpx.MockTransport(webhook_handler),
    )
    runtime.outbox_runner.exporters["smtp"] = SmtpExporter(
        host="mail.example.invalid",
        port=2525,
        mail_from="alerts@example.invalid",
        rcpt_to="soc@example.invalid",
        client_factory=lambda host, port, timeout: FakeSmtpClient(),
    )
    runtime.outbox_runner.exporters["telegram"] = TelegramExporter(
        bot_token="token-123",
        chat_id="chat-99",
        transport=httpx.MockTransport(telegram_handler),
    )

    event = runtime.event_recorder.build_event(
        event_type="system.site.low_output_observed",
        category="system",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="system",
        component="plant-sim",
        asset_id="site",
        action="observe_site_output",
        result="observed",
        resulting_value=1.9,
        tags=("diagnostics", "site-output"),
    )

    runtime.event_recorder.record(
        event,
        current_state_updates={
            "site": {
                "plant_power_mw": 1.9,
                "plant_power_limit_pct": 100,
                "breaker_state": "closed",
            },
            "weather_station": {
                "irradiance_w_m2": 892,
            },
            "grid_interconnect": {
                "export_path_available": True,
            },
            "alarms": [],
        },
        outbox_targets=("webhook", "smtp", "telegram"),
    )

    try:
        runtime.start()
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if len(outbox_entries) == 3 and all(entry.status == "delivered" for entry in outbox_entries):
                break
            sleep(0.05)
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()
    status_by_target = {entry.target_type: entry.status for entry in outbox_entries}

    assert len(outbox_entries) == 3
    assert status_by_target == {"webhook": "delivered", "smtp": "delivered", "telegram": "delivered"}
    assert runtime.outbox_runner_service.drain_count >= 1
    assert any(LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE in payload for payload in webhook_payloads)
    assert any(LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE in payload for payload in smtp_payloads)
    assert any(LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE in payload for payload in telegram_payloads)
    assert any(
        alert.alarm_code == LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE and alert.asset_id == "site" and alert.state != "cleared"
        for alert in alerts
    )


def test_build_local_runtime_recovers_multiple_stranded_targets_over_runner_intervals(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-test-16",
                f"EVENT_STORE_PATH={event_store_path}",
                "WEBHOOK_EXPORTER_ENABLED=1",
                "WEBHOOK_EXPORTER_URL=https://example.invalid/hook",
                "SMTP_EXPORTER_ENABLED=1",
                "SMTP_HOST=mail.example.invalid",
                "SMTP_PORT=2525",
                "SMTP_FROM=alerts@example.invalid",
                "SMTP_TO=soc@example.invalid",
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
    webhook_payloads: list[str] = []
    telegram_payloads: list[str] = []
    smtp_payloads: list[str] = []
    telegram_attempt_statuses = [429, 429, 429, 200, 200, 200, 200]
    smtp_attempt_statuses = ["fail", "fail", "fail", "fail", "fail", "success", "success", "success"]

    def wait_for(predicate, *, timeout: float = 6.0) -> None:
        deadline = monotonic() + timeout
        while monotonic() < deadline:
            if predicate():
                return
            sleep(0.05)
        raise AssertionError("Bedingung wurde nicht rechtzeitig erreicht")

    def fetch_entries():
        return runtime.event_store.fetch_outbox_entries()

    def webhook_handler(request: httpx.Request) -> httpx.Response:
        webhook_payloads.append(request.content.decode("utf-8"))
        return httpx.Response(202, json={"accepted": True})

    def telegram_handler(request: httpx.Request) -> httpx.Response:
        telegram_payloads.append(request.content.decode("utf-8"))
        status_code = telegram_attempt_statuses.pop(0) if telegram_attempt_statuses else 200
        return httpx.Response(
            status_code,
            json={"ok": status_code == 200, "error_code": status_code if status_code != 200 else None},
        )

    class RecoveringSmtpClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            del exc_type, exc, tb

        def send_message(self, message):
            smtp_payloads.append(message.get_content())
            state = smtp_attempt_statuses.pop(0) if smtp_attempt_statuses else "success"
            if state == "success":
                return {}
            raise OSError("connection refused")

    runtime.outbox_runner.exporters["webhook"] = runtime.outbox_runner.exporters["webhook"].__class__(
        url="https://example.invalid/hook",
        retry_after_seconds=1,
        transport=httpx.MockTransport(webhook_handler),
    )
    runtime.outbox_runner.exporters["smtp"] = SmtpExporter(
        host="mail.example.invalid",
        port=2525,
        mail_from="alerts@example.invalid",
        rcpt_to="soc@example.invalid",
        retry_after_seconds=1,
        client_factory=lambda host, port, timeout: RecoveringSmtpClient(),
    )
    runtime.outbox_runner.exporters["telegram"] = TelegramExporter(
        bot_token="token-123",
        chat_id="chat-99",
        retry_after_seconds=1,
        transport=httpx.MockTransport(telegram_handler),
    )

    def record_alert(*, event_type: str, category: str, severity: str, asset_id: str, action: str, alarm_code: str, message: str):
        event = runtime.event_recorder.build_event(
            event_type=event_type,
            category=category,
            severity=severity,
            source_ip="203.0.113.24",
            actor_type="system",
            component="runtime-soak",
            asset_id=asset_id,
            action=action,
            result="accepted",
            alarm_code=alarm_code,
            resulting_value=alarm_code.lower(),
            tags=("runtime-soak", "outbox", "exporter-recovery"),
        )
        alert = runtime.event_recorder.build_alert(
            event=event,
            alarm_code=alarm_code,
            severity="high" if alarm_code != MULTI_BLOCK_UNAVAILABLE_ALERT_CODE else "critical",
            state="active_unacknowledged",
            message=message,
        )
        runtime.event_recorder.record(event, alert=alert, outbox_targets=("webhook", "smtp", "telegram"))
        return alert

    alerts = []
    try:
        runtime.start()

        alerts.append(
            record_alert(
                event_type="process.breaker.state_changed",
                category="process",
                severity="high",
                asset_id="grid-01",
                action="breaker_open_request",
                alarm_code="BREAKER_OPEN",
                message="Breaker open erkannt",
            )
        )
        sleep(0.12)
        alerts.append(
            record_alert(
                event_type="system.communication.inverter_block_lost",
                category="system",
                severity="medium",
                asset_id="invb-02",
                action="simulate_comm_loss",
                alarm_code="COMM_LOSS_INVERTER_BLOCK",
                message="Kommunikationsverlust fuer Inverter-Block invb-02",
            )
        )
        sleep(0.12)
        alerts.append(
            record_alert(
                event_type="system.site.low_output_observed",
                category="system",
                severity="medium",
                asset_id="site",
                action="observe_site_output",
                alarm_code=LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE,
                message="Parkleistung deutlich unter erwarteter Verfuegbarkeit",
            )
        )
        sleep(0.12)
        alerts.append(
            record_alert(
                event_type="system.grid.export_path_unavailable",
                category="system",
                severity="high",
                asset_id="site",
                action="raise_follow_up_alert",
                alarm_code=GRID_PATH_UNAVAILABLE_ALERT_CODE,
                message="Netzpfad fuer Export derzeit nicht verfuegbar",
            )
        )

        wait_for(lambda: len(fetch_entries()) == 12)
        wait_for(
            lambda: (
                sum(1 for entry in fetch_entries() if entry.target_type == "smtp" and entry.status == "pending") >= 3
                and sum(1 for entry in fetch_entries() if entry.target_type == "telegram" and entry.status == "pending") >= 2
            )
        )
        stranded_entries = fetch_entries()

        wait_for(
            lambda: (
                sum(1 for entry in fetch_entries() if entry.target_type == "telegram" and entry.status == "delivered") == 4
                and any(entry.target_type == "smtp" and entry.status == "pending" for entry in fetch_entries())
            )
        )
        partial_recovery_entries = fetch_entries()

        wait_for(lambda: len(fetch_entries()) == 12 and all(entry.status == "delivered" for entry in fetch_entries()))
    finally:
        runtime.stop()

    outbox_entries = runtime.event_store.fetch_outbox_entries()
    alerts_in_store = runtime.event_store.fetch_alerts()
    entries_by_target = {
        target: [entry for entry in outbox_entries if entry.target_type == target]
        for target in ("webhook", "smtp", "telegram")
    }

    assert len(outbox_entries) == 12
    assert runtime.outbox_runner_service.drain_count >= 8
    assert sum(1 for entry in stranded_entries if entry.target_type == "smtp" and entry.status == "pending") >= 3
    assert sum(1 for entry in stranded_entries if entry.target_type == "telegram" and entry.status == "pending") >= 2
    assert sum(1 for entry in partial_recovery_entries if entry.target_type == "telegram" and entry.status == "delivered") == 4
    assert any(entry.target_type == "smtp" and entry.status == "pending" for entry in partial_recovery_entries)
    assert all(entry.status == "delivered" for entry in outbox_entries)
    assert all(entry.retry_count == 0 for entry in entries_by_target["webhook"])
    assert max(entry.retry_count for entry in entries_by_target["smtp"]) >= 2
    assert max(entry.retry_count for entry in entries_by_target["telegram"]) >= 1
    assert all(entry.last_error is None for entry in outbox_entries)
    assert len(entries_by_target["webhook"]) == 4
    assert len(entries_by_target["smtp"]) == 4
    assert len(entries_by_target["telegram"]) == 4
    assert any("BREAKER_OPEN" in payload for payload in webhook_payloads)
    assert any("COMM_LOSS_INVERTER_BLOCK" in payload for payload in webhook_payloads)
    assert any(LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE in payload for payload in webhook_payloads)
    assert any(GRID_PATH_UNAVAILABLE_ALERT_CODE in payload for payload in webhook_payloads)
    assert any("BREAKER_OPEN" in payload for payload in smtp_payloads)
    assert any("COMM_LOSS_INVERTER_BLOCK" in payload for payload in smtp_payloads)
    assert any(LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE in payload for payload in smtp_payloads)
    assert any(GRID_PATH_UNAVAILABLE_ALERT_CODE in payload for payload in smtp_payloads)
    assert any("BREAKER_OPEN" in payload for payload in telegram_payloads)
    assert any("COMM_LOSS_INVERTER_BLOCK" in payload for payload in telegram_payloads)
    assert any(LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE in payload for payload in telegram_payloads)
    assert any(GRID_PATH_UNAVAILABLE_ALERT_CODE in payload for payload in telegram_payloads)
    assert {alert.alarm_code for alert in alerts_in_store if alert.alert_id in {item.alert_id for item in alerts}} == {
        "BREAKER_OPEN",
        "COMM_LOSS_INVERTER_BLOCK",
        LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE,
        GRID_PATH_UNAVAILABLE_ALERT_CODE,
    }


def _build_inverter_blocks_state(*lost_asset_ids: str) -> list[dict[str, str]]:
    lost_assets = set(lost_asset_ids)
    return [
        {
            "asset_id": asset_id,
            "communication_state": "lost" if asset_id in lost_assets else "healthy",
        }
        for asset_id in ("invb-01", "invb-02", "invb-03")
    ]


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


def wait_for(predicate, *, timeout: float = 3.0) -> None:
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        if predicate():
            return
        sleep(0.05)
    raise AssertionError("Bedingung wurde nicht rechtzeitig erfuellt")
