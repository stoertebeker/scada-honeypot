from __future__ import annotations

import socket
from pathlib import Path
from struct import pack, unpack
from time import monotonic, sleep

import httpx

from honeypot.exporter_runner import SmtpExporter, TelegramExporter, WebhookExporter
from honeypot.main import build_local_runtime
from honeypot.protocol_modbus import READ_HOLDING_REGISTERS
from honeypot.rule_engine import (
    GRID_PATH_UNAVAILABLE_ALERT_CODE,
    LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE,
    MULTI_BLOCK_UNAVAILABLE_ALERT_CODE,
)


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


def build_low_output_state(
    *,
    plant_power_mw: float,
    irradiance_w_m2: int = 892,
    plant_power_limit_pct: float = 100,
    breaker_state: str = "closed",
    export_path_available: bool = True,
    alarms=(),
):
    return {
        "site": {
            "plant_power_mw": plant_power_mw,
            "plant_power_limit_pct": plant_power_limit_pct,
            "breaker_state": breaker_state,
        },
        "weather_station": {
            "irradiance_w_m2": irradiance_w_m2,
        },
        "grid_interconnect": {
            "export_path_available": export_path_available,
        },
        "alarms": list(alarms),
    }


def build_inverter_blocks_state(*lost_asset_ids: str) -> list[dict[str, str]]:
    lost_assets = set(lost_asset_ids)
    return [
        {
            "asset_id": asset_id,
            "communication_state": "lost" if asset_id in lost_assets else "healthy",
        }
        for asset_id in ("invb-01", "invb-02", "invb-03")
    ]


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
    assert runtime.outbox_runner_service is not None
    runtime.outbox_runner_service.drain_interval_seconds = 0.05

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
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and outbox_entries[0].retry_count == 1:
                break
            sleep(0.05)
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

    assert runtime.outbox_runner_service.drain_count >= 1
    assert outbox_entries[0].status == "pending"
    assert outbox_entries[0].retry_count == 1
    assert outbox_entries[0].last_error == "Webhook antwortete mit HTTP 503"
    assert overview.status_code == 200
    assert "Plant Overview" in overview.text
    assert "Webhook" not in overview.text
    assert transaction_id == 0x5544
    assert protocol_id == 0


def test_release_gate_follow_up_alerts_do_not_flood_alert_log_or_hmi(tmp_path: Path) -> None:
    env_file = write_env(
        tmp_path,
        f"EVENT_STORE_PATH={tmp_path / 'events' / 'honeypot.db'}",
    )
    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)

    open_state = {
        "grid_interconnect": {
            "breaker_state": "open",
            "export_path_available": False,
            "grid_acceptance_state": "unavailable",
        }
    }
    first_grid_event = runtime.event_recorder.build_event(
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
    second_grid_event = first_grid_event.model_copy(
        update={
            "event_id": "evt_release_gate_grid_repeat",
            "correlation_id": "corr_release_gate_grid_repeat",
        }
    )
    first_low_output_event = runtime.event_recorder.build_event(
        event_type="process.setpoint.block_enable_request_changed",
        category="process",
        severity="medium",
        source_ip="203.0.113.25",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="invb-02",
        action="set_block_enable_request",
        result="accepted",
        resulting_value=0,
        tags=("control-path", "inverter-block", "enable"),
    )
    second_low_output_event = first_low_output_event.model_copy(
        update={
            "event_id": "evt_release_gate_low_output_repeat",
            "correlation_id": "corr_release_gate_low_output_repeat",
        }
    )

    runtime.event_recorder.record(first_grid_event, current_state_updates=open_state, outbox_targets=("webhook",))
    runtime.event_recorder.record(second_grid_event, current_state_updates=open_state, outbox_targets=("webhook",))
    runtime.event_recorder.record(
        first_low_output_event,
        current_state_updates=build_low_output_state(plant_power_mw=1.9),
        outbox_targets=("webhook",),
    )
    runtime.event_recorder.record(
        second_low_output_event,
        current_state_updates=build_low_output_state(plant_power_mw=1.9),
        outbox_targets=("webhook",),
    )

    try:
        runtime.start()
        hmi_address = runtime.hmi_service.address
        response = httpx.get(
            f"http://{hmi_address[0]}:{hmi_address[1]}/alarms",
            timeout=5.0,
            trust_env=False,
        )
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()
    grid_path_alerts = tuple(alert for alert in alerts if alert.alarm_code == GRID_PATH_UNAVAILABLE_ALERT_CODE)
    low_output_alerts = tuple(alert for alert in alerts if alert.alarm_code == LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE)

    assert response.status_code == 200
    assert "Alarm Console" in response.text
    assert "traceback" not in response.text.lower()
    assert len(grid_path_alerts) == 1
    assert len(low_output_alerts) == 1
    assert sum(1 for entry in outbox_entries if entry.payload_ref == grid_path_alerts[0].alert_id) == 1
    assert sum(1 for entry in outbox_entries if entry.payload_ref == low_output_alerts[0].alert_id) == 1


def test_release_gate_multi_block_follow_up_does_not_flood_outbox_or_hmi(tmp_path: Path) -> None:
    env_file = write_env(
        tmp_path,
        f"EVENT_STORE_PATH={tmp_path / 'events' / 'honeypot.db'}",
    )
    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)

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
            "event_id": "evt_release_gate_multi_block_02",
            "correlation_id": "corr_release_gate_multi_block_02",
            "asset_id": "invb-02",
        }
    )
    third_event = first_event.model_copy(
        update={
            "event_id": "evt_release_gate_multi_block_03",
            "correlation_id": "corr_release_gate_multi_block_03",
            "asset_id": "invb-03",
        }
    )

    runtime.event_recorder.record(
        first_event,
        current_state_updates={"inverter_blocks": build_inverter_blocks_state("invb-01")},
        outbox_targets=("webhook",),
    )
    runtime.event_recorder.record(
        second_event,
        current_state_updates={"inverter_blocks": build_inverter_blocks_state("invb-01", "invb-02")},
        outbox_targets=("webhook",),
    )
    runtime.event_recorder.record(
        third_event,
        current_state_updates={"inverter_blocks": build_inverter_blocks_state("invb-01", "invb-02", "invb-03")},
        outbox_targets=("webhook",),
    )

    try:
        runtime.start()
        hmi_address = runtime.hmi_service.address
        response = httpx.get(
            f"http://{hmi_address[0]}:{hmi_address[1]}/alarms",
            timeout=5.0,
            trust_env=False,
        )
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()
    multi_block_alerts = tuple(alert for alert in alerts if alert.alarm_code == MULTI_BLOCK_UNAVAILABLE_ALERT_CODE)

    assert response.status_code == 200
    assert "Alarm Console" in response.text
    assert "traceback" not in response.text.lower()
    assert response.text.count("MULTI_BLOCK_UNAVAILABLE") == 1
    assert len(multi_block_alerts) == 1
    assert sum(1 for entry in outbox_entries if entry.payload_ref == multi_block_alerts[0].alert_id) == 1


def test_release_gate_smtp_failure_stays_internal_and_clients_remain_stable(tmp_path: Path) -> None:
    env_file = write_env(
        tmp_path,
        "SMTP_EXPORTER_ENABLED=1",
        "SMTP_HOST=mail.example.invalid",
        "SMTP_PORT=2525",
        "SMTP_FROM=alerts@example.invalid",
        "SMTP_TO=soc@example.invalid",
        "OUTBOX_RETRY_BACKOFF_SECONDS=45",
        f"EVENT_STORE_PATH={tmp_path / 'events' / 'honeypot.db'}",
    )
    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    assert runtime.outbox_runner is not None
    assert runtime.outbox_runner_service is not None
    runtime.outbox_runner_service.drain_interval_seconds = 0.05

    class FailingSmtpClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            del exc_type, exc, tb

        def send_message(self, message):
            del message
            raise OSError("smtp down")

    runtime.outbox_runner.exporters["smtp"] = SmtpExporter(
        host="mail.example.invalid",
        port=2525,
        mail_from="alerts@example.invalid",
        rcpt_to="soc@example.invalid",
        retry_after_seconds=45,
        client_factory=lambda host, port, timeout: FailingSmtpClient(),
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
        hmi_address = runtime.hmi_service.address
        modbus_address = runtime.modbus_service.address
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and outbox_entries[0].retry_count == 1:
                break
            sleep(0.05)
        overview = httpx.get(
            f"http://{hmi_address[0]}:{hmi_address[1]}/overview",
            timeout=5.0,
            trust_env=False,
        )
        modbus_response = send_modbus_request(
            modbus_address,
            transaction_id=0x6644,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 8),
        )
    finally:
        runtime.stop()

    outbox_entries = runtime.event_store.fetch_outbox_entries()
    transaction_id, protocol_id, _, _ = unpack(">HHHB", modbus_response[:7])

    assert runtime.outbox_runner_service.drain_count >= 1
    assert outbox_entries[0].status == "pending"
    assert outbox_entries[0].retry_count == 1
    assert outbox_entries[0].last_error == "SMTP-Transportfehler: OSError"
    assert overview.status_code == 200
    assert "Plant Overview" in overview.text
    assert "SMTP" not in overview.text
    assert transaction_id == 0x6644
    assert protocol_id == 0


def test_release_gate_multi_block_smtp_failure_stays_internal_and_alarm_view_remains_stable(tmp_path: Path) -> None:
    env_file = write_env(
        tmp_path,
        "SMTP_EXPORTER_ENABLED=1",
        "SMTP_HOST=mail.example.invalid",
        "SMTP_PORT=2525",
        "SMTP_FROM=alerts@example.invalid",
        "SMTP_TO=soc@example.invalid",
        "OUTBOX_RETRY_BACKOFF_SECONDS=45",
        f"EVENT_STORE_PATH={tmp_path / 'events' / 'honeypot.db'}",
    )
    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    assert runtime.outbox_runner is not None
    assert runtime.outbox_runner_service is not None
    runtime.outbox_runner_service.drain_interval_seconds = 0.05

    class FailingSmtpClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            del exc_type, exc, tb

        def send_message(self, message):
            del message
            raise OSError("smtp down")

    runtime.outbox_runner.exporters["smtp"] = SmtpExporter(
        host="mail.example.invalid",
        port=2525,
        mail_from="alerts@example.invalid",
        rcpt_to="soc@example.invalid",
        retry_after_seconds=45,
        client_factory=lambda host, port, timeout: FailingSmtpClient(),
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
            "event_id": "evt_release_gate_multi_block_smtp_02",
            "correlation_id": "corr_release_gate_multi_block_smtp_02",
            "asset_id": "invb-02",
        }
    )

    runtime.event_recorder.record(
        first_event,
        current_state_updates={"inverter_blocks": build_inverter_blocks_state("invb-01")},
        outbox_targets=("smtp",),
    )
    runtime.event_recorder.record(
        second_event,
        current_state_updates={"inverter_blocks": build_inverter_blocks_state("invb-01", "invb-02")},
        outbox_targets=("smtp",),
    )

    try:
        runtime.start()
        hmi_address = runtime.hmi_service.address
        modbus_address = runtime.modbus_service.address
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and all(entry.retry_count == 1 for entry in outbox_entries):
                break
            sleep(0.05)
        alarms_page = httpx.get(
            f"http://{hmi_address[0]}:{hmi_address[1]}/alarms",
            timeout=5.0,
            trust_env=False,
        )
        modbus_response = send_modbus_request(
            modbus_address,
            transaction_id=0x7744,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 8),
        )
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()
    multi_block_alert = next(alert for alert in alerts if alert.alarm_code == MULTI_BLOCK_UNAVAILABLE_ALERT_CODE)
    multi_block_outbox = next(entry for entry in outbox_entries if entry.payload_ref == multi_block_alert.alert_id)
    transaction_id, protocol_id, _, _ = unpack(">HHHB", modbus_response[:7])

    assert runtime.outbox_runner_service.drain_count >= 1
    assert multi_block_outbox.status == "pending"
    assert multi_block_outbox.retry_count == 1
    assert multi_block_outbox.last_error == "SMTP-Transportfehler: OSError"
    assert alarms_page.status_code == 200
    assert "Alarm Console" in alarms_page.text
    assert "MULTI_BLOCK_UNAVAILABLE" in alarms_page.text
    assert "SMTP" not in alarms_page.text
    assert transaction_id == 0x7744
    assert protocol_id == 0


def test_release_gate_grid_path_smtp_failure_stays_internal_and_alarm_view_remains_stable(tmp_path: Path) -> None:
    env_file = write_env(
        tmp_path,
        "SMTP_EXPORTER_ENABLED=1",
        "SMTP_HOST=mail.example.invalid",
        "SMTP_PORT=2525",
        "SMTP_FROM=alerts@example.invalid",
        "SMTP_TO=soc@example.invalid",
        "OUTBOX_RETRY_BACKOFF_SECONDS=45",
        f"EVENT_STORE_PATH={tmp_path / 'events' / 'honeypot.db'}",
    )
    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    assert runtime.outbox_runner is not None
    assert runtime.outbox_runner_service is not None
    runtime.outbox_runner_service.drain_interval_seconds = 0.05

    class FailingSmtpClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            del exc_type, exc, tb

        def send_message(self, message):
            del message
            raise OSError("smtp down")

    runtime.outbox_runner.exporters["smtp"] = SmtpExporter(
        host="mail.example.invalid",
        port=2525,
        mail_from="alerts@example.invalid",
        rcpt_to="soc@example.invalid",
        retry_after_seconds=45,
        client_factory=lambda host, port, timeout: FailingSmtpClient(),
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
        hmi_address = runtime.hmi_service.address
        modbus_address = runtime.modbus_service.address
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and all(entry.retry_count == 1 for entry in outbox_entries):
                break
            sleep(0.05)
        alarms_page = httpx.get(
            f"http://{hmi_address[0]}:{hmi_address[1]}/alarms",
            timeout=5.0,
            trust_env=False,
        )
        modbus_response = send_modbus_request(
            modbus_address,
            transaction_id=0x7844,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 8),
        )
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()
    grid_path_alert = next(alert for alert in alerts if alert.alarm_code == GRID_PATH_UNAVAILABLE_ALERT_CODE)
    grid_path_outbox = next(entry for entry in outbox_entries if entry.payload_ref == grid_path_alert.alert_id)
    transaction_id, protocol_id, _, _ = unpack(">HHHB", modbus_response[:7])

    assert runtime.outbox_runner_service.drain_count >= 1
    assert grid_path_outbox.status == "pending"
    assert grid_path_outbox.retry_count == 1
    assert grid_path_outbox.last_error == "SMTP-Transportfehler: OSError"
    assert alarms_page.status_code == 200
    assert "Alarm Console" in alarms_page.text
    assert "GRID_PATH_UNAVAILABLE" in alarms_page.text
    assert "SMTP" not in alarms_page.text
    assert transaction_id == 0x7844
    assert protocol_id == 0


def test_release_gate_low_output_smtp_failure_stays_internal_and_alarm_view_remains_stable(tmp_path: Path) -> None:
    env_file = write_env(
        tmp_path,
        "SMTP_EXPORTER_ENABLED=1",
        "SMTP_HOST=mail.example.invalid",
        "SMTP_PORT=2525",
        "SMTP_FROM=alerts@example.invalid",
        "SMTP_TO=soc@example.invalid",
        "OUTBOX_RETRY_BACKOFF_SECONDS=45",
        f"EVENT_STORE_PATH={tmp_path / 'events' / 'honeypot.db'}",
    )
    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    assert runtime.outbox_runner is not None
    assert runtime.outbox_runner_service is not None
    runtime.outbox_runner_service.drain_interval_seconds = 0.05

    class FailingSmtpClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            del exc_type, exc, tb

        def send_message(self, message):
            del message
            raise OSError("smtp down")

    runtime.outbox_runner.exporters["smtp"] = SmtpExporter(
        host="mail.example.invalid",
        port=2525,
        mail_from="alerts@example.invalid",
        rcpt_to="soc@example.invalid",
        retry_after_seconds=45,
        client_factory=lambda host, port, timeout: FailingSmtpClient(),
    )

    event = runtime.event_recorder.build_event(
        event_type="process.setpoint.block_enable_request_changed",
        category="process",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="invb-02",
        action="set_block_enable_request",
        result="accepted",
        resulting_value=0,
        tags=("control-path", "inverter-block", "enable"),
    )

    runtime.event_recorder.record(
        event,
        current_state_updates=build_low_output_state(plant_power_mw=1.9),
        outbox_targets=("smtp",),
    )

    try:
        runtime.start()
        hmi_address = runtime.hmi_service.address
        modbus_address = runtime.modbus_service.address
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and all(entry.retry_count == 1 for entry in outbox_entries):
                break
            sleep(0.05)
        alarms_page = httpx.get(
            f"http://{hmi_address[0]}:{hmi_address[1]}/alarms",
            timeout=5.0,
            trust_env=False,
        )
        modbus_response = send_modbus_request(
            modbus_address,
            transaction_id=0x7944,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 8),
        )
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()
    low_output_alert = next(alert for alert in alerts if alert.alarm_code == LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE)
    low_output_outbox = next(entry for entry in outbox_entries if entry.payload_ref == low_output_alert.alert_id)
    transaction_id, protocol_id, _, _ = unpack(">HHHB", modbus_response[:7])

    assert runtime.outbox_runner_service.drain_count >= 1
    assert low_output_outbox.status == "pending"
    assert low_output_outbox.retry_count == 1
    assert low_output_outbox.last_error == "SMTP-Transportfehler: OSError"
    assert alarms_page.status_code == 200
    assert "Alarm Console" in alarms_page.text
    assert "LOW_SITE_OUTPUT_UNEXPECTED" in alarms_page.text
    assert "SMTP" not in alarms_page.text
    assert transaction_id == 0x7944
    assert protocol_id == 0


def test_release_gate_multi_block_telegram_failure_stays_internal_and_alarm_view_remains_stable(tmp_path: Path) -> None:
    env_file = write_env(
        tmp_path,
        "TELEGRAM_EXPORTER_ENABLED=1",
        "TELEGRAM_BOT_TOKEN=token-123",
        "TELEGRAM_CHAT_ID=chat-99",
        "OUTBOX_RETRY_BACKOFF_SECONDS=45",
        f"EVENT_STORE_PATH={tmp_path / 'events' / 'honeypot.db'}",
    )
    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    assert runtime.outbox_runner is not None
    assert runtime.outbox_runner_service is not None
    runtime.outbox_runner_service.drain_interval_seconds = 0.05

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(429, json={"ok": False, "error_code": 429, "description": "Too Many Requests"})

    runtime.outbox_runner.exporters["telegram"] = TelegramExporter(
        bot_token="token-123",
        chat_id="chat-99",
        retry_after_seconds=45,
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
            "event_id": "evt_release_gate_multi_block_telegram_02",
            "correlation_id": "corr_release_gate_multi_block_telegram_02",
            "asset_id": "invb-02",
        }
    )

    runtime.event_recorder.record(
        first_event,
        current_state_updates={"inverter_blocks": build_inverter_blocks_state("invb-01")},
        outbox_targets=("telegram",),
    )
    runtime.event_recorder.record(
        second_event,
        current_state_updates={"inverter_blocks": build_inverter_blocks_state("invb-01", "invb-02")},
        outbox_targets=("telegram",),
    )

    try:
        runtime.start()
        hmi_address = runtime.hmi_service.address
        modbus_address = runtime.modbus_service.address
        deadline = monotonic() + 2.0
        while monotonic() < deadline:
            outbox_entries = runtime.event_store.fetch_outbox_entries()
            if outbox_entries and all(entry.retry_count == 1 for entry in outbox_entries):
                break
            sleep(0.05)
        alarms_page = httpx.get(
            f"http://{hmi_address[0]}:{hmi_address[1]}/alarms",
            timeout=5.0,
            trust_env=False,
        )
        modbus_response = send_modbus_request(
            modbus_address,
            transaction_id=0x7A44,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 8),
        )
    finally:
        runtime.stop()

    alerts = runtime.event_store.fetch_alerts()
    outbox_entries = runtime.event_store.fetch_outbox_entries()
    multi_block_alert = next(alert for alert in alerts if alert.alarm_code == MULTI_BLOCK_UNAVAILABLE_ALERT_CODE)
    multi_block_outbox = next(entry for entry in outbox_entries if entry.payload_ref == multi_block_alert.alert_id)
    transaction_id, protocol_id, _, _ = unpack(">HHHB", modbus_response[:7])

    assert runtime.outbox_runner_service.drain_count >= 1
    assert multi_block_outbox.status == "pending"
    assert multi_block_outbox.retry_count == 1
    assert multi_block_outbox.last_error == "Telegram antwortete mit HTTP 429"
    assert alarms_page.status_code == 200
    assert "Alarm Console" in alarms_page.text
    assert "MULTI_BLOCK_UNAVAILABLE" in alarms_page.text
    assert "Telegram" not in alarms_page.text
    assert transaction_id == 0x7A44
    assert protocol_id == 0
