import json
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from time import monotonic, sleep

import httpx

from honeypot.event_core import EventRecorder
from honeypot.exporter_runner import (
    BackgroundOutboxRunnerService,
    OutboxRunner,
    SmtpExporter,
    TelegramExporter,
    WebhookExporter,
)
from honeypot.storage import SQLiteEventStore
from honeypot.time_core import FrozenClock


def build_recorder(tmp_path):
    clock = FrozenClock(datetime(2026, 4, 17, 12, 0, tzinfo=UTC))
    store = SQLiteEventStore(tmp_path / "events" / "outbox-runner.db")
    recorder = EventRecorder(store=store, clock=clock)
    return recorder, clock


def seed_webhook_alert(tmp_path):
    recorder, clock = build_recorder(tmp_path)
    event = recorder.build_event(
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
    alert = recorder.build_alert(
        event=event,
        alarm_code="BREAKER_OPEN",
        severity="high",
        state="active_unacknowledged",
        message="Breaker open erkannt",
    )
    recorder.record(event, alert=alert, outbox_targets=("webhook",))
    return recorder, clock


def test_outbox_runner_delivers_webhook_alert_batch_and_marks_outbox_delivered(tmp_path) -> None:
    recorder, clock = seed_webhook_alert(tmp_path)
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        captured["json"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(202, json={"accepted": True})

    runner = OutboxRunner(
        store=recorder.store,
        exporters={
            "webhook": WebhookExporter(
                url="https://example.invalid/hook",
                transport=httpx.MockTransport(handler),
            )
        },
        clock=clock,
    )

    result = runner.drain_once()
    outbox_entries = recorder.store.fetch_outbox_entries()

    assert result.leased_count == 1
    assert result.delivered_count == 1
    assert result.retried_count == 0
    assert outbox_entries[0].status == "delivered"
    assert captured["method"] == "POST"
    assert captured["path"] == "/hook"
    assert captured["json"]["payload_kind"] == "alert"
    assert captured["json"]["items"][0]["alarm_code"] == "BREAKER_OPEN"


def test_outbox_runner_requeues_batch_with_backoff_on_webhook_error(tmp_path) -> None:
    recorder, clock = seed_webhook_alert(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(503, json={"accepted": False})

    runner = OutboxRunner(
        store=recorder.store,
        exporters={
            "webhook": WebhookExporter(
                url="https://example.invalid/hook",
                retry_after_seconds=45,
                transport=httpx.MockTransport(handler),
            )
        },
        retry_backoff_seconds=45,
        clock=clock,
    )

    result = runner.drain_once()
    outbox_entries = recorder.store.fetch_outbox_entries()

    assert result.leased_count == 1
    assert result.delivered_count == 0
    assert result.retried_count == 1
    assert outbox_entries[0].status == "pending"
    assert outbox_entries[0].retry_count == 1
    assert outbox_entries[0].next_attempt_at == clock.now() + timedelta(seconds=45)
    assert outbox_entries[0].last_error == "Webhook antwortete mit HTTP 503"


def test_telegram_exporter_posts_alert_batch_to_send_message(tmp_path) -> None:
    recorder, _ = seed_webhook_alert(tmp_path)
    alert = recorder.store.fetch_alerts()[0]
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["json"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json={"ok": True})

    exporter = TelegramExporter(
        bot_token="token-123",
        chat_id="chat-99",
        transport=httpx.MockTransport(handler),
    )

    delivery = exporter.deliver_alert_batch((alert,))

    assert delivery.status == "delivered"
    assert delivery.accepted_items == 1
    assert captured["path"] == "/bottoken-123/sendMessage"
    assert captured["json"]["chat_id"] == "chat-99"
    assert "BREAKER_OPEN" in captured["json"]["text"]
    assert "grid-01" in captured["json"]["text"]


def test_telegram_exporter_retries_on_http_error(tmp_path) -> None:
    recorder, _ = seed_webhook_alert(tmp_path)
    alert = recorder.store.fetch_alerts()[0]

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(429, json={"ok": False})

    exporter = TelegramExporter(
        bot_token="token-123",
        chat_id="chat-99",
        retry_after_seconds=90,
        transport=httpx.MockTransport(handler),
    )

    delivery = exporter.deliver_alert_batch((alert,))

    assert delivery.status == "retry_later"
    assert delivery.retry_after_seconds == 90
    assert delivery.detail == "Telegram antwortete mit HTTP 429"


def test_smtp_exporter_sends_alert_batch_via_client_factory(tmp_path) -> None:
    recorder, _ = seed_webhook_alert(tmp_path)
    alert = recorder.store.fetch_alerts()[0]
    captured = {}

    class FakeSmtpClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            del exc_type, exc, tb

        def send_message(self, message: EmailMessage):
            captured["from"] = message["From"]
            captured["to"] = message["To"]
            captured["subject"] = message["Subject"]
            captured["body"] = message.get_content()
            return {}

    exporter = SmtpExporter(
        host="mail.example.invalid",
        port=2525,
        mail_from="alerts@example.invalid",
        rcpt_to="soc@example.invalid",
        client_factory=lambda host, port, timeout: FakeSmtpClient(),
    )

    delivery = exporter.deliver_alert_batch((alert,))

    assert delivery.status == "delivered"
    assert delivery.accepted_items == 1
    assert captured["from"] == "alerts@example.invalid"
    assert captured["to"] == "soc@example.invalid"
    assert "SCADA Honeypot Alert Batch" in captured["subject"]
    assert "BREAKER_OPEN" in captured["body"]


def test_smtp_exporter_rejects_event_batches() -> None:
    exporter = SmtpExporter(
        host="mail.example.invalid",
        mail_from="alerts@example.invalid",
        rcpt_to="soc@example.invalid",
    )

    delivery = exporter.deliver_event_batch(())

    assert delivery.status == "retry_later"
    assert delivery.accepted_items == 0
    assert delivery.detail == "SmtpExporter unterstuetzt keine Event-Batches"


def test_outbox_runner_requeues_batch_on_smtp_transport_error(tmp_path) -> None:
    recorder, clock = build_recorder(tmp_path)
    event = recorder.build_event(
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
    alert = recorder.build_alert(
        event=event,
        alarm_code="BREAKER_OPEN",
        severity="high",
        state="active_unacknowledged",
        message="Breaker open erkannt",
    )
    recorder.record(event, alert=alert, outbox_targets=("smtp",))

    class FailingSmtpClient:
        def __enter__(self):
            raise OSError("connection refused")

        def __exit__(self, exc_type, exc, tb) -> None:
            del exc_type, exc, tb

        def send_message(self, message: EmailMessage):
            del message
            return {}

    runner = OutboxRunner(
        store=recorder.store,
        exporters={
            "smtp": SmtpExporter(
                host="mail.example.invalid",
                port=2525,
                mail_from="alerts@example.invalid",
                rcpt_to="soc@example.invalid",
                retry_after_seconds=75,
                client_factory=lambda host, port, timeout: FailingSmtpClient(),
            )
        },
        retry_backoff_seconds=75,
        clock=clock,
    )

    result = runner.drain_once()
    outbox_entries = recorder.store.fetch_outbox_entries()

    assert result.leased_count == 1
    assert result.delivered_count == 0
    assert result.retried_count == 1
    assert outbox_entries[0].status == "pending"
    assert outbox_entries[0].retry_count == 1
    assert outbox_entries[0].next_attempt_at == clock.now() + timedelta(seconds=75)
    assert outbox_entries[0].last_error == "SMTP-Transportfehler: OSError"


def test_outbox_runner_marks_entries_failed_when_exporter_is_missing(tmp_path) -> None:
    recorder, clock = seed_webhook_alert(tmp_path)
    runner = OutboxRunner(store=recorder.store, exporters={}, clock=clock)

    result = runner.drain_once()
    outbox_entries = recorder.store.fetch_outbox_entries()

    assert result.failed_count == 1
    assert result.delivered_count == 0
    assert outbox_entries[0].status == "failed"
    assert outbox_entries[0].retry_count == 1
    assert outbox_entries[0].last_error == "Kein Exporter registriert fuer webhook"


def test_outbox_runner_respects_backoff_per_target_across_multiple_cycles(tmp_path) -> None:
    recorder, clock = build_recorder(tmp_path)
    event = recorder.build_event(
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
    alert = recorder.build_alert(
        event=event,
        alarm_code="BREAKER_OPEN",
        severity="high",
        state="active_unacknowledged",
        message="Breaker open erkannt",
    )
    recorder.record(event, alert=alert, outbox_targets=("webhook", "smtp", "telegram"))

    webhook_payloads: list[dict] = []
    smtp_payloads: list[str] = []
    telegram_attempts: list[dict] = []

    def webhook_handler(request: httpx.Request) -> httpx.Response:
        webhook_payloads.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(202, json={"accepted": True})

    class FakeSmtpClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            del exc_type, exc, tb

        def send_message(self, message: EmailMessage):
            smtp_payloads.append(message.get_content())
            return {}

    def telegram_handler(request: httpx.Request) -> httpx.Response:
        telegram_attempts.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(429, json={"ok": False})

    runner = OutboxRunner(
        store=recorder.store,
        exporters={
            "webhook": WebhookExporter(
                url="https://example.invalid/hook",
                transport=httpx.MockTransport(webhook_handler),
            ),
            "smtp": SmtpExporter(
                host="mail.example.invalid",
                port=2525,
                mail_from="alerts@example.invalid",
                rcpt_to="soc@example.invalid",
                client_factory=lambda host, port, timeout: FakeSmtpClient(),
            ),
            "telegram": TelegramExporter(
                bot_token="token-123",
                chat_id="chat-99",
                retry_after_seconds=45,
                transport=httpx.MockTransport(telegram_handler),
            ),
        },
        retry_backoff_seconds=45,
        clock=clock,
    )

    initial_now = clock.now()
    first_result = runner.drain_once()
    first_entries = recorder.store.fetch_outbox_entries()
    first_by_target = {entry.target_type: entry for entry in first_entries}

    second_result = runner.drain_once()
    second_entries = recorder.store.fetch_outbox_entries()
    second_by_target = {entry.target_type: entry for entry in second_entries}

    advanced_now = clock.advance(timedelta(seconds=45))
    third_result = runner.drain_once()
    third_entries = recorder.store.fetch_outbox_entries()
    third_by_target = {entry.target_type: entry for entry in third_entries}

    assert first_result.leased_count == 3
    assert first_result.delivered_count == 2
    assert first_result.retried_count == 1
    assert first_by_target["webhook"].status == "delivered"
    assert first_by_target["smtp"].status == "delivered"
    assert first_by_target["telegram"].status == "pending"
    assert first_by_target["telegram"].retry_count == 1
    assert first_by_target["telegram"].next_attempt_at == initial_now + timedelta(seconds=45)
    assert first_by_target["telegram"].last_error == "Telegram antwortete mit HTTP 429"

    assert second_result.leased_count == 0
    assert second_result.delivered_count == 0
    assert second_result.retried_count == 0
    assert second_by_target["telegram"].retry_count == 1

    assert third_result.leased_count == 1
    assert third_result.delivered_count == 0
    assert third_result.retried_count == 1
    assert third_by_target["webhook"].status == "delivered"
    assert third_by_target["smtp"].status == "delivered"
    assert third_by_target["telegram"].status == "pending"
    assert third_by_target["telegram"].retry_count == 2
    assert third_by_target["telegram"].next_attempt_at == advanced_now + timedelta(seconds=45)
    assert third_by_target["telegram"].last_error == "Telegram antwortete mit HTTP 429"

    assert len(webhook_payloads) == 1
    assert len(smtp_payloads) == 1
    assert len(telegram_attempts) == 2
    assert webhook_payloads[0]["items"][0]["alarm_code"] == "BREAKER_OPEN"
    assert "BREAKER_OPEN" in smtp_payloads[0]
    assert "BREAKER_OPEN" in telegram_attempts[0]["text"]


def test_outbox_runner_handles_multiple_alerts_with_staggered_target_backoff_windows(tmp_path) -> None:
    recorder, clock = build_recorder(tmp_path)

    breaker_event = recorder.build_event(
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
    breaker_alert = recorder.build_alert(
        event=breaker_event,
        alarm_code="BREAKER_OPEN",
        severity="high",
        state="active_unacknowledged",
        message="Breaker open erkannt",
    )
    recorder.record(breaker_event, alert=breaker_alert, outbox_targets=("webhook", "smtp", "telegram"))

    comms_event = recorder.build_event(
        event_type="system.communication.inverter_block_lost",
        category="system",
        severity="medium",
        source_ip="203.0.113.24",
        actor_type="system",
        component="plant-sim",
        asset_id="invb-02",
        action="simulate_comm_loss",
        result="accepted",
        alarm_code="COMM_LOSS_INVERTER_BLOCK",
        resulting_value="lost",
        tags=("fault-path", "communications", "inverter-block"),
    )
    comms_alert = recorder.build_alert(
        event=comms_event,
        alarm_code="COMM_LOSS_INVERTER_BLOCK",
        severity="medium",
        state="active_unacknowledged",
        message="Kommunikationsverlust fuer Inverter-Block invb-02",
    )
    recorder.record(comms_event, alert=comms_alert, outbox_targets=("webhook", "smtp", "telegram"))

    webhook_batches: list[dict] = []
    smtp_attempt_bodies: list[str] = []
    telegram_batches: list[dict] = []
    telegram_attempt_states = [429, 200]

    def webhook_handler(request: httpx.Request) -> httpx.Response:
        webhook_batches.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(202, json={"accepted": True})

    class FlakySmtpClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            del exc_type, exc, tb

        def send_message(self, message: EmailMessage):
            smtp_attempt_bodies.append(message.get_content())
            raise OSError("connection refused")

    def telegram_handler(request: httpx.Request) -> httpx.Response:
        telegram_batches.append(json.loads(request.content.decode("utf-8")))
        status_code = telegram_attempt_states.pop(0)
        if status_code == 200:
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(status_code, json={"ok": False})

    runner = OutboxRunner(
        store=recorder.store,
        exporters={
            "webhook": WebhookExporter(
                url="https://example.invalid/hook",
                transport=httpx.MockTransport(webhook_handler),
            ),
            "smtp": SmtpExporter(
                host="mail.example.invalid",
                port=2525,
                mail_from="alerts@example.invalid",
                rcpt_to="soc@example.invalid",
                retry_after_seconds=90,
                client_factory=lambda host, port, timeout: FlakySmtpClient(),
            ),
            "telegram": TelegramExporter(
                bot_token="token-123",
                chat_id="chat-99",
                retry_after_seconds=45,
                transport=httpx.MockTransport(telegram_handler),
            ),
        },
        retry_backoff_seconds=90,
        clock=clock,
    )

    def entries_for(target_type: str):
        return tuple(entry for entry in recorder.store.fetch_outbox_entries() if entry.target_type == target_type)

    initial_now = clock.now()
    first_result = runner.drain_once()
    first_webhook_entries = entries_for("webhook")
    first_smtp_entries = entries_for("smtp")
    first_telegram_entries = entries_for("telegram")

    second_result = runner.drain_once()

    t45 = clock.advance(timedelta(seconds=45))
    third_result = runner.drain_once()
    third_smtp_entries = entries_for("smtp")
    third_telegram_entries = entries_for("telegram")

    t90 = clock.advance(timedelta(seconds=45))
    fourth_result = runner.drain_once()
    fourth_webhook_entries = entries_for("webhook")
    fourth_smtp_entries = entries_for("smtp")
    fourth_telegram_entries = entries_for("telegram")

    assert first_result.leased_count == 6
    assert first_result.delivered_count == 2
    assert first_result.retried_count == 4
    assert all(entry.status == "delivered" for entry in first_webhook_entries)
    assert all(entry.status == "pending" for entry in first_smtp_entries)
    assert all(entry.retry_count == 1 for entry in first_smtp_entries)
    assert all(entry.next_attempt_at == initial_now + timedelta(seconds=90) for entry in first_smtp_entries)
    assert all(entry.last_error == "SMTP-Transportfehler: OSError" for entry in first_smtp_entries)
    assert all(entry.status == "pending" for entry in first_telegram_entries)
    assert all(entry.retry_count == 1 for entry in first_telegram_entries)
    assert all(entry.next_attempt_at == initial_now + timedelta(seconds=45) for entry in first_telegram_entries)
    assert all(entry.last_error == "Telegram antwortete mit HTTP 429" for entry in first_telegram_entries)

    assert second_result.leased_count == 0
    assert second_result.delivered_count == 0
    assert second_result.retried_count == 0

    assert third_result.leased_count == 2
    assert third_result.delivered_count == 2
    assert third_result.retried_count == 0
    assert all(entry.status == "pending" for entry in third_smtp_entries)
    assert all(entry.retry_count == 1 for entry in third_smtp_entries)
    assert all(entry.status == "delivered" for entry in third_telegram_entries)

    assert fourth_result.leased_count == 2
    assert fourth_result.delivered_count == 0
    assert fourth_result.retried_count == 2
    assert all(entry.status == "delivered" for entry in fourth_webhook_entries)
    assert all(entry.status == "pending" for entry in fourth_smtp_entries)
    assert all(entry.retry_count == 2 for entry in fourth_smtp_entries)
    assert all(entry.next_attempt_at == t90 + timedelta(seconds=90) for entry in fourth_smtp_entries)
    assert all(entry.last_error == "SMTP-Transportfehler: OSError" for entry in fourth_smtp_entries)
    assert all(entry.status == "delivered" for entry in fourth_telegram_entries)

    assert len(webhook_batches) == 1
    assert len(telegram_batches) == 2
    assert len(smtp_attempt_bodies) == 2
    assert len(webhook_batches[0]["items"]) == 2
    assert "BREAKER_OPEN" in smtp_attempt_bodies[0]
    assert "COMM_LOSS_INVERTER_BLOCK" in smtp_attempt_bodies[0]
    assert "BREAKER_OPEN" in telegram_batches[0]["text"]
    assert "COMM_LOSS_INVERTER_BLOCK" in telegram_batches[0]["text"]
    assert "BREAKER_OPEN" in telegram_batches[1]["text"]
    assert "COMM_LOSS_INVERTER_BLOCK" in telegram_batches[1]["text"]


def test_background_outbox_runner_service_delivers_pending_entry_without_manual_drain(tmp_path) -> None:
    recorder, clock = seed_webhook_alert(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(202, json={"accepted": True})

    runner = OutboxRunner(
        store=recorder.store,
        exporters={
            "webhook": WebhookExporter(
                url="https://example.invalid/hook",
                transport=httpx.MockTransport(handler),
            )
        },
        clock=clock,
    )
    service = BackgroundOutboxRunnerService(runner=runner, drain_interval_seconds=0.05)

    try:
        service.start_in_thread()
        deadline = monotonic() + 1.0
        while monotonic() < deadline:
            if recorder.store.fetch_outbox_entries()[0].status == "delivered":
                break
            sleep(0.02)
    finally:
        service.stop()

    outbox_entries = recorder.store.fetch_outbox_entries()

    assert outbox_entries[0].status == "delivered"
    assert service.drain_count >= 1


def test_background_outbox_runner_service_handles_new_alerts_during_open_retry_windows(tmp_path) -> None:
    recorder, clock = build_recorder(tmp_path)

    def wait_for(predicate, *, timeout: float = 1.5) -> None:
        deadline = monotonic() + timeout
        while monotonic() < deadline:
            if predicate():
                return
            sleep(0.02)
        raise AssertionError("Bedingung wurde nicht rechtzeitig erreicht")

    breaker_event = recorder.build_event(
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
    breaker_alert = recorder.build_alert(
        event=breaker_event,
        alarm_code="BREAKER_OPEN",
        severity="high",
        state="active_unacknowledged",
        message="Breaker open erkannt",
    )
    recorder.record(breaker_event, alert=breaker_alert, outbox_targets=("webhook", "smtp", "telegram"))

    webhook_batches: list[dict] = []
    smtp_attempt_bodies: list[str] = []
    telegram_batches: list[dict] = []
    telegram_attempt_states = [429, 200, 200]

    def webhook_handler(request: httpx.Request) -> httpx.Response:
        webhook_batches.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(202, json={"accepted": True})

    class FlakySmtpClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            del exc_type, exc, tb

        def send_message(self, message: EmailMessage):
            smtp_attempt_bodies.append(message.get_content())
            raise OSError("connection refused")

    def telegram_handler(request: httpx.Request) -> httpx.Response:
        telegram_batches.append(json.loads(request.content.decode("utf-8")))
        status_code = telegram_attempt_states.pop(0)
        if status_code == 200:
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(status_code, json={"ok": False})

    runner = OutboxRunner(
        store=recorder.store,
        exporters={
            "webhook": WebhookExporter(
                url="https://example.invalid/hook",
                transport=httpx.MockTransport(webhook_handler),
            ),
            "smtp": SmtpExporter(
                host="mail.example.invalid",
                port=2525,
                mail_from="alerts@example.invalid",
                rcpt_to="soc@example.invalid",
                retry_after_seconds=90,
                client_factory=lambda host, port, timeout: FlakySmtpClient(),
            ),
            "telegram": TelegramExporter(
                bot_token="token-123",
                chat_id="chat-99",
                retry_after_seconds=45,
                transport=httpx.MockTransport(telegram_handler),
            ),
        },
        retry_backoff_seconds=90,
        clock=clock,
    )
    service = BackgroundOutboxRunnerService(runner=runner, drain_interval_seconds=1.0)

    try:
        service.start_in_thread()

        wait_for(lambda: service.drain_count >= 1)
        first_entries = recorder.store.fetch_outbox_entries()
        first_status = {(entry.payload_ref, entry.target_type): entry for entry in first_entries}
        initial_now = clock.now()

        assert first_status[(breaker_alert.alert_id, "webhook")].status == "delivered"
        assert first_status[(breaker_alert.alert_id, "smtp")].status == "pending"
        assert first_status[(breaker_alert.alert_id, "smtp")].retry_count == 1
        assert first_status[(breaker_alert.alert_id, "smtp")].next_attempt_at == initial_now + timedelta(seconds=90)
        assert first_status[(breaker_alert.alert_id, "telegram")].status == "pending"
        assert first_status[(breaker_alert.alert_id, "telegram")].retry_count == 1
        assert first_status[(breaker_alert.alert_id, "telegram")].next_attempt_at == initial_now + timedelta(seconds=45)

        comms_event = recorder.build_event(
            event_type="system.communication.inverter_block_lost",
            category="system",
            severity="medium",
            source_ip="203.0.113.24",
            actor_type="system",
            component="plant-sim",
            asset_id="invb-02",
            action="simulate_comm_loss",
            result="accepted",
            alarm_code="COMM_LOSS_INVERTER_BLOCK",
            resulting_value="lost",
            tags=("fault-path", "communications", "inverter-block"),
        )
        comms_alert = recorder.build_alert(
            event=comms_event,
            alarm_code="COMM_LOSS_INVERTER_BLOCK",
            severity="medium",
            state="active_unacknowledged",
            message="Kommunikationsverlust fuer Inverter-Block invb-02",
        )
        recorder.record(comms_event, alert=comms_alert, outbox_targets=("webhook", "smtp", "telegram"))

        service.wake()
        wait_for(lambda: service.drain_count >= 2)
        second_entries = recorder.store.fetch_outbox_entries()
        second_status = {(entry.payload_ref, entry.target_type): entry for entry in second_entries}

        assert second_status[(breaker_alert.alert_id, "telegram")].retry_count == 1
        assert second_status[(comms_alert.alert_id, "webhook")].status == "delivered"
        assert second_status[(comms_alert.alert_id, "smtp")].status == "pending"
        assert second_status[(comms_alert.alert_id, "smtp")].retry_count == 1
        assert second_status[(comms_alert.alert_id, "telegram")].status == "delivered"

        clock.advance(timedelta(seconds=45))
        service.wake()
        wait_for(lambda: service.drain_count >= 3)
        third_entries = recorder.store.fetch_outbox_entries()
        third_status = {(entry.payload_ref, entry.target_type): entry for entry in third_entries}

        assert third_status[(breaker_alert.alert_id, "telegram")].status == "delivered"
        assert third_status[(breaker_alert.alert_id, "smtp")].retry_count == 1
        assert third_status[(comms_alert.alert_id, "smtp")].retry_count == 1

        now_t90 = clock.advance(timedelta(seconds=45))
        service.wake()
        wait_for(lambda: service.drain_count >= 4)
        fourth_entries = recorder.store.fetch_outbox_entries()
        fourth_status = {(entry.payload_ref, entry.target_type): entry for entry in fourth_entries}

        assert fourth_status[(breaker_alert.alert_id, "smtp")].status == "pending"
        assert fourth_status[(breaker_alert.alert_id, "smtp")].retry_count == 2
        assert fourth_status[(breaker_alert.alert_id, "smtp")].next_attempt_at == now_t90 + timedelta(seconds=90)
        assert fourth_status[(comms_alert.alert_id, "smtp")].status == "pending"
        assert fourth_status[(comms_alert.alert_id, "smtp")].retry_count == 2
        assert fourth_status[(comms_alert.alert_id, "smtp")].next_attempt_at == now_t90 + timedelta(seconds=90)

    finally:
        service.stop()

    assert len(webhook_batches) == 2
    assert len(telegram_batches) == 3
    assert len(smtp_attempt_bodies) == 3
    assert len(webhook_batches[0]["items"]) == 1
    assert len(webhook_batches[1]["items"]) == 1
    assert "BREAKER_OPEN" in telegram_batches[0]["text"]
    assert "COMM_LOSS_INVERTER_BLOCK" in telegram_batches[1]["text"]
    assert "BREAKER_OPEN" in telegram_batches[2]["text"]
    assert "BREAKER_OPEN" in smtp_attempt_bodies[2]
    assert "COMM_LOSS_INVERTER_BLOCK" in smtp_attempt_bodies[2]


def test_background_outbox_runner_service_handles_three_alert_waves_with_mixed_targets(tmp_path) -> None:
    recorder, clock = build_recorder(tmp_path)

    def wait_for(predicate, *, timeout: float = 1.5) -> None:
        deadline = monotonic() + timeout
        while monotonic() < deadline:
            if predicate():
                return
            sleep(0.02)
        raise AssertionError("Bedingung wurde nicht rechtzeitig erreicht")

    def status_map():
        return {(entry.payload_ref, entry.target_type): entry for entry in recorder.store.fetch_outbox_entries()}

    breaker_event = recorder.build_event(
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
    breaker_alert = recorder.build_alert(
        event=breaker_event,
        alarm_code="BREAKER_OPEN",
        severity="high",
        state="active_unacknowledged",
        message="Breaker open erkannt",
    )
    recorder.record(breaker_event, alert=breaker_alert, outbox_targets=("webhook", "smtp", "telegram"))

    webhook_batches: list[dict] = []
    smtp_attempt_bodies: list[str] = []
    telegram_batches: list[dict] = []
    telegram_attempt_states = [429, 200, 200, 200]

    def webhook_handler(request: httpx.Request) -> httpx.Response:
        webhook_batches.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(202, json={"accepted": True})

    class FlakySmtpClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            del exc_type, exc, tb

        def send_message(self, message: EmailMessage):
            smtp_attempt_bodies.append(message.get_content())
            raise OSError("connection refused")

    def telegram_handler(request: httpx.Request) -> httpx.Response:
        telegram_batches.append(json.loads(request.content.decode("utf-8")))
        status_code = telegram_attempt_states.pop(0)
        if status_code == 200:
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(status_code, json={"ok": False})

    runner = OutboxRunner(
        store=recorder.store,
        exporters={
            "webhook": WebhookExporter(
                url="https://example.invalid/hook",
                transport=httpx.MockTransport(webhook_handler),
            ),
            "smtp": SmtpExporter(
                host="mail.example.invalid",
                port=2525,
                mail_from="alerts@example.invalid",
                rcpt_to="soc@example.invalid",
                retry_after_seconds=90,
                client_factory=lambda host, port, timeout: FlakySmtpClient(),
            ),
            "telegram": TelegramExporter(
                bot_token="token-123",
                chat_id="chat-99",
                retry_after_seconds=45,
                transport=httpx.MockTransport(telegram_handler),
            ),
        },
        retry_backoff_seconds=90,
        clock=clock,
    )
    service = BackgroundOutboxRunnerService(runner=runner, drain_interval_seconds=0.2)

    try:
        initial_now = clock.now()
        service.start_in_thread()

        wait_for(
            lambda: (
                (breaker_alert.alert_id, "webhook") in status_map()
                and status_map()[(breaker_alert.alert_id, "webhook")].status == "delivered"
                and status_map()[(breaker_alert.alert_id, "smtp")].retry_count == 1
                and status_map()[(breaker_alert.alert_id, "telegram")].retry_count == 1
            )
        )
        first_status = status_map()
        assert first_status[(breaker_alert.alert_id, "smtp")].next_attempt_at == initial_now + timedelta(seconds=90)
        assert first_status[(breaker_alert.alert_id, "telegram")].next_attempt_at == initial_now + timedelta(seconds=45)

        comms_event = recorder.build_event(
            event_type="system.communication.inverter_block_lost",
            category="system",
            severity="medium",
            source_ip="203.0.113.24",
            actor_type="system",
            component="plant-sim",
            asset_id="invb-02",
            action="simulate_comm_loss",
            result="accepted",
            alarm_code="COMM_LOSS_INVERTER_BLOCK",
            resulting_value="lost",
            tags=("fault-path", "communications", "inverter-block"),
        )
        comms_alert = recorder.build_alert(
            event=comms_event,
            alarm_code="COMM_LOSS_INVERTER_BLOCK",
            severity="medium",
            state="active_unacknowledged",
            message="Kommunikationsverlust fuer Inverter-Block invb-02",
        )
        recorder.record(comms_event, alert=comms_alert, outbox_targets=("webhook", "smtp", "telegram"))

        service.wake()
        wait_for(
            lambda: (
                (comms_alert.alert_id, "webhook") in status_map()
                and status_map()[(comms_alert.alert_id, "webhook")].status == "delivered"
                and status_map()[(comms_alert.alert_id, "smtp")].retry_count == 1
                and status_map()[(comms_alert.alert_id, "telegram")].status == "delivered"
            )
        )

        clock.advance(timedelta(seconds=45))
        wait_for(lambda: status_map()[(breaker_alert.alert_id, "telegram")].status == "delivered")

        low_output_event = recorder.build_event(
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
        low_output_alert = recorder.build_alert(
            event=low_output_event,
            alarm_code="LOW_SITE_OUTPUT_UNEXPECTED",
            severity="high",
            state="active_unacknowledged",
            message="Parkleistung deutlich unter erwarteter Verfuegbarkeit",
        )
        recorder.record(low_output_event, alert=low_output_alert, outbox_targets=("webhook", "telegram"))

        service.wake()
        wait_for(
            lambda: (
                (low_output_alert.alert_id, "webhook") in status_map()
                and status_map()[(low_output_alert.alert_id, "webhook")].status == "delivered"
                and status_map()[(low_output_alert.alert_id, "telegram")].status == "delivered"
            )
        )

        now_t90 = clock.advance(timedelta(seconds=45))
        wait_for(
            lambda: (
                status_map()[(breaker_alert.alert_id, "smtp")].retry_count == 2
                and status_map()[(comms_alert.alert_id, "smtp")].retry_count == 2
            )
        )
        final_status = status_map()

    finally:
        service.stop()

    assert final_status[(breaker_alert.alert_id, "webhook")].status == "delivered"
    assert final_status[(comms_alert.alert_id, "webhook")].status == "delivered"
    assert final_status[(low_output_alert.alert_id, "webhook")].status == "delivered"
    assert final_status[(breaker_alert.alert_id, "telegram")].status == "delivered"
    assert final_status[(comms_alert.alert_id, "telegram")].status == "delivered"
    assert final_status[(low_output_alert.alert_id, "telegram")].status == "delivered"
    assert final_status[(breaker_alert.alert_id, "smtp")].status == "pending"
    assert final_status[(comms_alert.alert_id, "smtp")].status == "pending"
    assert final_status[(breaker_alert.alert_id, "smtp")].next_attempt_at == now_t90 + timedelta(seconds=90)
    assert final_status[(comms_alert.alert_id, "smtp")].next_attempt_at == now_t90 + timedelta(seconds=90)
    assert final_status[(breaker_alert.alert_id, "smtp")].last_error == "SMTP-Transportfehler: OSError"
    assert final_status[(comms_alert.alert_id, "smtp")].last_error == "SMTP-Transportfehler: OSError"

    assert len(webhook_batches) == 3
    assert len(telegram_batches) == 4
    assert len(smtp_attempt_bodies) == 3
    assert len(webhook_batches[0]["items"]) == 1
    assert len(webhook_batches[1]["items"]) == 1
    assert len(webhook_batches[2]["items"]) == 1
    assert "BREAKER_OPEN" in telegram_batches[0]["text"]
    assert "COMM_LOSS_INVERTER_BLOCK" in telegram_batches[1]["text"]
    assert "BREAKER_OPEN" in telegram_batches[2]["text"]
    assert "LOW_SITE_OUTPUT_UNEXPECTED" in telegram_batches[3]["text"]
    assert "BREAKER_OPEN" in smtp_attempt_bodies[0]
    assert "COMM_LOSS_INVERTER_BLOCK" in smtp_attempt_bodies[1]
    assert "BREAKER_OPEN" in smtp_attempt_bodies[2]
    assert "COMM_LOSS_INVERTER_BLOCK" in smtp_attempt_bodies[2]
    assert service.drain_count >= 5
