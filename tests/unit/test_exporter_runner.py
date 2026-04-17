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
