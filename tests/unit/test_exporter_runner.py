import json
from datetime import UTC, datetime, timedelta

import httpx

from honeypot.event_core import EventRecorder
from honeypot.exporter_runner import OutboxRunner, WebhookExporter
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
