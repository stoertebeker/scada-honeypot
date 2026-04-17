from datetime import UTC, datetime

import pytest

from honeypot.event_core.models import AlertRecord, EventRecord
from honeypot.exporter_sdk import ExportDelivery, LocalTestExporter


def build_event() -> EventRecord:
    return EventRecord(
        timestamp=datetime(2026, 4, 17, 10, 0, tzinfo=UTC),
        event_id="evt_exporter_sdk",
        correlation_id="corr_exporter_sdk",
        event_type="process.breaker.state_changed",
        category="process",
        severity="high",
        source_ip="203.0.113.24",
        actor_type="remote_client",
        component="plant-sim",
        asset_id="grid-01",
        action="breaker_open_request",
        result="accepted",
    )


def build_alert() -> AlertRecord:
    return AlertRecord(
        alert_id="alt_exporter_sdk",
        event_id="evt_exporter_sdk",
        correlation_id="corr_exporter_sdk",
        alarm_code="BREAKER_OPEN",
        severity="high",
        state="active_unacknowledged",
        component="plant-sim",
        asset_id="grid-01",
        message="Breaker open erkannt",
        created_at=datetime(2026, 4, 17, 10, 0, tzinfo=UTC),
    )


def test_export_delivery_validates_retry_contract() -> None:
    delivered = ExportDelivery(status="delivered", accepted_items=2, detail="ok")
    retry = ExportDelivery(status="retry_later", accepted_items=0, retry_after_seconds=30, detail="later")

    assert delivered.status == "delivered"
    assert retry.status == "retry_later"

    with pytest.raises(ValueError, match="retry_later"):
        ExportDelivery(status="retry_later", accepted_items=0)

    with pytest.raises(ValueError, match="retry_after_seconds"):
        ExportDelivery(status="delivered", accepted_items=1, retry_after_seconds=5)


def test_local_test_exporter_reports_capabilities_and_health() -> None:
    exporter = LocalTestExporter()

    capabilities = exporter.capabilities()
    health = exporter.health()

    assert capabilities.supports_events is True
    assert capabilities.supports_alerts is True
    assert capabilities.max_batch_size == 250
    assert health.status == "healthy"


def test_local_test_exporter_captures_event_and_alert_batches() -> None:
    exporter = LocalTestExporter()

    event_delivery = exporter.deliver_event_batch((build_event(),))
    alert_delivery = exporter.deliver_alert_batch((build_alert(),))

    assert event_delivery.status == "delivered"
    assert event_delivery.accepted_items == 1
    assert alert_delivery.status == "delivered"
    assert alert_delivery.accepted_items == 1
    assert exporter.delivered_event_batches[0][0].event_id == "evt_exporter_sdk"
    assert exporter.delivered_alert_batches[0][0].alert_id == "alt_exporter_sdk"


def test_local_test_exporter_forced_retry_keeps_batches_local_only_on_success() -> None:
    exporter = LocalTestExporter(fail_delivery=True, retry_after_seconds=45)

    delivery = exporter.deliver_event_batch((build_event(),))

    assert delivery.status == "retry_later"
    assert delivery.retry_after_seconds == 45
    assert exporter.delivered_event_batches == []
    assert exporter.health().status == "degraded"


def test_local_test_exporter_rejects_unknown_config_keys() -> None:
    exporter = LocalTestExporter()
    exporter.validate_config({"enabled": True})

    with pytest.raises(ValueError, match="Konfigurationsschluessel"):
        exporter.validate_config({"url": "https://example.invalid"})
