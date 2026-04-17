"""Webhook-Exporter auf Basis des Exporter-SDK-Vertrags."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import httpx

from honeypot.event_core.models import AlertRecord, EventRecord
from honeypot.exporter_sdk import ExportDelivery, ExporterCapabilities, ExporterHealth


@dataclass(slots=True)
class WebhookExporter:
    """Liefert Event- oder Alert-Batches an einen konfigurierten Webhook."""

    url: str
    retry_after_seconds: int = 30
    timeout_seconds: float = 5.0
    exporter_id: str = "webhook-exporter"
    target_type: str = "webhook"
    transport: httpx.BaseTransport | None = None

    def capabilities(self) -> ExporterCapabilities:
        return ExporterCapabilities(
            supports_events=True,
            supports_alerts=True,
            max_batch_size=100,
        )

    def validate_config(self, config: Mapping[str, Any]) -> None:
        resolved_url = str(config.get("url", self.url)).strip()
        if not resolved_url:
            raise ValueError("WebhookExporter braucht eine URL")

    def health(self) -> ExporterHealth:
        return ExporterHealth(status="healthy", detail=f"Webhook-Ziel {self.url} konfiguriert")

    def deliver_event_batch(self, batch: Sequence[EventRecord]) -> ExportDelivery:
        return self._post_payload(payload_kind="event", batch=batch)

    def deliver_alert_batch(self, batch: Sequence[AlertRecord]) -> ExportDelivery:
        return self._post_payload(payload_kind="alert", batch=batch)

    def _post_payload(self, *, payload_kind: str, batch: Sequence[Any]) -> ExportDelivery:
        payload = {
            "exporter_id": self.exporter_id,
            "target_type": self.target_type,
            "payload_kind": payload_kind,
            "items": [item.model_dump(mode="json") for item in batch],
        }
        try:
            with httpx.Client(timeout=self.timeout_seconds, transport=self.transport, trust_env=False) as client:
                response = client.post(self.url, json=payload)
        except httpx.HTTPError as exc:
            return ExportDelivery(
                status="retry_later",
                accepted_items=0,
                retry_after_seconds=self.retry_after_seconds,
                detail=f"Webhook-Transportfehler: {exc.__class__.__name__}",
            )

        if 200 <= response.status_code < 300:
            return ExportDelivery(
                status="delivered",
                accepted_items=len(batch),
                detail=f"Webhook akzeptierte Batch mit Status {response.status_code}",
            )

        return ExportDelivery(
            status="retry_later",
            accepted_items=0,
            retry_after_seconds=self.retry_after_seconds,
            detail=f"Webhook antwortete mit HTTP {response.status_code}",
        )
