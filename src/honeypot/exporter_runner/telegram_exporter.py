"""Telegram-Exporter auf Basis des Exporter-SDK-Vertrags."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import httpx

from honeypot.event_core.models import AlertRecord, EventRecord
from honeypot.exporter_sdk import ExportDelivery, ExporterCapabilities, ExporterHealth


@dataclass(slots=True)
class TelegramExporter:
    """Liefert Alert-Batches an einen Telegram-Bot-Chat."""

    bot_token: str
    chat_id: str
    retry_after_seconds: int = 30
    timeout_seconds: float = 5.0
    exporter_id: str = "telegram-exporter"
    target_type: str = "telegram"
    api_base_url: str = "https://api.telegram.org"
    transport: httpx.BaseTransport | None = None

    def capabilities(self) -> ExporterCapabilities:
        return ExporterCapabilities(
            supports_events=False,
            supports_alerts=True,
            max_batch_size=25,
        )

    def validate_config(self, config: Mapping[str, Any]) -> None:
        bot_token = str(config.get("bot_token", self.bot_token)).strip()
        chat_id = str(config.get("chat_id", self.chat_id)).strip()
        if not bot_token:
            raise ValueError("TelegramExporter braucht einen Bot-Token")
        if not chat_id:
            raise ValueError("TelegramExporter braucht eine Chat-ID")

    def health(self) -> ExporterHealth:
        return ExporterHealth(status="healthy", detail=f"Telegram-Ziel fuer Chat {self.chat_id} konfiguriert")

    def deliver_event_batch(self, batch: Sequence[EventRecord]) -> ExportDelivery:
        del batch
        return ExportDelivery(
            status="retry_later",
            accepted_items=0,
            retry_after_seconds=self.retry_after_seconds,
            detail="TelegramExporter unterstuetzt keine Event-Batches",
        )

    def deliver_alert_batch(self, batch: Sequence[AlertRecord]) -> ExportDelivery:
        if not batch:
            return ExportDelivery(
                status="delivered",
                accepted_items=0,
                detail="Leerer Alert-Batch wurde uebersprungen",
            )

        payload = {
            "chat_id": self.chat_id,
            "text": self._build_message(batch),
            "disable_web_page_preview": True,
        }
        url = f"{self.api_base_url.rstrip('/')}/bot{self.bot_token}/sendMessage"
        try:
            with httpx.Client(timeout=self.timeout_seconds, transport=self.transport, trust_env=False) as client:
                response = client.post(url, json=payload)
        except httpx.HTTPError as exc:
            return ExportDelivery(
                status="retry_later",
                accepted_items=0,
                retry_after_seconds=self.retry_after_seconds,
                detail=f"Telegram-Transportfehler: {exc.__class__.__name__}",
            )

        if 200 <= response.status_code < 300:
            return ExportDelivery(
                status="delivered",
                accepted_items=len(batch),
                detail=f"Telegram akzeptierte Batch mit Status {response.status_code}",
            )

        return ExportDelivery(
            status="retry_later",
            accepted_items=0,
            retry_after_seconds=self.retry_after_seconds,
            detail=f"Telegram antwortete mit HTTP {response.status_code}",
        )

    def _build_message(self, batch: Sequence[AlertRecord]) -> str:
        lines = ["SCADA Honeypot Alert Batch"]
        for alert in batch:
            lines.append(
                f"- {alert.alarm_code} | {alert.severity.upper()} | {alert.asset_id} | {alert.state} | {alert.message}"
            )
        return "\n".join(lines)
