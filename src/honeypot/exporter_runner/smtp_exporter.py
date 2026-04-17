"""SMTP-Exporter auf Basis des Exporter-SDK-Vertrags."""

from __future__ import annotations

import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Callable, Mapping, Protocol, Sequence

from honeypot.event_core.models import AlertRecord, EventRecord
from honeypot.exporter_sdk import ExportDelivery, ExporterCapabilities, ExporterHealth


class SmtpClient(Protocol):
    """Minimale SMTP-Client-Schnittstelle fuer Tests und Runtime."""

    def __enter__(self) -> "SmtpClient": ...

    def __exit__(self, exc_type, exc, tb) -> None: ...

    def send_message(self, message: EmailMessage) -> Mapping[str, tuple[int, bytes]]: ...


@dataclass(slots=True)
class SmtpExporter:
    """Liefert Alert-Batches als einfache SMTP-Nachricht an einen Zielserver."""

    host: str
    mail_from: str
    rcpt_to: str
    port: int = 25
    retry_after_seconds: int = 30
    timeout_seconds: float = 5.0
    exporter_id: str = "smtp-exporter"
    target_type: str = "smtp"
    subject_prefix: str = "SCADA Honeypot Alert Batch"
    client_factory: Callable[[str, int, float], SmtpClient] | None = None

    def capabilities(self) -> ExporterCapabilities:
        return ExporterCapabilities(
            supports_events=False,
            supports_alerts=True,
            max_batch_size=50,
        )

    def validate_config(self, config: Mapping[str, Any]) -> None:
        host = str(config.get("host", self.host)).strip()
        mail_from = str(config.get("mail_from", self.mail_from)).strip()
        rcpt_to = str(config.get("rcpt_to", self.rcpt_to)).strip()
        if not host:
            raise ValueError("SmtpExporter braucht einen SMTP-Host")
        if not mail_from:
            raise ValueError("SmtpExporter braucht einen Absender")
        if not rcpt_to:
            raise ValueError("SmtpExporter braucht einen Empfaenger")

    def health(self) -> ExporterHealth:
        return ExporterHealth(status="healthy", detail=f"SMTP-Ziel {self.host}:{self.port} konfiguriert")

    def deliver_event_batch(self, batch: Sequence[EventRecord]) -> ExportDelivery:
        del batch
        return ExportDelivery(
            status="retry_later",
            accepted_items=0,
            retry_after_seconds=self.retry_after_seconds,
            detail="SmtpExporter unterstuetzt keine Event-Batches",
        )

    def deliver_alert_batch(self, batch: Sequence[AlertRecord]) -> ExportDelivery:
        if not batch:
            return ExportDelivery(
                status="delivered",
                accepted_items=0,
                detail="Leerer Alert-Batch wurde uebersprungen",
            )

        message = self._build_message(batch)
        try:
            with self._connect_client() as client:
                refused_recipients = client.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            return ExportDelivery(
                status="retry_later",
                accepted_items=0,
                retry_after_seconds=self.retry_after_seconds,
                detail=f"SMTP-Transportfehler: {exc.__class__.__name__}",
            )

        if refused_recipients:
            return ExportDelivery(
                status="retry_later",
                accepted_items=0,
                retry_after_seconds=self.retry_after_seconds,
                detail="SMTP verweigerte mindestens einen Empfaenger",
            )

        return ExportDelivery(
            status="delivered",
            accepted_items=len(batch),
            detail=f"SMTP akzeptierte Batch fuer {self.rcpt_to}",
        )

    def _connect_client(self) -> SmtpClient:
        if self.client_factory is not None:
            return self.client_factory(self.host, self.port, self.timeout_seconds)
        return smtplib.SMTP(self.host, self.port, timeout=self.timeout_seconds)

    def _build_message(self, batch: Sequence[AlertRecord]) -> EmailMessage:
        message = EmailMessage()
        message["From"] = self.mail_from
        message["To"] = self.rcpt_to
        message["Subject"] = f"{self.subject_prefix} ({len(batch)})"
        body_lines = [self.subject_prefix]
        for alert in batch:
            body_lines.append(
                f"- {alert.alarm_code} | {alert.severity.upper()} | {alert.asset_id} | {alert.state} | {alert.message}"
            )
        message.set_content("\n".join(body_lines))
        return message
