"""Exporter-Vertraege fuer Outbox-getriebene Zielsysteme."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping, Protocol, Sequence

from honeypot.event_core.models import AlertRecord, EventRecord

ExporterHealthStatus = Literal["healthy", "degraded", "unavailable"]
DeliveryStatus = Literal["delivered", "retry_later"]


@dataclass(frozen=True, slots=True)
class ExporterCapabilities:
    """Beschreibt die minimalen technischen Faehigkeiten eines Exporters."""

    supports_events: bool
    supports_alerts: bool
    max_batch_size: int = 100


@dataclass(frozen=True, slots=True)
class ExporterHealth:
    """Leichter Health-Zustand fuer Runner und Tests."""

    status: ExporterHealthStatus
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class ExportDelivery:
    """Kontrolliertes Ergebnis einer Batch-Auslieferung."""

    status: DeliveryStatus
    accepted_items: int
    retry_after_seconds: int | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.accepted_items < 0:
            raise ValueError("accepted_items darf nicht negativ sein")
        if self.status == "retry_later":
            if self.retry_after_seconds is None or self.retry_after_seconds <= 0:
                raise ValueError("retry_later erfordert retry_after_seconds > 0")
            return
        if self.retry_after_seconds is not None:
            raise ValueError("retry_after_seconds ist nur fuer retry_later erlaubt")


class HoneypotExporter(Protocol):
    """Minimaler Vertrag fuer anbaubare Exporter."""

    exporter_id: str
    target_type: str

    def capabilities(self) -> ExporterCapabilities:
        """Meldet Event-/Alert-Unterstuetzung und grobe Batch-Grenzen."""

    def validate_config(self, config: Mapping[str, Any]) -> None:
        """Validiert exporter-spezifische Konfiguration oder wirft ValueError."""

    def health(self) -> ExporterHealth:
        """Liefert einen leichten Health-Zustand fuer Tests und spaetere Runner."""

    def deliver_event_batch(self, batch: Sequence[EventRecord]) -> ExportDelivery:
        """Verarbeitet eine Event-Lieferung fuer diesen Exporter."""

    def deliver_alert_batch(self, batch: Sequence[AlertRecord]) -> ExportDelivery:
        """Verarbeitet eine Alert-Lieferung fuer diesen Exporter."""
