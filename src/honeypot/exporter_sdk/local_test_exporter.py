"""Lokaler Test-Exporter ohne Netzwerkabhaengigkeit."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from honeypot.event_core.models import AlertRecord, EventRecord
from honeypot.exporter_sdk.contracts import ExportDelivery, ExporterCapabilities, ExporterHealth


@dataclass(slots=True)
class LocalTestExporter:
    """Speichert ausgelieferte Batches nur im Speicher fuer Vertriebs- und Runner-Tests."""

    exporter_id: str = "local-test-exporter"
    target_type: str = "local-test"
    fail_delivery: bool = False
    retry_after_seconds: int = 30
    delivered_event_batches: list[tuple[EventRecord, ...]] = field(default_factory=list, init=False, repr=False)
    delivered_alert_batches: list[tuple[AlertRecord, ...]] = field(default_factory=list, init=False, repr=False)

    def capabilities(self) -> ExporterCapabilities:
        return ExporterCapabilities(
            supports_events=True,
            supports_alerts=True,
            max_batch_size=250,
        )

    def validate_config(self, config: Mapping[str, Any]) -> None:
        unsupported_keys = tuple(sorted(str(key) for key in config if key not in {"enabled", "fail_delivery"}))
        if unsupported_keys:
            raise ValueError(f"LocalTestExporter kennt keine Konfigurationsschluessel: {', '.join(unsupported_keys)}")

    def health(self) -> ExporterHealth:
        if self.fail_delivery:
            return ExporterHealth(status="degraded", detail="Lieferungen sind fuer Tests auf retry_later gestellt")
        return ExporterHealth(status="healthy", detail="Lokaler Capture-Exporter bereit")

    def deliver_event_batch(self, batch: Sequence[EventRecord]) -> ExportDelivery:
        return self._deliver(batch=batch, sink=self.delivered_event_batches)

    def deliver_alert_batch(self, batch: Sequence[AlertRecord]) -> ExportDelivery:
        return self._deliver(batch=batch, sink=self.delivered_alert_batches)

    def _deliver(self, *, batch: Sequence[Any], sink: list[tuple[Any, ...]]) -> ExportDelivery:
        normalized_batch = tuple(batch)
        if self.fail_delivery:
            return ExportDelivery(
                status="retry_later",
                accepted_items=0,
                retry_after_seconds=self.retry_after_seconds,
                detail="Lokaler Test-Exporter erzwingt Retry fuer diesen Batch",
            )

        sink.append(normalized_batch)
        return ExportDelivery(
            status="delivered",
            accepted_items=len(normalized_batch),
            detail="Batch lokal erfasst",
        )
