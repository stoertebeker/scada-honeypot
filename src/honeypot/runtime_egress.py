"""Lokale Egress-Gates fuer bewusst freigegebene Exportziele."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from honeypot.config_core import RuntimeConfig
from honeypot.exporter_runner import SmtpExporter, TelegramExporter, WebhookExporter
from honeypot.exporter_sdk import HoneypotExporter


@dataclass(frozen=True, slots=True)
class EgressTarget:
    """Beschreibt ein bewusst zu genehmigendes Exportziel."""

    target_type: str
    host: str
    port: int

    @property
    def spec(self) -> str:
        return f"{self.target_type}:{self.host}:{self.port}"


def enforce_runtime_egress_policy(
    *,
    config: RuntimeConfig,
    exporters: dict[str, HoneypotExporter],
) -> tuple[str, ...]:
    """Prueft, ob alle aktiven Exportziele explizit freigegeben wurden."""

    planned_targets = planned_egress_targets(exporters)
    if not planned_targets:
        return ()

    approved_targets = set(config.approved_egress_targets)
    missing_targets = tuple(target.spec for target in planned_targets if target.spec not in approved_targets)
    if missing_targets:
        missing_list = ", ".join(missing_targets)
        raise RuntimeError(
            "Egress-Freigabe fehlt fuer aktive Exportziele: "
            f"{missing_list}. APPROVED_EGRESS_TARGETS muss diese Ziele explizit enthalten."
        )
    return tuple(target.spec for target in planned_targets)


def planned_egress_targets(exporters: dict[str, HoneypotExporter]) -> tuple[EgressTarget, ...]:
    """Leitet normalisierte Ziel-Spezifikationen aus aktiven Exportern ab."""

    targets: list[EgressTarget] = []
    for target_type, exporter in exporters.items():
        target = _target_from_exporter(target_type=target_type, exporter=exporter)
        if target.spec not in {existing.spec for existing in targets}:
            targets.append(target)
    return tuple(targets)


def _target_from_exporter(*, target_type: str, exporter: HoneypotExporter) -> EgressTarget:
    if isinstance(exporter, WebhookExporter):
        host, port = _url_host_port(exporter.url)
        return EgressTarget(target_type=target_type, host=host, port=port)
    if isinstance(exporter, TelegramExporter):
        host, port = _url_host_port(exporter.api_base_url)
        return EgressTarget(target_type=target_type, host=host, port=port)
    if isinstance(exporter, SmtpExporter):
        return EgressTarget(target_type=target_type, host=exporter.host.lower(), port=exporter.port)
    raise RuntimeError(f"unbekannter Exporter-Typ fuer Egress-Gate: {exporter.__class__.__name__}")


def _url_host_port(raw_url: str) -> tuple[str, int]:
    parts = urlsplit(raw_url)
    if not parts.hostname:
        raise RuntimeError(f"ungueltiges Egress-Ziel ohne Host: {raw_url}")
    if parts.port is not None:
        return parts.hostname.lower(), parts.port
    if parts.scheme == "https":
        return parts.hostname.lower(), 443
    if parts.scheme == "http":
        return parts.hostname.lower(), 80
    raise RuntimeError(f"ungueltiges Egress-Ziel ohne unterstuetztes Schema: {raw_url}")
