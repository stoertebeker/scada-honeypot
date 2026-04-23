"""Deployment-Gates fuer kontrollierte exposed-research-Runtime."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import urlsplit

from honeypot.config_core import RuntimeConfig
from honeypot.exporter_runner import SmtpExporter, TelegramExporter, WebhookExporter
from honeypot.exporter_sdk import HoneypotExporter

DOCUMENTATION_NETWORKS = (
    ip_network("192.0.2.0/24"),
    ip_network("198.51.100.0/24"),
    ip_network("203.0.113.0/24"),
)
DOCUMENTATION_HOST_SUFFIXES = (
    ".invalid",
    ".example",
    ".test",
    ".localhost",
)


@dataclass(frozen=True, slots=True)
class PublicIngressMapping:
    """Beschreibt den bewusst freigegebenen externen Ingress-Pfad."""

    service: str
    public_port: int
    internal_port: int

    @property
    def spec(self) -> str:
        return f"{self.service}:{self.public_port}:{self.internal_port}"


def append_exposed_research_finding(
    *,
    config: RuntimeConfig,
    status: str,
    summary: str,
    details: tuple[str, ...] = (),
) -> Path:
    """Schreibt einen nachvollziehbaren Sweep-Eintrag fuer exposed-research."""

    findings_path = config.findings_log_path
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    is_new_file = not findings_path.exists()
    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    public_mappings = ", ".join(config.public_ingress_mappings) or "none"
    recipients = ", ".join(config.approved_egress_recipients) or "none"

    with findings_path.open("a", encoding="utf-8") as handle:
        if is_new_file:
            handle.write("# Exposed Research Findings\n\n")
            handle.write(
                "Automatisch erzeugte Sweep-Eintraege fuer `uv run python -m honeypot.main --verify-exposed-research`.\n\n"
            )
        handle.write(f"## {timestamp} verify-exposed-research {status}\n")
        handle.write(f"- site_code: `{config.site_code}`\n")
        handle.write(f"- watch_officer: `{config.watch_officer_name or 'unset'}`\n")
        handle.write(f"- duty_engineer: `{config.duty_engineer_name or 'unset'}`\n")
        handle.write(f"- public_ingress_mappings: `{public_mappings}`\n")
        handle.write(f"- approved_egress_recipients: `{recipients}`\n")
        handle.write(f"- summary: {summary}\n")
        for detail in details:
            handle.write(f"- {detail}\n")
        handle.write("\n")
    return findings_path


def enforce_exposed_research_policy(
    *,
    config: RuntimeConfig,
    exporters: dict[str, HoneypotExporter],
) -> tuple[str, ...]:
    """Erzwingt die letzten Runtime-Gates fuer echten exposed-research-Betrieb."""

    if not config.exposed_research_enabled:
        return ()

    if not config.allow_nonlocal_bind:
        raise RuntimeError(
            "exposed-research erfordert ALLOW_NONLOCAL_BIND=1 fuer den bewusst freigegebenen Ingress-Pfad"
        )

    if not config.watch_officer_name:
        raise RuntimeError("exposed-research erfordert einen benannten WATCH_OFFICER_NAME")
    if not config.duty_engineer_name:
        raise RuntimeError("exposed-research erfordert einen benannten DUTY_ENGINEER_NAME")

    mappings = planned_public_ingress_mappings(config)
    if len(mappings) != 2:
        raise RuntimeError(
            "exposed-research erfordert PUBLIC_INGRESS_MAPPINGS fuer modbus und hmi im Format service:public_port:internal_port"
        )

    expected_mappings = {
        PublicIngressMapping("modbus", mapping.public_port, config.modbus_port).spec
        for mapping in mappings
        if mapping.service == "modbus"
    } | {
        PublicIngressMapping("hmi", mapping.public_port, config.hmi_port).spec
        for mapping in mappings
        if mapping.service == "hmi"
    }
    provided_mappings = {mapping.spec for mapping in mappings}
    if provided_mappings != expected_mappings:
        raise RuntimeError(
            "PUBLIC_INGRESS_MAPPINGS muessen exakt die internen Runtime-Ports fuer modbus und hmi referenzieren"
        )

    approved_recipients = {
        recipient.split(":", 1)[0]: recipient.split(":", 1)[1]
        for recipient in config.approved_egress_recipients
        if ":" in recipient
    }
    active_target_types = {target_type for target_type in exporters}
    missing_recipient_types = tuple(
        sorted(target_type for target_type in active_target_types if target_type not in approved_recipients)
    )
    if missing_recipient_types:
        missing_list = ", ".join(missing_recipient_types)
        raise RuntimeError(
            "exposed-research erfordert benannte Export-Empfaenger fuer aktive Kanaele: "
            f"{missing_list}. APPROVED_EGRESS_RECIPIENTS muss target_type:name enthalten."
        )

    placeholder_targets = tuple(
        sorted(
            target_type
            for target_type, exporter in exporters.items()
            if _uses_documentation_only_target(exporter)
        )
    )
    if placeholder_targets:
        placeholder_list = ", ".join(placeholder_targets)
        raise RuntimeError(
            "exposed-research verbietet Dokumentations- oder Platzhalterziele fuer aktive Exporter: "
            f"{placeholder_list}. Echte Zielsysteme muessen gesetzt sein."
        )

    return tuple(sorted(provided_mappings))


def planned_public_ingress_mappings(config: RuntimeConfig) -> tuple[PublicIngressMapping, ...]:
    """Normalisiert die oeffentlich dokumentierten Ingress-Mappings."""

    mappings: list[PublicIngressMapping] = []
    for raw_mapping in config.public_ingress_mappings:
        service, public_port, internal_port = _parse_public_ingress_mapping(raw_mapping)
        mapping = PublicIngressMapping(service=service, public_port=public_port, internal_port=internal_port)
        if mapping.spec not in {existing.spec for existing in mappings}:
            mappings.append(mapping)
    return tuple(mappings)


def _parse_public_ingress_mapping(raw_mapping: str) -> tuple[str, int, int]:
    parts = raw_mapping.split(":")
    if len(parts) != 3:
        raise RuntimeError(
            "ungueltiges PUBLIC_INGRESS_MAPPINGS-Element; erwartet service:public_port:internal_port"
        )
    service = parts[0].strip().lower()
    if service not in {"modbus", "hmi"}:
        raise RuntimeError("PUBLIC_INGRESS_MAPPINGS unterstuetzt nur modbus und hmi")
    try:
        public_port = int(parts[1])
        internal_port = int(parts[2])
    except ValueError as exc:
        raise RuntimeError(
            "ungueltiges PUBLIC_INGRESS_MAPPINGS-Element; Ports muessen ganzzahlig sein"
        ) from exc
    if not (1 <= public_port <= 65535 and 1 <= internal_port <= 65535):
        raise RuntimeError(
            "ungueltiges PUBLIC_INGRESS_MAPPINGS-Element; Ports muessen zwischen 1 und 65535 liegen"
        )
    return service, public_port, internal_port


def _uses_documentation_only_target(exporter: HoneypotExporter) -> bool:
    host = _target_host(exporter)
    if any(host.endswith(suffix) for suffix in DOCUMENTATION_HOST_SUFFIXES):
        return True
    try:
        parsed_ip = ip_address(host)
    except ValueError:
        return False
    return any(parsed_ip in network for network in DOCUMENTATION_NETWORKS)


def _target_host(exporter: HoneypotExporter) -> str:
    if isinstance(exporter, WebhookExporter):
        return _hostname_from_url(exporter.url)
    if isinstance(exporter, TelegramExporter):
        return _hostname_from_url(exporter.api_base_url)
    if isinstance(exporter, SmtpExporter):
        return exporter.host.lower()
    raise RuntimeError(f"unbekannter Exporter-Typ fuer exposed-research-Gate: {exporter.__class__.__name__}")


def _hostname_from_url(raw_url: str) -> str:
    parts = urlsplit(raw_url)
    if not parts.hostname:
        raise RuntimeError(f"ungueltige Exporter-URL ohne Host: {raw_url}")
    return parts.hostname.lower()
