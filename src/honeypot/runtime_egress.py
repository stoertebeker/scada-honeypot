"""Lokale Egress-Gates fuer bewusst freigegebene Exportziele."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
import socket
from urllib.parse import urlsplit

from honeypot.config_core import RuntimeConfig
from honeypot.exporter_runner import SmtpExporter, TelegramExporter, WebhookExporter
from honeypot.exporter_runner.pinned_http import PinnedHttpTransport
from honeypot.exporter_sdk import HoneypotExporter
from honeypot.weather_core.open_meteo import OPEN_METEO_ARCHIVE_BASE_URL, OPEN_METEO_LIVE_BASE_URL

WEATHER_LIVE_EGRESS_TYPE = "weather-open-meteo"
WEATHER_ARCHIVE_EGRESS_TYPE = "weather-open-meteo-archive"


@dataclass(frozen=True, slots=True)
class EgressTarget:
    """Beschreibt ein bewusst zu genehmigendes Exportziel."""

    target_type: str
    host: str
    port: int
    addresses: tuple[str, ...] = ()

    @property
    def spec(self) -> str:
        return f"{self.target_type}:{self.host}:{self.port}"


def enforce_runtime_egress_policy(
    *,
    config: RuntimeConfig,
    exporters: dict[str, HoneypotExporter],
    resolver: Callable[[str, int], Sequence[str]] | None = None,
) -> tuple[str, ...]:
    """Approve, resolve, classify and pin every active exporter destination."""

    resolved_targets = resolve_approved_egress_targets(
        targets=planned_egress_targets(exporters),
        approved_target_specs=config.approved_egress_targets,
        approved_cidrs=config.approved_egress_cidrs,
        prohibited_cidrs=config.prohibited_ot_cidrs,
        resolver=resolver,
    )
    for target_type, exporter in exporters.items():
        target = next(target for target in resolved_targets if target.target_type == target_type)
        _pin_exporter_destination(exporter=exporter, target=target)
    return tuple(target.spec for target in resolved_targets)


def planned_auxiliary_egress_targets(config: RuntimeConfig) -> tuple[EgressTarget, ...]:
    """Return fixed auxiliary HTTPS targets required by the selected runtime."""

    if config.weather_provider not in {"open_meteo_forecast", "open_meteo_satellite"}:
        return ()
    live_host, live_port = _url_host_port(OPEN_METEO_LIVE_BASE_URL)
    archive_host, archive_port = _url_host_port(OPEN_METEO_ARCHIVE_BASE_URL)
    return (
        EgressTarget(target_type=WEATHER_LIVE_EGRESS_TYPE, host=live_host, port=live_port),
        EgressTarget(target_type=WEATHER_ARCHIVE_EGRESS_TYPE, host=archive_host, port=archive_port),
    )


def enforce_auxiliary_egress_policy(
    *,
    config: RuntimeConfig,
    resolver: Callable[[str, int], Sequence[str]] | None = None,
) -> tuple[EgressTarget, ...]:
    """Approve and resolve fixed weather targets before any provider call."""

    return resolve_approved_egress_targets(
        targets=planned_auxiliary_egress_targets(config),
        approved_target_specs=config.approved_egress_targets,
        approved_cidrs=config.approved_egress_cidrs,
        prohibited_cidrs=config.prohibited_ot_cidrs,
        resolver=resolver,
    )


def resolve_approved_egress_targets(
    *,
    targets: Sequence[EgressTarget],
    approved_target_specs: Sequence[str],
    approved_cidrs: Sequence[str],
    prohibited_cidrs: Sequence[str] = (),
    resolver: Callable[[str, int], Sequence[str]] | None = None,
) -> tuple[EgressTarget, ...]:
    """Apply the shared target, address-class, CIDR, and OT-deny policy."""

    if not targets:
        return ()
    approved_targets = set(approved_target_specs)
    missing_targets = tuple(target.spec for target in targets if target.spec not in approved_targets)
    if missing_targets:
        missing_list = ", ".join(missing_targets)
        raise RuntimeError(
            "Egress-Freigabe fehlt fuer aktive Ziele: "
            f"{missing_list}. APPROVED_EGRESS_TARGETS muss diese Ziele explizit enthalten."
        )
    allowed_networks = _allowed_egress_networks(approved_cidrs)
    prohibited_networks = _parse_networks(prohibited_cidrs)
    resolve = _resolve_host_addresses if resolver is None else resolver
    return tuple(
        _resolve_and_validate_target(
            target,
            resolver=resolve,
            allowed_networks=allowed_networks,
            prohibited_networks=prohibited_networks,
        )
        for target in targets
    )


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
    if parts.username is not None or parts.password is not None:
        raise RuntimeError("Egress-URL darf kein userinfo enthalten")
    if parts.scheme.lower() != "https":
        raise RuntimeError("Egress-URL muss HTTPS verwenden")
    if not parts.hostname:
        raise RuntimeError("ungueltiges Egress-Ziel ohne Host")
    try:
        port = 443 if parts.port is None else parts.port
    except ValueError as exc:
        raise RuntimeError("ungueltiger Egress-Port") from exc
    return parts.hostname.lower(), port


def _resolve_host_addresses(host: str, port: int) -> tuple[str, ...]:
    try:
        answers = socket.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise RuntimeError(f"Egress-Ziel kann nicht aufgeloest werden: {host}") from exc
    addresses = tuple(dict.fromkeys(str(answer[4][0]) for answer in answers))
    if not addresses:
        raise RuntimeError(f"Egress-Ziel liefert keine A-/AAAA-Adresse: {host}")
    return addresses


def resolve_host_addresses(host: str, port: int) -> tuple[str, ...]:
    """Resolve a policy target for auxiliary CLI consumers."""

    return _resolve_host_addresses(host, port)


def _allowed_egress_networks(raw_cidrs: Sequence[str]) -> tuple[IPv4Network | IPv6Network, ...]:
    if not raw_cidrs:
        raise RuntimeError(
            "APPROVED_EGRESS_CIDRS muss alle aktiven Exportziele unabhaengig freigeben"
        )
    return _parse_networks(raw_cidrs)


def _parse_networks(raw_cidrs: Sequence[str]) -> tuple[IPv4Network | IPv6Network, ...]:
    return tuple(ip_network(raw_cidr, strict=False) for raw_cidr in raw_cidrs)


def _resolve_and_validate_target(
    target: EgressTarget,
    *,
    resolver: Callable[[str, int], Sequence[str]],
    allowed_networks: tuple[IPv4Network | IPv6Network, ...],
    prohibited_networks: tuple[IPv4Network | IPv6Network, ...],
) -> EgressTarget:
    try:
        raw_addresses = resolver(target.host, target.port)
    except OSError as exc:
        raise RuntimeError(f"Egress-Ziel kann nicht aufgeloest werden: {target.host}") from exc
    addresses = tuple(dict.fromkeys(str(ip_address(raw_address)) for raw_address in raw_addresses))
    if not addresses:
        raise RuntimeError(f"Egress-Ziel liefert keine A-/AAAA-Adresse: {target.host}")
    for raw_address in addresses:
        address = ip_address(raw_address)
        if (
            not address.is_global
            or address.is_loopback
            or address.is_private
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            raise RuntimeError(
                f"nicht-globales Egress-Ziel ist gesperrt: {target.host} -> {address}"
            )
        if not any(
            address.version == network.version and address in network
            for network in allowed_networks
        ):
            raise RuntimeError(
                f"APPROVED_EGRESS_CIDRS deckt {target.host} -> {address} nicht ab"
            )
        if any(
            address.version == network.version and address in network
            for network in prohibited_networks
        ):
            raise RuntimeError(
                f"PROHIBITED_OT_CIDRS sperrt {target.host} -> {address}"
            )
    return EgressTarget(
        target_type=target.target_type,
        host=target.host,
        port=target.port,
        addresses=addresses,
    )


def _pin_exporter_destination(*, exporter: HoneypotExporter, target: EgressTarget) -> None:
    if isinstance(exporter, WebhookExporter | TelegramExporter):
        if exporter.transport is None:
            exporter.transport = PinnedHttpTransport(
                host=target.host,
                addresses=target.addresses,
            )
        return
    if isinstance(exporter, SmtpExporter):
        exporter.pinned_addresses = target.addresses
        return
    raise RuntimeError(f"unbekannter Exporter-Typ fuer Egress-Pinning: {exporter.__class__.__name__}")
