"""IP-Anreicherung fuer die interne Ops-Source-Sicht."""

from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
from functools import lru_cache
import ipaddress
import json
from pathlib import Path
import socket
from typing import Any

from honeypot.ops_web.settings import OpsBackendSettings

_COUNTRY_CODE_ALIASES = {
    "AT": "AUT",
    "AU": "AUS",
    "BE": "BEL",
    "BR": "BRA",
    "CA": "CAN",
    "CH": "SUI",
    "CN": "CHN",
    "DE": "GER",
    "DEU": "GER",
    "GERMANY": "GER",
    "DK": "DEN",
    "ES": "ESP",
    "FI": "FIN",
    "FR": "FRA",
    "GB": "GBR",
    "GR": "GRE",
    "IE": "IRL",
    "IN": "IND",
    "IT": "ITA",
    "JP": "JPN",
    "NL": "NED",
    "NO": "NOR",
    "PL": "POL",
    "PT": "POR",
    "RU": "RUS",
    "SE": "SWE",
    "TR": "TUR",
    "UA": "UKR",
    "UK": "GBR",
    "US": "USA",
    "USA": "USA",
}
_DEFAULT_ASN_MMDB_PATHS = (
    "/app/data/geoip/GeoLite2-ASN.mmdb",
    "/app/data/geoip/dbip-asn-lite.mmdb",
    "data/geoip/GeoLite2-ASN.mmdb",
    "data/geoip/dbip-asn-lite.mmdb",
)
_ASN_ORGANIZATION_KEYS = frozenset(
    {
        "autonomous_system_organization",
        "as_organization",
        "as_org",
        "asn_org",
        "isp",
        "organization",
        "org",
        "name",
    }
)


@dataclass(frozen=True, slots=True)
class SourceEnrichment:
    country_code: str = "-"
    rdns: str = "-"
    isp: str = "-"


class IpEnricher:
    """Reichert Source-IPs ohne externe HTTP-APIs an."""

    def __init__(self) -> None:
        self._rdns_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ops-rdns")
        self._cache: dict[tuple[str, tuple[Any, ...]], SourceEnrichment] = {}

    def enrich(self, source_ip: str, settings: OpsBackendSettings) -> SourceEnrichment:
        if not settings.ip_enrichment_enabled:
            return SourceEnrichment()

        fingerprint = _settings_fingerprint(settings)
        cache_key = (source_ip, fingerprint)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        enriched = self._enrich_uncached(source_ip=source_ip, settings=settings)
        self._cache[cache_key] = enriched
        return enriched

    def _enrich_uncached(self, *, source_ip: str, settings: OpsBackendSettings) -> SourceEnrichment:
        try:
            ip_value = ipaddress.ip_address(source_ip)
        except ValueError:
            return SourceEnrichment(country_code="INV", rdns="-", isp="invalid")

        static_hit = _lookup_static_enrichment(
            source_ip=source_ip,
            static_map_path=settings.ip_enrichment_static_map_path,
        )
        country_code = _country_code(static_hit.get("country_code") or static_hit.get("country"))
        rdns = _text_value(static_hit.get("rdns") or static_hit.get("reverse_dns"))
        isp = _text_value(static_hit.get("isp") or static_hit.get("asn_org") or static_hit.get("organization"))

        if not country_code:
            country_code = _lookup_country_mmdb(source_ip, settings.ip_enrichment_country_mmdb_path)
        if not isp:
            isp = _lookup_asn_mmdb(source_ip, settings.ip_enrichment_asn_mmdb_path)

        if ip_value.is_loopback or ip_value.is_private or ip_value.is_link_local:
            country_code = country_code or "LOC"
            rdns = rdns or "local"
            isp = isp or "local"
        elif ip_value.is_reserved or ip_value.is_multicast or ip_value.is_unspecified:
            country_code = country_code or "RES"
            rdns = rdns or "reserved"
            isp = isp or "reserved"
        elif settings.ip_enrichment_rdns_enabled and not rdns:
            rdns = self._lookup_rdns(source_ip=source_ip, timeout_ms=settings.ip_enrichment_rdns_timeout_ms)

        if not isp:
            isp = _isp_from_rdns(rdns)

        return SourceEnrichment(
            country_code=country_code or "UNK",
            rdns=_compact_text(rdns or "-"),
            isp=_compact_text(isp or "-", max_length=36),
        )

    def _lookup_rdns(self, *, source_ip: str, timeout_ms: int) -> str:
        future = self._rdns_executor.submit(socket.gethostbyaddr, source_ip)
        try:
            hostname, _, _ = future.result(timeout=timeout_ms / 1000)
        except TimeoutError:
            return "timeout"
        except OSError:
            return "-"
        return str(hostname).rstrip(".")


def _settings_fingerprint(settings: OpsBackendSettings) -> tuple[Any, ...]:
    return (
        settings.ip_enrichment_enabled,
        settings.ip_enrichment_rdns_enabled,
        settings.ip_enrichment_static_map_path,
        settings.ip_enrichment_country_mmdb_path,
        settings.ip_enrichment_asn_mmdb_path,
        settings.ip_enrichment_rdns_timeout_ms,
    )


def _lookup_static_enrichment(*, source_ip: str, static_map_path: str) -> dict[str, Any]:
    if not static_map_path:
        return {}

    mappings = _load_static_map(static_map_path, _static_map_mtime_ns(static_map_path))
    direct_hit = mappings.get(source_ip)
    if isinstance(direct_hit, dict):
        return dict(direct_hit)

    try:
        ip_value = ipaddress.ip_address(source_ip)
    except ValueError:
        return {}

    for network_or_ip, enrichment in mappings.items():
        if network_or_ip == source_ip or not isinstance(enrichment, dict):
            continue
        try:
            network = ipaddress.ip_network(network_or_ip, strict=False)
        except ValueError:
            continue
        if ip_value in network:
            return dict(enrichment)
    return {}


def _static_map_mtime_ns(static_map_path: str) -> int:
    try:
        return Path(static_map_path).expanduser().stat().st_mtime_ns
    except OSError:
        return 0


@lru_cache(maxsize=16)
def _load_static_map(static_map_path: str, mtime_ns: int) -> dict[str, Any]:
    _ = mtime_ns
    path = Path(static_map_path).expanduser()
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(content, dict):
        return {}
    return content


def _lookup_country_mmdb(source_ip: str, country_mmdb_path: str) -> str:
    if not country_mmdb_path:
        return ""
    try:
        import geoip2.database  # type: ignore[import-not-found]
    except ImportError:
        return ""
    try:
        with geoip2.database.Reader(str(Path(country_mmdb_path).expanduser())) as reader:
            response = reader.country(source_ip)
    except Exception:
        return ""
    return _country_code(getattr(response.country, "iso_code", None))


def _lookup_asn_mmdb(source_ip: str, asn_mmdb_path: str) -> str:
    for candidate_path in _asn_mmdb_paths(asn_mmdb_path):
        organization = _lookup_geoip2_asn_mmdb(source_ip, candidate_path)
        if organization:
            return organization
        organization = _lookup_generic_asn_mmdb(source_ip, candidate_path)
        if organization:
            return organization
    return ""


def _asn_mmdb_paths(asn_mmdb_path: str) -> tuple[str, ...]:
    configured_path = _text_value(asn_mmdb_path)
    if configured_path:
        return (configured_path,)
    return tuple(path for path in _DEFAULT_ASN_MMDB_PATHS if Path(path).expanduser().is_file())


def _lookup_geoip2_asn_mmdb(source_ip: str, asn_mmdb_path: str) -> str:
    try:
        import geoip2.database  # type: ignore[import-not-found]
    except ImportError:
        return ""
    try:
        with geoip2.database.Reader(str(Path(asn_mmdb_path).expanduser())) as reader:
            response = reader.asn(source_ip)
    except Exception:
        return ""
    organization = getattr(response, "autonomous_system_organization", None)
    return _text_value(organization)


def _lookup_generic_asn_mmdb(source_ip: str, asn_mmdb_path: str) -> str:
    try:
        import maxminddb  # type: ignore[import-not-found]
    except ImportError:
        return ""

    reader = None
    try:
        reader = maxminddb.open_database(str(Path(asn_mmdb_path).expanduser()))
        record = reader.get(source_ip)
    except Exception:
        return ""
    finally:
        if reader is not None:
            reader.close()
    return _extract_asn_organization(record)


def _extract_asn_organization(value: Any) -> str:
    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            if str(key).lower() in _ASN_ORGANIZATION_KEYS:
                organization = _text_value(nested_value)
                if organization:
                    return organization
        for nested_value in value.values():
            organization = _extract_asn_organization(nested_value)
            if organization:
                return organization
    return ""


def _isp_from_rdns(rdns: str) -> str:
    hostname = _text_value(rdns).lower().rstrip(".")
    if hostname in {"", "-", "timeout", "local", "reserved"}:
        return ""
    labels = [label for label in hostname.split(".") if label]
    if len(labels) < 2:
        return ""

    suffix = ".".join(labels[-2:])
    if len(labels) >= 3 and suffix in {
        "ac.uk",
        "co.jp",
        "co.uk",
        "com.au",
        "com.br",
        "com.tr",
        "com.ua",
        "gov.uk",
        "net.au",
        "net.br",
        "org.uk",
    }:
        return ".".join(labels[-3:])
    return suffix


def _country_code(value: Any) -> str:
    normalized = _text_value(value).upper()
    if not normalized:
        return ""
    compact = normalized.replace(" ", "")
    aliased = _COUNTRY_CODE_ALIASES.get(compact)
    if aliased is not None:
        return aliased
    if len(compact) <= 3:
        return compact
    return compact[:3]


def _text_value(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        return str(value).strip()
    return value.strip()


def _compact_text(value: str, *, max_length: int = 44) -> str:
    if len(value) <= max_length:
        return value
    return f"{value[: max_length - 3]}..."
