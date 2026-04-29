from __future__ import annotations

from pathlib import Path

import pytest

from honeypot.ops_web import ip_enrichment
from honeypot.ops_web.ip_enrichment import IpEnricher
from honeypot.ops_web.settings import OpsBackendSettings


@pytest.fixture(autouse=True)
def isolate_geoip_mounts(monkeypatch) -> None:
    monkeypatch.setattr(ip_enrichment, "_DEFAULT_ASN_MMDB_PATHS", ())
    monkeypatch.setattr(ip_enrichment, "_DEFAULT_COUNTRY_MMDB_PATHS", ())
    monkeypatch.setattr(ip_enrichment, "_GEOIP_SEARCH_DIRS", ())


def test_ip_enrichment_derives_isp_from_rdns_when_asn_mmdb_is_unset(monkeypatch) -> None:
    enricher = IpEnricher()
    monkeypatch.setattr(
        enricher,
        "_lookup_rdns",
        lambda *, source_ip, timeout_ms: "scan-8-8-8-8.customer.example.net",
    )

    result = enricher.enrich(
        "8.8.8.8",
        OpsBackendSettings(
            ip_enrichment_enabled=True,
            ip_enrichment_rdns_enabled=True,
            ip_enrichment_country_mmdb_path="",
            ip_enrichment_asn_mmdb_path="",
            ip_enrichment_rdns_timeout_ms=300,
        ),
    )

    assert result.country_code == "UNK"
    assert result.rdns == "scan-8-8-8-8.customer.example.net"
    assert result.isp == "example.net"


def test_ip_enrichment_does_not_use_rdns_timeout_as_isp(monkeypatch) -> None:
    enricher = IpEnricher()
    monkeypatch.setattr(enricher, "_lookup_rdns", lambda *, source_ip, timeout_ms: "timeout")

    result = enricher.enrich(
        "8.8.4.4",
        OpsBackendSettings(ip_enrichment_enabled=True, ip_enrichment_rdns_enabled=True),
    )

    assert result.rdns == "timeout"
    assert result.isp == "-"


def test_ip_enrichment_prefers_configured_asn_mmdb_over_rdns(monkeypatch) -> None:
    enricher = IpEnricher()
    monkeypatch.setattr(
        ip_enrichment,
        "_lookup_asn_mmdb",
        lambda source_ip, asn_mmdb_path: "Example Backbone",
    )
    monkeypatch.setattr(
        enricher,
        "_lookup_rdns",
        lambda *, source_ip, timeout_ms: "scan.customer.example.net",
    )

    result = enricher.enrich(
        "8.8.8.8",
        OpsBackendSettings(
            ip_enrichment_enabled=True,
            ip_enrichment_rdns_enabled=True,
            ip_enrichment_asn_mmdb_path="/app/data/geoip/GeoLite2-ASN.mmdb",
        ),
    )

    assert result.rdns == "scan.customer.example.net"
    assert result.isp == "Example Backbone"


def test_lookup_asn_mmdb_auto_detects_standard_geoip_filename(monkeypatch, tmp_path: Path) -> None:
    asn_db = tmp_path / "GeoLite2-ASN.mmdb"
    asn_db.write_bytes(b"placeholder")
    monkeypatch.setattr(ip_enrichment, "_DEFAULT_ASN_MMDB_PATHS", (str(asn_db),))
    monkeypatch.setattr(ip_enrichment, "_lookup_geoip2_asn_mmdb", lambda source_ip, path: "Auto ASN Org")
    monkeypatch.setattr(
        ip_enrichment,
        "_lookup_generic_asn_mmdb",
        lambda source_ip, path: pytest.fail("generic fallback should not run"),
    )

    assert ip_enrichment._lookup_asn_mmdb("8.8.8.8", "") == "Auto ASN Org"


def test_lookup_asn_mmdb_auto_detects_variant_filename_in_geoip_mount(monkeypatch, tmp_path: Path) -> None:
    geoip_dir = tmp_path / "geoip"
    geoip_dir.mkdir()
    (geoip_dir / "ipinfo-lite-asn.mmdb").write_bytes(b"placeholder")
    monkeypatch.setattr(ip_enrichment, "_DEFAULT_ASN_MMDB_PATHS", ())
    monkeypatch.setattr(ip_enrichment, "_GEOIP_SEARCH_DIRS", (str(geoip_dir),))
    monkeypatch.setattr(
        ip_enrichment,
        "_lookup_geoip2_asn_mmdb",
        lambda source_ip, path: "Variant ASN Org" if path.endswith("ipinfo-lite-asn.mmdb") else "",
    )
    monkeypatch.setattr(ip_enrichment, "_lookup_generic_asn_mmdb", lambda source_ip, path: "")

    assert ip_enrichment._lookup_asn_mmdb("8.8.8.8", "") == "Variant ASN Org"


def test_lookup_asn_mmdb_uses_generic_schema_fallback(monkeypatch) -> None:
    monkeypatch.setattr(ip_enrichment, "_lookup_geoip2_asn_mmdb", lambda source_ip, path: "")
    monkeypatch.setattr(
        ip_enrichment,
        "_lookup_generic_asn_mmdb",
        lambda source_ip, path: "Generic Transit",
    )

    assert ip_enrichment._lookup_asn_mmdb("8.8.4.4", "/app/data/geoip/dbip-asn-lite.mmdb") == "Generic Transit"


def test_lookup_country_mmdb_auto_detects_standard_geoip_filename(monkeypatch, tmp_path: Path) -> None:
    country_db = tmp_path / "GeoLite2-Country.mmdb"
    country_db.write_bytes(b"placeholder")
    monkeypatch.setattr(ip_enrichment, "_DEFAULT_COUNTRY_MMDB_PATHS", (str(country_db),))
    monkeypatch.setattr(ip_enrichment, "_lookup_geoip2_country_mmdb", lambda source_ip, path: "GER")
    monkeypatch.setattr(
        ip_enrichment,
        "_lookup_generic_country_mmdb",
        lambda source_ip, path: pytest.fail("generic fallback should not run"),
    )

    assert ip_enrichment._lookup_country_mmdb("8.8.8.8", "") == "GER"


def test_lookup_country_mmdb_auto_detects_variant_filename_in_geoip_mount(monkeypatch, tmp_path: Path) -> None:
    geoip_dir = tmp_path / "geoip"
    geoip_dir.mkdir()
    (geoip_dir / "dbip-country-lite-2026-04.mmdb").write_bytes(b"placeholder")
    monkeypatch.setattr(ip_enrichment, "_DEFAULT_COUNTRY_MMDB_PATHS", ())
    monkeypatch.setattr(ip_enrichment, "_GEOIP_SEARCH_DIRS", (str(geoip_dir),))
    monkeypatch.setattr(ip_enrichment, "_lookup_geoip2_country_mmdb", lambda source_ip, path: "")
    monkeypatch.setattr(ip_enrichment, "_lookup_generic_country_mmdb", lambda source_ip, path: "USA")

    assert ip_enrichment._lookup_country_mmdb("8.8.4.4", "") == "USA"


def test_extract_asn_organization_from_nested_mmdb_record() -> None:
    record = {
        "country": {"iso_code": "US", "names": {"en": "United States"}},
        "traits": {
            "autonomous_system_number": 64500,
            "autonomous_system_organization": "Nested Transit LLC",
        },
    }

    assert ip_enrichment._extract_asn_organization(record) == "Nested Transit LLC"


def test_extract_country_code_from_nested_mmdb_record() -> None:
    record = {
        "registered_country": {"iso_code": "DE"},
        "traits": {"network": "203.0.113.0/24"},
    }

    assert ip_enrichment._extract_country_code(record) == "GER"
