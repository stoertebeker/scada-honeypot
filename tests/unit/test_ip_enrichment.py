from __future__ import annotations

from honeypot.ops_web.ip_enrichment import IpEnricher
from honeypot.ops_web.settings import OpsBackendSettings


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
