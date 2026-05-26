from __future__ import annotations

import csv
import html
import io
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import re

import httpx
import pytest

from honeypot.config_core import RuntimeConfig
from honeypot.event_core import AlertRecord, EventRecorder
from honeypot.history_core import PlantHistorySample
from honeypot.ops_web import create_ops_app
from honeypot.ops_web import app as ops_app_module
from honeypot.storage import SQLiteEventStore
from honeypot.time_core import FrozenClock


def build_config(tmp_path: Path, **overrides) -> RuntimeConfig:
    return RuntimeConfig(
        _env_file=None,
        event_store_path=tmp_path / "events" / "placeholder.db",
        jsonl_archive_enabled=False,
        **overrides,
    )


def seed_ops_store(store: SQLiteEventStore) -> None:
    clock = FrozenClock(datetime(2026, 4, 26, 20, 0, tzinfo=UTC))
    recorder = EventRecorder(store=store, clock=clock)
    event = recorder.build_event(
        event_type="hmi.action.unauthenticated_control_attempt",
        category="hmi",
        severity="medium",
        source_ip="203.0.113.44",
        actor_type="remote_client",
        component="hmi-web",
        asset_id="grid-01",
        action="single_line_breaker_click",
        result="rejected",
        session_id="hmi_test",
        protocol="http",
        service="web-hmi",
        endpoint_or_register="/single-line/breaker-attempt",
        requested_value={"control": "breaker"},
        resulting_value={"http_status": 303},
        error_code="service_auth_required",
        message="Rejected breaker click",
        tags=("single-line", "breaker"),
    )
    alert = AlertRecord(
        alert_id="alt_test",
        event_id=event.event_id,
        correlation_id=event.correlation_id,
        alarm_code="REPEATED_LOGIN_FAILURE",
        severity="medium",
        state="active_unacknowledged",
        component="hmi-web",
        asset_id="hmi-web",
        message="Repeated service login failures",
        created_at=clock.now(),
    )
    recorder.record(event, alert=alert)


def seed_source_sort_store(store: SQLiteEventStore) -> None:
    clock = FrozenClock(datetime(2026, 4, 26, 20, 0, tzinfo=UTC))
    recorder = EventRecorder(store=store, clock=clock)
    for source_ip, count in (
        ("203.0.113.44", 1),
        ("198.51.100.10", 3),
        ("192.0.2.9", 2),
    ):
        for index in range(count):
            event = recorder.build_event(
                event_type="hmi.page.overview_viewed",
                category="hmi",
                severity="low",
                source_ip=source_ip,
                actor_type="remote_client",
                component="hmi-web",
                asset_id="hmi-web",
                action="view_overview",
                result="served",
                session_id=f"session_{source_ip}_{index}",
                protocol="http",
                service="web-hmi",
                endpoint_or_register="/overview",
                requested_value={"http_method": "GET", "http_path": "/overview"},
                resulting_value={"http_status": 200},
                message="Overview viewed",
                tags=("read-only", "overview"),
            )
            recorder.record(event)
            clock.advance(timedelta(minutes=1))


def seed_event_export_store(store: SQLiteEventStore) -> None:
    clock = FrozenClock(datetime(2026, 4, 26, 20, 0, tzinfo=UTC))
    recorder = EventRecorder(store=store, clock=clock)
    page_view = recorder.build_event(
        event_type="hmi.page.overview_viewed",
        category="hmi",
        severity="low",
        source_ip="203.0.113.44",
        actor_type="remote_client",
        component="hmi-web",
        asset_id="hmi-web",
        action="view_overview",
        result="served",
        session_id="human_a",
        protocol="http",
        service="web-hmi",
        endpoint_or_register="/overview",
        requested_value={"http_method": "GET", "http_path": "/overview"},
        resulting_value={"http_status": 200},
        message="Overview viewed",
        tags=("read-only", "overview"),
    )
    recorder.record(page_view)
    clock.advance(timedelta(minutes=1))
    control_attempt = recorder.build_event(
        event_type="hmi.action.service_control_submitted",
        category="hmi",
        severity="medium",
        source_ip="198.51.100.66",
        actor_type="remote_client",
        component="hmi-web",
        asset_id="grid-01",
        action="=set_breaker",
        result="rejected",
        session_id="human_b",
        protocol="http",
        service="web-hmi",
        endpoint_or_register="@/service/panel/breaker",
        requested_value={"control": "breaker", "request": "open"},
        resulting_value={"http_status": 400},
        error_code="control_rejected",
        message="+clicked breaker",
        tags=("service-panel", "breaker"),
    )
    recorder.record(control_attempt)


def seed_many_event_store(store: SQLiteEventStore, *, count: int) -> None:
    clock = FrozenClock(datetime(2026, 4, 26, 20, 0, tzinfo=UTC))
    recorder = EventRecorder(store=store, clock=clock)
    for index in range(count):
        event = recorder.build_event(
            event_type="hmi.page.synthetic_event_viewed",
            category="hmi",
            severity="low",
            source_ip="203.0.113.44",
            actor_type="remote_client",
            component="hmi-web",
            asset_id="hmi-web",
            action=f"view_event_{index:03d}",
            result="served",
            session_id=f"event_page_{index:03d}",
            protocol="http",
            service="web-hmi",
            endpoint_or_register="/overview",
            requested_value={"index": index},
            resulting_value={"http_status": 200},
            message="Synthetic page event viewed",
            tags=("read-only", "events-page"),
        )
        recorder.record(event)
        clock.advance(timedelta(seconds=1))


@pytest.mark.asyncio
async def test_ops_dashboard_renders_events_alerts_and_sources(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops.db")
    seed_ops_store(store)
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        dashboard = await client.get("/")
        events = await client.get("/api/events")
        summary = await client.get("/api/summary")

    assert dashboard.status_code == 200
    assert "Ops Dashboard" in dashboard.text
    assert "max-width: calc(100vh * 16 / 9);" in dashboard.text
    assert "max-width: 1280px;" not in dashboard.text
    assert 'class="event-control-attempt"' in dashboard.text
    assert "Control attempt" in dashboard.text
    assert "hmi.action.unauthenticated_control_attempt" in dashboard.text
    assert "203.0.113.44" in dashboard.text
    assert 'class="mono cell-source">203.0.113.44' in dashboard.text
    assert "26.04.2026 20:00:00 UTC" in dashboard.text
    assert "2026-04-26T20:00:00" not in dashboard.text
    assert "REPEATED_LOGIN_FAILURE" in dashboard.text
    assert events.json()["events"][0]["event_type"] == "hmi.action.unauthenticated_control_attempt"
    assert summary.json()["summary"]["total_events"] == 1
    assert summary.json()["summary"]["active_alerts"] == 1
    assert summary.json()["summary"]["last_event_at"] == "2026-04-26T20:00:00Z"
    assert summary.json()["sources"][0]["rejected_count"] == 1
    assert summary.json()["sources"][0]["country_code"] == "-"


@pytest.mark.asyncio
async def test_ops_dashboard_top_sources_sort_by_event_count(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-dashboard-source-sort.db")
    seed_source_sort_store(store)
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        dashboard = await client.get("/")

    assert dashboard.status_code == 200
    top_sources = dashboard.text.split("<h2>Top Sources</h2>", maxsplit=1)[1]
    assert _source_ips(top_sources) == ["198.51.100.10", "192.0.2.9", "203.0.113.44"]


@pytest.mark.asyncio
async def test_ops_dashboard_and_summary_api_do_not_fetch_full_event_snapshots(
    monkeypatch,
    tmp_path: Path,
) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-dashboard-bounded.db")
    seed_many_event_store(store, count=30)

    def fail_full_event_fetch():
        raise AssertionError("dashboard should not load the full event log")

    def fail_full_alert_fetch():
        raise AssertionError("dashboard should not load the full alert log")

    monkeypatch.setattr(store, "fetch_events", fail_full_event_fetch)
    monkeypatch.setattr(store, "fetch_alerts", fail_full_alert_fetch)
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        dashboard = await client.get("/")
        summary = await client.get("/api/summary")

    assert dashboard.status_code == 200
    assert summary.status_code == 200
    assert summary.json()["summary"]["total_events"] == 30
    assert "view_event_029" in dashboard.text
    assert "view_event_005" in dashboard.text
    assert "view_event_004" not in dashboard.text


@pytest.mark.asyncio
async def test_ops_events_page_does_not_highlight_page_views_as_control_attempts(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-page-view-events.db")
    seed_source_sort_store(store)
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        events = await client.get("/events?source_ip=203.0.113.44&limit=10")

    assert events.status_code == 200
    assert "hmi.page.overview_viewed" in events.text
    assert 'class="event-control-attempt"' not in events.text
    assert "Control attempt" not in events.text


@pytest.mark.asyncio
async def test_ops_events_source_filter_supports_multi_include_and_exclude_tokens(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-events-source-filter.db")
    seed_source_sort_store(store)
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        include = await client.get(
            "/events",
            params={"source_ip": "203.0.113.44 198.51.100.10", "limit": "10"},
        )
        exclude = await client.get(
            "/events",
            params={"source_ip": "!203.0.113.44 AND !198.51.100.10", "limit": "10"},
        )
        mixed = await client.get(
            "/events",
            params={"source_ip": "203.0.113.44,198.51.100.10 !198.51.100.10", "limit": "10"},
        )

    assert include.status_code == 200
    assert _source_ips(include.text) == [
        "198.51.100.10",
        "198.51.100.10",
        "198.51.100.10",
        "203.0.113.44",
    ]
    assert "Source filter supports multiple IPs." in include.text

    assert exclude.status_code == 200
    assert _source_ips(exclude.text) == ["192.0.2.9", "192.0.2.9"]

    assert mixed.status_code == 200
    assert _source_ips(mixed.text) == ["203.0.113.44"]


@pytest.mark.asyncio
async def test_ops_events_page_links_next_hundred_events_without_repeating_current_page(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-events-pagination.db")
    seed_many_event_store(store, count=205)
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        first = await client.get("/events?limit=100")
        next_href = _extract_href(first.text, "Show next 100 events")
        second = await client.get(next_href)

    assert first.status_code == 200
    assert "view_event_204" in first.text
    assert "view_event_105" in first.text
    assert "view_event_104" not in first.text
    assert 'href="/events/export.csv?limit=100"' in first.text
    assert "Show next 100 events" in first.text

    assert second.status_code == 200
    assert "view_event_104" in second.text
    assert "view_event_005" in second.text
    assert "view_event_004" not in second.text
    assert "view_event_204" not in second.text
    assert 'href="/events/export.csv?limit=100&amp;before=' in second.text


@pytest.mark.asyncio
async def test_ops_events_export_uses_filters_and_neutralizes_csv_formulas(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-events-export.db")
    seed_event_export_store(store)
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        events = await client.get("/events?source_ip=198.51.100.66&result=rejected&limit=10")
        export = await client.get("/events/export.csv?source_ip=198.51.100.66&result=rejected&limit=10")
        exclude_export = await client.get(
            "/events/export.csv",
            params={"source_ip": "!203.0.113.44", "limit": "10"},
        )

    rows = list(csv.DictReader(io.StringIO(export.text)))
    excluded_rows = list(csv.DictReader(io.StringIO(exclude_export.text)))

    assert events.status_code == 200
    assert (
        'href="/events/export.csv?limit=10&amp;source_ip=198.51.100.66&amp;result=rejected"'
        in events.text
    )
    assert export.status_code == 200
    assert export.headers["content-type"].startswith("text/csv")
    assert 'filename="ops-events-filtered.csv"' in export.headers["content-disposition"]
    assert len(rows) == 1
    assert rows[0]["source_ip"] == "198.51.100.66"
    assert rows[0]["result"] == "rejected"
    assert rows[0]["action"] == "'=set_breaker"
    assert rows[0]["endpoint_or_register"] == "'@/service/panel/breaker"
    assert rows[0]["message"] == "'+clicked breaker"
    assert "203.0.113.44" not in export.text
    assert exclude_export.status_code == 200
    assert [row["source_ip"] for row in excluded_rows] == ["198.51.100.66"]


@pytest.mark.asyncio
async def test_ops_basic_auth_rejects_missing_and_wrong_credentials(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-auth.db")
    app = create_ops_app(
        event_store=store,
        config=build_config(
            tmp_path,
            ops_basic_auth_enabled=True,
            ops_basic_auth_username="watch",
            ops_basic_auth_password="correct-horse",
        ),
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        missing = await client.get("/")
        wrong = await client.get("/", auth=("watch", "wrong"))
        ok = await client.get("/", auth=("watch", "correct-horse"))
        versions_missing = await client.get("/api/versions")
        versions_wrong = await client.get("/api/versions", auth=("watch", "wrong"))
        versions_ok = await client.get("/api/versions", auth=("watch", "correct-horse"))

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert ok.status_code == 200
    assert versions_missing.status_code == 401
    assert versions_wrong.status_code == 401
    assert versions_ok.status_code == 200


@pytest.mark.asyncio
async def test_ops_versions_page_renders_backend_change_log(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-versions.db")
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        dashboard = await client.get("/")
        versions = await client.get("/versions")

    assert dashboard.status_code == 200
    assert "Versions" in dashboard.text
    assert versions.status_code == 200
    assert "Current backend version" in versions.text
    assert "v1.4.16" in versions.text
    assert "Protected versions API" in versions.text
    assert "v1.4.15" in versions.text
    assert "Ops-managed Modbus timing defaults" in versions.text
    assert "v1.4.14" in versions.text
    assert "Rare historical maintenance windows" in versions.text
    assert "v1.4.13" in versions.text
    assert "Bounded Modbus response timing" in versions.text
    assert "v1.4.12" in versions.text
    assert "Fictional Modbus identity profile" in versions.text
    assert "v1.4.11" in versions.text
    assert "Modbus fingerprint contract QA" in versions.text
    assert "v1.4.10" in versions.text
    assert "Attacker-facing leakage gate" in versions.text
    assert "v1.4.9" in versions.text
    assert "SQL-backed Ops dashboard" in versions.text
    assert "v1.4.8" in versions.text
    assert "Paged Ops events view" in versions.text
    assert "v1.4.7" in versions.text
    assert "Multi-source Ops event filters" in versions.text
    assert "v1.4.6" in versions.text
    assert "Dashboard top sources by event volume" in versions.text
    assert "v1.4.5" in versions.text
    assert "Filtered Ops events CSV export" in versions.text
    assert "v1.4.4" in versions.text
    assert "Highlighted Ops control attempts" in versions.text
    assert "v1.4.3" in versions.text
    assert "Widescreen-safe Ops backend layout" in versions.text
    assert "v1.4.2" in versions.text
    assert "Full-width inverter service controls" in versions.text
    assert "v1.4.1" in versions.text
    assert "Service portal logout" in versions.text
    assert "v1.4.0" in versions.text
    assert "Production Docker defaults and local debug mode" in versions.text
    assert "v1.3.2" in versions.text
    assert "Configurable service-login lure" in versions.text
    assert "v1.3.1" in versions.text
    assert "Service-login robots lure" in versions.text
    assert "v1.3.0" in versions.text
    assert "DB-IP Lite GeoIP auto-update" in versions.text
    assert "v1.2.2" in versions.text
    assert "GeoIP country and ASN autodetect" in versions.text
    assert "v1.2.1" in versions.text
    assert "ASN MMDB enrichment mount" in versions.text
    assert "v1.2.0" in versions.text
    assert "Single production Compose path" in versions.text
    assert "v1.1.1" in versions.text
    assert "Source ISP fallback" in versions.text
    assert "v1.1.0" in versions.text
    assert "Sortable source activity" in versions.text
    assert "v1.0.0" in versions.text
    assert "Initial exposed-research release" in versions.text
    assert "v0.9.8" in versions.text
    assert "Readable inverter fleet layout" in versions.text
    assert "v0.9.7" in versions.text
    assert "Quiet HMI HEAD probes" in versions.text
    assert "v0.9.6" in versions.text
    assert "Quiet HMI healthcheck endpoint" in versions.text
    assert "v0.9.5" in versions.text
    assert "Trusted proxy source IP handling" in versions.text
    assert "v0.9.4" in versions.text
    assert "Consistent HMI page width" in versions.text
    assert "v0.9.3" in versions.text
    assert "Service-login navigation placement" in versions.text
    assert "v0.9.2" in versions.text
    assert "Overview service-login lure" in versions.text
    assert "v0.9.1" in versions.text
    assert "Backend version log" in versions.text
    assert "v0.9.0" in versions.text
    assert "Credential campaign aggregation" in versions.text
    assert "The version log is only reachable through the protected Ops backend surface." in versions.text


@pytest.mark.asyncio
async def test_ops_versions_api_returns_backend_change_log(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-versions-api.db")
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        response = await client.get("/api/versions")

    assert response.status_code == 200
    payload = response.json()
    assert payload["latest_version"] == "v1.4.16"
    assert payload["latest_title"] == "Protected versions API"
    assert payload["released_at"] == "2026-05-26"
    assert payload["version_count"] == len(payload["versions"])
    assert payload["versions"][0] == {
        "version": "v1.4.16",
        "released_at": "2026-05-26",
        "category": "Feature",
        "title": "Protected versions API",
        "summary": "Adds a protected JSON endpoint for the backend version log so operators and deployment automation can verify the shipped backend without scraping HTML.",
        "areas": ["ops-web", "versions", "documentation", "tests"],
        "changes": [
            "Expose the backend version log at /api/versions behind the existing Ops authentication dependency.",
            "Return latest version metadata, total version count and structured version rows for automation-friendly checks.",
            "Cover the endpoint with integration tests, including route-specific Basic Auth enforcement.",
        ],
        "security_notes": [
            "The API is read-only, hidden from OpenAPI output and available only through the protected Ops backend surface.",
            "The payload contains release metadata only and does not expose host paths, secrets, credentials or attacker-facing debug detail.",
        ],
    }


@pytest.mark.asyncio
async def test_ops_pages_render_dbip_cc_by_attribution_when_metadata_exists(
    monkeypatch,
    tmp_path: Path,
) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-attribution.db")
    seed_ops_store(store)
    metadata_path = tmp_path / "geoip" / "metadata.json"
    metadata_path.parent.mkdir()
    metadata_path.write_text(
        json.dumps(
            {
                "provider": "DB-IP Lite",
                "license": "Creative Commons Attribution 4.0 International (CC BY 4.0)",
                "license_url": "https://creativecommons.org/licenses/by/4.0/",
                "attribution": {
                    "label": "IP Geolocation by DB-IP",
                    "url": "https://db-ip.com",
                },
                "downloaded_at": "2026-04-29T10:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(ops_app_module, "_GEOIP_METADATA_PATHS", (metadata_path,))
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        sources = await client.get("/sources")
        settings = await client.get("/settings")

    assert sources.status_code == 200
    assert 'href="https://db-ip.com"' in sources.text
    assert "IP Geolocation by DB-IP" in sources.text
    assert "CC BY 4.0" in sources.text
    assert "DB-IP Lite / 2026-04-29T10:00:00Z" in settings.text


@pytest.mark.asyncio
async def test_ops_settings_enable_static_ip_enrichment_and_audit_change(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-settings.db")
    seed_ops_store(store)
    static_map_path = tmp_path / "ip-map.json"
    static_map_path.write_text(
        json.dumps(
            {
                "203.0.113.44": {
                    "country_code": "DE",
                    "rdns": "scan.example.test",
                    "isp": "Example Transit",
                }
            }
        ),
        encoding="utf-8",
    )
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        settings_page = await client.get("/settings")
        csrf_token = _extract_csrf_token(settings_page.text)
        update = await client.post(
            "/settings",
            data={
                "csrf_token": csrf_token,
                "ip_enrichment_enabled": "on",
                "ip_enrichment_static_map_path": str(static_map_path),
                "ip_enrichment_country_mmdb_path": "",
                "ip_enrichment_asn_mmdb_path": "",
                "ip_enrichment_rdns_timeout_ms": "300",
                "events_default_limit": "25",
                "alerts_default_limit": "25",
                "sources_default_limit": "25",
            },
            follow_redirects=False,
        )
        sources = await client.get("/sources")
        summary = await client.get("/api/summary")

    assert update.status_code == 303
    assert "GER" in sources.text
    assert "scan.example.test" in sources.text
    assert "Example Transit" in sources.text
    enriched_sources = summary.json()["sources"]
    assert any(source["country_code"] == "GER" for source in enriched_sources)
    assert any(source["rdns"] == "scan.example.test" for source in enriched_sources)
    assert store.fetch_ops_settings()["ip_enrichment_enabled"] is True
    assert any(event.event_type == "ops.settings.updated" for event in store.fetch_events())


@pytest.mark.asyncio
async def test_ops_settings_updates_service_login_lure_credentials(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-service-login-settings.db")
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        settings_page = await client.get("/settings")
        csrf_token = _extract_csrf_token(settings_page.text)
        update = await client.post(
            "/settings",
            data={
                "csrf_token": csrf_token,
                "service_login_username": "maintenance",
                "service_login_password": "shadow",
                "ip_enrichment_static_map_path": "",
                "ip_enrichment_country_mmdb_path": "",
                "ip_enrichment_asn_mmdb_path": "",
                "ip_enrichment_rdns_timeout_ms": "300",
                "events_default_limit": "100",
                "alerts_default_limit": "100",
                "sources_default_limit": "100",
                "login_campaign_aggregation_enabled": "on",
                "login_credential_capture_enabled": "on",
                "login_password_capture_enabled": "on",
                "login_password_display_enabled": "on",
                "login_credential_export_enabled": "on",
                "login_capture_sample_attempts": "5",
                "login_capture_summary_interval_seconds": "60",
                "login_campaign_idle_timeout_minutes": "10",
                "login_capture_max_unique_passwords": "1000000",
                "login_capture_max_credential_length": "256",
            },
            follow_redirects=False,
        )
        saved_page = await client.get("/settings")

    stored_settings = store.fetch_ops_settings()
    settings_event = next(event for event in store.fetch_events() if event.event_type == "ops.settings.updated")

    assert settings_page.status_code == 200
    assert 'name="service_login_username"' in settings_page.text
    assert 'value="admin"' in settings_page.text
    assert 'name="service_login_password"' in settings_page.text
    assert 'value="sunshine"' in settings_page.text
    assert update.status_code == 303
    assert stored_settings["service_login_username"] == "maintenance"
    assert stored_settings["service_login_password"] == "shadow"
    assert 'value="maintenance"' in saved_page.text
    assert 'value="shadow"' in saved_page.text
    assert settings_event.requested_value["changed"]["service_login_username"]["after"] == "maintenance"
    assert settings_event.requested_value["changed"]["service_login_password"]["after"] == "shadow"


@pytest.mark.asyncio
async def test_ops_settings_updates_modbus_response_timing(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-modbus-timing-settings.db")
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        settings_page = await client.get("/settings")
        csrf_token = _extract_csrf_token(settings_page.text)
        update = await client.post(
            "/settings",
            data={
                "csrf_token": csrf_token,
                "ip_enrichment_static_map_path": "",
                "ip_enrichment_country_mmdb_path": "",
                "ip_enrichment_asn_mmdb_path": "",
                "ip_enrichment_rdns_timeout_ms": "300",
                "events_default_limit": "100",
                "alerts_default_limit": "100",
                "sources_default_limit": "100",
                "modbus_response_delay_min_ms": "20",
                "modbus_response_delay_max_ms": "75",
                "login_campaign_aggregation_enabled": "on",
                "login_credential_capture_enabled": "on",
                "login_password_capture_enabled": "on",
                "login_password_display_enabled": "on",
                "login_credential_export_enabled": "on",
                "login_capture_sample_attempts": "5",
                "login_capture_summary_interval_seconds": "60",
                "login_campaign_idle_timeout_minutes": "10",
                "login_capture_max_unique_passwords": "1000000",
                "login_capture_max_credential_length": "256",
            },
            follow_redirects=False,
        )
        saved_page = await client.get("/settings")

    stored_settings = store.fetch_ops_settings()
    settings_event = next(event for event in store.fetch_events() if event.event_type == "ops.settings.updated")

    assert settings_page.status_code == 200
    assert "Protocol Timing" in settings_page.text
    assert 'name="modbus_response_delay_min_ms"' in settings_page.text
    assert 'name="modbus_response_delay_max_ms"' in settings_page.text
    assert update.status_code == 303
    assert stored_settings["modbus_response_delay_min_ms"] == 20
    assert stored_settings["modbus_response_delay_max_ms"] == 75
    assert 'name="modbus_response_delay_min_ms" type="number" min="0" max="2000" value="20"' in saved_page.text
    assert 'name="modbus_response_delay_max_ms" type="number" min="0" max="2000" value="75"' in saved_page.text
    assert settings_event.requested_value["changed"]["modbus_response_delay_min_ms"]["after"] == 20
    assert settings_event.requested_value["changed"]["modbus_response_delay_max_ms"]["after"] == 75


@pytest.mark.asyncio
async def test_ops_settings_rejects_invalid_modbus_response_timing(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-invalid-modbus-timing-settings.db")
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        settings_page = await client.get("/settings")
        csrf_token = _extract_csrf_token(settings_page.text)
        response = await client.post(
            "/settings",
            data={
                "csrf_token": csrf_token,
                "ip_enrichment_static_map_path": "",
                "ip_enrichment_country_mmdb_path": "",
                "ip_enrichment_asn_mmdb_path": "",
                "ip_enrichment_rdns_timeout_ms": "300",
                "events_default_limit": "100",
                "alerts_default_limit": "100",
                "sources_default_limit": "100",
                "modbus_response_delay_min_ms": "90",
                "modbus_response_delay_max_ms": "20",
                "login_capture_sample_attempts": "5",
                "login_capture_summary_interval_seconds": "60",
                "login_campaign_idle_timeout_minutes": "10",
                "login_capture_max_unique_passwords": "1000000",
                "login_capture_max_credential_length": "256",
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "modbus_response_delay_min_ms darf modbus_response_delay_max_ms nicht ueberschreiten" in response.text
    assert "modbus_response_delay_min_ms" not in store.fetch_ops_settings()


@pytest.mark.asyncio
async def test_ops_sources_page_sorts_columns_with_allowlisted_parameters(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-source-sort.db")
    seed_source_sort_store(store)
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        by_events_desc = await client.get("/sources?sort=request_count&direction=desc&limit=10")
        by_events_asc = await client.get("/sources?sort=events&direction=asc&limit=10")
        invalid_sort = await client.get("/sources?sort=events;drop&direction=sideways&limit=10")

    assert by_events_desc.status_code == 200
    assert _source_ips(by_events_desc.text) == ["198.51.100.10", "192.0.2.9", "203.0.113.44"]
    assert 'href="/sources?limit=10&amp;sort=events&amp;direction=asc"' in by_events_desc.text
    assert 'name="sort" value="events"' in by_events_desc.text
    assert 'name="direction" value="desc"' in by_events_desc.text

    assert by_events_asc.status_code == 200
    assert _source_ips(by_events_asc.text) == ["203.0.113.44", "192.0.2.9", "198.51.100.10"]

    assert invalid_sort.status_code == 200
    assert _source_ips(invalid_sort.text) == ["192.0.2.9", "198.51.100.10", "203.0.113.44"]
    assert 'name="sort" value="last_seen"' in invalid_sort.text
    assert 'name="direction" value="desc"' in invalid_sort.text


@pytest.mark.asyncio
async def test_ops_audit_events_use_forwarded_source_ip_from_trusted_proxy(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-forwarded-source.db")
    seed_ops_store(store)
    app = create_ops_app(
        event_store=store,
        config=build_config(
            tmp_path,
            forwarded_header_enabled=True,
            trusted_proxy_cidrs=("10.14.0.53/32",),
        ),
    )

    transport = httpx.ASGITransport(app=app, client=("10.14.0.53", 45678))
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        settings_page = await client.get("/settings")
        csrf_token = _extract_csrf_token(settings_page.text)
        response = await client.post(
            "/settings",
            headers={"x-forwarded-for": "193.16.163.243"},
            data={
                "csrf_token": csrf_token,
                "ip_enrichment_rdns_enabled": "on",
                "ip_enrichment_static_map_path": "",
                "ip_enrichment_country_mmdb_path": "",
                "ip_enrichment_asn_mmdb_path": "",
                "ip_enrichment_rdns_timeout_ms": "300",
                "events_default_limit": "25",
                "alerts_default_limit": "25",
                "sources_default_limit": "25",
            },
            follow_redirects=False,
        )

    settings_event = next(event for event in reversed(store.fetch_events()) if event.event_type == "ops.settings.updated")

    assert response.status_code == 303
    assert settings_event.source_ip == "193.16.163.243"


@pytest.mark.asyncio
async def test_ops_settings_delete_plant_history_and_audit_event(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-history.db")
    seed_ops_store(store)
    store.append_plant_history_samples(
        (
            PlantHistorySample(
                observed_at=datetime(2026, 4, 26, 19, 0, tzinfo=UTC),
                plant_power_mw=4.2,
                active_power_limit_pct=100.0,
                irradiance_w_m2=640.0,
                export_power_mw=4.18,
                export_energy_mwh_total=12.5,
                block_power_kw=(("invb-01", 1400.0),),
            ),
            PlantHistorySample(
                observed_at=datetime(2026, 4, 26, 20, 0, tzinfo=UTC),
                plant_power_mw=3.6,
                active_power_limit_pct=100.0,
                irradiance_w_m2=520.0,
                export_power_mw=3.58,
                export_energy_mwh_total=16.08,
                block_power_kw=(("invb-01", 1200.0),),
            ),
        )
    )
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        settings_page = await client.get("/settings")
        csrf_token = _extract_csrf_token(settings_page.text)
        response = await client.post(
            "/settings/history/delete",
            data={"csrf_token": csrf_token},
            follow_redirects=False,
        )

    events = store.fetch_events()
    history_event = events[-1]

    assert response.status_code == 303
    assert response.headers["location"] == "/settings?history_deleted=1"
    assert store.count_rows("plant_history") == 0
    assert store.count_rows("event_log") == 2
    assert store.count_rows("alert_log") == 1
    assert history_event.event_type == "ops.history.deleted"
    assert history_event.action == "delete_plant_history"
    assert history_event.resulting_value == {"deleted_rows": 2}


@pytest.mark.asyncio
async def test_ops_credentials_page_shows_all_time_and_campaign_passwords(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "ops-credentials.db")
    observed_at = datetime(2026, 4, 26, 21, 0, tzinfo=UTC)
    for username, password in (
        ("admin", "solar123"),
        ("admin", "solar123"),
        ("operator", "winter2026"),
    ):
        store.record_login_credential_attempt(
            campaign_id="camp_test",
            source_ip="198.51.100.23",
            user_agent="curl/8.0",
            endpoint="/service/login",
            username=username,
            password=password,
            observed_at=observed_at,
            max_unique_passwords=1_000_000,
            max_credential_length=256,
            capture_password=True,
        )
    app = create_ops_app(event_store=store, config=build_config(tmp_path))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://ops") as client:
        credentials = await client.get("/credentials")
        campaign = await client.get("/credentials/campaign/camp_test")
        export = await client.get("/credentials/export/passwords.csv")

    assert credentials.status_code == 200
    assert "All-Time Top Passwords" in credentials.text
    assert "solar123" in credentials.text
    assert "winter2026" in credentials.text
    assert "camp_test" in credentials.text
    assert campaign.status_code == 200
    assert "Credential Campaign" in campaign.text
    assert "solar123" in campaign.text
    assert export.status_code == 200
    assert "credential_value,count" in export.text
    assert "solar123,2" in export.text
    assert "winter2026,1" in export.text


def test_login_credential_store_caps_unique_passwords_but_counts_existing(tmp_path: Path) -> None:
    store = SQLiteEventStore(tmp_path / "events" / "credential-limit.db")
    observed_at = datetime(2026, 4, 26, 21, 0, tzinfo=UTC)

    for password in ("first", "second", "first"):
        store.record_login_credential_attempt(
            campaign_id="camp_limit",
            source_ip="198.51.100.24",
            user_agent="curl/8.0",
            endpoint="/service/login",
            username="admin",
            password=password,
            observed_at=observed_at,
            max_unique_passwords=1,
            max_credential_length=256,
            capture_password=True,
        )

    stats = store.login_credential_stats()
    top_passwords = store.fetch_login_credential_top(value_type="password")

    assert stats.all_time_unique_passwords == 1
    assert stats.all_time_dropped_unique_passwords == 1
    assert len(top_passwords) == 1
    assert top_passwords[0].credential_value == "first"
    assert top_passwords[0].count == 2


def _extract_csrf_token(rendered_html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', rendered_html)
    assert match is not None
    return match.group(1)


def _extract_href(rendered_html: str, label: str) -> str:
    match = re.search(r'href="([^"]+)">' + re.escape(label), rendered_html)
    assert match is not None
    return html.unescape(match.group(1))


def _source_ips(rendered_html: str) -> list[str]:
    return re.findall(r'<td class="mono cell-source">([^<]+)</td>', rendered_html)
