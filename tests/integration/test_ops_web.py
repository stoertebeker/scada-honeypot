from __future__ import annotations

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

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert ok.status_code == 200


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


def _source_ips(rendered_html: str) -> list[str]:
    return re.findall(r'<td class="mono cell-source">([^<]+)</td>', rendered_html)
