from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import re

import httpx
import pytest

from honeypot.config_core import RuntimeConfig
from honeypot.event_core import AlertRecord, EventRecorder
from honeypot.history_core import PlantHistorySample
from honeypot.ops_web import create_ops_app
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


def _extract_csrf_token(rendered_html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', rendered_html)
    assert match is not None
    return match.group(1)
