from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from honeypot.config_core import RuntimeConfig
from honeypot.event_core import AlertRecord, EventRecorder
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
    assert "REPEATED_LOGIN_FAILURE" in dashboard.text
    assert events.json()["events"][0]["event_type"] == "hmi.action.unauthenticated_control_attempt"
    assert summary.json()["summary"]["total_events"] == 1
    assert summary.json()["summary"]["active_alerts"] == 1
    assert summary.json()["sources"][0]["rejected_count"] == 1


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
