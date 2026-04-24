from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.config_core import RuntimeConfig
from honeypot.event_core import EventRecorder
from honeypot.hmi_web import create_hmi_app
from honeypot.hmi_web.app import (
    SERVICE_LOGIN_PASSWORD,
    SERVICE_LOGIN_USERNAME,
    SERVICE_SESSION_COOKIE_NAME,
)
from honeypot.main import build_local_runtime
from honeypot.plant_sim import PlantSimulator
from honeypot.protocol_modbus import ReadOnlyRegisterMap
from honeypot.storage import SQLiteEventStore
from honeypot.time_core import FrozenClock


def build_snapshot() -> PlantSnapshot:
    return PlantSnapshot.from_fixture(load_plant_fixture("normal_operation"))


def build_config(tmp_path: Path) -> RuntimeConfig:
    return RuntimeConfig(
        _env_file=None,
        event_store_path=tmp_path / "events" / "placeholder.db",
        jsonl_archive_enabled=False,
    )


def build_service_app(
    *,
    snapshot: PlantSnapshot,
    tmp_path: Path,
    recorder: EventRecorder | None = None,
    config: RuntimeConfig | None = None,
):
    runtime_config = build_config(tmp_path) if config is None else config
    register_map = ReadOnlyRegisterMap(snapshot, event_recorder=recorder)
    app = create_hmi_app(
        snapshot_provider=lambda: register_map.snapshot,
        config=runtime_config,
        event_recorder=recorder,
        service_controls=register_map,
    )
    return app, register_map


@pytest.mark.asyncio
async def test_overview_page_renders_root_and_logs_hmi_events(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-overview.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        root_response = await client.get("/")
        overview_response = await client.get("/overview")
        client_session_id = client.cookies["hmi_session"]

    events = store.fetch_events()

    assert root_response.status_code == 200
    assert overview_response.status_code == 200
    assert "Plant Overview" in overview_response.text
    assert "Single Line" in overview_response.text
    assert "Inverters" in overview_response.text
    assert "Weather" in overview_response.text
    assert "Meter" in overview_response.text
    assert "Alarms" in overview_response.text
    assert "Trends" in overview_response.text
    assert "5.80 MW" in overview_response.text
    assert "100.0 %" in overview_response.text
    assert "Closed" in overview_response.text
    assert "invb-01" in overview_response.text
    assert "840 W/m2" in overview_response.text
    assert root_response.cookies["hmi_session"].startswith("hmi_")
    assert client_session_id == root_response.cookies["hmi_session"]
    assert len(events) == 2
    overview_event = next(event for event in events if event.endpoint_or_register == "/overview")
    assert overview_event.event_type == "hmi.page.overview_viewed"
    assert overview_event.component == "hmi-web"
    assert overview_event.service == "web-hmi"
    assert overview_event.requested_value == {"http_method": "GET", "http_path": "/overview"}
    assert overview_event.resulting_value == {"http_status": 200}
    assert overview_event.session_id is not None


@pytest.mark.asyncio
async def test_overview_page_uses_observed_at_for_snapshot_time(tmp_path: Path) -> None:
    snapshot = build_snapshot().model_copy(update={"observed_at": datetime(2026, 4, 1, 10, 7, tzinfo=UTC)})
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=None,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/overview")

    assert response.status_code == 200
    assert "2026-04-01 10:07:00 UTC" in response.text


@pytest.mark.asyncio
async def test_single_line_page_renders_breaker_path_and_logs_hmi_events(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    breaker_open_snapshot = PlantSimulator.from_snapshot(snapshot).open_breaker(snapshot)
    store = SQLiteEventStore(tmp_path / "events" / "hmi-single-line.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(breaker_open_snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: breaker_open_snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/single-line")

    events = store.fetch_events()
    single_line_event = next(event for event in events if event.endpoint_or_register == "/single-line")

    assert response.status_code == 200
    assert "Single-Line View" in response.text
    assert "Flow isolated by open breaker" in response.text
    assert "Open" in response.text
    assert "Unavailable" in response.text
    assert "BREAKER_OPEN" in response.text
    assert "invb-02" in response.text
    assert single_line_event.event_type == "hmi.page.single_line_viewed"
    assert single_line_event.component == "hmi-web"
    assert single_line_event.service == "web-hmi"
    assert single_line_event.requested_value == {"http_method": "GET", "http_path": "/single-line"}
    assert single_line_event.resulting_value == {"http_status": 200}
    assert single_line_event.resulting_state["breaker_state"] == "open"
    assert single_line_event.resulting_state["export_power_kw"] == 0.0


@pytest.mark.asyncio
async def test_inverters_page_renders_block_values_and_logs_hmi_events(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-inverters.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/inverters")

    events = store.fetch_events()
    inverters_event = next(event for event in events if event.endpoint_or_register == "/inverters")

    assert response.status_code == 200
    assert "Inverter Fleet" in response.text
    assert "invb-01" in response.text
    assert "1935.0 kW" in response.text
    assert "100 %" in response.text
    assert "Unavailable" in response.text
    assert inverters_event.event_type == "hmi.page.inverters_viewed"
    assert inverters_event.component == "hmi-web"
    assert inverters_event.service == "web-hmi"
    assert inverters_event.requested_value == {"http_method": "GET", "http_path": "/inverters"}
    assert inverters_event.resulting_value == {"http_status": 200}
    assert inverters_event.resulting_state["block_count"] == 3
    assert inverters_event.resulting_state["degraded_block_count"] == 0


@pytest.mark.asyncio
async def test_weather_page_renders_conditions_and_logs_hmi_events(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-weather.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/weather")

    events = store.fetch_events()
    weather_event = next(event for event in events if event.endpoint_or_register == "/weather")

    assert response.status_code == 200
    assert "Weather Context" in response.text
    assert "840 W/m2" in response.text
    assert "31.5 C" in response.text
    assert "22.0 C" in response.text
    assert "4.2 m/s" in response.text
    assert "Good" in response.text
    assert weather_event.event_type == "hmi.page.weather_viewed"
    assert weather_event.component == "hmi-web"
    assert weather_event.service == "web-hmi"
    assert weather_event.requested_value == {"http_method": "GET", "http_path": "/weather"}
    assert weather_event.resulting_value == {"http_status": 200}
    assert weather_event.resulting_state["irradiance_w_m2"] == 840
    assert weather_event.resulting_state["weather_quality"] == "good"


@pytest.mark.asyncio
async def test_meter_page_renders_export_view_and_logs_hmi_events(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-meter.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/meter")

    events = store.fetch_events()
    meter_event = next(event for event in events if event.endpoint_or_register == "/meter")

    assert response.status_code == 200
    assert "Meter Overview" in response.text
    assert "5.79 MW" in response.text
    assert "0.990" in response.text
    assert "Available" in response.text
    assert "Unavailable" in response.text
    assert "Meter Snapshot" in response.text
    assert meter_event.event_type == "hmi.page.meter_viewed"
    assert meter_event.component == "hmi-web"
    assert meter_event.service == "web-hmi"
    assert meter_event.requested_value == {"http_method": "GET", "http_path": "/meter"}
    assert meter_event.resulting_value == {"http_status": 200}
    assert meter_event.resulting_state["export_power_kw"] == 5790.0
    assert meter_event.resulting_state["export_path_available"] is True
    assert meter_event.resulting_state["breaker_state"] == "closed"
    assert meter_event.resulting_state["meter_quality"] == "good"


@pytest.mark.asyncio
async def test_meter_page_marks_breaker_open_export_loss(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    breaker_open_snapshot = PlantSimulator.from_snapshot(snapshot).open_breaker(snapshot)
    app = create_hmi_app(
        snapshot_provider=lambda: breaker_open_snapshot,
        config=build_config(tmp_path),
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/meter")

    assert response.status_code == 200
    assert "0 kW" in response.text
    assert "Open" in response.text
    assert "Unavailable" in response.text
    assert "Breaker open blocks export at the grid handoff." in response.text
    assert "BREAKER_OPEN" in response.text


@pytest.mark.asyncio
async def test_alarms_page_renders_alarm_history_and_logs_hmi_events(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-alarms.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    simulator = PlantSimulator.from_snapshot(snapshot, event_recorder=recorder)
    curtailed_snapshot = simulator.apply_curtailment(snapshot, active_power_limit_pct=55.5)
    acknowledged_snapshot = simulator.acknowledge_alarm(curtailed_snapshot, code="PLANT_CURTAILED")
    app = create_hmi_app(
        snapshot_provider=lambda: acknowledged_snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/alarms?sort=severity")

    events = store.fetch_events()
    alarms_event = next(event for event in events if event.endpoint_or_register == "/alarms")

    assert response.status_code == 200
    assert "Alarm Console" in response.text
    assert "Alarm Register" in response.text
    assert "PLANT_CURTAILED" in response.text
    assert "Acknowledged" in response.text
    assert "ppc-01" in response.text
    assert alarms_event.event_type == "hmi.page.alarms_viewed"
    assert alarms_event.component == "hmi-web"
    assert alarms_event.service == "web-hmi"
    assert alarms_event.resulting_state["visible_alarm_count"] == 1
    assert alarms_event.resulting_state["sort_order"] == "severity"


@pytest.mark.asyncio
async def test_alarms_page_filters_acknowledged_state(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-alarms-filter.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    simulator = PlantSimulator.from_snapshot(snapshot, event_recorder=recorder)
    curtailed_snapshot = simulator.apply_curtailment(snapshot, active_power_limit_pct=55.5)
    acknowledged_snapshot = simulator.acknowledge_alarm(curtailed_snapshot, code="PLANT_CURTAILED")
    app = create_hmi_app(
        snapshot_provider=lambda: acknowledged_snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/alarms?state=active_acknowledged")

    assert response.status_code == 200
    assert "PLANT_CURTAILED" in response.text
    assert "BREAKER_OPEN" not in response.text
    assert "Acknowledged" in response.text


@pytest.mark.asyncio
async def test_trends_page_renders_snapshot_derived_traces_and_logs_hmi_events(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-trends.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/trends")

    events = store.fetch_events()
    trends_event = next(event for event in events if event.endpoint_or_register == "/trends")

    assert response.status_code == 200
    assert "Trend Overview" in response.text
    assert "Trend Traces" in response.text
    assert "Plant Power" in response.text
    assert "Irradiance" in response.text
    assert "Export Power" in response.text
    assert "invb-01" in response.text
    assert "5.80 MW" in response.text
    assert "100.0 %" in response.text
    assert trends_event.event_type == "hmi.page.trends_viewed"
    assert trends_event.resulting_state["series_count"] == 7
    assert trends_event.resulting_state["plant_power_mw"] == 5.8


@pytest.mark.asyncio
async def test_hmi_404_page_uses_custom_template_and_logs_event(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-404.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/missing-page")

    events = store.fetch_events()
    error_event = next(event for event in events if event.endpoint_or_register == "/missing-page")

    assert response.status_code == 404
    assert "Page Unavailable" in response.text
    assert "The requested page is not available." in response.text
    assert "{\"detail\":\"Not Found\"}" not in response.text
    assert error_event.event_type == "hmi.error.not_found"
    assert error_event.error_code == "hmi_404"
    assert error_event.resulting_value == {"http_status": 404}


@pytest.mark.asyncio
async def test_hmi_500_page_uses_custom_template_and_logs_event(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-500.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: (_ for _ in ()).throw(RuntimeError("boom")),
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/overview")

    events = store.fetch_events()
    error_event = next(event for event in events if event.endpoint_or_register == "/overview")

    assert response.status_code == 500
    assert "View Temporarily Unavailable" in response.text
    assert "The page could not be loaded." in response.text
    assert "RuntimeError" not in response.text
    assert error_event.event_type == "hmi.error.internal"
    assert error_event.error_code == "hmi_500"
    assert error_event.resulting_value == {"http_status": 500}


@pytest.mark.asyncio
async def test_service_login_page_renders_and_logs_view_event(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-login.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/service/login")

    events = store.fetch_events()
    login_view_event = next(event for event in events if event.endpoint_or_register == "/service/login")

    assert response.status_code == 200
    assert "Service Login" in response.text
    assert "Username" in response.text
    assert "Password" in response.text
    assert login_view_event.event_type == "hmi.page.service_login_viewed"
    assert login_view_event.resulting_state["service_session_active"] is False


@pytest.mark.asyncio
async def test_service_login_failure_stays_quiet_and_logs_auth_event(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-login-fail.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/service/login",
            data={"username": "wrong", "password": "wrong"},
        )

    events = store.fetch_events()
    auth_event = next(event for event in events if event.event_type == "hmi.auth.service_login_attempt")

    assert response.status_code == 200
    assert "Authentication failed. Check credentials and retry." in response.text
    assert SERVICE_SESSION_COOKIE_NAME not in response.cookies
    assert auth_event.result == "failure"


@pytest.mark.asyncio
async def test_service_login_success_sets_session_and_opens_service_panel(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-login-success.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_response = await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        panel_response = await client.get("/service/panel")

    events = store.fetch_events()
    auth_event = next(event for event in events if event.event_type == "hmi.auth.service_login_attempt")
    panel_event = next(event for event in events if event.endpoint_or_register == "/service/panel")

    assert login_response.status_code == 303
    assert login_response.headers["location"] == "/service/panel"
    assert SERVICE_SESSION_COOKIE_NAME in login_response.cookies
    assert panel_response.status_code == 200
    assert "Service Panel" in panel_response.text
    assert "Service view active" not in panel_response.text
    assert SERVICE_LOGIN_USERNAME in panel_response.text
    assert auth_event.result == "success"
    assert panel_event.event_type == "hmi.page.service_panel_viewed"
    assert panel_event.session_id is not None


@pytest.mark.asyncio
async def test_service_panel_requires_authentication(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/service/panel")

    assert response.status_code == 401
    assert "Authentication Required" in response.text
    assert "Open /service/login to continue." in response.text


@pytest.mark.asyncio
async def test_service_session_expires_after_idle_timeout(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    clock = FrozenClock(snapshot.start_time)
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-session-expiry.db")
    recorder = EventRecorder(store=store, clock=clock)
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        clock.advance(timedelta(minutes=21))
        response = await client.get("/service/panel")

    assert response.status_code == 401
    assert "Authentication Required" in response.text


@pytest.mark.asyncio
async def test_service_login_returns_403_when_disabled(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    config = build_config(tmp_path).model_copy(update={"enable_service_login": False})
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=config,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/service/login")

    assert response.status_code == 403
    assert "Access Denied" in response.text


@pytest.mark.asyncio
async def test_service_panel_power_limit_updates_shared_truth_and_logs_control_event(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-power-limit.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app, register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        control_response = await client.post(
            "/service/panel/power-limit",
            data={"active_power_limit_pct": "55.5"},
            follow_redirects=False,
        )
        panel_response = await client.get(control_response.headers["location"])

    events = store.fetch_events()
    control_event = next(
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted" and event.action == "set_active_power_limit"
    )
    process_event = next(event for event in events if event.event_type == "process.setpoint.curtailment_changed")

    assert control_response.status_code == 303
    assert control_response.headers["location"] == "/service/panel?status=power_limit_updated"
    assert panel_response.status_code == 200
    assert "Active power limit updated successfully." in panel_response.text
    assert "55.5 %" in panel_response.text
    assert "3.22 MW" in panel_response.text
    assert register_map.snapshot.power_plant_controller.active_power_limit_pct == 55.5
    assert register_map.snapshot.site.plant_power_mw == 3.219
    assert control_event.result == "accepted"
    assert control_event.requested_value["active_power_limit_pct"] == 55.5
    assert control_event.resulting_state["active_power_limit_pct"] == 55.5
    assert control_event.correlation_id == process_event.correlation_id


@pytest.mark.asyncio
async def test_service_panel_reactive_power_updates_shared_truth_and_logs_control_event(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-reactive-power.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app, register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        control_response = await client.post(
            "/service/panel/reactive-power",
            data={"reactive_power_target_pct": "25.0"},
            follow_redirects=False,
        )
        panel_response = await client.get(control_response.headers["location"])

    events = store.fetch_events()
    control_event = next(
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted" and event.action == "set_reactive_power_target"
    )
    process_event = next(event for event in events if event.event_type == "process.setpoint.reactive_power_target_changed")

    assert control_response.status_code == 303
    assert control_response.headers["location"] == "/service/panel?status=reactive_power_updated"
    assert panel_response.status_code == 200
    assert "Reactive power target updated successfully." in panel_response.text
    assert 'value="25.0"' in panel_response.text
    assert register_map.snapshot.power_plant_controller.reactive_power_target == 0.25
    assert register_map.snapshot.site.reactive_power_setpoint == 0.25
    assert control_event.result == "accepted"
    assert control_event.requested_value["reactive_power_target_pct"] == 25.0
    assert control_event.resulting_value == {"http_status": 303, "value": 25.0}
    assert control_event.resulting_state["reactive_power_target"] == 0.25
    assert control_event.correlation_id == process_event.correlation_id


@pytest.mark.asyncio
async def test_service_panel_plant_mode_request_latches_and_logs_control_event(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-plant-mode.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app, register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        control_response = await client.post(
            "/service/panel/plant-mode",
            data={"plant_mode_request": "2"},
            follow_redirects=False,
        )
        panel_response = await client.get(control_response.headers["location"])

    events = store.fetch_events()
    control_event = next(
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted" and event.action == "set_plant_mode_request"
    )
    process_event = next(event for event in events if event.event_type == "process.setpoint.plant_mode_request_changed")

    assert control_response.status_code == 303
    assert control_response.headers["location"] == "/service/panel?status=plant_mode_updated"
    assert panel_response.status_code == 200
    assert "Plant mode request updated successfully." in panel_response.text
    assert 'option value="2" selected' in panel_response.text
    assert register_map.read_holding_registers(unit_id=1, start_offset=201, quantity=1).values == (2,)
    assert register_map.snapshot.site.operating_mode == "normal"
    assert control_event.result == "accepted"
    assert control_event.requested_value["plant_mode_request"] == 2
    assert control_event.resulting_value == {"http_status": 303, "value": 2}
    assert control_event.resulting_state["plant_mode_request"] == 2
    assert control_event.resulting_state["operating_mode"] == "normal"
    assert control_event.correlation_id == process_event.correlation_id


@pytest.mark.asyncio
async def test_service_panel_breaker_controls_shared_truth_and_log_events(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-breaker.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app, register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        open_response = await client.post(
            "/service/panel/breaker",
            data={"breaker_action": "open"},
            follow_redirects=False,
        )
        open_panel_response = await client.get(open_response.headers["location"])
        close_response = await client.post(
            "/service/panel/breaker",
            data={"breaker_action": "close"},
            follow_redirects=False,
        )
        close_panel_response = await client.get(close_response.headers["location"])

    events = store.fetch_events()
    breaker_events = [
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted"
        and event.action in {"breaker_open_request", "breaker_close_request"}
    ]
    process_events = [event for event in events if event.event_type == "process.breaker.state_changed"]

    assert open_response.status_code == 303
    assert open_response.headers["location"] == "/service/panel?status=breaker_open_requested"
    assert "Breaker open request accepted." in open_panel_response.text
    assert close_response.status_code == 303
    assert close_response.headers["location"] == "/service/panel?status=breaker_close_requested"
    assert "Breaker close request accepted." in close_panel_response.text
    assert register_map.snapshot.grid_interconnect.breaker_state == "closed"
    assert len(breaker_events) == 2
    assert len(process_events) == 2
    assert {event.correlation_id for event in breaker_events} == {event.correlation_id for event in process_events}


@pytest.mark.asyncio
async def test_service_panel_inverter_block_controls_shared_truth_and_log_events(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-inverter-block.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app, register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        control_response = await client.post(
            "/service/panel/inverter-block",
            data={
                "asset_id": "invb-02",
                "block_enable_request": "0",
                "block_power_limit_pct": "65.5",
            },
            follow_redirects=False,
        )
        panel_response = await client.get(control_response.headers["location"])

    events = store.fetch_events()
    control_event = next(
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted" and event.action == "set_block_control_state"
    )
    process_events = [
        event
        for event in events
        if event.event_type in {"process.setpoint.block_enable_request_changed", "process.setpoint.block_power_limit_changed"}
        and event.asset_id == "invb-02"
    ]

    assert control_response.status_code == 303
    assert control_response.headers["location"] == "/service/panel?status=block_control_updated"
    assert panel_response.status_code == 200
    assert "Inverter block control updated successfully." in panel_response.text
    assert register_map.read_holding_registers(unit_id=12, start_offset=199, quantity=2).values == (0, 655)
    assert register_map.snapshot.inverter_blocks[1].asset_id == "invb-02"
    assert register_map.snapshot.inverter_blocks[1].status == "offline"
    assert register_map.snapshot.inverter_blocks[1].block_power_kw == 0.0
    assert control_event.result == "accepted"
    assert control_event.requested_value["asset_id"] == "invb-02"
    assert control_event.requested_value["block_enable_request"] == 0
    assert control_event.requested_value["block_power_limit_pct"] == 65.5
    assert control_event.resulting_state["block_enable_request"] == 0
    assert control_event.resulting_state["block_power_limit_pct"] == 65.5
    assert len(process_events) == 2
    assert {event.correlation_id for event in process_events} == {control_event.correlation_id}


@pytest.mark.asyncio
async def test_service_panel_inverter_block_reset_recovers_comm_loss_and_logs_control_event(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    comm_loss_snapshot = PlantSimulator.from_snapshot(snapshot).lose_block_communications(snapshot, asset_id="invb-02")
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-inverter-reset.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(comm_loss_snapshot.start_time))
    app, register_map = build_service_app(snapshot=comm_loss_snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        control_response = await client.post(
            "/service/panel/inverter-block/reset",
            data={"asset_id": "invb-02"},
            follow_redirects=False,
        )
        panel_response = await client.get(control_response.headers["location"])

    events = store.fetch_events()
    control_event = next(
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted" and event.action == "block_reset_request"
    )
    process_event = next(event for event in events if event.event_type == "process.control.block_reset_requested")

    assert control_response.status_code == 303
    assert control_response.headers["location"] == "/service/panel?status=block_reset_requested"
    assert panel_response.status_code == 200
    assert "Inverter block reset pulse accepted." in panel_response.text
    assert register_map.read_holding_registers(unit_id=12, start_offset=201, quantity=1).values == (0,)
    assert register_map.snapshot.inverter_blocks[1].communication_state == "healthy"
    assert register_map.snapshot.inverter_blocks[1].quality == "good"
    assert control_event.result == "accepted"
    assert control_event.requested_value["asset_id"] == "invb-02"
    assert control_event.resulting_state["communication_state"] == "healthy"
    assert control_event.correlation_id == process_event.correlation_id


@pytest.mark.asyncio
async def test_service_panel_rejects_invalid_power_limit_without_state_change(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-power-limit-reject.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app, register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        control_response = await client.post(
            "/service/panel/power-limit",
            data={"active_power_limit_pct": "150.1"},
            follow_redirects=False,
        )
        panel_response = await client.get(control_response.headers["location"])

    events = store.fetch_events()
    control_event = next(
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted" and event.action == "set_active_power_limit"
    )

    assert control_response.status_code == 303
    assert control_response.headers["location"] == "/service/panel?status=control_rejected"
    assert panel_response.status_code == 200
    assert "Submitted control request was rejected by the local process model." in panel_response.text
    assert register_map.snapshot.power_plant_controller.active_power_limit_pct == 100.0
    assert control_event.result == "rejected"
    assert control_event.error_code == "service_control_rejected"


@pytest.mark.asyncio
async def test_service_panel_rejects_invalid_reactive_power_without_state_change(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-reactive-power-reject.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app, register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        control_response = await client.post(
            "/service/panel/reactive-power",
            data={"reactive_power_target_pct": "150.0"},
            follow_redirects=False,
        )
        panel_response = await client.get(control_response.headers["location"])

    events = store.fetch_events()
    control_event = next(
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted" and event.action == "set_reactive_power_target"
    )

    assert control_response.status_code == 303
    assert control_response.headers["location"] == "/service/panel?status=control_rejected"
    assert panel_response.status_code == 200
    assert "Submitted control request was rejected by the local process model." in panel_response.text
    assert register_map.snapshot.power_plant_controller.reactive_power_target == 0.0
    assert control_event.result == "rejected"
    assert control_event.error_code == "service_control_rejected"


@pytest.mark.asyncio
async def test_service_panel_rejects_invalid_plant_mode_without_state_change(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-plant-mode-reject.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app, register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        control_response = await client.post(
            "/service/panel/plant-mode",
            data={"plant_mode_request": "3"},
            follow_redirects=False,
        )
        panel_response = await client.get(control_response.headers["location"])

    events = store.fetch_events()
    control_event = next(
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted" and event.action == "set_plant_mode_request"
    )

    assert control_response.status_code == 303
    assert control_response.headers["location"] == "/service/panel?status=control_rejected"
    assert panel_response.status_code == 200
    assert "Submitted control request was rejected by the local process model." in panel_response.text
    assert register_map.read_holding_registers(unit_id=1, start_offset=201, quantity=1).values == (0,)
    assert control_event.result == "rejected"
    assert control_event.error_code == "service_control_rejected"


@pytest.mark.asyncio
async def test_service_panel_rejects_invalid_inverter_block_control_without_state_change(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-inverter-reject.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app, register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        control_response = await client.post(
            "/service/panel/inverter-block",
            data={
                "asset_id": "invb-02",
                "block_enable_request": "1",
                "block_power_limit_pct": "120.0",
            },
            follow_redirects=False,
        )
        panel_response = await client.get(control_response.headers["location"])

    events = store.fetch_events()
    control_event = next(
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted" and event.action == "set_block_control_state"
    )

    assert control_response.status_code == 303
    assert control_response.headers["location"] == "/service/panel?status=control_rejected"
    assert panel_response.status_code == 200
    assert "Submitted control request was rejected by the local process model." in panel_response.text
    assert register_map.read_holding_registers(unit_id=12, start_offset=199, quantity=2).values == (1, 1000)
    assert control_event.result == "rejected"
    assert control_event.error_code == "service_control_rejected"


@pytest.mark.asyncio
async def test_service_panel_write_requires_authentication(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    app, _ = build_service_app(snapshot=snapshot, tmp_path=tmp_path)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/service/panel/power-limit",
            data={"active_power_limit_pct": "55.5"},
        )

    assert response.status_code == 401
    assert "Authentication Required" in response.text


@pytest.mark.asyncio
async def test_overview_marks_comm_loss_block_and_alarm_context(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    comm_loss_snapshot = PlantSimulator.from_snapshot(snapshot).lose_block_communications(snapshot, asset_id="invb-02")
    store = SQLiteEventStore(tmp_path / "events" / "hmi-comm-loss.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(comm_loss_snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: comm_loss_snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/overview")

    assert response.status_code == 200
    assert "invb-02" in response.text
    assert "Lost" in response.text
    assert "Stale" in response.text
    assert "Inverter block communication lost" in response.text
    assert "COMM_LOSS_INVERTER_BLOCK" in response.text


@pytest.mark.asyncio
async def test_inverters_page_marks_comm_loss_block_and_quality_context(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    comm_loss_snapshot = PlantSimulator.from_snapshot(snapshot).lose_block_communications(snapshot, asset_id="invb-02")
    app = create_hmi_app(
        snapshot_provider=lambda: comm_loss_snapshot,
        config=build_config(tmp_path),
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/inverters")

    assert response.status_code == 200
    assert "invb-02" in response.text
    assert "Degraded" in response.text
    assert "Lost" in response.text
    assert "Stale" in response.text
    assert "COMM_LOSS_INVERTER_BLOCK" in response.text


@pytest.mark.asyncio
async def test_weather_page_marks_reduced_confidence_when_weather_data_is_stale(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    degraded_snapshot = snapshot.model_copy(
        update={
            "site": snapshot.site.model_copy(update={"communications_health": "degraded"}),
            "weather_station": snapshot.weather_station.model_copy(
                update={"status": "degraded", "communication_state": "lost", "quality": "stale"}
            ),
        }
    )
    app = create_hmi_app(
        snapshot_provider=lambda: degraded_snapshot,
        config=build_config(tmp_path),
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/weather")

    assert response.status_code == 200
    assert "Weather confidence is reduced" in response.text
    assert "Stale" in response.text
    assert "Lost" in response.text


@pytest.mark.asyncio
async def test_runtime_hmi_reads_same_truth_as_modbus_register_map(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0)
    runtime.modbus_service.register_map.write_single_register(unit_id=1, start_offset=199, value=555)

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/overview")

    assert response.status_code == 200
    assert "3.22 MW" in response.text
    assert "55.5 %" in response.text


@pytest.mark.asyncio
async def test_runtime_weather_page_reads_same_values_as_unit_21_registers(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    weather_result = runtime.modbus_service.register_map.read_holding_registers(unit_id=21, start_offset=99, quantity=8)

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/weather")

    assert response.status_code == 200
    assert weather_result.values == (0, 0, 0, 840, 315, 220, 42, 1000)
    assert "840 W/m2" in response.text
    assert "31.5 C" in response.text
    assert "22.0 C" in response.text
    assert "4.2 m/s" in response.text
    assert "Good" in response.text


@pytest.mark.asyncio
async def test_runtime_inverters_page_reads_curtailment_from_modbus_register_map(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    runtime.modbus_service.register_map.write_single_register(unit_id=1, start_offset=199, value=555)

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/inverters")

    assert response.status_code == 200
    assert "Inverter Fleet" in response.text
    assert "1073.9 kW" in response.text
    assert "1065.6 kW" in response.text
    assert "1079.5 kW" in response.text
    assert "PLANT_CURTAILED" in response.text


@pytest.mark.asyncio
async def test_runtime_single_line_reads_breaker_change_from_modbus_register_map(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    runtime.modbus_service.register_map.write_single_register(unit_id=41, start_offset=199, value=1)

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/single-line")

    assert response.status_code == 200
    assert "Single-Line View" in response.text
    assert "Flow isolated by open breaker" in response.text
    assert "Open" in response.text
    assert "0 kW" in response.text
    assert "Unavailable" in response.text


@pytest.mark.asyncio
async def test_runtime_meter_page_reads_same_values_as_unit_31_registers(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    runtime.modbus_service.register_map.write_single_register(unit_id=41, start_offset=199, value=1)
    meter_result = runtime.modbus_service.register_map.read_holding_registers(unit_id=31, start_offset=102, quantity=8)

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/meter")

    assert response.status_code == 200
    assert meter_result.values == (0, 0, 0, 0, 0, 0, 990, 0)
    assert "Meter Overview" in response.text
    assert "0 kW" in response.text
    assert "Unavailable" in response.text
    assert "Open" in response.text
    assert "0.990" in response.text
    assert "BREAKER_OPEN" in response.text


@pytest.mark.asyncio
async def test_runtime_alarms_page_reads_breaker_alert_from_event_trail(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    runtime.modbus_service.register_map.write_single_register(unit_id=41, start_offset=199, value=1)

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/alarms")

    assert response.status_code == 200
    assert "Alarm Console" in response.text
    assert "BREAKER_OPEN" in response.text
    assert "grid-01" in response.text
    assert "Active" in response.text


@pytest.mark.asyncio
async def test_runtime_alarms_page_reads_grid_path_follow_up_alert_from_event_trail(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    runtime.modbus_service.register_map.write_single_register(unit_id=41, start_offset=199, value=1)

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/alarms")

    alerts = runtime.event_store.fetch_alerts()

    assert response.status_code == 200
    assert "Alarm Console" in response.text
    assert "GRID_PATH_UNAVAILABLE" in response.text
    assert "Grid path unavailable" in response.text
    assert "grid-01" in response.text
    assert "Critical" in response.text
    assert "Active" in response.text
    assert any(
        alert.alarm_code == "GRID_PATH_UNAVAILABLE" and alert.asset_id == "grid-01" and alert.state != "cleared"
        for alert in alerts
    )


@pytest.mark.asyncio
async def test_runtime_alarms_page_reads_low_output_follow_up_alert_from_event_trail(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    runtime.modbus_service.register_map.set_block_control_state(
        asset_id="invb-01",
        block_enable_request=False,
        block_power_limit_pct=100.0,
    )
    runtime.modbus_service.register_map.set_block_control_state(
        asset_id="invb-02",
        block_enable_request=False,
        block_power_limit_pct=100.0,
    )

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/alarms")

    alerts = runtime.event_store.fetch_alerts()

    assert response.status_code == 200
    assert "Alarm Console" in response.text
    assert "LOW_SITE_OUTPUT_UNEXPECTED" in response.text
    assert "Unexpected low site output" in response.text
    assert "site" in response.text
    assert "High" in response.text
    assert "Active" in response.text
    assert any(
        alert.alarm_code == "LOW_SITE_OUTPUT_UNEXPECTED" and alert.asset_id == "site" and alert.state != "cleared"
        for alert in alerts
    )


@pytest.mark.asyncio
async def test_runtime_alarms_page_reads_multi_block_follow_up_alert_from_event_trail(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    _seed_runtime_comm_loss(runtime, asset_id="invb-01")
    _seed_runtime_comm_loss(runtime, asset_id="invb-02")

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/alarms")

    alerts = runtime.event_store.fetch_alerts()

    assert response.status_code == 200
    assert "Alarm Console" in response.text
    assert "MULTI_BLOCK_UNAVAILABLE" in response.text
    assert "Multiple inverter blocks unavailable" in response.text
    assert "site" in response.text
    assert "Critical" in response.text
    assert "Active" in response.text
    assert any(
        alert.alarm_code == "MULTI_BLOCK_UNAVAILABLE" and alert.asset_id == "site" and alert.state != "cleared"
        for alert in alerts
    )


@pytest.mark.asyncio
async def test_runtime_alarms_page_suppresses_duplicate_low_output_follow_up_alerts_while_active(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    runtime.modbus_service.register_map.set_block_control_state(
        asset_id="invb-01",
        block_enable_request=False,
        block_power_limit_pct=100.0,
    )
    runtime.modbus_service.register_map.set_block_control_state(
        asset_id="invb-02",
        block_enable_request=False,
        block_power_limit_pct=100.0,
    )
    runtime.modbus_service.register_map.set_block_control_state(
        asset_id="invb-03",
        block_enable_request=True,
        block_power_limit_pct=90.0,
    )

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/alarms")

    alerts = runtime.event_store.fetch_alerts()

    assert response.status_code == 200
    assert "Alarm Console" in response.text
    assert response.text.count("LOW_SITE_OUTPUT_UNEXPECTED") == 1
    assert "Unexpected low site output" in response.text
    assert "site" in response.text
    assert "Active" in response.text
    assert sum(
        1
        for alert in alerts
        if alert.alarm_code == "LOW_SITE_OUTPUT_UNEXPECTED" and alert.asset_id == "site"
    ) == 1


@pytest.mark.asyncio
async def test_runtime_alarms_page_shows_multi_block_follow_up_alert_cleared_after_block_reset(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    _seed_runtime_comm_loss(runtime, asset_id="invb-01")
    _seed_runtime_comm_loss(runtime, asset_id="invb-02")
    runtime.modbus_service.register_map.write_single_register(unit_id=12, start_offset=201, value=1)

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/alarms")

    alerts = runtime.event_store.fetch_alerts()

    assert response.status_code == 200
    assert "Alarm Console" in response.text
    assert "MULTI_BLOCK_UNAVAILABLE" in response.text
    assert "Multiple inverter blocks unavailable" in response.text
    assert "site" in response.text
    assert "Cleared" in response.text
    assert any(
        alert.alarm_code == "MULTI_BLOCK_UNAVAILABLE" and alert.asset_id == "site" and alert.state == "cleared"
        for alert in alerts
    )
    assert any(
        alert.alarm_code == "COMM_LOSS_INVERTER_BLOCK" and alert.asset_id == "invb-01" and alert.state != "cleared"
        for alert in alerts
    )


@pytest.mark.asyncio
async def test_runtime_alarms_page_suppresses_duplicate_multi_block_follow_up_alerts_while_active(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    _seed_runtime_comm_loss(runtime, asset_id="invb-01")
    _seed_runtime_comm_loss(runtime, asset_id="invb-02")
    _seed_runtime_comm_loss(runtime, asset_id="invb-03")

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/alarms")

    alerts = runtime.event_store.fetch_alerts()

    assert response.status_code == 200
    assert "Alarm Console" in response.text
    assert response.text.count("MULTI_BLOCK_UNAVAILABLE") == 1
    assert "Multiple inverter blocks unavailable" in response.text
    assert "site" in response.text
    assert "Critical" in response.text
    assert "Active" in response.text
    assert sum(
        1
        for alert in alerts
        if alert.alarm_code == "MULTI_BLOCK_UNAVAILABLE" and alert.asset_id == "site"
    ) == 1


@pytest.mark.asyncio
async def test_runtime_alarms_page_shows_low_output_follow_up_alert_cleared_after_block_recovery(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    runtime.modbus_service.register_map.set_block_control_state(
        asset_id="invb-01",
        block_enable_request=False,
        block_power_limit_pct=100.0,
    )
    runtime.modbus_service.register_map.set_block_control_state(
        asset_id="invb-02",
        block_enable_request=False,
        block_power_limit_pct=100.0,
    )
    runtime.modbus_service.register_map.set_block_control_state(
        asset_id="invb-01",
        block_enable_request=True,
        block_power_limit_pct=100.0,
    )

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/alarms")

    alerts = runtime.event_store.fetch_alerts()

    assert response.status_code == 200
    assert "Alarm Console" in response.text
    assert "LOW_SITE_OUTPUT_UNEXPECTED" in response.text
    assert "Unexpected low site output" in response.text
    assert "site" in response.text
    assert "Cleared" in response.text
    assert any(
        alert.alarm_code == "LOW_SITE_OUTPUT_UNEXPECTED" and alert.asset_id == "site" and alert.state == "cleared"
        for alert in alerts
    )
    assert sum(
        1
        for alert in alerts
        if alert.alarm_code == "LOW_SITE_OUTPUT_UNEXPECTED" and alert.asset_id == "site"
    ) == 2


@pytest.mark.asyncio
async def test_runtime_alarms_page_reads_repeated_login_failure_from_event_trail(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        for _ in range(3):
            response = await client.post(
                "/service/login",
                data={"username": SERVICE_LOGIN_USERNAME, "password": "wrong"},
            )
            assert response.status_code == 200
        response = await client.get("/alarms")

    alerts = runtime.event_store.fetch_alerts()

    assert response.status_code == 200
    assert "Alarm Console" in response.text
    assert "REPEATED_LOGIN_FAILURE" in response.text
    assert "Repeated service login failures" in response.text
    assert "hmi-web" in response.text
    assert "Active" in response.text
    assert any(
        alert.alarm_code == "REPEATED_LOGIN_FAILURE" and alert.asset_id == "hmi-web" and alert.state != "cleared"
        for alert in alerts
    )


@pytest.mark.asyncio
async def test_runtime_trends_page_reads_curtailment_from_shared_truth(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    runtime.modbus_service.register_map.write_single_register(unit_id=1, start_offset=199, value=555)

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/trends")

    assert response.status_code == 200
    assert "Trend Overview" in response.text
    assert "The trace shows curtailed output against the nominal baseline." in response.text
    assert "3.22 MW" in response.text
    assert "55.5 %" in response.text
    assert "1073.9 kW" in response.text


@pytest.mark.asyncio
async def test_runtime_hmi_404_page_uses_custom_template(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/not-present")

    assert response.status_code == 404
    assert "Page Unavailable" in response.text
    assert "The requested page is not available." in response.text


@pytest.mark.asyncio
async def test_runtime_service_login_opens_service_panel(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_response = await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        panel_response = await client.get("/service/panel")

    assert login_response.status_code == 303
    assert panel_response.status_code == 200
    assert "Service Panel" in panel_response.text


def _seed_runtime_comm_loss(runtime, *, asset_id: str) -> None:
    register_map = runtime.modbus_service.register_map
    with register_map._lock:
        register_map._snapshot = register_map._simulator.lose_block_communications(
            register_map._snapshot,
            asset_id=asset_id,
        )
