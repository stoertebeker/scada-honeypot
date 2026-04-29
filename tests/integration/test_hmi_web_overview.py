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
    MAX_FORM_BODY_BYTES,
    SERVICE_CSRF_FIELD_NAME,
    SERVICE_LOGIN_FAILURE_LIMIT,
    SERVICE_LOGIN_PASSWORD,
    SERVICE_LOGIN_USERNAME,
    SERVICE_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
)
from honeypot.main import build_local_runtime
from honeypot.ops_web.settings import OpsBackendSettings, save_ops_settings
from honeypot.plant_sim import PlantSimulator
from honeypot.protocol_modbus import ReadOnlyRegisterMap
from honeypot.runtime_evolution import TrendSample
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


def _trend_sample(
    snapshot: PlantSnapshot,
    *,
    observed_at: datetime,
    plant_power_mw: float,
    irradiance_w_m2: float,
    export_power_mw: float,
    export_energy_mwh_total: float | None = None,
) -> TrendSample:
    return TrendSample(
        observed_at=observed_at,
        plant_power_mw=plant_power_mw,
        active_power_limit_pct=snapshot.power_plant_controller.active_power_limit_pct,
        irradiance_w_m2=irradiance_w_m2,
        export_power_mw=export_power_mw,
        export_energy_mwh_total=export_energy_mwh_total,
        block_power_kw=tuple((block.asset_id, block.block_power_kw) for block in snapshot.inverter_blocks),
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


def extract_service_csrf_token(response_text: str) -> str:
    marker = f'name="{SERVICE_CSRF_FIELD_NAME}" value="'
    token_start = response_text.find(marker)
    assert token_start != -1
    token_start += len(marker)
    token_end = response_text.find('"', token_start)
    assert token_end != -1
    token = response_text[token_start:token_end]
    assert token
    return token


async def login_service_client(client: httpx.AsyncClient) -> str:
    login_response = await client.post(
        "/service/login",
        data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
        follow_redirects=False,
    )
    panel_response = await client.get("/service/panel")

    assert login_response.status_code == 303
    assert panel_response.status_code == 200
    return extract_service_csrf_token(panel_response.text)


def set_cookie_header(response: httpx.Response, cookie_name: str) -> str:
    for header in response.headers.get_list("set-cookie"):
        if header.startswith(f"{cookie_name}="):
            return header
    raise AssertionError(f"missing Set-Cookie header for {cookie_name}")


@pytest.mark.asyncio
async def test_hmi_pages_share_consistent_shell_width(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    app, _register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path)

    transport = httpx.ASGITransport(app=app)
    pages: list[tuple[str, str]] = []
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        for path in (
            "/overview",
            "/single-line",
            "/inverters",
            "/weather",
            "/meter",
            "/alarms",
            "/trends",
            "/service/login",
            "/missing-page",
        ):
            response = await client.get(path)
            assert response.status_code in {200, 404}, path
            pages.append((path, response.text))

        await login_service_client(client)
        panel_response = await client.get("/service/panel")
        assert panel_response.status_code == 200
        pages.append(("/service/panel", panel_response.text))

    for path, body in pages:
        assert "--hmi-shell-width: 1440px;" in body, path
        assert "max-width: var(--hmi-shell-width);" in body, path
        for stale_width in (
            "max-width: 980px;",
            "max-width: 1180px;",
            "max-width: 1260px;",
            "max-width: 1280px;",
        ):
            assert stale_width not in body, path


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
    assert "Service Login" in overview_response.text
    assert 'href="/service/login"' in overview_response.text
    assert "Service Access" not in overview_response.text
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
async def test_hmi_healthz_is_not_logged_as_page_activity(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-healthz.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "set-cookie" not in response.headers
    assert store.fetch_events() == ()


@pytest.mark.asyncio
async def test_hmi_healthz_head_is_not_logged_as_page_activity(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-healthz-head.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.head("/healthz")

    assert response.status_code == 200
    assert response.content == b""
    assert "set-cookie" not in response.headers
    assert store.fetch_events() == ()


@pytest.mark.asyncio
async def test_hmi_robots_txt_disallows_service_login_without_logging(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-robots.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/robots.txt")
        head_response = await client.head("/robots.txt")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.text == "User-agent: *\nDisallow: /service/login\n"
    assert "set-cookie" not in response.headers
    assert head_response.status_code == 200
    assert head_response.content == b""
    assert "set-cookie" not in head_response.headers
    assert store.fetch_events() == ()


@pytest.mark.asyncio
async def test_hmi_readonly_head_routes_do_not_create_page_events(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-head-routes.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        for path in (
            "/",
            "/overview",
            "/single-line",
            "/inverters",
            "/weather",
            "/meter",
            "/alarms",
            "/trends",
            "/service/login",
        ):
            response = await client.head(path)
            assert response.status_code == 200, path
            assert response.content == b"", path
            assert "set-cookie" not in response.headers, path

    assert store.fetch_events() == ()


@pytest.mark.asyncio
async def test_hmi_service_login_head_respects_disabled_service_login(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-head-service-disabled.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path).model_copy(update={"enable_service_login": False}),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.head("/service/login")

    assert response.status_code == 403
    assert response.content == b""
    assert "set-cookie" not in response.headers
    assert store.fetch_events() == ()


@pytest.mark.asyncio
async def test_hmi_events_use_forwarded_source_ip_from_trusted_proxy(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-forwarded-source.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    config = RuntimeConfig(
        _env_file=None,
        event_store_path=tmp_path / "events" / "placeholder.db",
        jsonl_archive_enabled=False,
        forwarded_header_enabled=True,
        trusted_proxy_cidrs=("10.14.0.53/32",),
    )
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=config,
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app, client=("10.14.0.53", 45678))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/overview", headers={"x-forwarded-for": "193.16.163.243"})

    overview_event = next(event for event in store.fetch_events() if event.endpoint_or_register == "/overview")

    assert response.status_code == 200
    assert overview_event.source_ip == "193.16.163.243"


@pytest.mark.asyncio
async def test_hmi_events_ignore_forwarded_source_ip_from_untrusted_peer(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-forwarded-spoof.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    config = RuntimeConfig(
        _env_file=None,
        event_store_path=tmp_path / "events" / "placeholder.db",
        jsonl_archive_enabled=False,
        forwarded_header_enabled=True,
        trusted_proxy_cidrs=("10.14.0.53/32",),
    )
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=config,
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app, client=("203.0.113.44", 45678))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/overview", headers={"x-forwarded-for": "193.16.163.243"})

    overview_event = next(event for event in store.fetch_events() if event.endpoint_or_register == "/overview")

    assert response.status_code == 200
    assert overview_event.source_ip == "203.0.113.44"


@pytest.mark.asyncio
async def test_overview_service_login_nav_is_visible_when_service_login_is_disabled(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    config = build_config(tmp_path).model_copy(update={"enable_service_login": False})
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=config,
        event_recorder=None,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        overview_response = await client.get("/overview")
        login_response = await client.get("/service/login")

    assert overview_response.status_code == 200
    assert "Service Login" in overview_response.text
    assert 'href="/service/login"' in overview_response.text
    assert "Service Access" not in overview_response.text
    assert login_response.status_code == 403


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
    assert "energy-map" in response.text
    assert 'data-flow-node="grid"' in response.text
    assert 'data-sld-symbol="breaker"' in response.text
    assert 'data-sld-symbol="dc-disconnect"' in response.text
    assert 'data-sld-symbol="block-enable-switch"' in response.text
    assert 'href="/single-line/breaker-attempt"' in response.text
    assert 'href="/single-line/inverter-attempt?asset_id=invb-02&amp;control=dc_disconnect"' in response.text
    assert 'href="/single-line/inverter-attempt?asset_id=invb-02&amp;control=block_enable"' in response.text
    assert 'data-sld-action="breaker-click"' in response.text
    assert 'data-sld-action="dc-disconnect-click"' in response.text
    assert 'data-sld-action="block-enable-click"' in response.text
    assert 'markerUnits="userSpaceOnUse"' in response.text
    assert "breaker-frame" in response.text
    assert "breaker-terminal" in response.text
    assert "disconnect-terminal" in response.text
    assert "collection-bus" in response.text
    assert 'data-sld-symbol="dc-strings"' in response.text
    assert 'data-sld-symbol="ac-feeder"' in response.text
    assert 'data-sld-symbol="grid-source"' in response.text
    assert "control-link" not in response.text
    assert "ppc-link" not in response.text
    assert "export-halted" in response.text
    assert "invb-02" in response.text
    assert single_line_event.event_type == "hmi.page.single_line_viewed"
    assert single_line_event.component == "hmi-web"
    assert single_line_event.service == "web-hmi"
    assert single_line_event.requested_value == {"http_method": "GET", "http_path": "/single-line"}
    assert single_line_event.resulting_value == {"http_status": 200}
    assert single_line_event.resulting_state["breaker_state"] == "open"
    assert single_line_event.resulting_state["export_power_kw"] == 0.0


@pytest.mark.asyncio
async def test_single_line_breaker_click_logs_rejected_attempt_without_state_change(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-single-line-breaker-attempt.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/single-line/breaker-attempt", follow_redirects=False)

    events = store.fetch_events()
    attempt_event = next(
        event for event in events if event.event_type == "hmi.action.unauthenticated_control_attempt"
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/service/login"
    assert snapshot.grid_interconnect.breaker_state == "closed"
    assert attempt_event.action == "single_line_breaker_click"
    assert attempt_event.result == "rejected"
    assert attempt_event.asset_id == snapshot.grid_interconnect.asset_id
    assert attempt_event.endpoint_or_register == "/single-line/breaker-attempt"
    assert attempt_event.error_code == "service_auth_required"
    assert attempt_event.requested_value == {
        "http_method": "GET",
        "http_path": "/single-line/breaker-attempt",
        "control": "breaker",
        "source_view": "/single-line",
    }
    assert attempt_event.previous_value == "closed"
    assert attempt_event.resulting_value == {"http_status": 303, "redirect_to": "/service/login"}
    assert attempt_event.resulting_state == {
        "breaker_state": "closed",
        "export_power_kw": snapshot.revenue_meter.export_power_kw,
        "export_path_available": True,
    }
    assert not any(event.event_type == "hmi.action.service_control_submitted" for event in events)
    assert not any(event.event_type == "process.breaker.state_changed" for event in events)


@pytest.mark.asyncio
async def test_single_line_inverter_switch_click_logs_rejected_attempt_without_state_change(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-single-line-inverter-attempt.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(
            "/single-line/inverter-attempt?asset_id=invb-02&control=dc_disconnect",
            follow_redirects=False,
        )

    events = store.fetch_events()
    attempt_event = next(
        event for event in events if event.event_type == "hmi.action.unauthenticated_control_attempt"
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/service/login"
    assert snapshot.inverter_blocks[1].dc_disconnect_state == "closed"
    assert attempt_event.action == "single_line_dc_disconnect_click"
    assert attempt_event.result == "rejected"
    assert attempt_event.asset_id == "invb-02"
    assert attempt_event.endpoint_or_register == "/single-line/inverter-attempt"
    assert attempt_event.error_code == "service_auth_required"
    assert attempt_event.requested_value == {
        "http_method": "GET",
        "http_path": "/single-line/inverter-attempt",
        "asset_id": "invb-02",
        "control": "dc_disconnect",
        "source_view": "/single-line",
    }
    assert attempt_event.previous_value == "closed"
    assert attempt_event.resulting_state["dc_disconnect_state"] == "closed"
    assert attempt_event.resulting_state["block_power_kw"] == pytest.approx(snapshot.inverter_blocks[1].block_power_kw)
    assert not any(event.event_type == "hmi.action.service_control_submitted" for event in events)
    assert not any(event.event_type == "process.control.block_dc_disconnect_changed" for event in events)


@pytest.mark.asyncio
async def test_single_line_authenticated_inverter_switches_use_service_controls(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-single-line-service-switches.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app, register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        csrf_token = await login_service_client(client)
        single_line_response = await client.get("/single-line")
        dc_response = await client.post(
            "/service/panel/inverter-block/dc-disconnect",
            data={
                SERVICE_CSRF_FIELD_NAME: csrf_token,
                "asset_id": "invb-02",
                "dc_disconnect_open": "1",
                "return_to": "/single-line",
            },
            follow_redirects=False,
        )
        block_response = await client.post(
            "/service/panel/inverter-block",
            data={
                SERVICE_CSRF_FIELD_NAME: csrf_token,
                "asset_id": "invb-03",
                "block_enable_request": "0",
                "block_power_limit_pct": "100.0",
                "return_to": "/single-line",
            },
            follow_redirects=False,
        )
        updated_response = await client.get(block_response.headers["location"])

    events = store.fetch_events()
    dc_event = next(
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted"
        and event.action == "set_block_dc_disconnect_state"
        and event.result == "accepted"
    )
    block_event = next(
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted"
        and event.action == "set_block_control_state"
        and event.result == "accepted"
    )
    dc_process_event = next(event for event in events if event.event_type == "process.control.block_dc_disconnect_changed")
    block_process_events = [
        event
        for event in events
        if event.event_type in {"process.setpoint.block_enable_request_changed", "process.setpoint.block_power_limit_changed"}
        and event.asset_id == "invb-03"
    ]

    assert single_line_response.status_code == 200
    assert f'name="service_csrf_token" value="{csrf_token}"' in single_line_response.text
    assert 'data-sld-action="dc-disconnect-submit"' in single_line_response.text
    assert 'data-sld-action="block-enable-submit"' in single_line_response.text
    assert 'name="return_to" value="/single-line"' in single_line_response.text
    assert dc_response.status_code == 303
    assert dc_response.headers["location"] == "/single-line?status=dc_disconnect_updated"
    assert block_response.status_code == 303
    assert block_response.headers["location"] == "/single-line?status=block_control_updated"
    assert updated_response.status_code == 200
    assert "Inverter block control updated successfully." in updated_response.text
    assert register_map.snapshot.inverter_blocks[1].dc_disconnect_state == "open"
    assert register_map.snapshot.inverter_blocks[1].status == "online"
    assert register_map.snapshot.inverter_blocks[1].block_power_kw == 0.0
    assert register_map.snapshot.inverter_blocks[2].status == "offline"
    assert register_map.snapshot.inverter_blocks[2].availability_pct == 0
    assert register_map.read_holding_registers(unit_id=12, start_offset=199, quantity=4).values == (1, 1000, 0, 1)
    assert register_map.read_holding_registers(unit_id=13, start_offset=199, quantity=4).values[0] == 0
    assert dc_event.requested_value["asset_id"] == "invb-02"
    assert dc_event.requested_value["dc_disconnect_state"] == "open"
    assert dc_event.correlation_id == dc_process_event.correlation_id
    assert block_event.requested_value["asset_id"] == "invb-03"
    assert block_event.requested_value["block_enable_request"] == 0
    assert len(block_process_events) == 2
    assert {event.correlation_id for event in block_process_events} == {block_event.correlation_id}


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
    assert "Not instrumented" in response.text
    assert "No thermal sensor" in response.text
    assert "table-scroll" in response.text
    assert "state-chip" in response.text
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
    assert "Export Energy" in response.text
    assert "History Window" in response.text
    assert "Daily Energy" in response.text
    assert "invb-01" in response.text
    assert "5.80 MW" in response.text
    assert "100.0 %" in response.text
    assert trends_event.event_type == "hmi.page.trends_viewed"
    assert trends_event.resulting_state["series_count"] == 8
    assert trends_event.resulting_state["trend_window"] == "30d"
    assert trends_event.resulting_state["daily_energy_days"] == 0
    assert trends_event.resulting_state["plant_power_mw"] == 5.8


@pytest.mark.asyncio
async def test_trends_page_uses_live_history_without_location_leak(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    config = RuntimeConfig(
        _env_file=None,
        event_store_path=tmp_path / "events" / "hmi-trends-live.db",
        jsonl_archive_enabled=False,
        weather_provider="deterministic",
        weather_latitude=52.52,
        weather_longitude=13.405,
        weather_elevation_m=34,
    )
    history = (
        _trend_sample(snapshot, observed_at=snapshot.start_time, plant_power_mw=5.8, irradiance_w_m2=840, export_power_mw=5.79),
        _trend_sample(
            snapshot,
            observed_at=snapshot.start_time + timedelta(minutes=5),
            plant_power_mw=5.2,
            irradiance_w_m2=710,
            export_power_mw=5.15,
        ),
    )
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot.model_copy(update={"observed_at": history[-1].observed_at}),
        trend_history_provider=lambda: history,
        config=config,
        event_recorder=None,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/trends")

    assert response.status_code == 200
    assert "Trend Overview" in response.text
    assert "The trace shows recent live movement across output and generation." in response.text
    assert "Start / 5.80 MW" in response.text
    assert "Current values stay aligned with the baseline operating trace." not in response.text
    assert "52.52" not in response.text
    assert "13.405" not in response.text


@pytest.mark.asyncio
async def test_trends_page_renders_daily_energy_bars_from_history(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    history = (
        _trend_sample(
            snapshot,
            observed_at=snapshot.start_time,
            plant_power_mw=4.8,
            irradiance_w_m2=690,
            export_power_mw=4.75,
            export_energy_mwh_total=100.0,
        ),
        _trend_sample(
            snapshot,
            observed_at=snapshot.start_time + timedelta(hours=12),
            plant_power_mw=5.4,
            irradiance_w_m2=800,
            export_power_mw=5.32,
            export_energy_mwh_total=124.0,
        ),
        _trend_sample(
            snapshot,
            observed_at=snapshot.start_time + timedelta(days=1, hours=12),
            plant_power_mw=5.1,
            irradiance_w_m2=760,
            export_power_mw=5.04,
            export_energy_mwh_total=164.0,
        ),
    )
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot.model_copy(update={"observed_at": history[-1].observed_at}),
        trend_history_provider=lambda: history,
        config=build_config(tmp_path),
        event_recorder=None,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/trends?window=7d")

    assert response.status_code == 200
    assert "Daily Energy" in response.text
    assert "MWh per day" in response.text
    assert "04-02 / 24.000 MWh" in response.text
    assert "04-03 / 40.000 MWh" in response.text
    assert "height: 60%" in response.text
    assert "height: 100%" in response.text


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
async def test_service_login_rejects_oversized_form_body_without_session(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-login-oversized.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )
    oversized_body = b"username=" + (b"a" * (MAX_FORM_BODY_BYTES + 1))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/service/login",
            content=oversized_body,
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    events = store.fetch_events()
    auth_events = [event for event in events if event.event_type == "hmi.auth.service_login_attempt"]

    assert response.status_code == 200
    assert "Authentication failed. Check credentials and retry." in response.text
    assert SERVICE_SESSION_COOKIE_NAME not in response.cookies
    assert len(auth_events) == 1
    assert auth_events[0].result == "failure"


@pytest.mark.asyncio
async def test_service_login_samples_repeated_failures_without_real_rate_limit(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-login-rate-limit.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        for _ in range(SERVICE_LOGIN_FAILURE_LIMIT):
            response = await client.post(
                "/service/login",
                data={"username": SERVICE_LOGIN_USERNAME, "password": "wrong"},
            )
            assert response.status_code == 200

        captured_response = await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": "still-wrong"},
        )
        blocked_response = await client.post(
            "/service/login",
            content=b"username=" + (b"a" * (MAX_FORM_BODY_BYTES + 1)),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    auth_events = [
        event for event in store.fetch_events() if event.event_type == "hmi.auth.service_login_attempt"
    ]

    campaigns = store.fetch_login_campaigns()
    top_passwords = store.fetch_login_credential_top(value_type="password")

    assert captured_response.status_code == 200
    assert blocked_response.status_code == 200
    assert "Authentication failed. Check credentials and retry." in blocked_response.text
    assert SERVICE_SESSION_COOKIE_NAME not in blocked_response.cookies
    assert len(auth_events) == SERVICE_LOGIN_FAILURE_LIMIT
    assert all(event.result == "failure" for event in auth_events)
    assert campaigns[0].attempt_count == SERVICE_LOGIN_FAILURE_LIMIT + 2
    assert any(row.credential_value == "still-wrong" and row.count == 1 for row in top_passwords)


@pytest.mark.asyncio
async def test_service_login_counts_all_time_and_campaign_credentials(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-login-credentials.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        for index in range(7):
            response = await client.post(
                "/service/login",
                data={"username": f"operator-{index % 2}", "password": f"guess-{index % 2}"},
            )
            assert response.status_code == 200

    auth_events = [
        event for event in store.fetch_events() if event.event_type == "hmi.auth.service_login_attempt"
    ]
    campaigns = store.fetch_login_campaigns()
    top_usernames = store.fetch_login_credential_top(value_type="username")
    top_passwords = store.fetch_login_credential_top(value_type="password")
    campaign_passwords = store.fetch_login_credential_top(
        value_type="password",
        scope_type="campaign",
        scope_id=campaigns[0].campaign_id,
    )

    assert len(auth_events) == 5
    assert len(campaigns) == 1
    assert campaigns[0].attempt_count == 7
    assert top_usernames[0].credential_value == "operator-0"
    assert top_usernames[0].count == 4
    assert top_passwords[0].credential_value == "guess-0"
    assert top_passwords[0].count == 4
    assert campaign_passwords[0].credential_value == "guess-0"
    assert campaign_passwords[0].count == 4


@pytest.mark.asyncio
async def test_service_login_emits_campaign_summary_after_interval(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    clock = FrozenClock(snapshot.start_time)
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-login-summary.db")
    recorder = EventRecorder(store=store, clock=clock)
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        for _ in range(5):
            response = await client.post(
                "/service/login",
                data={"username": SERVICE_LOGIN_USERNAME, "password": "wrong"},
            )
            assert response.status_code == 200
        clock.advance(timedelta(seconds=61))
        summary_response = await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": "wrong"},
        )

    summary_events = [
        event for event in store.fetch_events() if event.event_type == "hmi.auth.bruteforce_campaign_summary"
    ]

    assert summary_response.status_code == 200
    assert len(summary_events) == 1
    assert summary_events[0].resulting_value["attempt_count_total"] == 6
    assert summary_events[0].resulting_value["attempt_count_window"] == 6
    assert summary_events[0].requested_value["sampled_attempts"] == 5


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
async def test_service_login_uses_persisted_lure_credentials(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-login-settings.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    save_ops_settings(
        store,
        OpsBackendSettings(service_login_username="maintenance", service_login_password="shadow"),
        updated_at=snapshot.start_time,
    )
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=build_config(tmp_path),
        event_recorder=recorder,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        default_response = await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        custom_response = await client.post(
            "/service/login",
            data={"username": "maintenance", "password": "shadow"},
            follow_redirects=False,
        )
        panel_response = await client.get("/service/panel")

    auth_results = [
        event.result for event in store.fetch_events() if event.event_type == "hmi.auth.service_login_attempt"
    ]

    assert default_response.status_code == 200
    assert "Authentication failed. Check credentials and retry." in default_response.text
    assert custom_response.status_code == 303
    assert custom_response.headers["location"] == "/service/panel"
    assert panel_response.status_code == 200
    assert "maintenance" in panel_response.text
    assert auth_results == ["failure", "success"]


@pytest.mark.asyncio
async def test_service_login_marks_cookies_secure_when_tls_proxy_mode_is_enabled(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    config = build_config(tmp_path).model_copy(
        update={
            "hmi_cookie_secure": True,
            "service_cookie_secure": True,
        }
    )
    app = create_hmi_app(
        snapshot_provider=lambda: snapshot,
        config=config,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )

    hmi_cookie = set_cookie_header(response, SESSION_COOKIE_NAME).lower()
    service_cookie = set_cookie_header(response, SERVICE_SESSION_COOKIE_NAME).lower()

    assert response.status_code == 303
    assert "secure" in hmi_cookie
    assert "secure" in service_cookie


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
        csrf_token = await login_service_client(client)
        control_response = await client.post(
            "/service/panel/power-limit",
            data={
                SERVICE_CSRF_FIELD_NAME: csrf_token,
                "active_power_limit_pct": "55.5",
            },
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
async def test_service_panel_rejects_missing_csrf_token_without_state_change(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-csrf-reject.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app, register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await login_service_client(client)
        control_response = await client.post(
            "/service/panel/power-limit",
            data={"active_power_limit_pct": "55.5"},
            follow_redirects=False,
        )

    events = store.fetch_events()
    control_event = next(
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted" and event.action == "set_active_power_limit"
    )

    assert control_response.status_code == 303
    assert control_response.headers["location"] == "/service/panel?status=control_invalid"
    assert register_map.snapshot.power_plant_controller.active_power_limit_pct == 100.0
    assert not any(event.event_type == "process.setpoint.curtailment_changed" for event in events)
    assert control_event.result == "rejected"
    assert control_event.error_code == "service_control_invalid"


@pytest.mark.asyncio
async def test_service_panel_rejects_oversized_control_form_without_state_change(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-control-oversized.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app, register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path, recorder=recorder)
    oversized_body = b"active_power_limit_pct=" + (b"5" * (MAX_FORM_BODY_BYTES + 1))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        await client.post(
            "/service/login",
            data={"username": SERVICE_LOGIN_USERNAME, "password": SERVICE_LOGIN_PASSWORD},
            follow_redirects=False,
        )
        control_response = await client.post(
            "/service/panel/power-limit",
            content=oversized_body,
            headers={"content-type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )

    events = store.fetch_events()
    control_event = next(
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted" and event.action == "set_active_power_limit"
    )

    assert control_response.status_code == 303
    assert control_response.headers["location"] == "/service/panel?status=control_invalid"
    assert register_map.snapshot.power_plant_controller.active_power_limit_pct == 100.0
    assert control_event.result == "rejected"
    assert control_event.error_code == "service_control_invalid"


@pytest.mark.asyncio
async def test_service_panel_reactive_power_updates_shared_truth_and_logs_control_event(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-reactive-power.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app, register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        csrf_token = await login_service_client(client)
        control_response = await client.post(
            "/service/panel/reactive-power",
            data={
                SERVICE_CSRF_FIELD_NAME: csrf_token,
                "reactive_power_target_pct": "25.0",
            },
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
        csrf_token = await login_service_client(client)
        control_response = await client.post(
            "/service/panel/plant-mode",
            data={
                SERVICE_CSRF_FIELD_NAME: csrf_token,
                "plant_mode_request": "2",
            },
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
        csrf_token = await login_service_client(client)
        open_response = await client.post(
            "/service/panel/breaker",
            data={
                SERVICE_CSRF_FIELD_NAME: csrf_token,
                "breaker_action": "open",
            },
            follow_redirects=False,
        )
        open_panel_response = await client.get(open_response.headers["location"])
        close_response = await client.post(
            "/service/panel/breaker",
            data={
                SERVICE_CSRF_FIELD_NAME: csrf_token,
                "breaker_action": "close",
            },
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
        csrf_token = await login_service_client(client)
        control_response = await client.post(
            "/service/panel/inverter-block",
            data={
                SERVICE_CSRF_FIELD_NAME: csrf_token,
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
async def test_service_panel_dc_disconnect_switch_reduces_output_and_logs_events(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-dc-disconnect.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(snapshot.start_time))
    app, register_map = build_service_app(snapshot=snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        csrf_token = await login_service_client(client)
        control_response = await client.post(
            "/service/panel/inverter-block/dc-disconnect",
            data={
                SERVICE_CSRF_FIELD_NAME: csrf_token,
                "asset_id": "invb-02",
                "dc_disconnect_open": "1",
            },
            follow_redirects=False,
        )
        panel_response = await client.get(control_response.headers["location"])
        inverters_response = await client.get("/inverters")

    events = store.fetch_events()
    control_event = next(
        event
        for event in events
        if event.event_type == "hmi.action.service_control_submitted"
        and event.action == "set_block_dc_disconnect_state"
    )
    process_event = next(event for event in events if event.event_type == "process.control.block_dc_disconnect_changed")
    isolated_block = register_map.snapshot.inverter_blocks[1]

    assert control_response.status_code == 303
    assert control_response.headers["location"] == "/service/panel?status=dc_disconnect_updated"
    assert panel_response.status_code == 200
    assert "PV disconnect state updated successfully." in panel_response.text
    assert "PV Disconnect Open" in panel_response.text
    assert inverters_response.status_code == 200
    assert "PV Isolator" in inverters_response.text
    assert "PV isolated" in inverters_response.text
    assert isolated_block.asset_id == "invb-02"
    assert isolated_block.dc_disconnect_state == "open"
    assert isolated_block.status == "online"
    assert isolated_block.communication_state == "healthy"
    assert isolated_block.block_power_kw == 0.0
    assert register_map.snapshot.site.plant_power_mw == pytest.approx(3.88)
    assert register_map.read_holding_registers(unit_id=12, start_offset=199, quantity=4).values == (1, 1000, 0, 1)
    visible_status = register_map.read_holding_registers(unit_id=12, start_offset=99, quantity=13).values
    assert visible_status[0:6] == (
        0,
        0,
        0,
        0,
        0,
        0,
    )
    assert visible_status[12] == 1
    assert control_event.result == "accepted"
    assert control_event.requested_value["asset_id"] == "invb-02"
    assert control_event.requested_value["dc_disconnect_state"] == "open"
    assert control_event.requested_value["http_path"] == "/service/panel/inverter-block/dc-disconnect"
    assert control_event.previous_value == "closed"
    assert control_event.resulting_value["value"] == "open"
    assert control_event.resulting_value["http_status"] == 303
    assert control_event.resulting_state["block_power_kw"] == 0.0
    assert control_event.correlation_id == process_event.correlation_id


@pytest.mark.asyncio
async def test_service_panel_inverter_block_reset_recovers_comm_loss_and_logs_control_event(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    comm_loss_snapshot = PlantSimulator.from_snapshot(snapshot).lose_block_communications(snapshot, asset_id="invb-02")
    store = SQLiteEventStore(tmp_path / "events" / "hmi-service-inverter-reset.db")
    recorder = EventRecorder(store=store, clock=FrozenClock(comm_loss_snapshot.start_time))
    app, register_map = build_service_app(snapshot=comm_loss_snapshot, tmp_path=tmp_path, recorder=recorder)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        csrf_token = await login_service_client(client)
        control_response = await client.post(
            "/service/panel/inverter-block/reset",
            data={
                SERVICE_CSRF_FIELD_NAME: csrf_token,
                "asset_id": "invb-02",
            },
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
        csrf_token = await login_service_client(client)
        control_response = await client.post(
            "/service/panel/power-limit",
            data={
                SERVICE_CSRF_FIELD_NAME: csrf_token,
                "active_power_limit_pct": "150.1",
            },
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
        csrf_token = await login_service_client(client)
        control_response = await client.post(
            "/service/panel/reactive-power",
            data={
                SERVICE_CSRF_FIELD_NAME: csrf_token,
                "reactive_power_target_pct": "150.0",
            },
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
        csrf_token = await login_service_client(client)
        control_response = await client.post(
            "/service/panel/plant-mode",
            data={
                SERVICE_CSRF_FIELD_NAME: csrf_token,
                "plant_mode_request": "3",
            },
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
        csrf_token = await login_service_client(client)
        control_response = await client.post(
            "/service/panel/inverter-block",
            data={
                SERVICE_CSRF_FIELD_NAME: csrf_token,
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
    assert "Stale telemetry" in response.text
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
    clock = FrozenClock(build_snapshot().start_time)
    env_file.write_text(
        f"EVENT_STORE_PATH={event_store_path}\nJSONL_ARCHIVE_ENABLED=0\n",
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0, clock=clock)
    runtime.modbus_service.register_map.write_single_register(unit_id=1, start_offset=199, value=555)
    clock.advance(timedelta(minutes=5))
    runtime.evolution_service.evolve_once()

    transport = httpx.ASGITransport(app=runtime.hmi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/trends")

    assert response.status_code == 200
    assert "Trend Overview" in response.text
    assert "The live trace shows curtailed output across the recent history window." in response.text
    assert "2026-04-01 10:05:00 UTC" in response.text
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
