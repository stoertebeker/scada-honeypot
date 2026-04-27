from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path
from typing import Iterator

import pytest
from playwright.sync_api import Browser, Page, Playwright, expect, sync_playwright

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.config_core import load_runtime_config
from honeypot.event_core import EventRecorder
from honeypot.hmi_web import LocalHmiHttpService, create_hmi_app
from honeypot.hmi_web.app import SERVICE_LOGIN_PASSWORD, SERVICE_LOGIN_USERNAME, SERVICE_SESSION_COOKIE_NAME
from honeypot.main import LocalRuntime, bootstrap_runtime, build_local_runtime
from honeypot.protocol_modbus import ReadOnlyModbusTcpService, ReadOnlyRegisterMap
from honeypot.runtime_evolution import BackgroundPlantEvolutionService, TrendHistoryBuffer, trend_history_capacity
from honeypot.rule_engine import RuleEngine
from honeypot.storage import SQLiteEventStore
from honeypot.time_core import FrozenClock


def write_env(tmp_path: Path, *lines: str) -> Path:
    env_file = tmp_path / ".env"
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return env_file


@pytest.fixture
def runtime(tmp_path: Path) -> Iterator[LocalRuntime]:
    env_file = write_env(
        tmp_path,
        f"EVENT_STORE_PATH={tmp_path / 'events' / 'honeypot.db'}",
        "JSONL_ARCHIVE_ENABLED=0",
    )
    local_runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    local_runtime.start()
    try:
        yield local_runtime
    finally:
        local_runtime.stop()


@pytest.fixture
def expired_runtime(tmp_path: Path) -> Iterator[tuple[LocalRuntime, FrozenClock]]:
    clock = FrozenClock(load_plant_fixture("normal_operation").start_time)
    env_file = write_env(
        tmp_path,
        f"EVENT_STORE_PATH={tmp_path / 'events' / 'honeypot.db'}",
        "JSONL_ARCHIVE_ENABLED=0",
    )
    local_runtime = _build_runtime_with_clock(env_file=env_file, clock=clock)
    local_runtime.start()
    try:
        yield local_runtime, clock
    finally:
        local_runtime.stop()


@pytest.fixture
def disabled_service_runtime(tmp_path: Path) -> Iterator[LocalRuntime]:
    env_file = write_env(
        tmp_path,
        f"EVENT_STORE_PATH={tmp_path / 'events' / 'honeypot.db'}",
        "JSONL_ARCHIVE_ENABLED=0",
        "ENABLE_SERVICE_LOGIN=0",
    )
    local_runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    local_runtime.start()
    try:
        yield local_runtime
    finally:
        local_runtime.stop()


@pytest.fixture
def page() -> Iterator[Page]:
    with sync_playwright() as playwright:
        browser = _launch_browser(playwright)
        context = browser.new_context()
        try:
            yield context.new_page()
        finally:
            context.close()
            browser.close()


def test_playwright_service_login_failure_and_unauthorized_panel_stay_quiet(runtime: LocalRuntime, page: Page) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    panel_response = page.goto(f"{base_url}/service/panel", wait_until="networkidle")

    assert panel_response is not None
    assert panel_response.status == 401
    expect(page).to_have_url(re.compile(r".*/service/panel$"))
    _expect_quiet_error_page(
        page,
        title="Authentication Required",
        message="Authentication is required. Open /service/login to continue.",
    )

    page.goto(f"{base_url}/service/login", wait_until="networkidle")

    expect(page).to_have_url(re.compile(r".*/service/login$"))
    expect(page.get_by_role("heading", name="Service Login")).to_be_visible()
    page.get_by_label("Username").fill("wrong")
    page.get_by_label("Password").fill("wrong")
    page.get_by_role("button", name="Log In").click()

    expect(page).to_have_url(re.compile(r".*/service/login$"))
    expect(page.get_by_text("Authentication failed. Check credentials and retry.")).to_be_visible()
    assert not any(cookie["name"] == SERVICE_SESSION_COOKIE_NAME for cookie in page.context.cookies())

    events = runtime.event_store.fetch_events()

    assert any(
        event.event_type == "hmi.error.unauthorized"
        and event.endpoint_or_register == "/service/panel"
        and event.resulting_value["http_status"] == 401
        for event in events
    )
    assert any(
        event.event_type == "hmi.auth.service_login_attempt"
        and event.result == "failure"
        and event.requested_value["username"] == "wrong"
        for event in events
    )


def test_playwright_repeated_service_login_failures_raise_alarm(runtime: LocalRuntime, page: Page) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    page.goto(f"{base_url}/service/login", wait_until="networkidle")

    expect(page).to_have_url(re.compile(r".*/service/login$"))
    expect(page.get_by_role("heading", name="Service Login")).to_be_visible()
    for _ in range(3):
        page.get_by_label("Username").fill(SERVICE_LOGIN_USERNAME)
        page.get_by_label("Password").fill("wrong")
        page.get_by_role("button", name="Log In").click()
        expect(page).to_have_url(re.compile(r".*/service/login$"))
        expect(page.get_by_text("Authentication failed. Check credentials and retry.")).to_be_visible()

    assert not any(cookie["name"] == SERVICE_SESSION_COOKIE_NAME for cookie in page.context.cookies())

    page.get_by_role("link", name="Alarms").click()

    expect(page).to_have_url(re.compile(r".*/alarms$"))
    expect(page.get_by_role("heading", name="Alarm Console")).to_be_visible()
    expect(page.locator("body")).to_contain_text("REPEATED_LOGIN_FAILURE")
    expect(page.locator("body")).to_contain_text("Repeated service login failures")
    expect(page.locator("body")).to_contain_text("hmi-web")
    expect(page.locator("body")).to_contain_text("Medium")
    expect(page.locator("body")).to_contain_text("Active")

    events = runtime.event_store.fetch_events()
    alerts = runtime.event_store.fetch_alerts()

    assert sum(
        1
        for event in events
        if event.event_type == "hmi.auth.service_login_attempt"
        and event.result == "failure"
        and event.requested_value["username"] == SERVICE_LOGIN_USERNAME
    ) == 3
    assert any(event.event_type == "hmi.page.alarms_viewed" for event in events)
    assert any(
        alert.alarm_code == "REPEATED_LOGIN_FAILURE" and alert.asset_id == "hmi-web" and alert.state != "cleared"
        for alert in alerts
    )


def test_playwright_repeated_login_failure_alert_is_suppressed_after_additional_failures(
    runtime: LocalRuntime,
    page: Page,
) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    page.goto(f"{base_url}/service/login", wait_until="networkidle")

    expect(page).to_have_url(re.compile(r".*/service/login$"))
    expect(page.get_by_role("heading", name="Service Login")).to_be_visible()
    for _ in range(5):
        page.get_by_label("Username").fill(SERVICE_LOGIN_USERNAME)
        page.get_by_label("Password").fill("wrong")
        page.get_by_role("button", name="Log In").click()
        expect(page).to_have_url(re.compile(r".*/service/login$"))
        expect(page.get_by_text("Authentication failed. Check credentials and retry.")).to_be_visible()

    assert not any(cookie["name"] == SERVICE_SESSION_COOKIE_NAME for cookie in page.context.cookies())

    page.get_by_role("link", name="Alarms").click()

    expect(page).to_have_url(re.compile(r".*/alarms$"))
    expect(page.get_by_role("heading", name="Alarm Console")).to_be_visible()
    repeated_rows = page.locator("tbody tr").filter(has=page.get_by_text("REPEATED_LOGIN_FAILURE"))
    assert repeated_rows.count() == 1
    expect(repeated_rows.first).to_contain_text("Repeated service login failures")
    expect(repeated_rows.first).to_contain_text("hmi-web")
    expect(repeated_rows.first).to_contain_text("Medium")
    expect(repeated_rows.first).to_contain_text("Active")

    events = runtime.event_store.fetch_events()
    alerts = runtime.event_store.fetch_alerts()

    assert sum(
        1
        for event in events
        if event.event_type == "hmi.auth.service_login_attempt"
        and event.result == "failure"
        and event.requested_value["username"] == SERVICE_LOGIN_USERNAME
    ) == 5
    assert len(
        [
            alert
            for alert in alerts
            if alert.alarm_code == "REPEATED_LOGIN_FAILURE" and alert.asset_id == "hmi-web" and alert.state != "cleared"
        ]
    ) == 1


def test_playwright_successful_login_clears_repeated_login_failure_alarm(runtime: LocalRuntime, page: Page) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    page.goto(f"{base_url}/service/login", wait_until="networkidle")

    expect(page).to_have_url(re.compile(r".*/service/login$"))
    expect(page.get_by_role("heading", name="Service Login")).to_be_visible()
    for _ in range(3):
        page.get_by_label("Username").fill(SERVICE_LOGIN_USERNAME)
        page.get_by_label("Password").fill("wrong")
        page.get_by_role("button", name="Log In").click()
        expect(page).to_have_url(re.compile(r".*/service/login$"))
        expect(page.get_by_text("Authentication failed. Check credentials and retry.")).to_be_visible()

    page.get_by_label("Username").fill(SERVICE_LOGIN_USERNAME)
    page.get_by_label("Password").fill(SERVICE_LOGIN_PASSWORD)
    page.get_by_role("button", name="Log In").click()

    expect(page).to_have_url(re.compile(r".*/service/panel(?:\\?.*)?$"))
    expect(page.get_by_role("heading", name="Service Panel")).to_be_visible()
    assert any(cookie["name"] == SERVICE_SESSION_COOKIE_NAME for cookie in page.context.cookies())

    page.get_by_role("link", name="Alarms").click()

    expect(page).to_have_url(re.compile(r".*/alarms$"))
    expect(page.get_by_role("heading", name="Alarm Console")).to_be_visible()
    expect(page.locator("body")).to_contain_text("Active Alarms")
    expect(page.locator("body")).to_contain_text("0")
    repeated_rows = page.locator("tbody tr").filter(has=page.get_by_text("REPEATED_LOGIN_FAILURE"))
    assert repeated_rows.count() == 1
    expect(repeated_rows.first).to_contain_text("Repeated service login failures")
    expect(repeated_rows.first).to_contain_text("hmi-web")
    expect(repeated_rows.first).to_contain_text("Cleared")

    events = runtime.event_store.fetch_events()
    alerts = runtime.event_store.fetch_alerts()

    assert sum(
        1
        for event in events
        if event.event_type == "hmi.auth.service_login_attempt"
        and event.requested_value["username"] == SERVICE_LOGIN_USERNAME
    ) == 4
    assert any(event.event_type == "hmi.page.alarms_viewed" for event in events)
    assert any(
        alert.alarm_code == "REPEATED_LOGIN_FAILURE" and alert.asset_id == "hmi-web" and alert.state == "cleared"
        for alert in alerts
    )


def test_playwright_service_login_breaker_alarm_flow(runtime: LocalRuntime, page: Page) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    _login_to_service_panel(page, base_url=base_url)
    expect(page.get_by_role("heading", name="Grid Breaker Control")).to_be_visible()

    page.get_by_role("button", name="Open Breaker").click()

    expect(page).to_have_url(re.compile(r".*/service/panel\?status=breaker_open_requested$"))
    expect(page.get_by_text("Breaker open request accepted.")).to_be_visible()
    expect(page.get_by_text("Breaker State: Open")).to_be_visible()

    page.get_by_role("link", name="Alarms").click()

    expect(page).to_have_url(re.compile(r".*/alarms$"))
    expect(page.get_by_role("heading", name="Alarm Console")).to_be_visible()
    breaker_row = page.locator("tbody tr").filter(has=page.get_by_text("BREAKER_OPEN"))
    expect(breaker_row).to_contain_text("Grid breaker open")
    expect(breaker_row).to_contain_text("grid-01")

    events = runtime.event_store.fetch_events()
    alerts = runtime.event_store.fetch_alerts()

    assert any(
        event.event_type == "hmi.auth.service_login_attempt" and event.result == "success"
        for event in events
    )
    assert any(
        event.event_type == "hmi.action.service_control_submitted"
        and event.action == "breaker_open_request"
        and event.result == "accepted"
        for event in events
    )
    assert any(event.event_type == "hmi.page.alarms_viewed" for event in events)
    assert any(
        alert.alarm_code == "BREAKER_OPEN" and alert.asset_id == "grid-01" and alert.state != "cleared"
        for alert in alerts
    )


def test_playwright_breaker_open_shows_grid_path_follow_up_alarm(runtime: LocalRuntime, page: Page) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    _login_to_service_panel(page, base_url=base_url)
    expect(page.get_by_role("heading", name="Grid Breaker Control")).to_be_visible()

    page.get_by_role("button", name="Open Breaker").click()

    expect(page).to_have_url(re.compile(r".*/service/panel\?status=breaker_open_requested$"))
    expect(page.get_by_text("Breaker open request accepted.")).to_be_visible()

    page.get_by_role("link", name="Alarms").click()

    expect(page).to_have_url(re.compile(r".*/alarms$"))
    expect(page.get_by_role("heading", name="Alarm Console")).to_be_visible()
    grid_path_row = page.locator("tbody tr").filter(has=page.get_by_text("GRID_PATH_UNAVAILABLE"))
    expect(grid_path_row).to_contain_text("Grid path unavailable")
    expect(grid_path_row).to_contain_text("grid-01")
    expect(grid_path_row).to_contain_text("Critical")
    expect(grid_path_row).to_contain_text("Active")

    events = runtime.event_store.fetch_events()
    alerts = runtime.event_store.fetch_alerts()

    assert any(event.event_type == "hmi.page.alarms_viewed" for event in events)
    assert any(
        alert.alarm_code == "GRID_PATH_UNAVAILABLE" and alert.asset_id == "grid-01" and alert.state != "cleared"
        for alert in alerts
    )


def test_playwright_grid_path_follow_up_alert_is_suppressed_after_additional_breaker_open(
    runtime: LocalRuntime,
    page: Page,
) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    _login_to_service_panel(page, base_url=base_url)
    expect(page.get_by_role("heading", name="Grid Breaker Control")).to_be_visible()

    page.get_by_role("button", name="Open Breaker").click()

    expect(page).to_have_url(re.compile(r".*/service/panel\?status=breaker_open_requested$"))
    expect(page.get_by_text("Breaker open request accepted.")).to_be_visible()

    runtime.modbus_service.register_map.request_breaker_open()

    page.get_by_role("link", name="Alarms").click()

    expect(page).to_have_url(re.compile(r".*/alarms$"))
    expect(page.get_by_role("heading", name="Alarm Console")).to_be_visible()
    grid_path_rows = page.locator("tbody tr").filter(has=page.get_by_text("GRID_PATH_UNAVAILABLE"))
    assert grid_path_rows.count() == 1
    expect(grid_path_rows.first).to_contain_text("Grid path unavailable")
    expect(grid_path_rows.first).to_contain_text("grid-01")
    expect(grid_path_rows.first).to_contain_text("Critical")
    expect(grid_path_rows.first).to_contain_text("Active")

    events = runtime.event_store.fetch_events()
    alerts = runtime.event_store.fetch_alerts()

    assert sum(
        1
        for event in events
        if event.event_type == "process.breaker.state_changed"
        and event.action == "breaker_open_request"
        and event.result == "accepted"
    ) == 2
    assert any(event.event_type == "hmi.page.alarms_viewed" for event in events)
    assert len(
        [
            alert
            for alert in alerts
            if alert.alarm_code == "GRID_PATH_UNAVAILABLE"
            and alert.asset_id == "grid-01"
            and alert.state != "cleared"
        ]
    ) == 1


def test_playwright_low_site_output_follow_up_alarm_appears_after_multiple_block_outages(
    runtime: LocalRuntime,
    page: Page,
) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    _login_to_service_panel(page, base_url=base_url)

    for asset_id in ("invb-01", "invb-02"):
        block_card = page.locator("article.block-card").filter(has=page.get_by_text(asset_id))
        expect(block_card).to_contain_text(asset_id)
        block_card.get_by_label("Block Enable Request").select_option(label="Unavailable")
        block_card.get_by_label("Block Power Limit (%)").fill("100.0")
        block_card.get_by_role("button", name="Apply Block Control").click()

        expect(page).to_have_url(re.compile(r".*/service/panel\?status=block_control_updated$"))
        expect(page.get_by_text("Inverter block control updated successfully.")).to_be_visible()

    page.get_by_role("link", name="Alarms").click()

    expect(page).to_have_url(re.compile(r".*/alarms$"))
    expect(page.get_by_role("heading", name="Alarm Console")).to_be_visible()
    low_output_rows = page.locator("tbody tr").filter(has=page.get_by_text("LOW_SITE_OUTPUT_UNEXPECTED"))
    assert low_output_rows.count() == 1
    expect(low_output_rows.first).to_contain_text("Unexpected low site output")
    expect(low_output_rows.first).to_contain_text("site")
    expect(low_output_rows.first).to_contain_text("High")
    expect(low_output_rows.first).to_contain_text("Active")

    events = runtime.event_store.fetch_events()
    alerts = runtime.event_store.fetch_alerts()

    assert len(
        [
            event
            for event in events
            if event.event_type == "hmi.action.service_control_submitted"
            and event.action == "set_block_control_state"
            and event.result == "accepted"
            and event.asset_id in {"invb-01", "invb-02"}
        ]
    ) == 2
    assert any(event.event_type == "hmi.page.alarms_viewed" for event in events)
    assert any(
        alert.alarm_code == "LOW_SITE_OUTPUT_UNEXPECTED" and alert.asset_id == "site" and alert.state != "cleared"
        for alert in alerts
    )


def test_playwright_low_site_output_follow_up_alert_is_suppressed_after_additional_block_control(
    runtime: LocalRuntime,
    page: Page,
) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    _login_to_service_panel(page, base_url=base_url)

    for asset_id in ("invb-01", "invb-02"):
        block_card = page.locator("article.block-card").filter(has=page.get_by_text(asset_id))
        expect(block_card).to_contain_text(asset_id)
        block_card.get_by_label("Block Enable Request").select_option(label="Unavailable")
        block_card.get_by_label("Block Power Limit (%)").fill("100.0")
        block_card.get_by_role("button", name="Apply Block Control").click()

        expect(page).to_have_url(re.compile(r".*/service/panel\?status=block_control_updated$"))
        expect(page.get_by_text("Inverter block control updated successfully.")).to_be_visible()

    page.goto(f"{base_url}/service/panel", wait_until="networkidle")
    expect(page).to_have_url(re.compile(r".*/service/panel(?:\?.*)?$"))
    additional_block_card = page.locator("article.block-card").filter(has=page.get_by_text("invb-03"))
    additional_block_card.get_by_label("Block Enable Request").select_option(label="Available")
    additional_block_card.get_by_label("Block Power Limit (%)").fill("90.0")
    additional_block_card.get_by_role("button", name="Apply Block Control").click()

    expect(page).to_have_url(re.compile(r".*/service/panel\?status=block_control_updated$"))
    expect(page.get_by_text("Inverter block control updated successfully.")).to_be_visible()

    page.get_by_role("link", name="Alarms").click()

    expect(page).to_have_url(re.compile(r".*/alarms$"))
    expect(page.get_by_role("heading", name="Alarm Console")).to_be_visible()
    low_output_rows = page.locator("tbody tr").filter(has=page.get_by_text("LOW_SITE_OUTPUT_UNEXPECTED"))
    assert low_output_rows.count() == 1
    expect(low_output_rows.first).to_contain_text("Unexpected low site output")
    expect(low_output_rows.first).to_contain_text("site")
    expect(low_output_rows.first).to_contain_text("High")
    expect(low_output_rows.first).to_contain_text("Active")

    events = runtime.event_store.fetch_events()
    alerts = runtime.event_store.fetch_alerts()

    assert len(
        [
            event
            for event in events
            if event.event_type == "hmi.action.service_control_submitted"
            and event.action == "set_block_control_state"
            and event.result == "accepted"
            and event.asset_id in {"invb-01", "invb-02", "invb-03"}
        ]
    ) == 3
    assert any(
        event.event_type == "process.setpoint.block_power_limit_changed" and event.asset_id == "invb-03"
        for event in events
    )
    assert any(event.event_type == "hmi.page.alarms_viewed" for event in events)
    assert sum(
        1
        for alert in alerts
        if alert.alarm_code == "LOW_SITE_OUTPUT_UNEXPECTED" and alert.asset_id == "site"
    ) == 1


def test_playwright_low_site_output_follow_up_alarm_clears_after_block_recovery(
    runtime: LocalRuntime,
    page: Page,
) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    _login_to_service_panel(page, base_url=base_url)

    for asset_id in ("invb-01", "invb-02"):
        block_card = page.locator("article.block-card").filter(has=page.get_by_text(asset_id))
        expect(block_card).to_contain_text(asset_id)
        block_card.get_by_label("Block Enable Request").select_option(label="Unavailable")
        block_card.get_by_label("Block Power Limit (%)").fill("100.0")
        block_card.get_by_role("button", name="Apply Block Control").click()

        expect(page).to_have_url(re.compile(r".*/service/panel\?status=block_control_updated$"))
        expect(page.get_by_text("Inverter block control updated successfully.")).to_be_visible()

    page.goto(f"{base_url}/service/panel", wait_until="networkidle")
    expect(page).to_have_url(re.compile(r".*/service/panel(?:\?.*)?$"))
    recovery_block_card = page.locator("article.block-card").filter(has=page.get_by_text("invb-01"))
    recovery_block_card.get_by_label("Block Enable Request").select_option(label="Available")
    recovery_block_card.get_by_label("Block Power Limit (%)").fill("100.0")
    recovery_block_card.get_by_role("button", name="Apply Block Control").click()

    expect(page).to_have_url(re.compile(r".*/service/panel\?status=block_control_updated$"))
    expect(page.get_by_text("Inverter block control updated successfully.")).to_be_visible()

    page.get_by_role("link", name="Alarms").click()

    expect(page).to_have_url(re.compile(r".*/alarms$"))
    expect(page.get_by_role("heading", name="Alarm Console")).to_be_visible()
    low_output_rows = page.locator("tbody tr").filter(has=page.get_by_text("LOW_SITE_OUTPUT_UNEXPECTED"))
    assert low_output_rows.count() == 1
    expect(low_output_rows.first).to_contain_text("Unexpected low site output")
    expect(low_output_rows.first).to_contain_text("site")
    expect(low_output_rows.first).to_contain_text("Cleared")

    events = runtime.event_store.fetch_events()
    alerts = runtime.event_store.fetch_alerts()

    assert len(
        [
            event
            for event in events
            if event.event_type == "hmi.action.service_control_submitted"
            and event.action == "set_block_control_state"
            and event.result == "accepted"
            and event.asset_id in {"invb-01", "invb-02"}
        ]
    ) == 3
    assert any(event.event_type == "hmi.page.alarms_viewed" for event in events)
    assert any(
        alert.alarm_code == "LOW_SITE_OUTPUT_UNEXPECTED" and alert.asset_id == "site" and alert.state == "cleared"
        for alert in alerts
    )
    assert sum(
        1
        for alert in alerts
        if alert.alarm_code == "LOW_SITE_OUTPUT_UNEXPECTED" and alert.asset_id == "site"
    ) == 2


def test_playwright_reactive_power_target_updates_service_panel_and_shared_truth(
    runtime: LocalRuntime,
    page: Page,
) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    _login_to_service_panel(page, base_url=base_url)

    page.get_by_label("Reactive Power Target (%)").fill("25.0")
    page.get_by_role("button", name="Apply Reactive Target").click()

    expect(page).to_have_url(re.compile(r".*/service/panel\?status=reactive_power_updated$"))
    expect(page.get_by_text("Reactive power target updated successfully.")).to_be_visible()
    expect(page.locator("body")).to_contain_text("25.0 %")

    page.get_by_role("link", name="Overview").click()

    expect(page).to_have_url(re.compile(r".*/overview$"))
    expect(page.get_by_role("heading", name="Plant Overview")).to_be_visible()
    expect(page.locator("body")).to_contain_text("Reactive Power Target")
    expect(page.locator("body")).to_contain_text("25.0 %")

    events = runtime.event_store.fetch_events()

    assert any(
        event.event_type == "hmi.action.service_control_submitted"
        and event.action == "set_reactive_power_target"
        and event.result == "accepted"
        for event in events
    )
    assert any(event.event_type == "process.setpoint.reactive_power_target_changed" for event in events)
    assert any(event.event_type == "hmi.page.overview_viewed" for event in events)
    assert runtime.modbus_service.register_map.snapshot.power_plant_controller.reactive_power_target == 0.25
    assert runtime.modbus_service.register_map.snapshot.site.reactive_power_setpoint == 0.25
    assert runtime.modbus_service.register_map.read_holding_registers(unit_id=1, start_offset=109, quantity=1).values == (
        250,
    )


def test_playwright_plant_mode_request_latches_without_changing_actual_operating_mode(
    runtime: LocalRuntime,
    page: Page,
) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    _login_to_service_panel(page, base_url=base_url)

    plant_mode_select = page.locator("select[name='plant_mode_request']")
    plant_mode_select.select_option(label="Maintenance")
    page.get_by_role("button", name="Apply Plant Mode").click()

    expect(page).to_have_url(re.compile(r".*/service/panel\?status=plant_mode_updated$"))
    expect(page.get_by_text("Plant mode request updated successfully.")).to_be_visible()
    expect(plant_mode_select).to_have_value("2")

    events = runtime.event_store.fetch_events()

    assert any(
        event.event_type == "hmi.action.service_control_submitted"
        and event.action == "set_plant_mode_request"
        and event.result == "accepted"
        for event in events
    )
    assert any(event.event_type == "process.setpoint.plant_mode_request_changed" for event in events)
    assert runtime.modbus_service.register_map.get_plant_mode_request() == 2
    assert runtime.modbus_service.register_map.read_holding_registers(unit_id=1, start_offset=201, quantity=1).values == (
        2,
    )
    assert runtime.modbus_service.register_map.snapshot.site.operating_mode == "normal"
    assert runtime.modbus_service.register_map.read_holding_registers(unit_id=1, start_offset=99, quantity=1).values == (
        0,
    )


def test_playwright_single_line_reflects_breaker_open_shared_truth(
    runtime: LocalRuntime,
    page: Page,
) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    _login_to_service_panel(page, base_url=base_url)
    expect(page.get_by_role("heading", name="Grid Breaker Control")).to_be_visible()

    page.get_by_role("button", name="Open Breaker").click()

    expect(page).to_have_url(re.compile(r".*/service/panel\?status=breaker_open_requested$"))
    expect(page.get_by_text("Breaker open request accepted.")).to_be_visible()

    page.get_by_role("link", name="Single Line").click()

    expect(page).to_have_url(re.compile(r".*/single-line$"))
    expect(page.get_by_role("heading", name="Single-Line View")).to_be_visible()
    expect(page.locator(".energy-map")).to_be_visible()
    expect(page.locator(".energy-map [data-flow-node='grid']")).to_contain_text("Open")
    expect(page.locator(".energy-map [data-sld-symbol='breaker']")).to_be_visible()
    expect(page.locator(".energy-map [data-sld-symbol='dc-strings']").first).to_be_visible()
    expect(page.locator(".energy-map [data-sld-symbol='grid-source']")).to_be_visible()
    expect(page.locator(".flow-line.grid-link")).to_have_class(re.compile("export-halted"))
    expect(page.locator("body")).to_contain_text("Flow isolated by open breaker")
    expect(page.locator("body")).to_contain_text("Open")
    expect(page.locator("body")).to_contain_text("0 kW")
    expect(page.locator("body")).to_contain_text("Unavailable")

    events = runtime.event_store.fetch_events()

    assert any(
        event.event_type == "hmi.action.service_control_submitted"
        and event.action == "breaker_open_request"
        and event.result == "accepted"
        for event in events
    )
    assert any(event.event_type == "hmi.page.single_line_viewed" for event in events)
    assert runtime.modbus_service.register_map.snapshot.grid_interconnect.breaker_state == "open"
    assert runtime.modbus_service.register_map.snapshot.revenue_meter.export_power_kw == 0.0


def test_playwright_single_line_breaker_click_logs_rejected_attempt(runtime: LocalRuntime, page: Page) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    page.goto(f"{base_url}/single-line", wait_until="networkidle")

    expect(page).to_have_url(re.compile(r".*/single-line$"))
    expect(page.locator(".energy-map [data-sld-action='breaker-click']")).to_be_visible()

    page.locator(".energy-map [data-sld-action='breaker-click']").click()

    expect(page).to_have_url(re.compile(r".*/service/login$"))
    expect(page.get_by_role("heading", name="Service Login")).to_be_visible()

    events = runtime.event_store.fetch_events()

    assert any(
        event.event_type == "hmi.action.unauthenticated_control_attempt"
        and event.action == "single_line_breaker_click"
        and event.result == "rejected"
        and event.error_code == "service_auth_required"
        for event in events
    )
    assert not any(event.event_type == "process.breaker.state_changed" for event in events)
    assert runtime.modbus_service.register_map.snapshot.grid_interconnect.breaker_state == "closed"


def test_playwright_weather_page_reflects_unit_21_shared_truth(runtime: LocalRuntime, page: Page) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    page.goto(f"{base_url}/weather", wait_until="networkidle")

    expect(page).to_have_url(re.compile(r".*/weather$"))
    expect(page.get_by_role("heading", name="Weather Context")).to_be_visible()
    expect(page.locator("body")).to_contain_text("840 W/m2")
    expect(page.locator("body")).to_contain_text("31.5 C")
    expect(page.locator("body")).to_contain_text("22.0 C")
    expect(page.locator("body")).to_contain_text("4.2 m/s")
    expect(page.locator("body")).to_contain_text("Good")

    events = runtime.event_store.fetch_events()
    weather_registers = runtime.modbus_service.register_map.read_holding_registers(unit_id=21, start_offset=99, quantity=8)

    assert any(event.event_type == "hmi.page.weather_viewed" for event in events)
    assert weather_registers.values == (0, 0, 0, 840, 315, 220, 42, 1000)


def test_playwright_power_limit_updates_overview_and_trends(runtime: LocalRuntime, page: Page) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    _login_to_service_panel(page, base_url=base_url)

    page.get_by_label("Active Power Limit").fill("55.5")
    page.get_by_role("button", name="Apply Power Limit").click()

    expect(page).to_have_url(re.compile(r".*/service/panel\?status=power_limit_updated$"))
    expect(page.get_by_text("Active power limit updated successfully.")).to_be_visible()
    expect(page.get_by_text("55.5 %")).to_be_visible()
    expect(page.get_by_text("3.22 MW")).to_be_visible()

    page.get_by_role("link", name="Overview").click()

    expect(page).to_have_url(re.compile(r".*/overview$"))
    expect(page.get_by_role("heading", name="Plant Overview")).to_be_visible()
    expect(page.get_by_text("55.5 %")).to_be_visible()
    expect(page.get_by_text("3.22 MW")).to_be_visible()
    expect(page.get_by_text("Plant curtailed")).to_be_visible()

    page.get_by_role("link", name="Trends").click()

    expect(page).to_have_url(re.compile(r".*/trends$"))
    expect(page.get_by_role("heading", name="Trend Overview")).to_be_visible()
    expect(page.get_by_text("The live trace shows curtailed output across the recent history window.")).to_be_visible()
    expect(page.locator("body")).to_contain_text("55.5 %")
    expect(page.locator("body")).to_contain_text("3.22 MW")

    events = runtime.event_store.fetch_events()
    alerts = runtime.event_store.fetch_alerts()

    assert any(
        event.event_type == "hmi.action.service_control_submitted"
        and event.action == "set_active_power_limit"
        and event.result == "accepted"
        for event in events
    )
    assert any(event.event_type == "process.setpoint.curtailment_changed" for event in events)
    assert any(event.event_type == "hmi.page.overview_viewed" for event in events)
    assert any(event.event_type == "hmi.page.trends_viewed" for event in events)
    assert any(alert.alarm_code == "PLANT_CURTAILED" and alert.state != "cleared" for alert in alerts)


def test_playwright_breaker_recovery_updates_meter_and_clears_alarm(runtime: LocalRuntime, page: Page) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    _login_to_service_panel(page, base_url=base_url)

    page.get_by_role("button", name="Open Breaker").click()
    expect(page).to_have_url(re.compile(r".*/service/panel\?status=breaker_open_requested$"))
    expect(page.get_by_text("Breaker State: Open")).to_be_visible()

    page.get_by_role("button", name="Close Breaker").click()

    expect(page).to_have_url(re.compile(r".*/service/panel\?status=breaker_close_requested$"))
    expect(page.get_by_text("Breaker close request accepted.")).to_be_visible()
    expect(page.get_by_text("Breaker State: Closed")).to_be_visible()

    page.get_by_role("link", name="Meter").click()

    expect(page).to_have_url(re.compile(r".*/meter$"))
    expect(page.get_by_role("heading", name="Meter Overview")).to_be_visible()
    expect(page.locator("body")).to_contain_text("5.80 MW")
    expect(page.locator("body")).to_contain_text("Closed")
    expect(page.locator("body")).to_contain_text("Available")
    expect(page.locator("body")).not_to_contain_text("BREAKER_OPEN")

    page.get_by_role("link", name="Alarms").click()

    expect(page).to_have_url(re.compile(r".*/alarms$"))
    expect(page.get_by_role("heading", name="Alarm Console")).to_be_visible()
    expect(page.locator("body")).to_contain_text("Active Alarms")
    expect(page.locator("body")).to_contain_text("0")
    expect(page.locator("body")).to_contain_text("BREAKER_OPEN")
    expect(page.locator("body")).to_contain_text("Cleared")

    events = runtime.event_store.fetch_events()
    alerts = runtime.event_store.fetch_alerts()

    assert any(
        event.event_type == "hmi.action.service_control_submitted"
        and event.action == "breaker_open_request"
        and event.result == "accepted"
        for event in events
    )
    assert any(
        event.event_type == "hmi.action.service_control_submitted"
        and event.action == "breaker_close_request"
        and event.result == "accepted"
        for event in events
    )
    assert any(event.event_type == "hmi.page.meter_viewed" for event in events)
    assert any(event.event_type == "hmi.page.alarms_viewed" for event in events)
    assert any(
        alert.alarm_code == "BREAKER_OPEN" and alert.asset_id == "grid-01" and alert.state == "cleared"
        for alert in alerts
    )


def test_playwright_inverter_block_control_updates_inverters_view(runtime: LocalRuntime, page: Page) -> None:
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    _login_to_service_panel(page, base_url=base_url)

    block_card = page.locator("article.block-card").filter(has=page.get_by_text("invb-02"))
    expect(block_card).to_contain_text("invb-02")
    block_card.get_by_label("Block Enable Request").select_option(label="Unavailable")
    block_card.get_by_label("Block Power Limit (%)").fill("65.5")
    block_card.get_by_role("button", name="Apply Block Control").click()

    expect(page).to_have_url(re.compile(r".*/service/panel\?status=block_control_updated$"))
    expect(page.get_by_text("Inverter block control updated successfully.")).to_be_visible()
    expect(page.locator("body")).to_contain_text("65.5 %")

    page.get_by_role("link", name="Inverters").click()

    expect(page).to_have_url(re.compile(r".*/inverters$"))
    expect(page.get_by_role("heading", name="Inverter Fleet")).to_be_visible()
    expect(page.locator("body")).to_contain_text("invb-02")
    expect(page.locator("body")).to_contain_text("Offline")
    expect(page.locator("body")).to_contain_text("0.0 kW")
    expect(page.locator("body")).to_contain_text("Offline by request")
    expect(page.locator("body")).to_contain_text("No active alarms")

    events = runtime.event_store.fetch_events()
    alerts = runtime.event_store.fetch_alerts()

    assert any(
        event.event_type == "hmi.action.service_control_submitted"
        and event.action == "set_block_control_state"
        and event.result == "accepted"
        and event.asset_id == "invb-02"
        for event in events
    )
    assert any(
        event.event_type == "process.setpoint.block_enable_request_changed" and event.asset_id == "invb-02"
        for event in events
    )
    assert any(
        event.event_type == "process.setpoint.block_power_limit_changed" and event.asset_id == "invb-02"
        for event in events
    )
    assert any(event.event_type == "hmi.page.inverters_viewed" for event in events)
    assert not any(
        alert.alarm_code == "COMM_LOSS_INVERTER_BLOCK" and alert.asset_id == "invb-02" and alert.state != "cleared"
        for alert in alerts
    )


def test_playwright_block_reset_recovers_comm_loss_in_inverters_and_alarms(runtime: LocalRuntime, page: Page) -> None:
    _seed_runtime_comm_loss(runtime, asset_id="invb-02")

    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    page.goto(f"{base_url}/inverters", wait_until="networkidle")

    expect(page).to_have_url(re.compile(r".*/inverters$"))
    expect(page.get_by_role("heading", name="Inverter Fleet")).to_be_visible()
    inverter_row = page.locator("tbody tr").filter(has=page.get_by_text("invb-02"))
    expect(inverter_row).to_contain_text("Degraded")
    expect(inverter_row).to_contain_text("Lost")
    expect(inverter_row).to_contain_text("Stale")
    expect(page.locator("body")).to_contain_text("COMM_LOSS_INVERTER_BLOCK")

    _login_to_service_panel(page, base_url=base_url)

    block_card = page.locator("article.block-card").filter(has=page.get_by_text("invb-02"))
    expect(block_card).to_contain_text("invb-02")
    block_card.locator("form[action='/service/panel/inverter-block/reset'] button").click()

    expect(page).to_have_url(re.compile(r".*/service/panel\?status=block_reset_requested$"))
    expect(page.get_by_text("Inverter block reset pulse accepted.")).to_be_visible()

    page.get_by_role("link", name="Inverters").click()

    expect(page).to_have_url(re.compile(r".*/inverters$"))
    expect(page.get_by_role("heading", name="Inverter Fleet")).to_be_visible()
    inverter_row = page.locator("tbody tr").filter(has=page.get_by_text("invb-02"))
    expect(inverter_row).to_contain_text("Online")
    expect(inverter_row).to_contain_text("Healthy")
    expect(inverter_row).to_contain_text("Good")
    expect(inverter_row).not_to_contain_text("Lost")
    expect(inverter_row).not_to_contain_text("Stale")
    expect(page.locator("body")).to_contain_text("No active alarms")
    expect(page.locator("body")).not_to_contain_text("COMM_LOSS_INVERTER_BLOCK")

    page.get_by_role("link", name="Alarms").click()

    expect(page).to_have_url(re.compile(r".*/alarms$"))
    expect(page.get_by_role("heading", name="Alarm Console")).to_be_visible()
    expect(page.locator("body")).to_contain_text("Active Alarms")
    expect(page.locator("body")).to_contain_text("0")
    expect(page.locator("body")).to_contain_text("COMM_LOSS_INVERTER_BLOCK")
    expect(page.locator("body")).to_contain_text("Cleared")

    events = runtime.event_store.fetch_events()
    alerts = runtime.event_store.fetch_alerts()

    assert any(
        event.event_type == "hmi.action.service_control_submitted"
        and event.action == "block_reset_request"
        and event.result == "accepted"
        and event.asset_id == "invb-02"
        for event in events
    )
    assert any(event.event_type == "process.control.block_reset_requested" and event.asset_id == "invb-02" for event in events)
    assert any(event.event_type == "hmi.page.inverters_viewed" for event in events)
    assert any(event.event_type == "hmi.page.alarms_viewed" for event in events)
    assert any(
        alert.alarm_code == "COMM_LOSS_INVERTER_BLOCK" and alert.asset_id == "invb-02" and alert.state != "cleared"
        for alert in alerts
    )
    assert any(
        alert.alarm_code == "COMM_LOSS_INVERTER_BLOCK" and alert.asset_id == "invb-02" and alert.state == "cleared"
        for alert in alerts
    )


def test_playwright_block_reset_clears_multi_block_follow_up_in_alarms(runtime: LocalRuntime, page: Page) -> None:
    _seed_runtime_comm_loss(runtime, asset_id="invb-01")
    _seed_runtime_comm_loss(runtime, asset_id="invb-02")

    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    page.goto(f"{base_url}/alarms", wait_until="networkidle")

    expect(page).to_have_url(re.compile(r".*/alarms$"))
    expect(page.get_by_role("heading", name="Alarm Console")).to_be_visible()
    expect(page.locator("body")).to_contain_text("MULTI_BLOCK_UNAVAILABLE")
    expect(page.locator("body")).to_contain_text("Multiple inverter blocks unavailable")
    expect(page.locator("body")).to_contain_text("site")
    expect(page.locator("body")).to_contain_text("Active")

    _login_to_service_panel(page, base_url=base_url)

    block_card = page.locator("article.block-card").filter(has=page.get_by_text("invb-02"))
    expect(block_card).to_contain_text("invb-02")
    block_card.locator("form[action='/service/panel/inverter-block/reset'] button").click()

    expect(page).to_have_url(re.compile(r".*/service/panel\?status=block_reset_requested$"))
    expect(page.get_by_text("Inverter block reset pulse accepted.")).to_be_visible()

    page.get_by_role("link", name="Alarms").click()

    expect(page).to_have_url(re.compile(r".*/alarms$"))
    expect(page.get_by_role("heading", name="Alarm Console")).to_be_visible()
    expect(page.locator("body")).to_contain_text("MULTI_BLOCK_UNAVAILABLE")
    expect(page.locator("body")).to_contain_text("Multiple inverter blocks unavailable")
    expect(page.locator("body")).to_contain_text("Cleared")
    expect(page.locator("body")).to_contain_text("COMM_LOSS_INVERTER_BLOCK")

    events = runtime.event_store.fetch_events()
    alerts = runtime.event_store.fetch_alerts()

    assert any(
        event.event_type == "hmi.action.service_control_submitted"
        and event.action == "block_reset_request"
        and event.result == "accepted"
        and event.asset_id == "invb-02"
        for event in events
    )
    assert any(event.event_type == "hmi.page.alarms_viewed" for event in events)
    assert any(
        alert.alarm_code == "MULTI_BLOCK_UNAVAILABLE" and alert.asset_id == "site" and alert.state != "cleared"
        for alert in alerts
    )
    assert any(
        alert.alarm_code == "MULTI_BLOCK_UNAVAILABLE" and alert.asset_id == "site" and alert.state == "cleared"
        for alert in alerts
    )
    assert any(
        alert.alarm_code == "COMM_LOSS_INVERTER_BLOCK" and alert.asset_id == "invb-01" and alert.state != "cleared"
        for alert in alerts
    )


def test_playwright_additional_comm_loss_does_not_duplicate_multi_block_follow_up(runtime: LocalRuntime, page: Page) -> None:
    _seed_runtime_comm_loss(runtime, asset_id="invb-01")
    _seed_runtime_comm_loss(runtime, asset_id="invb-02")
    _seed_runtime_comm_loss(runtime, asset_id="invb-03")

    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    page.goto(f"{base_url}/alarms", wait_until="networkidle")

    expect(page).to_have_url(re.compile(r".*/alarms$"))
    expect(page.get_by_role("heading", name="Alarm Console")).to_be_visible()
    expect(page.locator("body")).to_contain_text("MULTI_BLOCK_UNAVAILABLE")
    expect(page.locator("body")).to_contain_text("Multiple inverter blocks unavailable")

    body_text = page.locator("body").text_content() or ""
    alerts = runtime.event_store.fetch_alerts()

    assert body_text.count("MULTI_BLOCK_UNAVAILABLE") == 1
    assert sum(
        1
        for alert in alerts
        if alert.alarm_code == "MULTI_BLOCK_UNAVAILABLE" and alert.asset_id == "site"
    ) == 1


def test_playwright_service_session_expiry_returns_quiet_unauthorized_page(
    expired_runtime: tuple[LocalRuntime, FrozenClock],
    page: Page,
) -> None:
    runtime, clock = expired_runtime
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    _login_to_service_panel(page, base_url=base_url)
    clock.advance(timedelta(minutes=21))

    panel_response = page.goto(f"{base_url}/service/panel", wait_until="networkidle")

    assert panel_response is not None
    assert panel_response.status == 401
    expect(page).to_have_url(re.compile(r".*/service/panel$"))
    _expect_quiet_error_page(
        page,
        title="Authentication Required",
        message="Authentication is required. Open /service/login to continue.",
    )

    events = runtime.event_store.fetch_events()

    assert any(
        event.event_type == "hmi.auth.service_login_attempt" and event.result == "success"
        for event in events
    )
    assert any(
        event.event_type == "hmi.error.unauthorized"
        and event.endpoint_or_register == "/service/panel"
        and event.resulting_value["http_status"] == 401
        for event in events
    )


def test_playwright_service_login_disabled_returns_quiet_forbidden_page(
    disabled_service_runtime: LocalRuntime,
    page: Page,
) -> None:
    runtime = disabled_service_runtime
    hmi_host, hmi_port = runtime.hmi_service.address
    base_url = f"http://{hmi_host}:{hmi_port}"

    login_response = page.goto(f"{base_url}/service/login", wait_until="networkidle")

    assert login_response is not None
    assert login_response.status == 403
    expect(page).to_have_url(re.compile(r".*/service/login$"))
    _expect_quiet_error_page(
        page,
        title="Access Denied",
        message="Access to this service area is denied in the current deployment.",
    )

    panel_response = page.goto(f"{base_url}/service/panel", wait_until="networkidle")

    assert panel_response is not None
    assert panel_response.status == 403
    expect(page).to_have_url(re.compile(r".*/service/panel$"))
    _expect_quiet_error_page(
        page,
        title="Access Denied",
        message="Access to this service area is denied in the current deployment.",
    )

    events = runtime.event_store.fetch_events()

    assert any(
        event.event_type == "hmi.error.forbidden"
        and event.endpoint_or_register == "/service/login"
        and event.resulting_value["http_status"] == 403
        for event in events
    )
    assert any(
        event.event_type == "hmi.error.forbidden"
        and event.endpoint_or_register == "/service/panel"
        and event.resulting_value["http_status"] == 403
        for event in events
    )


def _login_to_service_panel(page: Page, *, base_url: str) -> None:
    page.goto(f"{base_url}/service/login", wait_until="networkidle")

    expect(page).to_have_url(re.compile(r".*/service/login$"))
    expect(page.get_by_role("heading", name="Service Login")).to_be_visible()
    expect(page.get_by_role("heading", name="Service Authentication")).to_be_visible()

    page.get_by_label("Username").fill(SERVICE_LOGIN_USERNAME)
    page.get_by_label("Password").fill(SERVICE_LOGIN_PASSWORD)
    page.get_by_role("button", name="Log In").click()

    expect(page).to_have_url(re.compile(r".*/service/panel(?:\?.*)?$"))
    expect(page.get_by_role("heading", name="Service Panel")).to_be_visible()


def _launch_browser(playwright: Playwright) -> Browser:
    return playwright.chromium.launch(headless=True)


def _expect_quiet_error_page(page: Page, *, title: str, message: str) -> None:
    expect(page.get_by_role("heading", name=title)).to_be_visible()
    expect(page.locator("body")).to_contain_text(message)
    expect(page.locator("body")).not_to_contain_text("Traceback")
    expect(page.locator("body")).not_to_contain_text("FastAPI")
    expect(page.locator("body")).not_to_contain_text("Starlette")


def _build_runtime_with_clock(*, env_file: Path, clock: FrozenClock) -> LocalRuntime:
    config = load_runtime_config(env_file=str(env_file))
    snapshot = PlantSnapshot.from_fixture(load_plant_fixture("normal_operation"))
    event_store = SQLiteEventStore(config.event_store_path)
    event_recorder = EventRecorder(
        store=event_store,
        clock=clock,
        rule_engine=RuleEngine.default_v1(
            min_severity=config.alert_min_severity,
            capacity_mw=config.capacity_mw,
            low_output_threshold_pct=config.alarm_threshold_low_output_pct,
        ),
    )
    register_map = ReadOnlyRegisterMap(snapshot, event_recorder=event_recorder)
    trend_history = TrendHistoryBuffer(
        max_samples=trend_history_capacity(window_minutes=config.trend_window_minutes, interval_seconds=5.0)
    )
    evolution_service = BackgroundPlantEvolutionService(
        register_map=register_map,
        history=trend_history,
        clock=clock,
        interval_seconds=5.0,
    )
    hmi_app = create_hmi_app(
        snapshot_provider=lambda: register_map.snapshot,
        trend_history_provider=trend_history.snapshot,
        config=config,
        event_recorder=event_recorder,
        service_controls=register_map,
    )
    return LocalRuntime(
        config=config,
        manifest=bootstrap_runtime(),
        snapshot=snapshot,
        event_store=event_store,
        event_recorder=event_recorder,
        hmi_app=hmi_app,
        hmi_service=LocalHmiHttpService(
            app=hmi_app,
            bind_host=config.hmi_bind_host,
            port=0,
            log_level=config.log_level,
        ),
        modbus_service=ReadOnlyModbusTcpService(
            register_map=register_map,
            bind_host=config.modbus_bind_host,
            port=0,
            event_recorder=event_recorder,
        ),
        trend_history=trend_history,
        evolution_service=evolution_service,
    )


def _seed_runtime_comm_loss(runtime: LocalRuntime, *, asset_id: str) -> None:
    register_map = runtime.modbus_service.register_map
    register_map.replace_snapshot(
        register_map._simulator.lose_block_communications(
            register_map.snapshot,
            asset_id=asset_id,
        )
    )
