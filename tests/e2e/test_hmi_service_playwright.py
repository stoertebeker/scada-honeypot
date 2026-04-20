from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

import pytest
from playwright.sync_api import Browser, Page, Playwright, expect, sync_playwright

from honeypot.hmi_web.app import SERVICE_LOGIN_PASSWORD, SERVICE_LOGIN_USERNAME
from honeypot.main import LocalRuntime, build_local_runtime


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
def page() -> Iterator[Page]:
    with sync_playwright() as playwright:
        browser = _launch_browser(playwright)
        context = browser.new_context()
        try:
            yield context.new_page()
        finally:
            context.close()
            browser.close()


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
    expect(page.get_by_text("Grid breaker open")).to_be_visible()
    expect(page.get_by_text("grid-01")).to_be_visible()

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
    expect(page.get_by_text("The trace shows curtailed output against the nominal baseline.")).to_be_visible()
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
