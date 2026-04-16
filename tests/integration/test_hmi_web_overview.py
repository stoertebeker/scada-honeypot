from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.config_core import RuntimeConfig
from honeypot.event_core import EventRecorder
from honeypot.hmi_web import create_hmi_app
from honeypot.main import build_local_runtime
from honeypot.plant_sim import PlantSimulator
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
