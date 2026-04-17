"""Read-only HMI-Slices fuer die ersten sichtbaren Web-Oberflaechen."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from honeypot.asset_domain import PlantSnapshot
from honeypot.config_core import RuntimeConfig
from honeypot.event_core import EventRecorder

HMI_COMPONENT = "hmi-web"
HMI_SERVICE = "web-hmi"
HMI_PROTOCOL = "http"
SESSION_COOKIE_NAME = "hmi_session"
_REPO_ROOT = Path(__file__).resolve().parents[3]
_LOCALE_DIR = _REPO_ROOT / "resources" / "locales" / "attacker-ui"
_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


@dataclass(frozen=True, slots=True)
class NavItem:
    href: str
    label_key: str
    is_current: bool


@dataclass(frozen=True, slots=True)
class OverviewMetric:
    label_key: str
    value: str
    tone: str


@dataclass(frozen=True, slots=True)
class OverviewInverterRow:
    asset_id: str
    status_label: str
    communication_label: str
    quality_label: str
    power_label: str
    local_alarm_count: int
    tone: str


@dataclass(frozen=True, slots=True)
class OverviewFact:
    label_key: str
    value: str


@dataclass(frozen=True, slots=True)
class OverviewAlarm:
    code: str
    label: str
    severity_label: str
    state_label: str
    tone: str


@dataclass(frozen=True, slots=True)
class OverviewViewModel:
    page_title: str
    page_subtitle: str
    site_name: str
    site_code: str
    snapshot_time: str
    metrics: tuple[OverviewMetric, ...]
    inverter_rows: tuple[OverviewInverterRow, ...]
    weather_facts: tuple[OverviewFact, ...]
    active_alarms: tuple[OverviewAlarm, ...]


@dataclass(frozen=True, slots=True)
class SingleLineNode:
    asset_id: str
    title: str
    status_label: str
    detail_label: str
    tone: str


@dataclass(frozen=True, slots=True)
class SingleLineFact:
    label_key: str
    value: str
    tone: str


@dataclass(frozen=True, slots=True)
class SingleLineViewModel:
    page_title: str
    page_subtitle: str
    site_name: str
    site_code: str
    snapshot_time: str
    flow_label: str
    flow_tone: str
    breaker_label: str
    breaker_tone: str
    grid_label: str
    grid_tone: str
    export_path_label: str
    export_path_tone: str
    facts: tuple[SingleLineFact, ...]
    inverter_nodes: tuple[SingleLineNode, ...]
    active_alarms: tuple[OverviewAlarm, ...]


@dataclass(frozen=True, slots=True)
class InverterDetailRow:
    asset_id: str
    status_label: str
    communication_label: str
    quality_label: str
    power_label: str
    availability_label: str
    dc_label: str
    ac_label: str
    temperature_label: str
    local_alarm_count: int
    tone: str


@dataclass(frozen=True, slots=True)
class InvertersViewModel:
    page_title: str
    page_subtitle: str
    site_name: str
    site_code: str
    snapshot_time: str
    metrics: tuple[OverviewMetric, ...]
    rows: tuple[InverterDetailRow, ...]
    active_alarms: tuple[OverviewAlarm, ...]


@dataclass(frozen=True, slots=True)
class WeatherViewModel:
    page_title: str
    page_subtitle: str
    site_name: str
    site_code: str
    snapshot_time: str
    metrics: tuple[OverviewMetric, ...]
    facts: tuple[OverviewFact, ...]
    context_label: str
    context_tone: str
    active_alarms: tuple[OverviewAlarm, ...]


@dataclass(frozen=True, slots=True)
class MeterViewModel:
    page_title: str
    page_subtitle: str
    site_name: str
    site_code: str
    snapshot_time: str
    metrics: tuple[OverviewMetric, ...]
    facts: tuple[OverviewFact, ...]
    context_label: str
    context_tone: str
    active_alarms: tuple[OverviewAlarm, ...]


def create_hmi_app(
    *,
    snapshot_provider: Callable[[], PlantSnapshot],
    config: RuntimeConfig,
    event_recorder: EventRecorder | None = None,
) -> FastAPI:
    """Erzeugt die ersten read-only HMI-Seiten fuer die lokale Runtime."""

    texts = _load_locale_texts(config)
    templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
    app = FastAPI(
        title=config.hmi_title,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/overview", response_class=HTMLResponse, include_in_schema=False)
    async def overview(request: Request) -> HTMLResponse:
        snapshot = snapshot_provider()
        session_id, set_cookie = _session_state(request)
        view_model = build_overview_view_model(snapshot=snapshot, config=config, texts=texts)
        response = templates.TemplateResponse(
            request=request,
            name="overview.html",
            context=_template_context(
                config=config,
                texts=texts,
                current_path=request.url.path,
                page=view_model,
            ),
        )
        if set_cookie:
            _set_session_cookie(response, session_id)

        _record_page_view(
            request=request,
            snapshot=snapshot,
            session_id=session_id,
            event_recorder=event_recorder,
            event_type="hmi.page.overview_viewed",
            action="view_overview",
            asset_id=snapshot.power_plant_controller.asset_id,
            resulting_state={
                "plant_power_mw": snapshot.site.plant_power_mw,
                "active_power_limit_pct": snapshot.power_plant_controller.active_power_limit_pct,
                "breaker_state": snapshot.site.breaker_state,
                "active_alarm_count": snapshot.site.active_alarm_count,
            },
            message="Overview page rendered",
            tags=("read-only", "overview", "web"),
        )
        return response

    @app.get("/single-line", response_class=HTMLResponse, include_in_schema=False)
    async def single_line(request: Request) -> HTMLResponse:
        snapshot = snapshot_provider()
        session_id, set_cookie = _session_state(request)
        view_model = build_single_line_view_model(snapshot=snapshot, config=config, texts=texts)
        response = templates.TemplateResponse(
            request=request,
            name="single_line.html",
            context=_template_context(
                config=config,
                texts=texts,
                current_path=request.url.path,
                page=view_model,
            ),
        )
        if set_cookie:
            _set_session_cookie(response, session_id)

        _record_page_view(
            request=request,
            snapshot=snapshot,
            session_id=session_id,
            event_recorder=event_recorder,
            event_type="hmi.page.single_line_viewed",
            action="view_single_line",
            asset_id=snapshot.grid_interconnect.asset_id,
            resulting_state={
                "breaker_state": snapshot.grid_interconnect.breaker_state,
                "export_power_kw": snapshot.revenue_meter.export_power_kw,
                "export_path_available": snapshot.grid_interconnect.export_path_available,
                "active_alarm_count": snapshot.site.active_alarm_count,
            },
            message="Single-line page rendered",
            tags=("read-only", "single-line", "web"),
        )
        return response

    @app.get("/inverters", response_class=HTMLResponse, include_in_schema=False)
    async def inverters(request: Request) -> HTMLResponse:
        snapshot = snapshot_provider()
        session_id, set_cookie = _session_state(request)
        view_model = build_inverters_view_model(snapshot=snapshot, config=config, texts=texts)
        response = templates.TemplateResponse(
            request=request,
            name="inverters.html",
            context=_template_context(
                config=config,
                texts=texts,
                current_path=request.url.path,
                page=view_model,
            ),
        )
        if set_cookie:
            _set_session_cookie(response, session_id)

        _record_page_view(
            request=request,
            snapshot=snapshot,
            session_id=session_id,
            event_recorder=event_recorder,
            event_type="hmi.page.inverters_viewed",
            action="view_inverters",
            asset_id=snapshot.power_plant_controller.asset_id,
            resulting_state={
                "block_count": len(snapshot.inverter_blocks),
                "degraded_block_count": _count_degraded_blocks(snapshot),
                "total_inverter_power_kw": snapshot.total_inverter_power_kw,
                "active_alarm_count": snapshot.site.active_alarm_count,
            },
            message="Inverters page rendered",
            tags=("read-only", "inverters", "web"),
        )
        return response

    @app.get("/weather", response_class=HTMLResponse, include_in_schema=False)
    async def weather(request: Request) -> HTMLResponse:
        snapshot = snapshot_provider()
        session_id, set_cookie = _session_state(request)
        view_model = build_weather_view_model(snapshot=snapshot, config=config, texts=texts)
        response = templates.TemplateResponse(
            request=request,
            name="weather.html",
            context=_template_context(
                config=config,
                texts=texts,
                current_path=request.url.path,
                page=view_model,
            ),
        )
        if set_cookie:
            _set_session_cookie(response, session_id)

        _record_page_view(
            request=request,
            snapshot=snapshot,
            session_id=session_id,
            event_recorder=event_recorder,
            event_type="hmi.page.weather_viewed",
            action="view_weather",
            asset_id=snapshot.weather_station.asset_id,
            resulting_state={
                "irradiance_w_m2": snapshot.weather_station.irradiance_w_m2,
                "weather_quality": snapshot.weather_station.quality,
                "weather_communications": snapshot.weather_station.communication_state,
                "plant_power_mw": snapshot.site.plant_power_mw,
            },
            message="Weather page rendered",
            tags=("read-only", "weather", "web"),
        )
        return response

    @app.get("/meter", response_class=HTMLResponse, include_in_schema=False)
    async def meter(request: Request) -> HTMLResponse:
        snapshot = snapshot_provider()
        session_id, set_cookie = _session_state(request)
        view_model = build_meter_view_model(snapshot=snapshot, config=config, texts=texts)
        response = templates.TemplateResponse(
            request=request,
            name="meter.html",
            context=_template_context(
                config=config,
                texts=texts,
                current_path=request.url.path,
                page=view_model,
            ),
        )
        if set_cookie:
            _set_session_cookie(response, session_id)

        _record_page_view(
            request=request,
            snapshot=snapshot,
            session_id=session_id,
            event_recorder=event_recorder,
            event_type="hmi.page.meter_viewed",
            action="view_meter",
            asset_id=snapshot.revenue_meter.asset_id,
            resulting_state={
                "export_power_kw": snapshot.revenue_meter.export_power_kw,
                "export_path_available": snapshot.grid_interconnect.export_path_available,
                "breaker_state": snapshot.grid_interconnect.breaker_state,
                "meter_quality": snapshot.revenue_meter.quality,
            },
            message="Meter page rendered",
            tags=("read-only", "meter", "web"),
        )
        return response

    return app


def build_overview_view_model(
    *,
    snapshot: PlantSnapshot,
    config: RuntimeConfig,
    texts: dict[str, str],
) -> OverviewViewModel:
    """Bereitet die sichtbaren Werte fuer die HMI-Uebersicht auf."""

    metrics = (
        OverviewMetric("label.plant_power", _format_power_mw(snapshot.site.plant_power_mw), _tone_for_power(snapshot)),
        OverviewMetric(
            "label.power_limit",
            f"{snapshot.power_plant_controller.active_power_limit_pct:.1f} %",
            _tone_for_limit(snapshot),
        ),
        OverviewMetric(
            "label.reactive_power",
            f"{snapshot.power_plant_controller.reactive_power_target:.2f}",
            "neutral",
        ),
        OverviewMetric(
            "label.breaker_state",
            _enum_text(texts, snapshot.site.breaker_state),
            _tone_for_breaker(snapshot.site.breaker_state),
        ),
        OverviewMetric(
            "label.active_alarms",
            str(snapshot.site.active_alarm_count),
            "alarm" if snapshot.site.active_alarm_count else "good",
        ),
        OverviewMetric(
            "label.communications",
            _enum_text(texts, snapshot.site.communications_health),
            _tone_for_communications(snapshot.site.communications_health),
        ),
    )

    inverter_rows = tuple(
        OverviewInverterRow(
            asset_id=block.asset_id,
            status_label=_enum_text(texts, block.status),
            communication_label=_enum_text(texts, block.communication_state),
            quality_label=_enum_text(texts, block.quality),
            power_label=f"{block.block_power_kw:.0f} kW",
            local_alarm_count=_inverter_local_alarm_count(block),
            tone=_tone_for_block(block.status, block.communication_state),
        )
        for block in snapshot.inverter_blocks
    )

    weather_facts = (
        OverviewFact("label.irradiance", f"{snapshot.weather_station.irradiance_w_m2} W/m2"),
        OverviewFact("label.module_temperature", f"{snapshot.weather_station.module_temperature_c:.1f} C"),
        OverviewFact("label.ambient_temperature", f"{snapshot.weather_station.ambient_temperature_c:.1f} C"),
        OverviewFact("label.wind_speed", f"{snapshot.weather_station.wind_speed_m_s:.1f} m/s"),
    )

    return OverviewViewModel(
        page_title=texts["page.overview.title"],
        page_subtitle=texts["page.overview.subtitle"],
        site_name=config.site_name,
        site_code=config.site_code,
        snapshot_time=_snapshot_time(snapshot),
        metrics=metrics,
        inverter_rows=inverter_rows,
        weather_facts=weather_facts,
        active_alarms=_active_alarm_view_models(snapshot, texts),
    )


def build_single_line_view_model(
    *,
    snapshot: PlantSnapshot,
    config: RuntimeConfig,
    texts: dict[str, str],
) -> SingleLineViewModel:
    """Bereitet die sichtbaren Werte fuer das einfache Einlinienschema auf."""

    flow_label, flow_tone = _single_line_flow(snapshot, texts)
    breaker_label = _enum_text(texts, snapshot.grid_interconnect.breaker_state)
    grid_label = _enum_text(texts, snapshot.grid_interconnect.grid_acceptance_state)
    export_path_label = (
        texts["state.available"] if snapshot.grid_interconnect.export_path_available else texts["state.unavailable"]
    )

    facts = (
        SingleLineFact("label.plant_power", _format_power_mw(snapshot.site.plant_power_mw), _tone_for_power(snapshot)),
        SingleLineFact(
            "label.export_power",
            _format_power_kw(snapshot.revenue_meter.export_power_kw),
            "good" if snapshot.revenue_meter.export_power_kw > 0 else "alarm",
        ),
        SingleLineFact(
            "label.power_limit",
            f"{snapshot.power_plant_controller.active_power_limit_pct:.1f} %",
            _tone_for_limit(snapshot),
        ),
        SingleLineFact(
            "label.communications",
            _enum_text(texts, snapshot.site.communications_health),
            _tone_for_communications(snapshot.site.communications_health),
        ),
    )

    inverter_nodes = tuple(
        SingleLineNode(
            asset_id=block.asset_id,
            title=block.asset_id.upper(),
            status_label=_enum_text(texts, block.status),
            detail_label=f"{_format_power_kw(block.block_power_kw)} / {_enum_text(texts, block.communication_state)}",
            tone=_tone_for_block(block.status, block.communication_state),
        )
        for block in snapshot.inverter_blocks
    )

    return SingleLineViewModel(
        page_title=texts["page.single_line.title"],
        page_subtitle=texts["page.single_line.subtitle"],
        site_name=config.site_name,
        site_code=config.site_code,
        snapshot_time=_snapshot_time(snapshot),
        flow_label=flow_label,
        flow_tone=flow_tone,
        breaker_label=breaker_label,
        breaker_tone=_tone_for_breaker(snapshot.grid_interconnect.breaker_state),
        grid_label=grid_label,
        grid_tone="good" if snapshot.grid_interconnect.grid_acceptance_state == "accepted" else "warn",
        export_path_label=export_path_label,
        export_path_tone="good" if snapshot.grid_interconnect.export_path_available else "alarm",
        facts=facts,
        inverter_nodes=inverter_nodes,
        active_alarms=_active_alarm_view_models(snapshot, texts),
    )


def build_inverters_view_model(
    *,
    snapshot: PlantSnapshot,
    config: RuntimeConfig,
    texts: dict[str, str],
) -> InvertersViewModel:
    """Bereitet die sichtbaren Werte fuer die Inverter-Vergleichssicht auf."""

    rows = tuple(
        InverterDetailRow(
            asset_id=block.asset_id,
            status_label=_enum_text(texts, block.status),
            communication_label=_enum_text(texts, block.communication_state),
            quality_label=_enum_text(texts, block.quality),
            power_label=_format_block_power_kw(block.block_power_kw),
            availability_label=f"{block.availability_pct} %",
            dc_label=_format_bus_values(block.block_dc_voltage_v, block.block_dc_current_a, texts),
            ac_label=_format_bus_values(block.block_ac_voltage_v, block.block_ac_current_a, texts),
            temperature_label=_format_temperature(block.internal_temperature_c, texts),
            local_alarm_count=_inverter_local_alarm_count(block),
            tone=_tone_for_block(block.status, block.communication_state),
        )
        for block in snapshot.inverter_blocks
    )

    metrics = (
        OverviewMetric("label.plant_power", _format_power_mw(snapshot.site.plant_power_mw), _tone_for_power(snapshot)),
        OverviewMetric(
            "label.active_blocks",
            f"{_count_active_blocks(snapshot)} / {len(snapshot.inverter_blocks)}",
            "good" if _count_active_blocks(snapshot) == len(snapshot.inverter_blocks) else "warn",
        ),
        OverviewMetric(
            "label.degraded_blocks",
            str(_count_degraded_blocks(snapshot)),
            "alarm" if _count_degraded_blocks(snapshot) else "good",
        ),
        OverviewMetric(
            "label.power_limit",
            f"{snapshot.power_plant_controller.active_power_limit_pct:.1f} %",
            _tone_for_limit(snapshot),
        ),
    )

    return InvertersViewModel(
        page_title=texts["page.inverters.title"],
        page_subtitle=texts["page.inverters.subtitle"],
        site_name=config.site_name,
        site_code=config.site_code,
        snapshot_time=_snapshot_time(snapshot),
        metrics=metrics,
        rows=rows,
        active_alarms=_active_alarm_view_models(snapshot, texts),
    )


def build_weather_view_model(
    *,
    snapshot: PlantSnapshot,
    config: RuntimeConfig,
    texts: dict[str, str],
) -> WeatherViewModel:
    """Bereitet die sichtbaren Werte fuer die Wetter- und Verfuegbarkeitssicht auf."""

    context_label, context_tone = _weather_output_context(snapshot, texts)
    metrics = (
        OverviewMetric(
            "label.irradiance",
            f"{snapshot.weather_station.irradiance_w_m2} W/m2",
            "good" if snapshot.weather_station.irradiance_w_m2 >= 700 else "warn",
        ),
        OverviewMetric(
            "label.weather_quality",
            _enum_text(texts, snapshot.weather_station.quality),
            _tone_for_quality(snapshot.weather_station.quality),
        ),
        OverviewMetric(
            "label.communications",
            _enum_text(texts, snapshot.weather_station.communication_state),
            _tone_for_communications(snapshot.weather_station.communication_state),
        ),
        OverviewMetric(
            "label.plant_power",
            _format_power_mw(snapshot.site.plant_power_mw),
            _tone_for_power(snapshot),
        ),
    )
    facts = (
        OverviewFact("label.module_temperature", f"{snapshot.weather_station.module_temperature_c:.1f} C"),
        OverviewFact("label.ambient_temperature", f"{snapshot.weather_station.ambient_temperature_c:.1f} C"),
        OverviewFact("label.wind_speed", f"{snapshot.weather_station.wind_speed_m_s:.1f} m/s"),
        OverviewFact("label.breaker_state", _enum_text(texts, snapshot.site.breaker_state)),
    )

    return WeatherViewModel(
        page_title=texts["page.weather.title"],
        page_subtitle=texts["page.weather.subtitle"],
        site_name=config.site_name,
        site_code=config.site_code,
        snapshot_time=_snapshot_time(snapshot),
        metrics=metrics,
        facts=facts,
        context_label=context_label,
        context_tone=context_tone,
        active_alarms=_active_alarm_view_models(snapshot, texts),
    )


def build_meter_view_model(
    *,
    snapshot: PlantSnapshot,
    config: RuntimeConfig,
    texts: dict[str, str],
) -> MeterViewModel:
    """Bereitet die sichtbaren Werte fuer die Einspeise- und Netzsicht auf."""

    context_label, context_tone = _meter_context(snapshot, texts)
    metrics = (
        OverviewMetric(
            "label.export_power",
            _format_power_kw(snapshot.revenue_meter.export_power_kw),
            "good" if snapshot.revenue_meter.export_power_kw > 0 else "alarm",
        ),
        OverviewMetric(
            "label.export_path",
            _availability_text(snapshot.grid_interconnect.export_path_available, texts),
            "good" if snapshot.grid_interconnect.export_path_available else "alarm",
        ),
        OverviewMetric(
            "label.breaker_state",
            _enum_text(texts, snapshot.grid_interconnect.breaker_state),
            _tone_for_breaker(snapshot.grid_interconnect.breaker_state),
        ),
        OverviewMetric(
            "label.data_quality",
            _enum_text(texts, snapshot.revenue_meter.quality),
            _tone_for_quality(snapshot.revenue_meter.quality),
        ),
    )
    facts = (
        OverviewFact(
            "label.export_energy",
            _format_optional_measurement(snapshot.revenue_meter.export_energy_mwh_total, "MWh", texts),
        ),
        OverviewFact(
            "label.grid_voltage",
            _format_optional_measurement(snapshot.revenue_meter.grid_voltage_v, "V", texts),
        ),
        OverviewFact(
            "label.grid_frequency",
            _format_optional_measurement(snapshot.revenue_meter.grid_frequency_hz, "Hz", texts),
        ),
        OverviewFact("label.power_factor", _format_power_factor(snapshot.revenue_meter.power_factor)),
        OverviewFact("label.communications", _enum_text(texts, snapshot.revenue_meter.communication_state)),
    )

    return MeterViewModel(
        page_title=texts["page.meter.title"],
        page_subtitle=texts["page.meter.subtitle"],
        site_name=config.site_name,
        site_code=config.site_code,
        snapshot_time=_snapshot_time(snapshot),
        metrics=metrics,
        facts=facts,
        context_label=context_label,
        context_tone=context_tone,
        active_alarms=_active_alarm_view_models(snapshot, texts),
    )


def _active_alarm_view_models(snapshot: PlantSnapshot, texts: dict[str, str]) -> tuple[OverviewAlarm, ...]:
    return tuple(
        OverviewAlarm(
            code=alarm.code,
            label=texts.get(f"alarm.{alarm.code}", alarm.code),
            severity_label=_severity_text(texts, alarm.severity),
            state_label=_alarm_state_text(texts, alarm.state),
            tone=_tone_for_severity(alarm.severity),
        )
        for alarm in _sorted_active_alarms(snapshot)[:3]
    )


def _template_context(
    *,
    config: RuntimeConfig,
    texts: dict[str, str],
    current_path: str,
    page: OverviewViewModel | SingleLineViewModel | InvertersViewModel | WeatherViewModel | MeterViewModel,
) -> dict[str, Any]:
    return {
        "config": config,
        "page": page,
        "lang": config.attacker_ui_locale,
        "nav_items": _nav_items(current_path),
        "t": lambda key: texts.get(key, key),
    }


def _nav_items(current_path: str) -> tuple[NavItem, ...]:
    current = "/overview" if current_path == "/" else current_path
    return (
        NavItem(href="/overview", label_key="nav.overview", is_current=current == "/overview"),
        NavItem(href="/single-line", label_key="nav.single_line", is_current=current == "/single-line"),
        NavItem(href="/inverters", label_key="nav.inverters", is_current=current == "/inverters"),
        NavItem(href="/weather", label_key="nav.weather", is_current=current == "/weather"),
        NavItem(href="/meter", label_key="nav.meter", is_current=current == "/meter"),
    )


def _load_locale_texts(config: RuntimeConfig) -> dict[str, str]:
    for locale in config.attacker_ui_locale_resolution_chain:
        locale_file = _LOCALE_DIR / f"{locale}.json"
        if not locale_file.is_file():
            continue
        with locale_file.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if not isinstance(loaded, dict):
            raise RuntimeError(f"Locale-Paket {locale_file} muss ein JSON-Objekt liefern")
        return {str(key): str(value) for key, value in loaded.items()}
    raise RuntimeError("Kein passendes Locale-Paket fuer die HMI gefunden")


def _session_state(request: Request) -> tuple[str, bool]:
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id is not None:
        return session_id, False
    return f"hmi_{uuid4().hex}", True


def _set_session_cookie(response: HTMLResponse, session_id: str) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        httponly=True,
        samesite="lax",
    )


def _record_page_view(
    *,
    request: Request,
    snapshot: PlantSnapshot,
    session_id: str,
    event_recorder: EventRecorder | None,
    event_type: str,
    action: str,
    asset_id: str,
    resulting_state: dict[str, Any],
    message: str,
    tags: tuple[str, ...],
) -> None:
    if event_recorder is None:
        return

    path = request.url.path
    event = event_recorder.build_event(
        event_type=event_type,
        category="hmi",
        severity="info",
        source_ip=request.client.host if request.client is not None else "127.0.0.1",
        actor_type="remote_client",
        component=HMI_COMPONENT,
        asset_id=asset_id,
        action=action,
        result="served",
        session_id=session_id,
        protocol=HMI_PROTOCOL,
        service=HMI_SERVICE,
        endpoint_or_register=path,
        requested_value={
            "http_method": request.method,
            "http_path": path,
        },
        resulting_value={"http_status": 200},
        resulting_state=resulting_state,
        message=message,
        tags=tags,
    )
    event_recorder.record(event)


def _sorted_active_alarms(snapshot: PlantSnapshot):
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return tuple(
        sorted(
            snapshot.active_alarms,
            key=lambda alarm: (-severity_order[alarm.severity], alarm.code),
        )
    )


def _enum_text(texts: dict[str, str], value: str) -> str:
    return texts.get(f"state.{value}", value.replace("_", " ").title())


def _severity_text(texts: dict[str, str], value: str) -> str:
    return texts.get(f"severity.{value}", value.title())


def _alarm_state_text(texts: dict[str, str], value: str) -> str:
    return texts.get(f"alarm_state.{value}", value.replace("_", " ").title())


def _tone_for_power(snapshot: PlantSnapshot) -> str:
    if snapshot.site.plant_power_mw <= 0:
        return "alarm"
    if snapshot.site.plant_power_limit_pct < 100:
        return "warn"
    return "good"


def _tone_for_limit(snapshot: PlantSnapshot) -> str:
    return "warn" if snapshot.power_plant_controller.active_power_limit_pct < 100 else "good"


def _tone_for_breaker(state: str) -> str:
    return "alarm" if state != "closed" else "good"


def _tone_for_communications(state: str) -> str:
    if state == "healthy":
        return "good"
    if state == "degraded":
        return "warn"
    return "alarm"


def _tone_for_quality(quality: str) -> str:
    if quality == "good":
        return "good"
    if quality == "estimated":
        return "warn"
    return "alarm"


def _tone_for_block(status: str, communication_state: str) -> str:
    if communication_state == "lost" or status == "faulted":
        return "alarm"
    if status == "degraded" or communication_state == "degraded":
        return "warn"
    return "good"


def _tone_for_severity(severity: str) -> str:
    if severity in {"high", "critical"}:
        return "alarm"
    if severity == "medium":
        return "warn"
    return "good"


def _inverter_local_alarm_count(block: Any) -> int:
    count = 0
    if block.communication_state == "lost":
        count += 1
    if block.status == "faulted":
        count += 1
    if block.status == "offline" or block.availability_pct == 0:
        count += 1
    return count


def _snapshot_time(snapshot: PlantSnapshot) -> str:
    return snapshot.start_time.strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_power_mw(value: float) -> str:
    return f"{value:.2f} MW"


def _format_power_kw(value: float) -> str:
    if value >= 1000:
        return f"{value / 1000:.2f} MW"
    return f"{value:.0f} kW"


def _format_block_power_kw(value: float) -> str:
    return f"{value:.1f} kW"


def _format_bus_values(voltage_v: float | None, current_a: float | None, texts: dict[str, str]) -> str:
    if voltage_v is None and current_a is None:
        return texts["state.unavailable"]
    if voltage_v is None:
        return f"-- V / {current_a:.1f} A"
    if current_a is None:
        return f"{voltage_v:.1f} V / -- A"
    return f"{voltage_v:.1f} V / {current_a:.1f} A"


def _format_temperature(value_c: float | None, texts: dict[str, str]) -> str:
    if value_c is None:
        return texts["state.unavailable"]
    return f"{value_c:.1f} C"


def _format_optional_measurement(value: float | None, unit: str, texts: dict[str, str]) -> str:
    if value is None:
        return texts["state.unavailable"]
    return f"{value:.3f} {unit}" if unit == "MWh" else f"{value:.1f} {unit}"


def _format_power_factor(value: float) -> str:
    return f"{value:.3f}"


def _availability_text(is_available: bool, texts: dict[str, str]) -> str:
    return texts["state.available"] if is_available else texts["state.unavailable"]


def _count_active_blocks(snapshot: PlantSnapshot) -> int:
    return sum(1 for block in snapshot.inverter_blocks if block.status in {"online", "degraded"} and block.availability_pct > 0)


def _count_degraded_blocks(snapshot: PlantSnapshot) -> int:
    return sum(
        1
        for block in snapshot.inverter_blocks
        if block.status != "online" or block.communication_state != "healthy" or block.quality != "good"
    )


def _weather_output_context(snapshot: PlantSnapshot, texts: dict[str, str]) -> tuple[str, str]:
    if snapshot.weather_station.communication_state == "lost" or snapshot.weather_station.quality in {"stale", "invalid"}:
        return texts["weather.context.reduced_confidence"], "alarm"
    if snapshot.power_plant_controller.active_power_limit_pct < 100:
        return texts["weather.context.curtailment_limits_output"], "warn"
    if snapshot.weather_station.irradiance_w_m2 >= 700 and snapshot.site.plant_power_mw >= 5:
        return texts["weather.context.strong_output_supported"], "good"
    if snapshot.weather_station.irradiance_w_m2 < 400 and snapshot.site.plant_power_mw < 3:
        return texts["weather.context.low_irradiance_explains_output"], "good"
    return texts["weather.context.review_alignment"], "warn"


def _meter_context(snapshot: PlantSnapshot, texts: dict[str, str]) -> tuple[str, str]:
    if snapshot.grid_interconnect.breaker_state != "closed":
        return texts["meter.context.breaker_open_blocks_export"], "alarm"
    if not snapshot.grid_interconnect.export_path_available:
        return texts["meter.context.export_path_unavailable"], "alarm"
    if snapshot.revenue_meter.communication_state != "healthy" or snapshot.revenue_meter.quality in {"stale", "invalid"}:
        return texts["meter.context.reduced_confidence"], "warn"
    if snapshot.revenue_meter.export_power_kw > 0:
        return texts["meter.context.normal_export"], "good"
    return texts["meter.context.review_alignment"], "warn"


def _single_line_flow(snapshot: PlantSnapshot, texts: dict[str, str]) -> tuple[str, str]:
    if snapshot.grid_interconnect.breaker_state != "closed":
        return texts["line.flow_isolated"], "alarm"
    if not snapshot.grid_interconnect.export_path_available:
        return texts["line.grid_path_unavailable"], "alarm"
    if snapshot.site.communications_health != "healthy":
        return f"{texts['line.exporting']} {_format_power_kw(snapshot.revenue_meter.export_power_kw)}", "warn"
    return f"{texts['line.exporting']} {_format_power_kw(snapshot.revenue_meter.export_power_kw)}", "good"
