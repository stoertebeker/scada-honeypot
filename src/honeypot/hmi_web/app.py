"""Read-only HMI-Slices fuer die ersten sichtbaren Web-Oberflaechen."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import parse_qs, urlencode
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.config_core import RuntimeConfig
from honeypot.event_core import AlertRecord, EventRecorder
from honeypot.plant_sim import SimulationEventContext
from honeypot.time_core import Clock, SystemClock, ensure_utc_datetime

HMI_COMPONENT = "hmi-web"
HMI_SERVICE = "web-hmi"
HMI_PROTOCOL = "http"
SESSION_COOKIE_NAME = "hmi_session"
SERVICE_SESSION_COOKIE_NAME = "service_session"
SERVICE_SESSION_IDLE_TIMEOUT = timedelta(minutes=20)
_REPO_ROOT = Path(__file__).resolve().parents[3]
_LOCALE_DIR = _REPO_ROOT / "resources" / "locales" / "attacker-ui"
_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
SERVICE_LOGIN_USERNAME = "field.service"
SERVICE_LOGIN_PASSWORD = "Solar-Field-2026"


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


@dataclass(frozen=True, slots=True)
class AlarmFilterLink:
    label: str
    href: str
    is_current: bool


@dataclass(frozen=True, slots=True)
class AlarmListRow:
    code: str
    label: str
    category_label: str
    severity_label: str
    severity_key: str
    state_label: str
    ack_state_label: str
    asset_id: str
    first_seen: str
    last_changed: str
    last_changed_sort: str
    tone: str


@dataclass(frozen=True, slots=True)
class AlarmsViewModel:
    page_title: str
    page_subtitle: str
    site_name: str
    site_code: str
    snapshot_time: str
    metrics: tuple[OverviewMetric, ...]
    rows: tuple[AlarmListRow, ...]
    severity_filters: tuple[AlarmFilterLink, ...]
    state_filters: tuple[AlarmFilterLink, ...]
    sort_filters: tuple[AlarmFilterLink, ...]
    empty_label: str


@dataclass(frozen=True, slots=True)
class TrendSeriesView:
    asset_id: str
    title: str
    current_value: str
    baseline_value: str
    polyline_points: str
    tone: str
    min_label: str
    max_label: str


@dataclass(frozen=True, slots=True)
class TrendsViewModel:
    page_title: str
    page_subtitle: str
    site_name: str
    site_code: str
    snapshot_time: str
    metrics: tuple[OverviewMetric, ...]
    series: tuple[TrendSeriesView, ...]
    context_label: str
    context_tone: str


@dataclass(frozen=True, slots=True)
class ErrorViewModel:
    page_title: str
    page_subtitle: str
    site_name: str
    site_code: str
    status_code: int
    error_label: str
    error_message: str


@dataclass(frozen=True, slots=True)
class ServiceLoginViewModel:
    page_title: str
    page_subtitle: str
    site_name: str
    site_code: str
    status_label: str | None
    status_tone: str
    session_active: bool


@dataclass(frozen=True, slots=True)
class ServicePanelViewModel:
    page_title: str
    page_subtitle: str
    site_name: str
    site_code: str
    snapshot_time: str
    operator_label: str
    session_expires_at: str
    status_label: str | None
    status_tone: str
    controls_available: bool
    power_limit_value: str
    breaker_state_label: str
    breaker_open_enabled: bool
    breaker_close_enabled: bool
    metrics: tuple[OverviewMetric, ...]
    allowed_actions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ServiceSession:
    handle: str
    username: str
    expires_at: Any


class ServiceControlPort(Protocol):
    def set_active_power_limit_pct(
        self,
        *,
        active_power_limit_pct: float,
        event_context: SimulationEventContext | None = None,
    ) -> Any: ...

    def request_breaker_open(
        self,
        *,
        event_context: SimulationEventContext | None = None,
    ) -> Any: ...

    def request_breaker_close(
        self,
        *,
        event_context: SimulationEventContext | None = None,
    ) -> Any: ...


@dataclass(slots=True)
class ServiceSessionStore:
    clock: Clock
    idle_timeout: timedelta = SERVICE_SESSION_IDLE_TIMEOUT
    _sessions: dict[str, ServiceSession] = field(default_factory=dict, init=False, repr=False)

    def create(self, *, username: str) -> ServiceSession:
        now = self.clock.now()
        session = ServiceSession(
            handle=f"svc_{uuid4().hex}",
            username=username,
            expires_at=ensure_utc_datetime(now + self.idle_timeout),
        )
        self._sessions[session.handle] = session
        return session

    def touch(self, handle: str | None) -> ServiceSession | None:
        if handle is None:
            return None
        session = self._sessions.get(handle)
        if session is None:
            return None
        now = ensure_utc_datetime(self.clock.now())
        if now >= ensure_utc_datetime(session.expires_at):
            self._sessions.pop(handle, None)
            return None
        refreshed = ServiceSession(
            handle=session.handle,
            username=session.username,
            expires_at=ensure_utc_datetime(now + self.idle_timeout),
        )
        self._sessions[handle] = refreshed
        return refreshed


def create_hmi_app(
    *,
    snapshot_provider: Callable[[], PlantSnapshot],
    config: RuntimeConfig,
    event_recorder: EventRecorder | None = None,
    service_controls: ServiceControlPort | None = None,
) -> FastAPI:
    """Erzeugt die ersten HMI-Seiten fuer die lokale Runtime inklusive Service-Pfad."""

    texts = _load_locale_texts(config)
    templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
    service_sessions = ServiceSessionStore(clock=_hmi_clock(event_recorder))
    app = FastAPI(
        title=config.hmi_title,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.exception_handler(StarletteHTTPException)
    async def hmi_http_exception(request: Request, exc: StarletteHTTPException) -> HTMLResponse:
        error_page = {
            401: (
                texts["error.401.title"],
                texts["error.401.subtitle"],
                texts["error.401.message"],
                "hmi.error.unauthorized",
                "hmi_401",
            ),
            403: (
                texts["error.403.title"],
                texts["error.403.subtitle"],
                texts["error.403.message"],
                "hmi.error.forbidden",
                "hmi_403",
            ),
            404: (
                texts["error.404.title"],
                texts["error.404.subtitle"],
                texts["error.404.message"],
                "hmi.error.not_found",
                "hmi_404",
            ),
        }.get(exc.status_code)
        if error_page is None:
            raise exc
        return _render_error_page(
            request=request,
            templates=templates,
            config=config,
            texts=texts,
            event_recorder=event_recorder,
            status_code=exc.status_code,
            page_title=error_page[0],
            page_subtitle=error_page[1],
            error_message=error_page[2],
            event_type=error_page[3],
            error_code=error_page[4],
        )

    @app.exception_handler(Exception)
    async def hmi_internal_exception(request: Request, exc: Exception) -> HTMLResponse:
        return _render_error_page(
            request=request,
            templates=templates,
            config=config,
            texts=texts,
            event_recorder=event_recorder,
            status_code=500,
            page_title=texts["error.500.title"],
            page_subtitle=texts["error.500.subtitle"],
            error_message=texts["error.500.message"],
            event_type="hmi.error.internal",
            error_code="hmi_500",
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

    @app.get("/alarms", response_class=HTMLResponse, include_in_schema=False)
    async def alarms(request: Request) -> HTMLResponse:
        snapshot = snapshot_provider()
        session_id, set_cookie = _session_state(request)
        severity_filter = _normalize_alarm_filter(request.query_params.get("severity"), allowed={"low", "medium", "high", "critical"})
        state_filter = _normalize_alarm_filter(
            request.query_params.get("state"),
            allowed={"active_unacknowledged", "active_acknowledged", "cleared"},
        )
        sort_order = _normalize_alarm_sort(request.query_params.get("sort"))
        view_model = build_alarms_view_model(
            snapshot=snapshot,
            config=config,
            texts=texts,
            alert_history=_alert_history(event_recorder),
            severity_filter=severity_filter,
            state_filter=state_filter,
            sort_order=sort_order,
        )
        response = templates.TemplateResponse(
            request=request,
            name="alarms.html",
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
            event_type="hmi.page.alarms_viewed",
            action="view_alarms",
            asset_id=view_model.rows[0].asset_id if view_model.rows else snapshot.power_plant_controller.asset_id,
            resulting_state={
                "visible_alarm_count": len(view_model.rows),
                "severity_filter": severity_filter or "all",
                "state_filter": state_filter or "all",
                "sort_order": sort_order,
            },
            message="Alarms page rendered",
            tags=("read-only", "alarms", "web"),
        )
        return response

    @app.get("/trends", response_class=HTMLResponse, include_in_schema=False)
    async def trends(request: Request) -> HTMLResponse:
        snapshot = snapshot_provider()
        session_id, set_cookie = _session_state(request)
        view_model = build_trends_view_model(snapshot=snapshot, config=config, texts=texts)
        response = templates.TemplateResponse(
            request=request,
            name="trends.html",
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
            event_type="hmi.page.trends_viewed",
            action="view_trends",
            asset_id=snapshot.power_plant_controller.asset_id,
            resulting_state={
                "series_count": len(view_model.series),
                "plant_power_mw": snapshot.site.plant_power_mw,
                "active_power_limit_pct": snapshot.power_plant_controller.active_power_limit_pct,
                "export_power_kw": snapshot.revenue_meter.export_power_kw,
            },
            message="Trends page rendered",
            tags=("read-only", "trends", "web"),
        )
        return response

    @app.get("/service/login", response_class=HTMLResponse, include_in_schema=False)
    async def service_login_get(request: Request) -> HTMLResponse:
        if not config.enable_service_login:
            raise StarletteHTTPException(status_code=403)
        session_id, set_cookie = _session_state(request)
        service_session = service_sessions.touch(request.cookies.get(SERVICE_SESSION_COOKIE_NAME))
        view_model = build_service_login_view_model(
            config=config,
            texts=texts,
            status_label=(texts["service.session_active"] if service_session is not None else None),
            status_tone=("good" if service_session is not None else "neutral"),
            session_active=service_session is not None,
        )
        response = templates.TemplateResponse(
            request=request,
            name="service_login.html",
            context=_template_context(
                config=config,
                texts=texts,
                current_path=request.url.path,
                page=view_model,
            ),
        )
        if set_cookie:
            _set_session_cookie(response, session_id)
        if service_session is not None:
            _set_service_session_cookie(response, service_session)

        _record_page_view(
            request=request,
            snapshot=snapshot_provider(),
            session_id=session_id,
            event_recorder=event_recorder,
            event_type="hmi.page.service_login_viewed",
            action="view_service_login",
            asset_id=HMI_COMPONENT,
            resulting_state={"service_session_active": service_session is not None},
            message="Service login page rendered",
            tags=("auth", "service", "web"),
        )
        return response

    @app.post("/service/login", response_class=HTMLResponse, include_in_schema=False)
    async def service_login_post(request: Request) -> HTMLResponse:
        if not config.enable_service_login:
            raise StarletteHTTPException(status_code=403)
        session_id, set_cookie = _session_state(request)
        raw_body = (await request.body()).decode("utf-8")
        form = parse_qs(raw_body, keep_blank_values=True)
        username = (form.get("username", [""])[0]).strip()
        password = form.get("password", [""])[0]
        login_success = username == SERVICE_LOGIN_USERNAME and password == SERVICE_LOGIN_PASSWORD
        auth_event = _build_service_auth_event(
            request=request,
            event_recorder=event_recorder,
            session_id=session_id,
            username=username,
            result="success" if login_success else "failure",
        )
        if auth_event is not None:
            event_recorder.record(auth_event)

        if not login_success:
            view_model = build_service_login_view_model(
                config=config,
                texts=texts,
                status_label=texts["service.login_failed"],
                status_tone="alarm",
                session_active=False,
            )
            response = templates.TemplateResponse(
                request=request,
                name="service_login.html",
                context=_template_context(
                    config=config,
                    texts=texts,
                    current_path=request.url.path,
                    page=view_model,
                ),
            )
            if set_cookie:
                _set_session_cookie(response, session_id)
            return response

        service_session = service_sessions.create(username=username)
        response = RedirectResponse(url="/service/panel", status_code=303)
        if set_cookie:
            _set_session_cookie(response, session_id)
        _set_service_session_cookie(response, service_session)
        return response

    @app.get("/service/panel", response_class=HTMLResponse, include_in_schema=False)
    async def service_panel(request: Request) -> HTMLResponse:
        service_session = _require_service_session(
            request,
            config=config,
            service_sessions=service_sessions,
        )
        session_id, set_cookie = _session_state(request)
        snapshot = snapshot_provider()
        status_label, status_tone = _service_panel_status(request=request, texts=texts)
        view_model = build_service_panel_view_model(
            snapshot=snapshot,
            config=config,
            texts=texts,
            service_session=service_session,
            status_label=status_label,
            status_tone=status_tone,
            controls_available=service_controls is not None,
        )
        response = templates.TemplateResponse(
            request=request,
            name="service_panel.html",
            context=_template_context(
                config=config,
                texts=texts,
                current_path=request.url.path,
                page=view_model,
            ),
        )
        if set_cookie:
            _set_session_cookie(response, session_id)
        _set_service_session_cookie(response, service_session)
        _record_page_view(
            request=request,
            snapshot=snapshot,
            session_id=service_session.handle,
            event_recorder=event_recorder,
            event_type="hmi.page.service_panel_viewed",
            action="view_service_panel",
            asset_id=snapshot.power_plant_controller.asset_id,
            resulting_state={
                "service_view": True,
                "plant_power_mw": snapshot.site.plant_power_mw,
                "breaker_state": snapshot.grid_interconnect.breaker_state,
            },
            message="Service panel rendered",
            tags=("service", "panel", "web"),
        )
        return response

    @app.post("/service/panel/power-limit", response_class=HTMLResponse, include_in_schema=False)
    async def service_panel_power_limit(request: Request) -> HTMLResponse:
        service_session = _require_service_session(
            request,
            config=config,
            service_sessions=service_sessions,
        )
        session_id, set_cookie = _session_state(request)
        source_ip = request.client.host if request.client is not None else "127.0.0.1"
        before_snapshot = snapshot_provider()
        correlation_id = uuid4().hex

        if service_controls is None:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=before_snapshot.power_plant_controller.asset_id,
                action="set_active_power_limit",
                result="rejected",
                requested_value={"active_power_limit_pct": None},
                resulting_state={"controls_available": False},
                message="Service power limit path unavailable",
                tags=("service", "control", "curtailment", "web"),
                error_code="service_control_unavailable",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                status_code="control_unavailable",
            )

        raw_body = (await request.body()).decode("utf-8")
        form = parse_qs(raw_body, keep_blank_values=True)
        raw_limit = (form.get("active_power_limit_pct", [""])[0]).strip()
        try:
            active_power_limit_pct = float(raw_limit)
        except ValueError:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=before_snapshot.power_plant_controller.asset_id,
                action="set_active_power_limit",
                result="rejected",
                requested_value={"active_power_limit_pct": raw_limit},
                previous_value=before_snapshot.power_plant_controller.active_power_limit_pct,
                resulting_state={"active_power_limit_pct": before_snapshot.power_plant_controller.active_power_limit_pct},
                message="Service power limit request could not be parsed",
                tags=("service", "control", "curtailment", "web"),
                error_code="service_control_invalid",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                status_code="control_invalid",
            )

        event_context = SimulationEventContext(
            source_ip=source_ip,
            actor_type="remote_client",
            correlation_id=correlation_id,
            session_id=service_session.handle,
            protocol=HMI_PROTOCOL,
            service=HMI_SERVICE,
        )
        try:
            result = service_controls.set_active_power_limit_pct(
                active_power_limit_pct=active_power_limit_pct,
                event_context=event_context,
            )
        except ValueError as exc:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=before_snapshot.power_plant_controller.asset_id,
                action="set_active_power_limit",
                result="rejected",
                requested_value={"active_power_limit_pct": active_power_limit_pct},
                previous_value=before_snapshot.power_plant_controller.active_power_limit_pct,
                resulting_state={"active_power_limit_pct": before_snapshot.power_plant_controller.active_power_limit_pct},
                message=f"Service power limit request rejected: {exc}",
                tags=("service", "control", "curtailment", "web"),
                error_code="service_control_rejected",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                status_code="control_rejected",
            )

        after_snapshot = snapshot_provider()
        _record_service_control_event(
            request=request,
            event_recorder=event_recorder,
            session_id=service_session.handle,
            correlation_id=correlation_id,
            asset_id=result.asset_id,
            action="set_active_power_limit",
            result="accepted",
            requested_value={"active_power_limit_pct": active_power_limit_pct},
            previous_value=before_snapshot.power_plant_controller.active_power_limit_pct,
            resulting_value=after_snapshot.power_plant_controller.active_power_limit_pct,
            resulting_state=result.resulting_state,
            message="Service power limit request accepted",
            tags=("service", "control", "curtailment", "web"),
        )
        return _service_panel_redirect_response(
            session_id=session_id,
            set_cookie=set_cookie,
            service_session=service_session,
            status_code="power_limit_updated",
        )

    @app.post("/service/panel/breaker", response_class=HTMLResponse, include_in_schema=False)
    async def service_panel_breaker(request: Request) -> HTMLResponse:
        service_session = _require_service_session(
            request,
            config=config,
            service_sessions=service_sessions,
        )
        session_id, set_cookie = _session_state(request)
        before_snapshot = snapshot_provider()
        correlation_id = uuid4().hex

        if service_controls is None:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=before_snapshot.grid_interconnect.asset_id,
                action="breaker_request",
                result="rejected",
                requested_value={"breaker_action": None},
                resulting_state={"controls_available": False},
                message="Service breaker path unavailable",
                tags=("service", "control", "breaker", "web"),
                error_code="service_control_unavailable",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                status_code="control_unavailable",
            )

        raw_body = (await request.body()).decode("utf-8")
        form = parse_qs(raw_body, keep_blank_values=True)
        breaker_action = (form.get("breaker_action", [""])[0]).strip().lower()
        if breaker_action not in {"open", "close"}:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=before_snapshot.grid_interconnect.asset_id,
                action="breaker_request",
                result="rejected",
                requested_value={"breaker_action": breaker_action},
                previous_value=before_snapshot.grid_interconnect.breaker_state,
                resulting_state={"breaker_state": before_snapshot.grid_interconnect.breaker_state},
                message="Service breaker request used an invalid action",
                tags=("service", "control", "breaker", "web"),
                error_code="service_control_invalid",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                status_code="control_invalid",
            )

        event_context = SimulationEventContext(
            source_ip=request.client.host if request.client is not None else "127.0.0.1",
            actor_type="remote_client",
            correlation_id=correlation_id,
            session_id=service_session.handle,
            protocol=HMI_PROTOCOL,
            service=HMI_SERVICE,
        )
        try:
            result = (
                service_controls.request_breaker_open(event_context=event_context)
                if breaker_action == "open"
                else service_controls.request_breaker_close(event_context=event_context)
            )
        except ValueError as exc:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=before_snapshot.grid_interconnect.asset_id,
                action=f"breaker_{breaker_action}_request",
                result="rejected",
                requested_value={"breaker_action": breaker_action},
                previous_value=before_snapshot.grid_interconnect.breaker_state,
                resulting_state={"breaker_state": before_snapshot.grid_interconnect.breaker_state},
                message=f"Service breaker request rejected: {exc}",
                tags=("service", "control", "breaker", "web"),
                error_code="service_control_rejected",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                status_code="control_rejected",
            )

        after_snapshot = snapshot_provider()
        _record_service_control_event(
            request=request,
            event_recorder=event_recorder,
            session_id=service_session.handle,
            correlation_id=correlation_id,
            asset_id=result.asset_id,
            action=f"breaker_{breaker_action}_request",
            result="accepted",
            requested_value={"breaker_action": breaker_action},
            previous_value=before_snapshot.grid_interconnect.breaker_state,
            resulting_value=after_snapshot.grid_interconnect.breaker_state,
            resulting_state=result.resulting_state,
            message=f"Service breaker {breaker_action} request accepted",
            tags=("service", "control", "breaker", "web"),
        )
        return _service_panel_redirect_response(
            session_id=session_id,
            set_cookie=set_cookie,
            service_session=service_session,
            status_code=("breaker_open_requested" if breaker_action == "open" else "breaker_close_requested"),
        )

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


def build_alarms_view_model(
    *,
    snapshot: PlantSnapshot,
    config: RuntimeConfig,
    texts: dict[str, str],
    alert_history: tuple[AlertRecord, ...],
    severity_filter: str | None,
    state_filter: str | None,
    sort_order: str,
) -> AlarmsViewModel:
    """Bereitet die sichtbaren Werte fuer die zentrale Alarmliste auf."""

    rows = _alarm_rows(
        snapshot,
        texts=texts,
        alert_history=alert_history,
        severity_filter=severity_filter,
        state_filter=state_filter,
        sort_order=sort_order,
    )
    acknowledged_count = sum(1 for alarm in snapshot.alarms if alarm.state == "active_acknowledged")
    communication_count = sum(1 for alarm in snapshot.alarms if alarm.category == "communication" and alarm.is_active)
    highest_severity = _highest_alarm_severity(snapshot)
    metrics = (
        OverviewMetric(
            "label.active_alarms",
            str(len(snapshot.active_alarms)),
            "alarm" if snapshot.active_alarms else "good",
        ),
        OverviewMetric(
            "label.acknowledged_alarms",
            str(acknowledged_count),
            "warn" if acknowledged_count else "good",
        ),
        OverviewMetric(
            "label.communication_alarms",
            str(communication_count),
            "warn" if communication_count else "good",
        ),
        OverviewMetric(
            "label.highest_severity",
            _severity_text(texts, highest_severity) if highest_severity is not None else texts["state.normal"],
            "alarm" if highest_severity in {"high", "critical"} else "good",
        ),
    )

    return AlarmsViewModel(
        page_title=texts["page.alarms.title"],
        page_subtitle=texts["page.alarms.subtitle"],
        site_name=config.site_name,
        site_code=config.site_code,
        snapshot_time=_snapshot_time(snapshot),
        metrics=metrics,
        rows=rows,
        severity_filters=_alarm_filter_links(
            texts,
            filter_name="severity",
            current_value=severity_filter,
            selected_state=state_filter,
            sort_order=sort_order,
            options=(
                (None, texts["filter.all_severities"]),
                ("low", _severity_text(texts, "low")),
                ("medium", _severity_text(texts, "medium")),
                ("high", _severity_text(texts, "high")),
                ("critical", _severity_text(texts, "critical")),
            ),
        ),
        state_filters=_alarm_filter_links(
            texts,
            filter_name="state",
            current_value=state_filter,
            selected_severity=severity_filter,
            sort_order=sort_order,
            options=(
                (None, texts["filter.all_states"]),
                ("active_unacknowledged", texts["alarm_state.active_unacknowledged"]),
                ("active_acknowledged", texts["alarm_state.active_acknowledged"]),
                ("cleared", texts["alarm_state.cleared"]),
            ),
        ),
        sort_filters=_alarm_sort_links(
            texts,
            current_value=sort_order,
            selected_severity=severity_filter,
            selected_state=state_filter,
        ),
        empty_label=texts["alarm.none_matching"],
    )


def build_trends_view_model(
    *,
    snapshot: PlantSnapshot,
    config: RuntimeConfig,
    texts: dict[str, str],
) -> TrendsViewModel:
    """Bereitet eine kleine glaubhafte Verlaufssicht aus Baseline und aktuellem Snapshot auf."""

    baseline_snapshot = PlantSnapshot.from_fixture(load_plant_fixture(snapshot.fixture_name))
    context_label, context_tone = _trends_context(snapshot, baseline_snapshot, texts)
    metrics = (
        OverviewMetric("label.plant_power", _format_power_mw(snapshot.site.plant_power_mw), _tone_for_power(snapshot)),
        OverviewMetric(
            "label.power_limit",
            f"{snapshot.power_plant_controller.active_power_limit_pct:.1f} %",
            _tone_for_limit(snapshot),
        ),
        OverviewMetric(
            "label.export_power",
            _format_power_kw(snapshot.revenue_meter.export_power_kw),
            "good" if snapshot.revenue_meter.export_power_kw > 0 else "alarm",
        ),
        OverviewMetric(
            "label.active_alarms",
            str(snapshot.site.active_alarm_count),
            "alarm" if snapshot.site.active_alarm_count else "good",
        ),
    )
    series = (
        _trend_series_view(
            asset_id="site",
            title=texts["trend.plant_power"],
            baseline_value=baseline_snapshot.site.plant_power_mw,
            current_value=snapshot.site.plant_power_mw,
            value_formatter=_format_power_mw,
            tone=_tone_for_power(snapshot),
        ),
        _trend_series_view(
            asset_id=snapshot.power_plant_controller.asset_id,
            title=texts["trend.power_limit"],
            baseline_value=baseline_snapshot.power_plant_controller.active_power_limit_pct,
            current_value=snapshot.power_plant_controller.active_power_limit_pct,
            value_formatter=lambda value: f"{value:.1f} %",
            tone=_tone_for_limit(snapshot),
        ),
        _trend_series_view(
            asset_id=snapshot.weather_station.asset_id,
            title=texts["trend.irradiance"],
            baseline_value=float(baseline_snapshot.weather_station.irradiance_w_m2),
            current_value=float(snapshot.weather_station.irradiance_w_m2),
            value_formatter=lambda value: f"{value:.0f} W/m2",
            tone="good" if snapshot.weather_station.irradiance_w_m2 >= 700 else "warn",
        ),
        _trend_series_view(
            asset_id=snapshot.revenue_meter.asset_id,
            title=texts["trend.export_power"],
            baseline_value=baseline_snapshot.revenue_meter.export_power_kw / 1000,
            current_value=snapshot.revenue_meter.export_power_kw / 1000,
            value_formatter=lambda value: f"{value:.2f} MW",
            tone="good" if snapshot.revenue_meter.export_power_kw > 0 else "alarm",
        ),
        *tuple(
            _trend_series_view(
                asset_id=current_block.asset_id,
                title=f"{texts['trend.block_power']} {current_block.asset_id.upper()}",
                baseline_value=baseline_block.block_power_kw,
                current_value=current_block.block_power_kw,
                value_formatter=lambda value: f"{value:.1f} kW",
                tone=_tone_for_block(current_block.status, current_block.communication_state),
            )
            for baseline_block, current_block in zip(
                baseline_snapshot.inverter_blocks,
                snapshot.inverter_blocks,
                strict=True,
            )
        ),
    )

    return TrendsViewModel(
        page_title=texts["page.trends.title"],
        page_subtitle=texts["page.trends.subtitle"],
        site_name=config.site_name,
        site_code=config.site_code,
        snapshot_time=_snapshot_time(snapshot),
        metrics=metrics,
        series=series,
        context_label=context_label,
        context_tone=context_tone,
    )


def build_service_login_view_model(
    *,
    config: RuntimeConfig,
    texts: dict[str, str],
    status_label: str | None,
    status_tone: str,
    session_active: bool,
) -> ServiceLoginViewModel:
    return ServiceLoginViewModel(
        page_title=texts["page.service_login.title"],
        page_subtitle=texts["page.service_login.subtitle"],
        site_name=config.site_name,
        site_code=config.site_code,
        status_label=status_label,
        status_tone=status_tone,
        session_active=session_active,
    )


def build_service_panel_view_model(
    *,
    snapshot: PlantSnapshot,
    config: RuntimeConfig,
    texts: dict[str, str],
    service_session: ServiceSession,
    status_label: str | None,
    status_tone: str,
    controls_available: bool,
) -> ServicePanelViewModel:
    metrics = (
        OverviewMetric("label.plant_power", _format_power_mw(snapshot.site.plant_power_mw), _tone_for_power(snapshot)),
        OverviewMetric(
            "label.power_limit",
            f"{snapshot.power_plant_controller.active_power_limit_pct:.1f} %",
            _tone_for_limit(snapshot),
        ),
        OverviewMetric(
            "label.breaker_state",
            _enum_text(texts, snapshot.grid_interconnect.breaker_state),
            _tone_for_breaker(snapshot.grid_interconnect.breaker_state),
        ),
        OverviewMetric(
            "label.communications",
            _enum_text(texts, snapshot.site.communications_health),
            _tone_for_communications(snapshot.site.communications_health),
        ),
    )
    return ServicePanelViewModel(
        page_title=texts["page.service_panel.title"],
        page_subtitle=texts["page.service_panel.subtitle"],
        site_name=config.site_name,
        site_code=config.site_code,
        snapshot_time=_snapshot_time(snapshot),
        operator_label=service_session.username,
        session_expires_at=_history_time(service_session.expires_at),
        status_label=status_label,
        status_tone=status_tone,
        controls_available=controls_available,
        power_limit_value=f"{snapshot.power_plant_controller.active_power_limit_pct:.1f}",
        breaker_state_label=_enum_text(texts, snapshot.grid_interconnect.breaker_state),
        breaker_open_enabled=snapshot.grid_interconnect.breaker_state != "open",
        breaker_close_enabled=snapshot.grid_interconnect.breaker_state != "closed",
        metrics=metrics,
        allowed_actions=(
            texts["service.action.power_limit"],
            texts["service.action.breaker"],
            texts["service.action.block_enable_reset"],
        ),
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
    page: OverviewViewModel | SingleLineViewModel | InvertersViewModel | WeatherViewModel | MeterViewModel | AlarmsViewModel | TrendsViewModel | ErrorViewModel | ServiceLoginViewModel | ServicePanelViewModel,
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
        NavItem(href="/alarms", label_key="nav.alarms", is_current=current == "/alarms"),
        NavItem(href="/trends", label_key="nav.trends", is_current=current == "/trends"),
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


def _set_service_session_cookie(response: HTMLResponse, service_session: ServiceSession) -> None:
    max_age = int(SERVICE_SESSION_IDLE_TIMEOUT.total_seconds())
    response.set_cookie(
        SERVICE_SESSION_COOKIE_NAME,
        service_session.handle,
        httponly=True,
        samesite="lax",
        max_age=max_age,
    )


def _service_panel_status(*, request: Request, texts: dict[str, str]) -> tuple[str | None, str]:
    status_code = request.query_params.get("status")
    if status_code is None:
        return None, "neutral"

    status_map = {
        "power_limit_updated": ("service.status.power_limit_updated", "good"),
        "breaker_open_requested": ("service.status.breaker_open_requested", "good"),
        "breaker_close_requested": ("service.status.breaker_close_requested", "good"),
        "control_invalid": ("service.status.control_invalid", "alarm"),
        "control_rejected": ("service.status.control_rejected", "alarm"),
        "control_unavailable": ("service.status.control_unavailable", "warn"),
    }
    label_key, tone = status_map.get(status_code, (None, "neutral"))
    if label_key is None:
        return None, "neutral"
    return texts[label_key], tone


def _service_panel_redirect_response(
    *,
    session_id: str,
    set_cookie: bool,
    service_session: ServiceSession,
    status_code: str,
) -> RedirectResponse:
    response = RedirectResponse(
        url=f"/service/panel?{urlencode({'status': status_code})}",
        status_code=303,
    )
    if set_cookie:
        _set_session_cookie(response, session_id)
    _set_service_session_cookie(response, service_session)
    return response


def _render_error_page(
    *,
    request: Request,
    templates: Jinja2Templates,
    config: RuntimeConfig,
    texts: dict[str, str],
    event_recorder: EventRecorder | None,
    status_code: int,
    page_title: str,
    page_subtitle: str,
    error_message: str,
    event_type: str,
    error_code: str,
) -> HTMLResponse:
    response = templates.TemplateResponse(
        request=request,
        name="error_page.html",
        context=_template_context(
            config=config,
            texts=texts,
            current_path=request.url.path,
            page=ErrorViewModel(
                page_title=page_title,
                page_subtitle=page_subtitle,
                site_name=config.site_name,
                site_code=config.site_code,
                status_code=status_code,
                error_label=texts["label.error_status"],
                error_message=error_message,
            ),
        ),
        status_code=status_code,
    )
    _record_error_page(
        request=request,
        event_recorder=event_recorder,
        status_code=status_code,
        event_type=event_type,
        error_code=error_code,
    )
    return response


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


def _record_error_page(
    *,
    request: Request,
    event_recorder: EventRecorder | None,
    status_code: int,
    event_type: str,
    error_code: str,
) -> None:
    if event_recorder is None:
        return

    path = request.url.path
    event = event_recorder.build_event(
        event_type=event_type,
        category="hmi",
        severity="medium" if status_code == 404 else "high",
        source_ip=request.client.host if request.client is not None else "127.0.0.1",
        actor_type="remote_client",
        component=HMI_COMPONENT,
        asset_id=HMI_COMPONENT,
        action="error_page",
        result="served",
        protocol=HMI_PROTOCOL,
        service=HMI_SERVICE,
        endpoint_or_register=path,
        requested_value={"http_method": request.method, "http_path": path},
        resulting_value={"http_status": status_code},
        error_code=error_code,
        message=f"HMI error page rendered for status {status_code}",
        tags=("error", "web"),
    )
    event_recorder.record(event)


def _build_service_auth_event(
    *,
    request: Request,
    event_recorder: EventRecorder | None,
    session_id: str,
    username: str,
    result: str,
):
    if event_recorder is None:
        return None
    return event_recorder.build_event(
        event_type="hmi.auth.service_login_attempt",
        category="auth",
        severity="low" if result == "success" else "medium",
        source_ip=request.client.host if request.client is not None else "127.0.0.1",
        actor_type="remote_client",
        component=HMI_COMPONENT,
        asset_id=HMI_COMPONENT,
        action="login",
        result=result,
        session_id=session_id,
        protocol=HMI_PROTOCOL,
        service=HMI_SERVICE,
        endpoint_or_register=request.url.path,
        requested_value={"username": username, "http_path": request.url.path},
        resulting_value={"http_status": 303 if result == "success" else 200},
        message=f"Service login attempt {result}",
        tags=("auth", "service", "web"),
    )


def _record_service_control_event(
    *,
    request: Request,
    event_recorder: EventRecorder | None,
    session_id: str,
    correlation_id: str,
    asset_id: str,
    action: str,
    result: str,
    requested_value: dict[str, Any],
    message: str,
    tags: tuple[str, ...],
    previous_value: Any | None = None,
    resulting_value: Any | None = None,
    resulting_state: dict[str, Any] | None = None,
    error_code: str | None = None,
) -> None:
    if event_recorder is None:
        return

    event = event_recorder.build_event(
        event_type="hmi.action.service_control_submitted",
        category="hmi",
        severity="low" if result == "accepted" else "medium",
        source_ip=request.client.host if request.client is not None else "127.0.0.1",
        actor_type="remote_client",
        component=HMI_COMPONENT,
        asset_id=asset_id,
        action=action,
        result=result,
        session_id=session_id,
        correlation_id=correlation_id,
        protocol=HMI_PROTOCOL,
        service=HMI_SERVICE,
        endpoint_or_register=request.url.path,
        requested_value={
            "http_method": request.method,
            "http_path": request.url.path,
            **requested_value,
        },
        previous_value=previous_value,
        resulting_value={"http_status": 303, "value": resulting_value},
        resulting_state=resulting_state,
        error_code=error_code,
        message=message,
        tags=tags,
    )
    event_recorder.record(event)


def _require_service_session(
    request: Request,
    *,
    config: RuntimeConfig,
    service_sessions: ServiceSessionStore,
) -> ServiceSession:
    if not config.enable_service_login:
        raise StarletteHTTPException(status_code=403)
    service_session = service_sessions.touch(request.cookies.get(SERVICE_SESSION_COOKIE_NAME))
    if service_session is None:
        raise StarletteHTTPException(status_code=401)
    return service_session


def _hmi_clock(event_recorder: EventRecorder | None) -> Clock:
    if event_recorder is not None:
        return event_recorder.clock
    return SystemClock()


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


def _alert_history(event_recorder: EventRecorder | None) -> tuple[AlertRecord, ...]:
    if event_recorder is None:
        return ()
    return event_recorder.store.fetch_alerts()


def _normalize_alarm_filter(value: str | None, *, allowed: set[str]) -> str | None:
    if value is None or value == "all":
        return None
    return value if value in allowed else None


def _normalize_alarm_sort(value: str | None) -> str:
    if value in {"severity", "code"}:
        return value
    return "recent"


def _highest_alarm_severity(snapshot: PlantSnapshot) -> str | None:
    if not snapshot.active_alarms:
        return None
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return max(snapshot.active_alarms, key=lambda alarm: severity_order[alarm.severity]).severity


def _alarm_rows(
    snapshot: PlantSnapshot,
    *,
    texts: dict[str, str],
    alert_history: tuple[AlertRecord, ...],
    severity_filter: str | None,
    state_filter: str | None,
    sort_order: str,
) -> tuple[AlarmListRow, ...]:
    rows = []
    for alarm in snapshot.alarms:
        if severity_filter is not None and alarm.severity != severity_filter:
            continue
        if state_filter is not None and alarm.state != state_filter:
            continue
        asset_id = _alarm_asset_id(snapshot, alarm.code, alert_history)
        history = tuple(
            entry for entry in alert_history if entry.alarm_code == alarm.code and entry.asset_id == asset_id
        )
        first_seen = snapshot.start_time if not history else min(entry.created_at for entry in history)
        last_changed = snapshot.start_time if not history else max(entry.created_at for entry in history)
        rows.append(
            AlarmListRow(
                code=alarm.code,
                label=texts.get(f"alarm.{alarm.code}", alarm.code),
                category_label=_alarm_category_text(texts, alarm.category),
                severity_label=_severity_text(texts, alarm.severity),
                severity_key=alarm.severity,
                state_label=_alarm_state_text(texts, alarm.state),
                ack_state_label=_ack_state_text(texts, alarm.state),
                asset_id=asset_id,
                first_seen=_history_time(first_seen),
                last_changed=_history_time(last_changed),
                last_changed_sort=ensure_utc_datetime(last_changed).isoformat(),
                tone=_tone_for_severity(alarm.severity),
            )
        )

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    if sort_order == "severity":
        rows.sort(key=lambda row: (-severity_order[row.severity_key], row.code, row.asset_id))
    elif sort_order == "code":
        rows.sort(key=lambda row: (row.code, row.asset_id))
    else:
        rows.sort(key=lambda row: (row.last_changed_sort, row.code, row.asset_id), reverse=True)
    return tuple(rows)


def _alarm_asset_id(snapshot: PlantSnapshot, code: str, alert_history: tuple[AlertRecord, ...]) -> str:
    matching_history = tuple(entry for entry in alert_history if entry.alarm_code == code)
    if matching_history:
        latest = max(matching_history, key=lambda entry: entry.created_at)
        return latest.asset_id
    if code == "PLANT_CURTAILED":
        return snapshot.power_plant_controller.asset_id
    if code == "BREAKER_OPEN":
        return snapshot.grid_interconnect.asset_id
    if code == "COMM_LOSS_INVERTER_BLOCK":
        for block in snapshot.inverter_blocks:
            if block.communication_state == "lost":
                return block.asset_id
    return snapshot.power_plant_controller.asset_id


def _alarm_category_text(texts: dict[str, str], value: str) -> str:
    return texts.get(f"alarm_category.{value}", value.replace("_", " ").title())


def _ack_state_text(texts: dict[str, str], value: str) -> str:
    if value == "active_acknowledged":
        return texts["ack.acknowledged"]
    if value == "active_unacknowledged":
        return texts["ack.unacknowledged"]
    if value == "cleared":
        return texts["ack.cleared"]
    return texts["ack.none"]


def _history_time(value) -> str:
    return ensure_utc_datetime(value).strftime("%Y-%m-%d %H:%M:%S UTC")


def _alarm_filter_links(
    texts: dict[str, str],
    *,
    filter_name: str,
    current_value: str | None,
    sort_order: str,
    options: tuple[tuple[str | None, str], ...],
    selected_severity: str | None = None,
    selected_state: str | None = None,
) -> tuple[AlarmFilterLink, ...]:
    links = []
    for value, label in options:
        query: dict[str, str] = {"sort": sort_order}
        if filter_name != "severity" and selected_severity is not None:
            query["severity"] = selected_severity
        if filter_name != "state" and selected_state is not None:
            query["state"] = selected_state
        if value is not None:
            query[filter_name] = value
        href = "/alarms"
        if query:
            href = f"/alarms?{urlencode(query)}"
        links.append(AlarmFilterLink(label=label, href=href, is_current=current_value == value))
    return tuple(links)


def _alarm_sort_links(
    texts: dict[str, str],
    *,
    current_value: str,
    selected_severity: str | None,
    selected_state: str | None,
) -> tuple[AlarmFilterLink, ...]:
    links = []
    for value, label in (
        ("recent", texts["sort.recent"]),
        ("severity", texts["sort.severity"]),
        ("code", texts["sort.code"]),
    ):
        query = {"sort": value}
        if selected_severity is not None:
            query["severity"] = selected_severity
        if selected_state is not None:
            query["state"] = selected_state
        links.append(
            AlarmFilterLink(
                label=label,
                href=f"/alarms?{urlencode(query)}",
                is_current=current_value == value,
            )
        )
    return tuple(links)


def _trend_series_view(
    *,
    asset_id: str,
    title: str,
    baseline_value: float,
    current_value: float,
    value_formatter: Callable[[float], str],
    tone: str,
) -> TrendSeriesView:
    values = _interpolate_values(baseline_value, current_value, steps=6)
    min_value = min(values)
    max_value = max(values)
    return TrendSeriesView(
        asset_id=asset_id,
        title=title,
        current_value=value_formatter(current_value),
        baseline_value=value_formatter(baseline_value),
        polyline_points=_sparkline_points(values),
        tone=tone,
        min_label=value_formatter(min_value),
        max_label=value_formatter(max_value),
    )


def _interpolate_values(start_value: float, end_value: float, *, steps: int) -> tuple[float, ...]:
    if steps < 2:
        raise ValueError("steps muss mindestens 2 sein")
    delta = end_value - start_value
    return tuple(round(start_value + delta * (index / (steps - 1)), 3) for index in range(steps))


def _sparkline_points(values: tuple[float, ...], *, width: int = 280, height: int = 90, padding: int = 10) -> str:
    min_value = min(values)
    max_value = max(values)
    span = max(max_value - min_value, 1e-9)
    x_step = (width - padding * 2) / max(len(values) - 1, 1)
    points = []
    for index, value in enumerate(values):
        x = padding + x_step * index
        y = height - padding - ((value - min_value) / span) * (height - padding * 2)
        points.append(f"{x:.1f},{y:.1f}")
    return " ".join(points)


def _trends_context(
    snapshot: PlantSnapshot,
    baseline_snapshot: PlantSnapshot,
    texts: dict[str, str],
) -> tuple[str, str]:
    if snapshot.grid_interconnect.breaker_state != "closed":
        return texts["trends.context.breaker_open"], "alarm"
    if snapshot.power_plant_controller.active_power_limit_pct < baseline_snapshot.power_plant_controller.active_power_limit_pct:
        return texts["trends.context.curtailment_visible"], "warn"
    if snapshot.site.communications_health != "healthy":
        return texts["trends.context.comms_degraded"], "warn"
    return texts["trends.context.baseline_aligned"], "good"


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
