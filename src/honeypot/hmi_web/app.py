"""Read-only HMI-Slices fuer die ersten sichtbaren Web-Oberflaechen."""

from __future__ import annotations

import json
import secrets
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import parse_qs, urlencode
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from honeypot.asset_domain import PlantSnapshot
from honeypot.config_core import RuntimeConfig
from honeypot.event_core import AlertRecord, EventRecorder
from honeypot.ops_web.settings import OpsBackendSettings, load_ops_settings
from honeypot.plant_sim import SimulationEventContext
from honeypot.runtime_evolution import TrendSample
from honeypot.time_core import Clock, SystemClock, ensure_utc_datetime

HMI_COMPONENT = "hmi-web"
HMI_SERVICE = "web-hmi"
HMI_PROTOCOL = "http"
SESSION_COOKIE_NAME = "hmi_session"
SERVICE_SESSION_COOKIE_NAME = "service_session"
SERVICE_SESSION_IDLE_TIMEOUT = timedelta(minutes=20)
MAX_FORM_BODY_BYTES = 8 * 1024
MAX_FORM_FIELD_COUNT = 32
SERVICE_LOGIN_FAILURE_LIMIT = 5
SERVICE_LOGIN_FAILURE_WINDOW = timedelta(minutes=5)
SERVICE_LOGIN_BACKOFF = timedelta(minutes=5)
SERVICE_LOGIN_THROTTLE_MAX_SOURCES = 256
SERVICE_CSRF_FIELD_NAME = "service_csrf_token"
SERVICE_CSRF_TOKEN_BYTES = 32
DEFAULT_TREND_WINDOW = "30d"
MAX_TREND_RENDER_POINTS = 180
TREND_WINDOWS: dict[str, tuple[str, timedelta]] = {
    "1h": ("1 h", timedelta(hours=1)),
    "6h": ("6 h", timedelta(hours=6)),
    "24h": ("24 h", timedelta(hours=24)),
    "7d": ("7 d", timedelta(days=7)),
    "30d": ("30 d", timedelta(days=30)),
}
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
    block_enable_request: int
    block_enable_label: str
    block_enable_tone: str
    block_enable_next_value: str
    block_power_limit_pct_value: str
    dc_disconnect_state: str
    dc_disconnect_label: str
    dc_disconnect_tone: str
    dc_disconnect_next_value: str


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
    status_label: str | None
    status_tone: str
    service_csrf_token: str | None
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
    dc_disconnect_label: str
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
class VisibleAlarmEntry:
    code: str
    category: str
    severity: str
    state: str
    asset_id: str
    first_seen: Any
    last_changed: Any


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
    start_value: str
    polyline_points: str
    tone: str
    min_label: str
    max_label: str


@dataclass(frozen=True, slots=True)
class TrendWindowLink:
    label: str
    href: str
    is_current: bool


@dataclass(frozen=True, slots=True)
class DailyEnergyBar:
    day_label: str
    value_label: str
    title_label: str
    height_pct: int
    tone: str


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
    window_label: str
    window_links: tuple[TrendWindowLink, ...]
    sample_count: int
    window_energy_label: str
    daily_energy_bars: tuple[DailyEnergyBar, ...]


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
class ServiceInverterControl:
    asset_id: str
    status_label: str
    communication_label: str
    power_label: str
    enable_request_value: str
    power_limit_pct_value: str
    dc_disconnect_state_value: str
    dc_disconnect_label: str
    dc_disconnect_checked: bool
    tone: str


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
    csrf_token: str
    power_limit_value: str
    reactive_power_target_pct_value: str
    plant_mode_request_value: str
    breaker_state_label: str
    breaker_open_enabled: bool
    breaker_close_enabled: bool
    inverter_controls: tuple[ServiceInverterControl, ...]
    metrics: tuple[OverviewMetric, ...]
    allowed_actions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ServiceSession:
    handle: str
    username: str
    expires_at: Any
    csrf_token: str


class ServiceControlPort(Protocol):
    def set_active_power_limit_pct(
        self,
        *,
        active_power_limit_pct: float,
        event_context: SimulationEventContext | None = None,
    ) -> Any: ...

    def set_reactive_power_target_pct(
        self,
        *,
        reactive_power_target_pct: float,
        event_context: SimulationEventContext | None = None,
    ) -> Any: ...

    def get_plant_mode_request(self) -> int: ...

    def set_plant_mode_request(
        self,
        *,
        plant_mode_request: int,
        event_context: SimulationEventContext | None = None,
    ) -> Any: ...

    def get_block_enable_request(self, *, asset_id: str) -> int: ...

    def get_block_power_limit_pct(self, *, asset_id: str) -> float: ...

    def get_block_dc_disconnect_state(self, *, asset_id: str) -> str: ...

    def set_block_dc_disconnect_state(
        self,
        *,
        asset_id: str,
        dc_disconnect_state: str,
        event_context: SimulationEventContext | None = None,
    ) -> Any: ...

    def set_block_control_state(
        self,
        *,
        asset_id: str,
        block_enable_request: bool,
        block_power_limit_pct: float,
        event_context: SimulationEventContext | None = None,
    ) -> Any: ...

    def request_block_reset(
        self,
        *,
        asset_id: str,
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
            csrf_token=secrets.token_urlsafe(SERVICE_CSRF_TOKEN_BYTES),
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
            csrf_token=session.csrf_token,
        )
        self._sessions[handle] = refreshed
        return refreshed


class HmiFormRequestError(ValueError):
    """Signalisiert ungueltige oder zu grosse HMI-Formular-Requests."""


@dataclass(slots=True)
class ServiceLoginCampaignState:
    campaign_id: str
    source_ip: str
    user_agent: str
    endpoint: str
    first_seen: Any
    last_seen: Any
    next_summary_at: Any
    total_attempts: int = 0
    window_attempts: int = 0


@dataclass(frozen=True, slots=True)
class ServiceLoginCaptureDecision:
    campaign_id: str
    emit_attempt_event: bool
    summary_event: Any | None = None


@dataclass(slots=True)
class ServiceLoginCampaignTracker:
    clock: Clock
    event_recorder: EventRecorder | None
    max_sources: int = SERVICE_LOGIN_THROTTLE_MAX_SOURCES
    _campaigns_by_key: dict[tuple[str, str, str], ServiceLoginCampaignState] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    def record_failure(
        self,
        *,
        request: Request,
        username: str,
        password: str | None,
    ) -> ServiceLoginCaptureDecision:
        now = ensure_utc_datetime(self.clock.now())
        settings = self._settings()
        state = self._state_for_request(request=request, now=now, settings=settings)
        state.total_attempts += 1
        state.window_attempts += 1
        state.last_seen = now

        if settings.login_credential_capture_enabled and self.event_recorder is not None:
            self.event_recorder.store.record_login_credential_attempt(
                campaign_id=state.campaign_id,
                source_ip=state.source_ip,
                user_agent=state.user_agent,
                endpoint=state.endpoint,
                username=username,
                password=password,
                observed_at=now,
                max_unique_passwords=settings.login_capture_max_unique_passwords,
                max_credential_length=settings.login_capture_max_credential_length,
                capture_password=settings.login_password_capture_enabled,
            )

        if not settings.login_campaign_aggregation_enabled:
            self._trim_sources()
            return ServiceLoginCaptureDecision(campaign_id=state.campaign_id, emit_attempt_event=True)

        emit_attempt_event = state.total_attempts <= settings.login_capture_sample_attempts
        summary_event = None
        if state.total_attempts > settings.login_capture_sample_attempts and now >= ensure_utc_datetime(
            state.next_summary_at
        ):
            summary_event = self._build_summary_event(
                request=request,
                state=state,
                settings=settings,
            )
            state.window_attempts = 0
            state.next_summary_at = now + timedelta(seconds=settings.login_capture_summary_interval_seconds)
        self._trim_sources()
        return ServiceLoginCaptureDecision(
            campaign_id=state.campaign_id,
            emit_attempt_event=emit_attempt_event,
            summary_event=summary_event,
        )

    def register_success(self, request: Request) -> None:
        self._campaigns_by_key.pop(self._request_key(request), None)

    def _settings(self) -> OpsBackendSettings:
        if self.event_recorder is None:
            return OpsBackendSettings()
        return load_ops_settings(self.event_recorder.store)

    def _state_for_request(
        self,
        *,
        request: Request,
        now: Any,
        settings: OpsBackendSettings,
    ) -> ServiceLoginCampaignState:
        normalized_now = ensure_utc_datetime(now)
        key = self._request_key(request)
        existing = self._campaigns_by_key.get(key)
        idle_timeout = timedelta(minutes=settings.login_campaign_idle_timeout_minutes)
        if existing is not None and normalized_now - ensure_utc_datetime(existing.last_seen) <= idle_timeout:
            return existing

        source_ip, user_agent, endpoint = key
        state = ServiceLoginCampaignState(
            campaign_id=f"camp_{uuid4().hex}",
            source_ip=source_ip,
            user_agent=user_agent,
            endpoint=endpoint,
            first_seen=normalized_now,
            last_seen=normalized_now,
            next_summary_at=normalized_now + timedelta(seconds=settings.login_capture_summary_interval_seconds),
        )
        self._campaigns_by_key[key] = state
        return state

    def _request_key(self, request: Request) -> tuple[str, str, str]:
        return (_request_source_ip(request), _request_user_agent(request), request.url.path)

    def _build_summary_event(
        self,
        *,
        request: Request,
        state: ServiceLoginCampaignState,
        settings: OpsBackendSettings,
    ):
        if self.event_recorder is None:
            return None
        top_usernames = [
            {"username": row.credential_value, "count": row.count}
            for row in self.event_recorder.store.fetch_login_credential_top(
                value_type="username",
                scope_type="campaign",
                scope_id=state.campaign_id,
                limit=5,
            )
        ]
        return self.event_recorder.build_event(
            event_type="hmi.auth.bruteforce_campaign_summary",
            category="auth",
            severity="medium",
            source_ip=state.source_ip,
            actor_type="remote_client",
            component=HMI_COMPONENT,
            asset_id=HMI_COMPONENT,
            action="login_campaign_summary",
            result="observed",
            protocol=HMI_PROTOCOL,
            service=HMI_SERVICE,
            endpoint_or_register=request.url.path,
            requested_value={
                "campaign_id": state.campaign_id,
                "sampled_attempts": min(state.total_attempts, settings.login_capture_sample_attempts),
                "top_usernames": top_usernames,
            },
            resulting_value={
                "attempt_count_total": state.total_attempts,
                "attempt_count_window": state.window_attempts,
                "first_seen": ensure_utc_datetime(state.first_seen).isoformat().replace("+00:00", "Z"),
                "last_seen": ensure_utc_datetime(state.last_seen).isoformat().replace("+00:00", "Z"),
            },
            message="Aggregated service login brute-force campaign",
            tags=("auth", "service", "web", "bruteforce", "summary"),
        )

    def _trim_sources(self) -> None:
        while len(self._campaigns_by_key) > self.max_sources:
            oldest_key = next(iter(self._campaigns_by_key))
            self._campaigns_by_key.pop(oldest_key, None)


def create_hmi_app(
    *,
    snapshot_provider: Callable[[], PlantSnapshot],
    trend_history_provider: Callable[[], tuple[TrendSample, ...]] | None = None,
    config: RuntimeConfig,
    event_recorder: EventRecorder | None = None,
    service_controls: ServiceControlPort | None = None,
) -> FastAPI:
    """Erzeugt die ersten HMI-Seiten fuer die lokale Runtime inklusive Service-Pfad."""

    texts = _load_locale_texts(config)
    templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
    hmi_clock = _hmi_clock(event_recorder)
    service_sessions = ServiceSessionStore(clock=hmi_clock)
    service_login_tracker = ServiceLoginCampaignTracker(clock=hmi_clock, event_recorder=event_recorder)
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
            _set_session_cookie(response, session_id, secure=config.hmi_cookie_secure)

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
        service_session = (
            service_sessions.touch(request.cookies.get(SERVICE_SESSION_COOKIE_NAME))
            if config.enable_service_login
            else None
        )
        status_label, status_tone = _service_panel_status(request=request, texts=texts)
        view_model = build_single_line_view_model(
            snapshot=snapshot,
            config=config,
            texts=texts,
            service_controls=service_controls,
            service_csrf_token=(service_session.csrf_token if service_session is not None else None),
            status_label=status_label,
            status_tone=status_tone,
        )
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
            _set_session_cookie(response, session_id, secure=config.hmi_cookie_secure)
        if service_session is not None:
            _set_service_session_cookie(response, service_session, secure=config.service_cookie_secure)

        _record_page_view(
            request=request,
            snapshot=snapshot,
            session_id=(service_session.handle if service_session is not None else session_id),
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

    @app.get("/single-line/inverter-attempt", include_in_schema=False)
    async def single_line_inverter_attempt(request: Request) -> RedirectResponse:
        snapshot = snapshot_provider()
        session_id, set_cookie = _session_state(request)
        asset_id = request.query_params.get("asset_id", "").strip()
        control = request.query_params.get("control", "").strip()
        response = RedirectResponse(url="/service/login", status_code=303)
        if set_cookie:
            _set_session_cookie(response, session_id, secure=config.hmi_cookie_secure)

        try:
            block = _require_inverter_block(snapshot, asset_id)
        except ValueError:
            _record_unauthenticated_control_attempt(
                request=request,
                event_recorder=event_recorder,
                session_id=session_id,
                asset_id=asset_id or "inverter-block",
                action="single_line_inverter_click",
                requested_value={"asset_id": asset_id, "control": control, "source_view": "/single-line"},
                previous_value=None,
                resulting_state={"asset_id": asset_id, "plant_power_mw": snapshot.site.plant_power_mw},
                message="Single-line inverter control click used an invalid asset id",
                tags=("single-line", "inverter-block", "control-attempt", "unauthenticated", "web"),
            )
            return response

        block_enable_request = 0 if block.status == "offline" and block.availability_pct == 0 else 1
        if control == "dc_disconnect":
            action = "single_line_dc_disconnect_click"
            previous_value: object = block.dc_disconnect_state
            resulting_state = {
                "dc_disconnect_state": block.dc_disconnect_state,
                "status": block.status,
                "communication_state": block.communication_state,
                "block_power_kw": block.block_power_kw,
                "plant_power_mw": snapshot.site.plant_power_mw,
            }
            tags = ("single-line", "inverter-block", "dc-disconnect", "control-attempt", "unauthenticated", "web")
        elif control == "block_enable":
            action = "single_line_block_enable_click"
            previous_value = block_enable_request
            resulting_state = {
                "block_enable_request": block_enable_request,
                "status": block.status,
                "communication_state": block.communication_state,
                "availability_pct": block.availability_pct,
                "block_power_kw": block.block_power_kw,
                "plant_power_mw": snapshot.site.plant_power_mw,
            }
            tags = ("single-line", "inverter-block", "block-enable", "control-attempt", "unauthenticated", "web")
        else:
            action = "single_line_inverter_click"
            previous_value = None
            resulting_state = {
                "status": block.status,
                "communication_state": block.communication_state,
                "block_power_kw": block.block_power_kw,
                "plant_power_mw": snapshot.site.plant_power_mw,
            }
            tags = ("single-line", "inverter-block", "control-attempt", "unauthenticated", "web")

        _record_unauthenticated_control_attempt(
            request=request,
            event_recorder=event_recorder,
            session_id=session_id,
            asset_id=block.asset_id,
            action=action,
            requested_value={"asset_id": block.asset_id, "control": control, "source_view": "/single-line"},
            previous_value=previous_value,
            resulting_state=resulting_state,
            message="Single-line inverter control click rejected before service authentication",
            tags=tags,
        )
        return response

    @app.get("/single-line/breaker-attempt", include_in_schema=False)
    async def single_line_breaker_attempt(request: Request) -> RedirectResponse:
        snapshot = snapshot_provider()
        session_id, set_cookie = _session_state(request)
        response = RedirectResponse(url="/service/login", status_code=303)
        if set_cookie:
            _set_session_cookie(response, session_id, secure=config.hmi_cookie_secure)

        _record_unauthenticated_control_attempt(
            request=request,
            event_recorder=event_recorder,
            session_id=session_id,
            asset_id=snapshot.grid_interconnect.asset_id,
            action="single_line_breaker_click",
            requested_value={"control": "breaker", "source_view": "/single-line"},
            previous_value=snapshot.grid_interconnect.breaker_state,
            resulting_state={
                "breaker_state": snapshot.grid_interconnect.breaker_state,
                "export_power_kw": snapshot.revenue_meter.export_power_kw,
                "export_path_available": snapshot.grid_interconnect.export_path_available,
            },
            message="Single-line breaker click rejected before service authentication",
            tags=("single-line", "breaker", "control-attempt", "unauthenticated", "web"),
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
            _set_session_cookie(response, session_id, secure=config.hmi_cookie_secure)

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
            _set_session_cookie(response, session_id, secure=config.hmi_cookie_secure)

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
            _set_session_cookie(response, session_id, secure=config.hmi_cookie_secure)

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
            _set_session_cookie(response, session_id, secure=config.hmi_cookie_secure)

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
        trend_window = _normalize_trend_window(request.query_params.get("window"))
        view_model = build_trends_view_model(
            snapshot=snapshot,
            config=config,
            texts=texts,
            trend_history=() if trend_history_provider is None else trend_history_provider(),
            trend_window=trend_window,
        )
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
            _set_session_cookie(response, session_id, secure=config.hmi_cookie_secure)

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
                "trend_window": trend_window,
                "history_points": view_model.sample_count,
                "window_energy": view_model.window_energy_label,
                "daily_energy_days": len(view_model.daily_energy_bars),
                "plant_power_mw": snapshot.site.plant_power_mw,
                "active_power_limit_pct": snapshot.power_plant_controller.active_power_limit_pct,
                "export_power_kw": snapshot.revenue_meter.export_power_kw,
                "export_energy_mwh_total": snapshot.revenue_meter.export_energy_mwh_total,
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
            _set_session_cookie(response, session_id, secure=config.hmi_cookie_secure)
        if service_session is not None:
            _set_service_session_cookie(response, service_session, secure=config.service_cookie_secure)

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
        try:
            form = await _read_urlencoded_form(request)
        except HmiFormRequestError:
            capture_decision = service_login_tracker.record_failure(
                request=request,
                username="unknown",
                password=None,
            )
            auth_event = _build_service_auth_event(
                request=request,
                event_recorder=event_recorder,
                session_id=session_id,
                username="unknown",
                result="failure",
                campaign_id=capture_decision.campaign_id,
            )
            if auth_event is not None and capture_decision.emit_attempt_event:
                event_recorder.record(auth_event)
            if capture_decision.summary_event is not None:
                event_recorder.record(capture_decision.summary_event)
            return _service_login_failure_response(
                request=request,
                templates=templates,
                config=config,
                texts=texts,
                session_id=session_id,
                set_cookie=set_cookie,
            )
        username = (form.get("username", [""])[0]).strip()
        password = form.get("password", [""])[0]
        login_success = username == SERVICE_LOGIN_USERNAME and password == SERVICE_LOGIN_PASSWORD

        if not login_success:
            capture_decision = service_login_tracker.record_failure(
                request=request,
                username=username,
                password=password,
            )
            auth_event = _build_service_auth_event(
                request=request,
                event_recorder=event_recorder,
                session_id=session_id,
                username=username,
                result="failure",
                campaign_id=capture_decision.campaign_id,
            )
            if auth_event is not None and capture_decision.emit_attempt_event:
                event_recorder.record(auth_event)
            if capture_decision.summary_event is not None:
                event_recorder.record(capture_decision.summary_event)
            return _service_login_failure_response(
                request=request,
                templates=templates,
                config=config,
                texts=texts,
                session_id=session_id,
                set_cookie=set_cookie,
            )

        service_login_tracker.register_success(request)
        auth_event = _build_service_auth_event(
            request=request,
            event_recorder=event_recorder,
            session_id=session_id,
            username=username,
            result="success",
            campaign_id=None,
        )
        if auth_event is not None:
            event_recorder.record(auth_event)
        service_session = service_sessions.create(username=username)
        response = RedirectResponse(url="/service/panel", status_code=303)
        if set_cookie:
            _set_session_cookie(response, session_id, secure=config.hmi_cookie_secure)
        _set_service_session_cookie(response, service_session, secure=config.service_cookie_secure)
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
        plant_mode_request_value = (
            service_controls.get_plant_mode_request()
            if service_controls is not None
            else _default_plant_mode_request(snapshot)
        )
        view_model = build_service_panel_view_model(
            snapshot=snapshot,
            config=config,
            texts=texts,
            service_session=service_session,
            status_label=status_label,
            status_tone=status_tone,
            controls_available=service_controls is not None,
            plant_mode_request_value=plant_mode_request_value,
            inverter_controls=_service_panel_inverter_controls(
                snapshot=snapshot,
                texts=texts,
                service_controls=service_controls,
            ),
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
            _set_session_cookie(response, session_id, secure=config.hmi_cookie_secure)
        _set_service_session_cookie(response, service_session, secure=config.service_cookie_secure)
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
                config=config,
                status_code="control_unavailable",
            )

        raw_limit = ""
        try:
            form = await _read_urlencoded_form(request)
            raw_limit = (form.get("active_power_limit_pct", [""])[0]).strip()
            _validate_service_csrf_token(form, service_session)
            active_power_limit_pct = float(raw_limit)
        except (HmiFormRequestError, ValueError):
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
                config=config,
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
                config=config,
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
            config=config,
            status_code="power_limit_updated",
        )

    @app.post("/service/panel/reactive-power", response_class=HTMLResponse, include_in_schema=False)
    async def service_panel_reactive_power(request: Request) -> HTMLResponse:
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
                action="set_reactive_power_target",
                result="rejected",
                requested_value={"reactive_power_target_pct": None},
                resulting_state={"controls_available": False},
                message="Service reactive power path unavailable",
                tags=("service", "control", "reactive-power", "web"),
                error_code="service_control_unavailable",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_unavailable",
            )

        raw_target = ""
        try:
            form = await _read_urlencoded_form(request)
            raw_target = (form.get("reactive_power_target_pct", [""])[0]).strip()
            _validate_service_csrf_token(form, service_session)
            reactive_power_target_pct = float(raw_target)
        except (HmiFormRequestError, ValueError):
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=before_snapshot.power_plant_controller.asset_id,
                action="set_reactive_power_target",
                result="rejected",
                requested_value={"reactive_power_target_pct": raw_target},
                previous_value=round(before_snapshot.power_plant_controller.reactive_power_target * 100, 1),
                resulting_state={
                    "reactive_power_target": before_snapshot.power_plant_controller.reactive_power_target,
                },
                message="Service reactive power request could not be parsed",
                tags=("service", "control", "reactive-power", "web"),
                error_code="service_control_invalid",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
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
            result = service_controls.set_reactive_power_target_pct(
                reactive_power_target_pct=reactive_power_target_pct,
                event_context=event_context,
            )
        except ValueError as exc:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=before_snapshot.power_plant_controller.asset_id,
                action="set_reactive_power_target",
                result="rejected",
                requested_value={"reactive_power_target_pct": reactive_power_target_pct},
                previous_value=round(before_snapshot.power_plant_controller.reactive_power_target * 100, 1),
                resulting_state={
                    "reactive_power_target": before_snapshot.power_plant_controller.reactive_power_target,
                },
                message=f"Service reactive power request rejected: {exc}",
                tags=("service", "control", "reactive-power", "web"),
                error_code="service_control_rejected",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_rejected",
            )

        after_snapshot = snapshot_provider()
        _record_service_control_event(
            request=request,
            event_recorder=event_recorder,
            session_id=service_session.handle,
            correlation_id=correlation_id,
            asset_id=result.asset_id,
            action="set_reactive_power_target",
            result="accepted",
            requested_value={"reactive_power_target_pct": reactive_power_target_pct},
            previous_value=round(before_snapshot.power_plant_controller.reactive_power_target * 100, 1),
            resulting_value=round(after_snapshot.power_plant_controller.reactive_power_target * 100, 1),
            resulting_state=result.resulting_state,
            message="Service reactive power request accepted",
            tags=("service", "control", "reactive-power", "web"),
        )
        return _service_panel_redirect_response(
            session_id=session_id,
            set_cookie=set_cookie,
            service_session=service_session,
            config=config,
            status_code="reactive_power_updated",
        )

    @app.post("/service/panel/plant-mode", response_class=HTMLResponse, include_in_schema=False)
    async def service_panel_plant_mode(request: Request) -> HTMLResponse:
        service_session = _require_service_session(
            request,
            config=config,
            service_sessions=service_sessions,
        )
        session_id, set_cookie = _session_state(request)
        source_ip = request.client.host if request.client is not None else "127.0.0.1"
        before_snapshot = snapshot_provider()
        current_mode_request = (
            service_controls.get_plant_mode_request()
            if service_controls is not None
            else _default_plant_mode_request(before_snapshot)
        )
        correlation_id = uuid4().hex

        if service_controls is None:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=before_snapshot.power_plant_controller.asset_id,
                action="set_plant_mode_request",
                result="rejected",
                requested_value={"plant_mode_request": None},
                resulting_state={"controls_available": False},
                message="Service plant mode path unavailable",
                tags=("service", "control", "plant-mode", "web"),
                error_code="service_control_unavailable",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_unavailable",
            )

        raw_mode_request = ""
        try:
            form = await _read_urlencoded_form(request)
            raw_mode_request = (form.get("plant_mode_request", [""])[0]).strip()
            _validate_service_csrf_token(form, service_session)
            plant_mode_request = int(raw_mode_request)
        except (HmiFormRequestError, ValueError):
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=before_snapshot.power_plant_controller.asset_id,
                action="set_plant_mode_request",
                result="rejected",
                requested_value={"plant_mode_request": raw_mode_request},
                previous_value=current_mode_request,
                resulting_state={"plant_mode_request": current_mode_request},
                message="Service plant mode request could not be parsed",
                tags=("service", "control", "plant-mode", "web"),
                error_code="service_control_invalid",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
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
            result = service_controls.set_plant_mode_request(
                plant_mode_request=plant_mode_request,
                event_context=event_context,
            )
        except ValueError as exc:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=before_snapshot.power_plant_controller.asset_id,
                action="set_plant_mode_request",
                result="rejected",
                requested_value={"plant_mode_request": plant_mode_request},
                previous_value=current_mode_request,
                resulting_state={"plant_mode_request": current_mode_request},
                message=f"Service plant mode request rejected: {exc}",
                tags=("service", "control", "plant-mode", "web"),
                error_code="service_control_rejected",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_rejected",
            )

        _record_service_control_event(
            request=request,
            event_recorder=event_recorder,
            session_id=service_session.handle,
            correlation_id=correlation_id,
            asset_id=result.asset_id,
            action="set_plant_mode_request",
            result="accepted",
            requested_value={"plant_mode_request": plant_mode_request},
            previous_value=current_mode_request,
            resulting_value=result.resulting_state.get("plant_mode_request"),
            resulting_state=result.resulting_state,
            message="Service plant mode request accepted",
            tags=("service", "control", "plant-mode", "web"),
        )
        return _service_panel_redirect_response(
            session_id=session_id,
            set_cookie=set_cookie,
            service_session=service_session,
            config=config,
            status_code="plant_mode_updated",
        )

    @app.post("/service/panel/inverter-block", response_class=HTMLResponse, include_in_schema=False)
    async def service_panel_inverter_block(request: Request) -> HTMLResponse:
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
                asset_id="inverter-block",
                action="set_block_control_state",
                result="rejected",
                requested_value={
                    "asset_id": None,
                    "block_enable_request": None,
                    "block_power_limit_pct": None,
                },
                resulting_state={"controls_available": False},
                message="Service inverter block control path unavailable",
                tags=("service", "control", "inverter-block", "web"),
                error_code="service_control_unavailable",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_unavailable",
            )

        try:
            form = await _read_urlencoded_form(request)
            return_to = _service_return_path(form)
            _validate_service_csrf_token(form, service_session)
        except HmiFormRequestError:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id="inverter-block",
                action="set_block_control_state",
                result="rejected",
                requested_value={
                    "asset_id": "",
                    "block_enable_request": "",
                    "block_power_limit_pct": "",
                },
                resulting_state={"asset_id": ""},
                message="Service inverter block control used an invalid form body",
                tags=("service", "control", "inverter-block", "web"),
                error_code="service_control_invalid",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_invalid",
            )
        return_to = _service_return_path(form)
        asset_id = (form.get("asset_id", [""])[0]).strip()

        try:
            before_block = _require_inverter_block(before_snapshot, asset_id)
            current_enable_request = service_controls.get_block_enable_request(asset_id=asset_id)
            current_power_limit_pct = service_controls.get_block_power_limit_pct(asset_id=asset_id)
        except ValueError:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=asset_id or "inverter-block",
                action="set_block_control_state",
                result="rejected",
                requested_value={
                    "asset_id": asset_id,
                    "block_enable_request": form.get("block_enable_request", [""])[0],
                    "block_power_limit_pct": form.get("block_power_limit_pct", [""])[0],
                },
                resulting_state={"asset_id": asset_id},
                message="Service inverter block control used an invalid asset id",
                tags=("service", "control", "inverter-block", "web"),
                error_code="service_control_invalid",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_invalid",
                return_to=return_to,
            )

        raw_enable_request = (form.get("block_enable_request", [""])[0]).strip()
        raw_power_limit_pct = (form.get("block_power_limit_pct", [""])[0]).strip()
        try:
            block_enable_request_value = int(raw_enable_request)
            if block_enable_request_value not in {0, 1}:
                raise ValueError
            block_power_limit_pct = float(raw_power_limit_pct)
        except ValueError:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=asset_id,
                action="set_block_control_state",
                result="rejected",
                requested_value={
                    "asset_id": asset_id,
                    "block_enable_request": raw_enable_request,
                    "block_power_limit_pct": raw_power_limit_pct,
                },
                previous_value={
                    "block_enable_request": current_enable_request,
                    "block_power_limit_pct": current_power_limit_pct,
                },
                resulting_state={
                    "block_enable_request": current_enable_request,
                    "block_power_limit_pct": current_power_limit_pct,
                    "status": before_block.status,
                    "communication_state": before_block.communication_state,
                },
                message="Service inverter block control request could not be parsed",
                tags=("service", "control", "inverter-block", "web"),
                error_code="service_control_invalid",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_invalid",
                return_to=return_to,
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
            result = service_controls.set_block_control_state(
                asset_id=asset_id,
                block_enable_request=bool(block_enable_request_value),
                block_power_limit_pct=block_power_limit_pct,
                event_context=event_context,
            )
        except ValueError as exc:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=asset_id,
                action="set_block_control_state",
                result="rejected",
                requested_value={
                    "asset_id": asset_id,
                    "block_enable_request": block_enable_request_value,
                    "block_power_limit_pct": block_power_limit_pct,
                },
                previous_value={
                    "block_enable_request": current_enable_request,
                    "block_power_limit_pct": current_power_limit_pct,
                },
                resulting_state={
                    "block_enable_request": current_enable_request,
                    "block_power_limit_pct": current_power_limit_pct,
                    "status": before_block.status,
                    "communication_state": before_block.communication_state,
                    "block_power_kw": before_block.block_power_kw,
                },
                message=f"Service inverter block control request rejected: {exc}",
                tags=("service", "control", "inverter-block", "web"),
                error_code="service_control_rejected",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_rejected",
                return_to=return_to,
            )

        _record_service_control_event(
            request=request,
            event_recorder=event_recorder,
            session_id=service_session.handle,
            correlation_id=correlation_id,
            asset_id=result.asset_id,
            action="set_block_control_state",
            result="accepted",
            requested_value={
                "asset_id": asset_id,
                "block_enable_request": block_enable_request_value,
                "block_power_limit_pct": block_power_limit_pct,
            },
            previous_value={
                "block_enable_request": current_enable_request,
                "block_power_limit_pct": current_power_limit_pct,
            },
            resulting_value={
                "asset_id": asset_id,
                "block_enable_request": result.resulting_state.get("block_enable_request"),
                "block_power_limit_pct": result.resulting_state.get("block_power_limit_pct"),
            },
            resulting_state=result.resulting_state,
            message="Service inverter block control request accepted",
            tags=("service", "control", "inverter-block", "web"),
        )
        return _service_panel_redirect_response(
            session_id=session_id,
            set_cookie=set_cookie,
            service_session=service_session,
            config=config,
            status_code="block_control_updated",
            return_to=return_to,
        )

    @app.post("/service/panel/inverter-block/dc-disconnect", response_class=HTMLResponse, include_in_schema=False)
    async def service_panel_inverter_block_dc_disconnect(request: Request) -> HTMLResponse:
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
                asset_id="inverter-block",
                action="set_block_dc_disconnect_state",
                result="rejected",
                requested_value={"asset_id": None, "dc_disconnect_state": None},
                resulting_state={"controls_available": False},
                message="Service inverter block PV/DC disconnect path unavailable",
                tags=("service", "control", "inverter-block", "dc-disconnect", "web"),
                error_code="service_control_unavailable",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_unavailable",
            )

        try:
            form = await _read_urlencoded_form(request)
            return_to = _service_return_path(form)
            _validate_service_csrf_token(form, service_session)
        except HmiFormRequestError:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id="inverter-block",
                action="set_block_dc_disconnect_state",
                result="rejected",
                requested_value={"asset_id": "", "dc_disconnect_open": ""},
                resulting_state={"asset_id": ""},
                message="Service inverter block PV/DC disconnect used an invalid form body",
                tags=("service", "control", "inverter-block", "dc-disconnect", "web"),
                error_code="service_control_invalid",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_invalid",
            )

        return_to = _service_return_path(form)
        asset_id = (form.get("asset_id", [""])[0]).strip()
        raw_disconnect_open = (form.get("dc_disconnect_open", ["0"])[0]).strip()
        try:
            before_block = _require_inverter_block(before_snapshot, asset_id)
            current_dc_disconnect_state = service_controls.get_block_dc_disconnect_state(asset_id=asset_id)
        except ValueError:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=asset_id or "inverter-block",
                action="set_block_dc_disconnect_state",
                result="rejected",
                requested_value={"asset_id": asset_id, "dc_disconnect_open": raw_disconnect_open},
                resulting_state={"asset_id": asset_id},
                message="Service inverter block PV/DC disconnect used an invalid asset id",
                tags=("service", "control", "inverter-block", "dc-disconnect", "web"),
                error_code="service_control_invalid",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_invalid",
                return_to=return_to,
            )

        if raw_disconnect_open not in {"0", "1"}:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=asset_id,
                action="set_block_dc_disconnect_state",
                result="rejected",
                requested_value={"asset_id": asset_id, "dc_disconnect_open": raw_disconnect_open},
                previous_value=current_dc_disconnect_state,
                resulting_state={
                    "dc_disconnect_state": current_dc_disconnect_state,
                    "status": before_block.status,
                    "communication_state": before_block.communication_state,
                    "block_power_kw": before_block.block_power_kw,
                },
                message="Service inverter block PV/DC disconnect request could not be parsed",
                tags=("service", "control", "inverter-block", "dc-disconnect", "web"),
                error_code="service_control_invalid",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_invalid",
                return_to=return_to,
            )

        requested_dc_disconnect_state = "open" if raw_disconnect_open == "1" else "closed"
        event_context = SimulationEventContext(
            source_ip=source_ip,
            actor_type="remote_client",
            correlation_id=correlation_id,
            session_id=service_session.handle,
            protocol=HMI_PROTOCOL,
            service=HMI_SERVICE,
        )
        try:
            result = service_controls.set_block_dc_disconnect_state(
                asset_id=asset_id,
                dc_disconnect_state=requested_dc_disconnect_state,
                event_context=event_context,
            )
        except ValueError as exc:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=asset_id,
                action="set_block_dc_disconnect_state",
                result="rejected",
                requested_value={"asset_id": asset_id, "dc_disconnect_state": requested_dc_disconnect_state},
                previous_value=current_dc_disconnect_state,
                resulting_state={
                    "dc_disconnect_state": current_dc_disconnect_state,
                    "status": before_block.status,
                    "communication_state": before_block.communication_state,
                    "block_power_kw": before_block.block_power_kw,
                },
                message=f"Service inverter block PV/DC disconnect request rejected: {exc}",
                tags=("service", "control", "inverter-block", "dc-disconnect", "web"),
                error_code="service_control_rejected",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_rejected",
                return_to=return_to,
            )

        _record_service_control_event(
            request=request,
            event_recorder=event_recorder,
            session_id=service_session.handle,
            correlation_id=correlation_id,
            asset_id=result.asset_id,
            action="set_block_dc_disconnect_state",
            result="accepted",
            requested_value={"asset_id": asset_id, "dc_disconnect_state": requested_dc_disconnect_state},
            previous_value=current_dc_disconnect_state,
            resulting_value=result.resulting_value,
            resulting_state=result.resulting_state,
            message="Service inverter block PV/DC disconnect request accepted",
            tags=("service", "control", "inverter-block", "dc-disconnect", "web"),
        )
        return _service_panel_redirect_response(
            session_id=session_id,
            set_cookie=set_cookie,
            service_session=service_session,
            config=config,
            status_code="dc_disconnect_updated",
            return_to=return_to,
        )

    @app.post("/service/panel/inverter-block/reset", response_class=HTMLResponse, include_in_schema=False)
    async def service_panel_inverter_block_reset(request: Request) -> HTMLResponse:
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
                asset_id="inverter-block",
                action="block_reset_request",
                result="rejected",
                requested_value={"asset_id": None, "block_reset_request": None},
                resulting_state={"controls_available": False},
                message="Service inverter block reset path unavailable",
                tags=("service", "control", "inverter-block", "reset", "web"),
                error_code="service_control_unavailable",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_unavailable",
            )

        try:
            form = await _read_urlencoded_form(request)
            _validate_service_csrf_token(form, service_session)
        except HmiFormRequestError:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id="inverter-block",
                action="block_reset_request",
                result="rejected",
                requested_value={"asset_id": "", "block_reset_request": 1},
                resulting_state={"asset_id": ""},
                message="Service inverter block reset used an invalid form body",
                tags=("service", "control", "inverter-block", "reset", "web"),
                error_code="service_control_invalid",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_invalid",
            )
        asset_id = (form.get("asset_id", [""])[0]).strip()

        try:
            before_block = _require_inverter_block(before_snapshot, asset_id)
            current_enable_request = service_controls.get_block_enable_request(asset_id=asset_id)
            current_power_limit_pct = service_controls.get_block_power_limit_pct(asset_id=asset_id)
        except ValueError:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=asset_id or "inverter-block",
                action="block_reset_request",
                result="rejected",
                requested_value={"asset_id": asset_id, "block_reset_request": 1},
                resulting_state={"asset_id": asset_id},
                message="Service inverter block reset used an invalid asset id",
                tags=("service", "control", "inverter-block", "reset", "web"),
                error_code="service_control_invalid",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
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
            result = service_controls.request_block_reset(
                asset_id=asset_id,
                event_context=event_context,
            )
        except ValueError as exc:
            _record_service_control_event(
                request=request,
                event_recorder=event_recorder,
                session_id=service_session.handle,
                correlation_id=correlation_id,
                asset_id=asset_id,
                action="block_reset_request",
                result="rejected",
                requested_value={"asset_id": asset_id, "block_reset_request": 1},
                previous_value={
                    "status": before_block.status,
                    "communication_state": before_block.communication_state,
                    "quality": before_block.quality,
                },
                resulting_state={
                    "block_enable_request": current_enable_request,
                    "block_power_limit_pct": current_power_limit_pct,
                    "status": before_block.status,
                    "communication_state": before_block.communication_state,
                    "quality": before_block.quality,
                },
                message=f"Service inverter block reset request rejected: {exc}",
                tags=("service", "control", "inverter-block", "reset", "web"),
                error_code="service_control_rejected",
            )
            return _service_panel_redirect_response(
                session_id=session_id,
                set_cookie=set_cookie,
                service_session=service_session,
                config=config,
                status_code="control_rejected",
            )

        _record_service_control_event(
            request=request,
            event_recorder=event_recorder,
            session_id=service_session.handle,
            correlation_id=correlation_id,
            asset_id=result.asset_id,
            action="block_reset_request",
            result="accepted",
            requested_value={"asset_id": asset_id, "block_reset_request": 1},
            previous_value={
                "status": before_block.status,
                "communication_state": before_block.communication_state,
                "quality": before_block.quality,
            },
            resulting_value={"asset_id": asset_id, "block_reset_request": "pulse"},
            resulting_state=result.resulting_state,
            message="Service inverter block reset request accepted",
            tags=("service", "control", "inverter-block", "reset", "web"),
        )
        return _service_panel_redirect_response(
            session_id=session_id,
            set_cookie=set_cookie,
            service_session=service_session,
            config=config,
            status_code="block_reset_requested",
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
                config=config,
                status_code="control_unavailable",
            )

        try:
            form = await _read_urlencoded_form(request)
            _validate_service_csrf_token(form, service_session)
        except HmiFormRequestError:
            form = {}
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
                config=config,
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
                config=config,
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
            config=config,
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
            f"{snapshot.power_plant_controller.reactive_power_target * 100:.1f} %",
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
            tone=_tone_for_inverter_block(block),
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
    service_controls: ServiceControlPort | None = None,
    service_csrf_token: str | None = None,
    status_label: str | None = None,
    status_tone: str = "neutral",
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

    inverter_nodes: list[SingleLineNode] = []
    for block in snapshot.inverter_blocks:
        if service_controls is None:
            block_enable_request = 0 if block.status == "offline" and block.availability_pct == 0 else 1
            block_power_limit_pct = 100.0
            dc_disconnect_state = block.dc_disconnect_state
        else:
            block_enable_request = service_controls.get_block_enable_request(asset_id=block.asset_id)
            block_power_limit_pct = service_controls.get_block_power_limit_pct(asset_id=block.asset_id)
            dc_disconnect_state = service_controls.get_block_dc_disconnect_state(asset_id=block.asset_id)

        inverter_nodes.append(
            SingleLineNode(
                asset_id=block.asset_id,
                title=block.asset_id.upper(),
                status_label=_enum_text(texts, block.status),
                detail_label=_single_line_inverter_detail_label(block, texts),
                tone=_tone_for_inverter_block(block),
                block_enable_request=block_enable_request,
                block_enable_label=texts["state.enabled"] if block_enable_request == 1 else texts["state.disabled"],
                block_enable_tone="good" if block_enable_request == 1 else "alarm",
                block_enable_next_value="0" if block_enable_request == 1 else "1",
                block_power_limit_pct_value=f"{block_power_limit_pct:.1f}",
                dc_disconnect_state=dc_disconnect_state,
                dc_disconnect_label=_dc_disconnect_label(dc_disconnect_state, texts),
                dc_disconnect_tone="alarm" if dc_disconnect_state == "open" else "good",
                dc_disconnect_next_value="0" if dc_disconnect_state == "open" else "1",
            )
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
        status_label=status_label,
        status_tone=status_tone,
        service_csrf_token=service_csrf_token,
        facts=facts,
        inverter_nodes=tuple(inverter_nodes),
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
            dc_disconnect_label=_inverter_dc_disconnect_label(block, texts),
            dc_label=_format_block_bus_values(block, block.block_dc_voltage_v, block.block_dc_current_a, texts),
            ac_label=_format_block_bus_values(block, block.block_ac_voltage_v, block.block_ac_current_a, texts),
            temperature_label=_format_block_temperature(block, texts),
            local_alarm_count=_inverter_local_alarm_count(block),
            tone=_tone_for_inverter_block(block),
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
            "label.pv_isolated_blocks",
            str(_count_dc_isolated_blocks(snapshot)),
            "warn" if _count_dc_isolated_blocks(snapshot) else "good",
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

    visible_alarms = _visible_alarm_entries(snapshot, alert_history=alert_history)
    rows = _alarm_rows(
        visible_alarms,
        texts=texts,
        severity_filter=severity_filter,
        state_filter=state_filter,
        sort_order=sort_order,
    )
    active_alarm_count = sum(1 for alarm in visible_alarms if _is_active_alarm_state(alarm.state))
    acknowledged_count = sum(1 for alarm in visible_alarms if alarm.state == "active_acknowledged")
    communication_count = sum(
        1 for alarm in visible_alarms if alarm.category == "communication" and _is_active_alarm_state(alarm.state)
    )
    highest_severity = _highest_alarm_severity(visible_alarms)
    metrics = (
        OverviewMetric(
            "label.active_alarms",
            str(active_alarm_count),
            "alarm" if active_alarm_count else "good",
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
    trend_history: tuple[TrendSample, ...] = (),
    trend_window: str = DEFAULT_TREND_WINDOW,
) -> TrendsViewModel:
    """Bereitet eine kleine glaubhafte Verlaufssicht aus echter Mini-Historie auf."""

    resolved_window = _normalize_trend_window(trend_window)
    history = _trend_history_for_window(
        snapshot=snapshot,
        trend_history=trend_history,
        trend_window=resolved_window,
    )
    render_history = _decimate_trend_history(history, max_points=MAX_TREND_RENDER_POINTS)
    window_energy_mwh = _window_energy_mwh(history)
    daily_energy_bars = _daily_energy_bars(history, timezone=config.timezone)
    context_label, context_tone = _trends_context(snapshot, history, texts)
    metrics = (
        OverviewMetric("label.plant_power", _format_power_mw(snapshot.site.plant_power_mw), _tone_for_power(snapshot)),
        OverviewMetric(
            "label.export_power",
            _format_power_kw(snapshot.revenue_meter.export_power_kw),
            "good" if snapshot.revenue_meter.export_power_kw > 0 else "alarm",
        ),
        OverviewMetric(
            "label.window_energy",
            _format_energy_mwh(window_energy_mwh),
            "good" if window_energy_mwh > 0 else "warn",
        ),
        OverviewMetric(
            "label.power_limit",
            f"{snapshot.power_plant_controller.active_power_limit_pct:.1f} %",
            _tone_for_limit(snapshot),
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
            values=tuple(sample.plant_power_mw for sample in render_history),
            value_formatter=_format_power_mw,
            tone=_tone_for_power(snapshot),
        ),
        _trend_series_view(
            asset_id=snapshot.power_plant_controller.asset_id,
            title=texts["trend.power_limit"],
            values=tuple(sample.active_power_limit_pct for sample in render_history),
            value_formatter=lambda value: f"{value:.1f} %",
            tone=_tone_for_limit(snapshot),
        ),
        _trend_series_view(
            asset_id=snapshot.weather_station.asset_id,
            title=texts["trend.irradiance"],
            values=tuple(sample.irradiance_w_m2 for sample in render_history),
            value_formatter=lambda value: f"{value:.0f} W/m2",
            tone="good" if snapshot.weather_station.irradiance_w_m2 >= 700 else "warn",
        ),
        _trend_series_view(
            asset_id=snapshot.revenue_meter.asset_id,
            title=texts["trend.export_power"],
            values=tuple(sample.export_power_mw for sample in render_history),
            value_formatter=lambda value: f"{value:.2f} MW",
            tone="good" if snapshot.revenue_meter.export_power_kw > 0 else "alarm",
        ),
        _trend_series_view(
            asset_id=snapshot.revenue_meter.asset_id,
            title=texts["trend.export_energy"],
            values=_export_energy_series(render_history),
            value_formatter=_format_energy_mwh,
            tone="good" if window_energy_mwh > 0 else "warn",
        ),
        *tuple(
            _trend_series_view(
                asset_id=current_block.asset_id,
                title=f"{texts['trend.block_power']} {current_block.asset_id.upper()}",
                values=_block_series(render_history, current_block.asset_id),
                value_formatter=lambda value: f"{value:.1f} kW",
                tone=_tone_for_inverter_block(current_block),
            )
            for current_block in snapshot.inverter_blocks
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
        window_label=TREND_WINDOWS[resolved_window][0],
        window_links=_trend_window_links(resolved_window),
        sample_count=len(history),
        window_energy_label=_format_energy_mwh(window_energy_mwh),
        daily_energy_bars=daily_energy_bars,
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
    plant_mode_request_value: int,
    inverter_controls: tuple[ServiceInverterControl, ...],
) -> ServicePanelViewModel:
    metrics = (
        OverviewMetric("label.plant_power", _format_power_mw(snapshot.site.plant_power_mw), _tone_for_power(snapshot)),
        OverviewMetric(
            "label.power_limit",
            f"{snapshot.power_plant_controller.active_power_limit_pct:.1f} %",
            _tone_for_limit(snapshot),
        ),
        OverviewMetric(
            "label.reactive_power",
            f"{snapshot.power_plant_controller.reactive_power_target * 100:.1f} %",
            "neutral",
        ),
        OverviewMetric(
            "label.operating_mode",
            _enum_text(texts, snapshot.site.operating_mode),
            "warn" if snapshot.site.operating_mode == "curtailed" else "neutral",
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
        csrf_token=service_session.csrf_token,
        power_limit_value=f"{snapshot.power_plant_controller.active_power_limit_pct:.1f}",
        reactive_power_target_pct_value=f"{snapshot.power_plant_controller.reactive_power_target * 100:.1f}",
        plant_mode_request_value=str(plant_mode_request_value),
        breaker_state_label=_enum_text(texts, snapshot.grid_interconnect.breaker_state),
        breaker_open_enabled=snapshot.grid_interconnect.breaker_state != "open",
        breaker_close_enabled=snapshot.grid_interconnect.breaker_state != "closed",
        inverter_controls=inverter_controls,
        metrics=metrics,
        allowed_actions=(
            texts["service.action.power_limit"],
            texts["service.action.reactive_power"],
            texts["service.action.plant_mode"],
            texts["service.action.breaker"],
            texts["service.action.block_control"],
            texts["service.action.dc_disconnect"],
            texts["service.action.block_reset"],
        ),
    )


def _service_panel_inverter_controls(
    *,
    snapshot: PlantSnapshot,
    texts: dict[str, str],
    service_controls: ServiceControlPort | None,
) -> tuple[ServiceInverterControl, ...]:
    controls: list[ServiceInverterControl] = []
    for block in snapshot.inverter_blocks:
        if service_controls is None:
            enable_request = 0 if block.status == "offline" and block.availability_pct == 0 else 1
            power_limit_pct = 100.0
            dc_disconnect_state = block.dc_disconnect_state
        else:
            enable_request = service_controls.get_block_enable_request(asset_id=block.asset_id)
            power_limit_pct = service_controls.get_block_power_limit_pct(asset_id=block.asset_id)
            dc_disconnect_state = service_controls.get_block_dc_disconnect_state(asset_id=block.asset_id)
        controls.append(
            ServiceInverterControl(
                asset_id=block.asset_id,
                status_label=_enum_text(texts, block.status),
                communication_label=_enum_text(texts, block.communication_state),
                power_label=_format_power_kw(block.block_power_kw),
                enable_request_value=str(enable_request),
                power_limit_pct_value=f"{power_limit_pct:.1f}",
                dc_disconnect_state_value=dc_disconnect_state,
                dc_disconnect_label=_dc_disconnect_label(dc_disconnect_state, texts),
                dc_disconnect_checked=dc_disconnect_state == "open",
                tone=_tone_for_inverter_block(block),
            )
        )
    return tuple(controls)


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
        NavItem(href="/service/login", label_key="page.service_login.title", is_current=current == "/service/login"),
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


async def _read_urlencoded_form(request: Request) -> dict[str, list[str]]:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        raise HmiFormRequestError("unsupported form content type")

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_size = int(content_length)
        except ValueError as exc:
            raise HmiFormRequestError("invalid content length") from exc
        if declared_size > MAX_FORM_BODY_BYTES:
            raise HmiFormRequestError("form body too large")

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_FORM_BODY_BYTES:
            raise HmiFormRequestError("form body too large")

    try:
        raw_body = bytes(body).decode("utf-8")
        return parse_qs(
            raw_body,
            keep_blank_values=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=MAX_FORM_FIELD_COUNT,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise HmiFormRequestError("invalid form body") from exc


def _request_source_ip(request: Request) -> str:
    return request.client.host if request.client is not None else "127.0.0.1"


def _request_user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")


def _validate_service_csrf_token(form: dict[str, list[str]], service_session: ServiceSession) -> None:
    submitted_token = form.get(SERVICE_CSRF_FIELD_NAME, [""])[0]
    if not submitted_token or not secrets.compare_digest(submitted_token, service_session.csrf_token):
        raise HmiFormRequestError("invalid service csrf token")


def _service_login_failure_response(
    *,
    request: Request,
    templates: Jinja2Templates,
    config: RuntimeConfig,
    texts: dict[str, str],
    session_id: str,
    set_cookie: bool,
) -> HTMLResponse:
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
        _set_session_cookie(response, session_id, secure=config.hmi_cookie_secure)
    return response


def _session_state(request: Request) -> tuple[str, bool]:
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id is not None:
        return session_id, False
    return f"hmi_{uuid4().hex}", True


def _set_session_cookie(response: HTMLResponse, session_id: str, *, secure: bool) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        httponly=True,
        samesite="lax",
        secure=secure,
    )


def _set_service_session_cookie(response: HTMLResponse, service_session: ServiceSession, *, secure: bool) -> None:
    max_age = int(SERVICE_SESSION_IDLE_TIMEOUT.total_seconds())
    response.set_cookie(
        SERVICE_SESSION_COOKIE_NAME,
        service_session.handle,
        httponly=True,
        samesite="lax",
        max_age=max_age,
        secure=secure,
    )


def _service_panel_status(*, request: Request, texts: dict[str, str]) -> tuple[str | None, str]:
    status_code = request.query_params.get("status")
    if status_code is None:
        return None, "neutral"

    status_map = {
        "power_limit_updated": ("service.status.power_limit_updated", "good"),
        "reactive_power_updated": ("service.status.reactive_power_updated", "good"),
        "plant_mode_updated": ("service.status.plant_mode_updated", "good"),
        "block_control_updated": ("service.status.block_control_updated", "good"),
        "dc_disconnect_updated": ("service.status.dc_disconnect_updated", "good"),
        "block_reset_requested": ("service.status.block_reset_requested", "good"),
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


def _default_plant_mode_request(snapshot: PlantSnapshot) -> int:
    if snapshot.site.operating_mode == "maintenance":
        return 2
    if snapshot.site.operating_mode == "curtailed" or snapshot.site.plant_power_limit_pct < 100:
        return 1
    return 0


def _require_inverter_block(snapshot: PlantSnapshot, asset_id: str):
    for block in snapshot.inverter_blocks:
        if block.asset_id == asset_id:
            return block
    raise ValueError(f"asset_id {asset_id} ist im Snapshot kein Inverter-Block")


def _service_panel_redirect_response(
    *,
    session_id: str,
    set_cookie: bool,
    service_session: ServiceSession,
    config: RuntimeConfig,
    status_code: str,
    return_to: str = "/service/panel",
) -> RedirectResponse:
    response = RedirectResponse(
        url=f"{return_to}?{urlencode({'status': status_code})}",
        status_code=303,
    )
    if set_cookie:
        _set_session_cookie(response, session_id, secure=config.hmi_cookie_secure)
    _set_service_session_cookie(response, service_session, secure=config.service_cookie_secure)
    return response


def _service_return_path(form: dict[str, list[str]]) -> str:
    return_to = form.get("return_to", ["/service/panel"])[0].strip()
    if return_to == "/single-line":
        return "/single-line"
    return "/service/panel"


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
    campaign_id: str | None,
):
    if event_recorder is None:
        return None
    requested_value = {"username": username, "http_path": request.url.path}
    if campaign_id is not None:
        requested_value["campaign_id"] = campaign_id
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
        requested_value=requested_value,
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


def _record_unauthenticated_control_attempt(
    *,
    request: Request,
    event_recorder: EventRecorder | None,
    session_id: str,
    asset_id: str,
    action: str,
    requested_value: dict[str, Any],
    previous_value: Any | None,
    resulting_state: dict[str, Any],
    message: str,
    tags: tuple[str, ...],
) -> None:
    if event_recorder is None:
        return

    event = event_recorder.build_event(
        event_type="hmi.action.unauthenticated_control_attempt",
        category="hmi",
        severity="medium",
        source_ip=request.client.host if request.client is not None else "127.0.0.1",
        actor_type="remote_client",
        component=HMI_COMPONENT,
        asset_id=asset_id,
        action=action,
        result="rejected",
        session_id=session_id,
        protocol=HMI_PROTOCOL,
        service=HMI_SERVICE,
        endpoint_or_register=request.url.path,
        requested_value={
            "http_method": request.method,
            "http_path": request.url.path,
            **requested_value,
        },
        previous_value=previous_value,
        resulting_value={"http_status": 303, "redirect_to": "/service/login"},
        resulting_state=resulting_state,
        error_code="service_auth_required",
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


def _tone_for_inverter_block(block: Any) -> str:
    if block.dc_disconnect_state == "open":
        return "warn"
    if block.availability_pct == 0 and block.status != "faulted":
        return "warn"
    return _tone_for_block(block.status, block.communication_state)


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


def _dc_disconnect_label(dc_disconnect_state: str, texts: dict[str, str]) -> str:
    return texts["state.pv_isolated"] if dc_disconnect_state == "open" else texts["state.connected"]


def _inverter_dc_disconnect_label(block: Any, texts: dict[str, str]) -> str:
    return _dc_disconnect_label(block.dc_disconnect_state, texts)


def _single_line_inverter_detail_label(block: Any, texts: dict[str, str]) -> str:
    if block.dc_disconnect_state == "open":
        return f"{_format_power_kw(block.block_power_kw)} / {_inverter_dc_disconnect_label(block, texts)}"
    return f"{_format_power_kw(block.block_power_kw)} / {_enum_text(texts, block.communication_state)}"


def _snapshot_time(snapshot: PlantSnapshot) -> str:
    return snapshot.observed_at.strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_power_mw(value: float) -> str:
    return f"{value:.2f} MW"


def _format_power_kw(value: float) -> str:
    if value >= 1000:
        return f"{value / 1000:.2f} MW"
    return f"{value:.0f} kW"


def _format_energy_mwh(value: float) -> str:
    return f"{value:.3f} MWh"


def _format_block_power_kw(value: float) -> str:
    return f"{value:.1f} kW"


def _format_block_bus_values(block, voltage_v: float | None, current_a: float | None, texts: dict[str, str]) -> str:
    if voltage_v is None and current_a is None:
        return _missing_block_telemetry_label(block, texts, field="bus")
    if voltage_v is None:
        return f"{texts['telemetry.no_voltage']} / {current_a:.1f} A"
    if current_a is None:
        return f"{voltage_v:.1f} V / {texts['telemetry.no_current']}"
    return f"{voltage_v:.1f} V / {current_a:.1f} A"


def _format_block_temperature(block, texts: dict[str, str]) -> str:
    if block.internal_temperature_c is None:
        return _missing_block_telemetry_label(block, texts, field="temperature")
    return f"{block.internal_temperature_c:.1f} C"


def _missing_block_telemetry_label(block, texts: dict[str, str], *, field: str) -> str:
    if block.communication_state == "lost" or block.quality in {"stale", "invalid"}:
        return texts["telemetry.stale"]
    if block.status == "offline" or block.availability_pct == 0:
        return texts["telemetry.offline_by_request"]
    if field == "temperature":
        return texts["telemetry.no_thermal_sensor"]
    return texts["telemetry.not_instrumented"]


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


def _count_dc_isolated_blocks(snapshot: PlantSnapshot) -> int:
    return sum(1 for block in snapshot.inverter_blocks if block.dc_disconnect_state == "open")


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


def _is_active_alarm_state(value: str) -> bool:
    return value in {"active_unacknowledged", "active_acknowledged"}


def _highest_alarm_severity(visible_alarms: tuple[VisibleAlarmEntry, ...]) -> str | None:
    active_alarms = tuple(alarm for alarm in visible_alarms if _is_active_alarm_state(alarm.state))
    if not active_alarms:
        return None
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return max(active_alarms, key=lambda alarm: severity_order[alarm.severity]).severity


def _visible_alarm_entries(
    snapshot: PlantSnapshot,
    *,
    alert_history: tuple[AlertRecord, ...],
) -> tuple[VisibleAlarmEntry, ...]:
    snapshot_entries: dict[tuple[str, str], VisibleAlarmEntry] = {}
    for alarm in snapshot.alarms:
        asset_id = _alarm_asset_id(snapshot, alarm.code, alert_history)
        history = tuple(
            entry for entry in alert_history if entry.alarm_code == alarm.code and entry.asset_id == asset_id
        )
        first_seen = snapshot.start_time if not history else min(entry.created_at for entry in history)
        last_changed = snapshot.start_time if not history else max(entry.created_at for entry in history)
        snapshot_entries[(alarm.code, asset_id)] = VisibleAlarmEntry(
            code=alarm.code,
            category=alarm.category,
            severity=alarm.severity,
            state=alarm.state,
            asset_id=asset_id,
            first_seen=first_seen,
            last_changed=last_changed,
        )
    history_entries = {
        (entry.alarm_code, entry.asset_id): tuple(
            item
            for item in alert_history
            if item.alarm_code == entry.alarm_code and item.asset_id == entry.asset_id
        )
        for entry in alert_history
    }
    history_only_entries = {}
    for key, history in history_entries.items():
        if key in snapshot_entries:
            continue
        latest = max(history, key=lambda entry: entry.created_at)
        history_only_entries[key] = VisibleAlarmEntry(
            code=latest.alarm_code,
            category=_history_alarm_category(latest.alarm_code),
            severity=latest.severity,
            state=latest.state,
            asset_id=latest.asset_id,
            first_seen=min(entry.created_at for entry in history),
            last_changed=max(entry.created_at for entry in history),
        )
    return tuple(snapshot_entries.values()) + tuple(history_only_entries.values())


def _alarm_rows(
    visible_alarms: tuple[VisibleAlarmEntry, ...],
    *,
    texts: dict[str, str],
    severity_filter: str | None,
    state_filter: str | None,
    sort_order: str,
) -> tuple[AlarmListRow, ...]:
    rows = []
    for alarm in visible_alarms:
        if severity_filter is not None and alarm.severity != severity_filter:
            continue
        if state_filter is not None and alarm.state != state_filter:
            continue
        rows.append(
            AlarmListRow(
                code=alarm.code,
                label=texts.get(f"alarm.{alarm.code}", alarm.code),
                category_label=_alarm_category_text(texts, alarm.category),
                severity_label=_severity_text(texts, alarm.severity),
                severity_key=alarm.severity,
                state_label=_alarm_state_text(texts, alarm.state),
                ack_state_label=_ack_state_text(texts, alarm.state),
                asset_id=alarm.asset_id,
                first_seen=_history_time(alarm.first_seen),
                last_changed=_history_time(alarm.last_changed),
                last_changed_sort=ensure_utc_datetime(alarm.last_changed).isoformat(),
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


def _history_alarm_category(code: str) -> str:
    if code == "REPEATED_LOGIN_FAILURE":
        return "control"
    if code == "SETPOINT_CHANGE_ACCEPTED":
        return "control"
    if code == "COMM_LOSS_INVERTER_BLOCK":
        return "communication"
    if code in {"GRID_PATH_UNAVAILABLE", "LOW_SITE_OUTPUT_UNEXPECTED", "MULTI_BLOCK_UNAVAILABLE"}:
        return "site"
    return "site"


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
    values: tuple[float, ...],
    value_formatter: Callable[[float], str],
    tone: str,
) -> TrendSeriesView:
    if not values:
        raise ValueError("values muss mindestens einen Verlaufspunkt enthalten")
    start_value = values[0]
    current_value = values[-1]
    min_value = min(values)
    max_value = max(values)
    return TrendSeriesView(
        asset_id=asset_id,
        title=title,
        current_value=value_formatter(current_value),
        start_value=value_formatter(start_value),
        polyline_points=_sparkline_points(values),
        tone=tone,
        min_label=value_formatter(min_value),
        max_label=value_formatter(max_value),
    )


def _trend_history_or_fallback(
    snapshot: PlantSnapshot,
    trend_history: tuple[TrendSample, ...],
) -> tuple[TrendSample, ...]:
    if trend_history:
        return trend_history
    return (
        TrendSample.from_snapshot(snapshot),
    )


def _trend_history_for_window(
    *,
    snapshot: PlantSnapshot,
    trend_history: tuple[TrendSample, ...],
    trend_window: str,
) -> tuple[TrendSample, ...]:
    history = tuple(sorted(_trend_history_or_fallback(snapshot, trend_history), key=lambda sample: sample.observed_at))
    window_delta = TREND_WINDOWS[_normalize_trend_window(trend_window)][1]
    cutoff = ensure_utc_datetime(snapshot.observed_at) - window_delta
    filtered = tuple(sample for sample in history if ensure_utc_datetime(sample.observed_at) >= cutoff)
    if not filtered:
        filtered = (history[-1],)
    return filtered


def _decimate_trend_history(history: tuple[TrendSample, ...], *, max_points: int) -> tuple[TrendSample, ...]:
    if len(history) <= max_points:
        return history
    step = (len(history) - 1) / (max_points - 1)
    selected_indexes = {round(index * step) for index in range(max_points)}
    selected_indexes.add(0)
    selected_indexes.add(len(history) - 1)
    return tuple(history[index] for index in sorted(selected_indexes))


def _block_series(history: tuple[TrendSample, ...], asset_id: str) -> tuple[float, ...]:
    return tuple(dict(sample.block_power_kw).get(asset_id, 0.0) for sample in history)


def _export_energy_series(history: tuple[TrendSample, ...]) -> tuple[float, ...]:
    return tuple(0.0 if sample.export_energy_mwh_total is None else sample.export_energy_mwh_total for sample in history)


def _window_energy_mwh(history: tuple[TrendSample, ...]) -> float:
    totals = tuple(sample.export_energy_mwh_total for sample in history if sample.export_energy_mwh_total is not None)
    if len(totals) < 2:
        return 0.0
    return round(max(totals[-1] - totals[0], 0.0), 3)


def _daily_energy_bars(history: tuple[TrendSample, ...], *, timezone: str) -> tuple[DailyEnergyBar, ...]:
    totals = _daily_energy_totals(history, timezone=timezone)
    if not totals:
        return ()

    max_value = max(totals.values())
    bars: list[DailyEnergyBar] = []
    for day, value in totals.items():
        height_pct = 0 if value <= 0 or max_value <= 0 else max(3, round((value / max_value) * 100))
        value_label = f"{value:.1f}"
        day_label = day.strftime("%m-%d")
        bars.append(
            DailyEnergyBar(
                day_label=day_label,
                value_label=value_label,
                title_label=f"{day_label} / {_format_energy_mwh(value)}",
                height_pct=height_pct,
                tone="good" if value > 0 else "warn",
            )
        )
    return tuple(bars)


def _daily_energy_totals(history: tuple[TrendSample, ...], *, timezone: str):
    samples = tuple(
        sample for sample in sorted(history, key=lambda item: item.observed_at)
        if sample.export_energy_mwh_total is not None
    )
    if len(samples) < 2:
        return {}

    zone = _trend_zoneinfo(timezone)
    first_day = ensure_utc_datetime(samples[0].observed_at).astimezone(zone).date()
    last_day = ensure_utc_datetime(samples[-1].observed_at).astimezone(zone).date()
    totals = defaultdict(float)
    current_day = first_day
    while current_day <= last_day:
        totals[current_day] = 0.0
        current_day = current_day + timedelta(days=1)

    previous = samples[0]
    for sample in samples[1:]:
        delta = max((sample.export_energy_mwh_total or 0.0) - (previous.export_energy_mwh_total or 0.0), 0.0)
        day = ensure_utc_datetime(sample.observed_at).astimezone(zone).date()
        totals[day] += delta
        previous = sample

    ordered_days = tuple(sorted(totals))[-31:]
    return {day: round(totals[day], 3) for day in ordered_days}


def _trend_zoneinfo(timezone: str) -> ZoneInfo:
    try:
        return ZoneInfo(timezone)
    except ZoneInfoNotFoundError:
        return ZoneInfo("UTC")


def _normalize_trend_window(value: str | None) -> str:
    if value in TREND_WINDOWS:
        return value
    return DEFAULT_TREND_WINDOW


def _trend_window_links(current_window: str) -> tuple[TrendWindowLink, ...]:
    return tuple(
        TrendWindowLink(
            label=label,
            href=f"/trends?{urlencode({'window': window_key})}",
            is_current=window_key == current_window,
        )
        for window_key, (label, _) in TREND_WINDOWS.items()
    )


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
    history: tuple[TrendSample, ...],
    texts: dict[str, str],
) -> tuple[str, str]:
    if snapshot.grid_interconnect.breaker_state != "closed":
        return texts["trends.context.breaker_open"], "alarm"
    if snapshot.site.communications_health != "healthy":
        return texts["trends.context.comms_degraded"], "warn"
    if snapshot.power_plant_controller.active_power_limit_pct < 100:
        return texts["trends.context.curtailment_visible"], "warn"
    if len(history) >= 2 and (
        abs(history[-1].plant_power_mw - history[0].plant_power_mw) >= 0.1
        or abs(history[-1].irradiance_w_m2 - history[0].irradiance_w_m2) >= 25
    ):
        return texts["trends.context.live_history_visible"], "good"
    return texts["trends.context.stable_live_history"], "good"


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
