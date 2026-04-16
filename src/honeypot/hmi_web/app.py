"""Read-only HMI-Slice fuer die erste sichtbare Web-Oberflaeche."""

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


def create_hmi_app(
    *,
    snapshot_provider: Callable[[], PlantSnapshot],
    config: RuntimeConfig,
    event_recorder: EventRecorder | None = None,
) -> FastAPI:
    """Erzeugt die erste read-only HMI-App fuer `/` und `/overview`."""

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
        session_id = request.cookies.get(SESSION_COOKIE_NAME) or f"hmi_{uuid4().hex}"
        view_model = build_overview_view_model(snapshot=snapshot, config=config, texts=texts)

        response = templates.TemplateResponse(
            request=request,
            name="overview.html",
            context={
                "config": config,
                "page": view_model,
                "lang": config.attacker_ui_locale,
                "t": lambda key: texts.get(key, key),
            },
        )
        if request.cookies.get(SESSION_COOKIE_NAME) is None:
            response.set_cookie(
                SESSION_COOKIE_NAME,
                session_id,
                httponly=True,
                samesite="lax",
            )

        _record_page_view(
            request=request,
            snapshot=snapshot,
            session_id=session_id,
            event_recorder=event_recorder,
        )
        return response

    return app


def build_overview_view_model(
    *,
    snapshot: PlantSnapshot,
    config: RuntimeConfig,
    texts: dict[str, str],
) -> OverviewViewModel:
    """Bereitet die sichtbaren Werte fuer die erste HMI-Uebersicht auf."""

    metrics = (
        OverviewMetric("label.plant_power", f"{snapshot.site.plant_power_mw:.2f} MW", _tone_for_power(snapshot)),
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

    active_alarms = tuple(
        OverviewAlarm(
            code=alarm.code,
            label=texts.get(f"alarm.{alarm.code}", alarm.code),
            severity_label=_severity_text(texts, alarm.severity),
            state_label=_alarm_state_text(texts, alarm.state),
            tone=_tone_for_severity(alarm.severity),
        )
        for alarm in _sorted_active_alarms(snapshot)[:3]
    )

    return OverviewViewModel(
        page_title=texts["page.overview.title"],
        page_subtitle=texts["page.overview.subtitle"],
        site_name=config.site_name,
        site_code=config.site_code,
        snapshot_time=snapshot.start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        metrics=metrics,
        inverter_rows=inverter_rows,
        weather_facts=weather_facts,
        active_alarms=active_alarms,
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


def _record_page_view(
    *,
    request: Request,
    snapshot: PlantSnapshot,
    session_id: str,
    event_recorder: EventRecorder | None,
) -> None:
    if event_recorder is None:
        return

    path = request.url.path
    event = event_recorder.build_event(
        event_type="hmi.page.overview_viewed",
        category="hmi",
        severity="info",
        source_ip=request.client.host if request.client is not None else "127.0.0.1",
        actor_type="remote_client",
        component=HMI_COMPONENT,
        asset_id=snapshot.power_plant_controller.asset_id,
        action="view_overview",
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
        resulting_state={
            "plant_power_mw": snapshot.site.plant_power_mw,
            "active_power_limit_pct": snapshot.power_plant_controller.active_power_limit_pct,
            "breaker_state": snapshot.site.breaker_state,
            "active_alarm_count": snapshot.site.active_alarm_count,
        },
        message="Overview page rendered",
        tags=("read-only", "overview", "web"),
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
