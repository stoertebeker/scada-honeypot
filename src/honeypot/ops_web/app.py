"""Interne read-only Ops-Sicht auf Eventstore und Alerts."""

from __future__ import annotations

import json
import secrets
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from honeypot.config_core import RuntimeConfig
from honeypot.event_core import AlertRecord, EventRecord
from honeypot.storage import SQLiteEventStore

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_OPS_SECURITY = HTTPBasic(auto_error=False)


@dataclass(frozen=True, slots=True)
class OpsSummary:
    total_events: int
    total_alerts: int
    active_alerts: int
    unique_sources: int
    rejected_events: int
    last_event_at: str


@dataclass(frozen=True, slots=True)
class EventRow:
    timestamp: str
    event_type: str
    source_ip: str
    action: str
    result: str
    severity: str
    asset_id: str
    endpoint_or_register: str
    error_code: str
    session_id: str
    message: str
    requested_value: str


@dataclass(frozen=True, slots=True)
class AlertRow:
    created_at: str
    alarm_code: str
    severity: str
    state: str
    asset_id: str
    message: str


@dataclass(frozen=True, slots=True)
class SourceRow:
    source_ip: str
    event_count: int
    rejected_count: int
    session_count: int
    first_seen: str
    last_seen: str
    top_event_type: str
    top_endpoint: str


def create_ops_app(*, event_store: SQLiteEventStore, config: RuntimeConfig) -> FastAPI:
    """Erzeugt die interne Operator-Sicht ohne Schreibpfade in den Honeypot."""

    templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
    app = FastAPI(
        title="SCADA Honeypot Ops",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    require_ops_auth = _build_auth_dependency(config)

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard(request: Request, _: None = Depends(require_ops_auth)) -> HTMLResponse:
        events = event_store.fetch_events()
        alerts = event_store.fetch_alerts()
        context = _template_context(
            request=request,
            config=config,
            current_path="/",
            summary=_build_summary(events=events, alerts=alerts),
            events=_event_rows(tuple(reversed(events))[:25]),
            alerts=_alert_rows(tuple(reversed(alerts))[:10]),
            sources=_source_rows(events)[:8],
        )
        return templates.TemplateResponse(request=request, name="dashboard.html", context=context)

    @app.get("/events", response_class=HTMLResponse, include_in_schema=False)
    async def events_page(
        request: Request,
        event_type: str | None = None,
        source_ip: str | None = None,
        result: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
        _: None = Depends(require_ops_auth),
    ) -> HTMLResponse:
        events = _filter_events(
            tuple(reversed(event_store.fetch_events())),
            event_type=event_type,
            source_ip=source_ip,
            result=result,
        )
        context = _template_context(
            request=request,
            config=config,
            current_path="/events",
            events=_event_rows(events[:limit]),
            event_type=event_type or "",
            source_ip=source_ip or "",
            result=result or "",
            limit=limit,
        )
        return templates.TemplateResponse(request=request, name="events.html", context=context)

    @app.get("/alerts", response_class=HTMLResponse, include_in_schema=False)
    async def alerts_page(
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
        _: None = Depends(require_ops_auth),
    ) -> HTMLResponse:
        alerts = tuple(reversed(event_store.fetch_alerts()))
        context = _template_context(
            request=request,
            config=config,
            current_path="/alerts",
            alerts=_alert_rows(alerts[:limit]),
            limit=limit,
        )
        return templates.TemplateResponse(request=request, name="alerts.html", context=context)

    @app.get("/sources", response_class=HTMLResponse, include_in_schema=False)
    async def sources_page(request: Request, _: None = Depends(require_ops_auth)) -> HTMLResponse:
        context = _template_context(
            request=request,
            config=config,
            current_path="/sources",
            sources=_source_rows(event_store.fetch_events()),
        )
        return templates.TemplateResponse(request=request, name="sources.html", context=context)

    @app.get("/api/summary", include_in_schema=False)
    async def api_summary(_: None = Depends(require_ops_auth)) -> dict[str, Any]:
        events = event_store.fetch_events()
        alerts = event_store.fetch_alerts()
        return {
            "summary": asdict(_build_summary(events=events, alerts=alerts, display_timestamps=False)),
            "sources": [asdict(source) for source in _source_rows(events)[:25]],
        }

    @app.get("/api/events", include_in_schema=False)
    async def api_events(
        event_type: str | None = None,
        source_ip: str | None = None,
        result: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
        _: None = Depends(require_ops_auth),
    ) -> dict[str, Any]:
        events = _filter_events(
            tuple(reversed(event_store.fetch_events())),
            event_type=event_type,
            source_ip=source_ip,
            result=result,
        )
        return {"events": [event.model_dump(mode="json") for event in events[:limit]]}

    @app.get("/api/alerts", include_in_schema=False)
    async def api_alerts(
        limit: int = Query(default=100, ge=1, le=500),
        _: None = Depends(require_ops_auth),
    ) -> dict[str, Any]:
        alerts = tuple(reversed(event_store.fetch_alerts()))
        return {"alerts": [alert.model_dump(mode="json") for alert in alerts[:limit]]}

    @app.get("/healthz", include_in_schema=False)
    async def healthz(_: None = Depends(require_ops_auth)) -> dict[str, str]:
        return {"status": "ok"}

    return app


def _build_auth_dependency(config: RuntimeConfig):
    async def require_ops_auth(credentials: HTTPBasicCredentials | None = Depends(_OPS_SECURITY)) -> None:
        if not config.ops_basic_auth_enabled:
            return None
        if credentials is None:
            _raise_auth_required()

        username_ok = secrets.compare_digest(credentials.username, config.ops_basic_auth_username or "")
        password_ok = secrets.compare_digest(credentials.password, config.ops_basic_auth_password or "")
        if not username_ok or not password_ok:
            _raise_auth_required()
        return None

    return require_ops_auth


def _raise_auth_required() -> None:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Ops authentication required",
        headers={"WWW-Authenticate": "Basic"},
    )


def _template_context(
    *,
    request: Request,
    config: RuntimeConfig,
    current_path: str,
    **extra: Any,
) -> dict[str, Any]:
    context = {
        "request": request,
        "site_code": config.site_code,
        "current_path": current_path,
        "ops_bind": f"{config.ops_bind_host}:{config.ops_port}",
        "nav_items": (
            ("/", "Dashboard"),
            ("/events", "Events"),
            ("/alerts", "Alerts"),
            ("/sources", "Sources"),
        ),
    }
    context.update(extra)
    return context


def _build_summary(
    *,
    events: tuple[EventRecord, ...],
    alerts: tuple[AlertRecord, ...],
    display_timestamps: bool = True,
) -> OpsSummary:
    timestamp_formatter = _format_dt_display if display_timestamps else _format_dt_iso
    return OpsSummary(
        total_events=len(events),
        total_alerts=len(alerts),
        active_alerts=sum(1 for alert in alerts if alert.state.startswith("active")),
        unique_sources=len({event.source_ip for event in events}),
        rejected_events=sum(1 for event in events if event.result == "rejected"),
        last_event_at=timestamp_formatter(events[-1].timestamp) if events else "none",
    )


def _filter_events(
    events: tuple[EventRecord, ...],
    *,
    event_type: str | None,
    source_ip: str | None,
    result: str | None,
) -> tuple[EventRecord, ...]:
    filtered = events
    if event_type:
        filtered = tuple(event for event in filtered if event.event_type == event_type)
    if source_ip:
        filtered = tuple(event for event in filtered if event.source_ip == source_ip)
    if result:
        filtered = tuple(event for event in filtered if event.result == result)
    return filtered


def _event_rows(events: tuple[EventRecord, ...]) -> tuple[EventRow, ...]:
    return tuple(
        EventRow(
            timestamp=_format_dt_display(event.timestamp),
            event_type=event.event_type,
            source_ip=event.source_ip,
            action=event.action,
            result=event.result,
            severity=event.severity,
            asset_id=event.asset_id,
            endpoint_or_register=event.endpoint_or_register or "",
            error_code=event.error_code or "",
            session_id=event.session_id or "",
            message=event.message or "",
            requested_value=_compact_json(event.requested_value),
        )
        for event in events
    )


def _alert_rows(alerts: tuple[AlertRecord, ...]) -> tuple[AlertRow, ...]:
    return tuple(
        AlertRow(
            created_at=_format_dt_display(alert.created_at),
            alarm_code=alert.alarm_code,
            severity=alert.severity,
            state=alert.state,
            asset_id=alert.asset_id,
            message=alert.message or "",
        )
        for alert in alerts
    )


def _source_rows(events: tuple[EventRecord, ...]) -> tuple[SourceRow, ...]:
    grouped: dict[str, list[EventRecord]] = defaultdict(list)
    for event in events:
        grouped[event.source_ip].append(event)

    rows: list[tuple[datetime, SourceRow]] = []
    for source_ip, source_events in grouped.items():
        event_type_counts = Counter(event.event_type for event in source_events)
        endpoint_counts = Counter(event.endpoint_or_register or "" for event in source_events)
        sessions = {event.session_id for event in source_events if event.session_id}
        last_seen = source_events[-1].timestamp
        rows.append(
            (
                last_seen,
                SourceRow(
                    source_ip=source_ip,
                    event_count=len(source_events),
                    rejected_count=sum(1 for event in source_events if event.result == "rejected"),
                    session_count=len(sessions),
                    first_seen=_format_dt_display(source_events[0].timestamp),
                    last_seen=_format_dt_display(last_seen),
                    top_event_type=event_type_counts.most_common(1)[0][0] if event_type_counts else "",
                    top_endpoint=endpoint_counts.most_common(1)[0][0] if endpoint_counts else "",
                ),
            )
        )
    return tuple(row for _, row in sorted(rows, key=lambda item: item[0], reverse=True))


def _format_dt_iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _format_dt_display(value: datetime) -> str:
    normalized = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return normalized.astimezone(UTC).strftime("%d.%m.%Y %H:%M:%S UTC")


def _compact_json(value: Any, *, max_length: int = 180) -> str:
    if value is None:
        return ""
    rendered = json.dumps(value, ensure_ascii=True, sort_keys=True)
    if len(rendered) <= max_length:
        return rendered
    return f"{rendered[: max_length - 3]}..."
