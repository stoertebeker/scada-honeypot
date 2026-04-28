"""Laden und Validieren der Runtime-Konfiguration fuer Phase A."""

from __future__ import annotations

from ipaddress import ip_network
import re
from pathlib import Path
from typing import Annotated
from typing import Literal

from pydantic import AnyUrl, Field, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

LOCALE_PATTERN = re.compile(r"^[a-z]{2}(?:-[A-Z]{2})?$")
ATTACKER_UI_LOCALE_DIR = Path("resources/locales/attacker-ui")


def _normalize_optional_string(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return str(value)


def _normalize_string_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        raw_items = value.split(",")
    elif isinstance(value, tuple | list | set | frozenset):
        raw_items = list(value)
    else:
        raw_items = [value]

    normalized_items: list[str] = []
    for item in raw_items:
        normalized = _normalize_optional_string(item)
        if normalized is None:
            continue
        lowered = normalized.lower()
        if lowered not in normalized_items:
            normalized_items.append(lowered)
    return tuple(normalized_items)


def _locale_resolution_chain(locale: str, fallback_locale: str) -> tuple[str, ...]:
    candidates: list[str] = [locale]
    if "-" in locale:
        base_locale = locale.split("-", 1)[0]
        if base_locale not in candidates:
            candidates.append(base_locale)
    if fallback_locale not in candidates:
        candidates.append(fallback_locale)
    return tuple(candidates)


class RuntimeConfig(BaseSettings):
    """Normalisierte und validierte Laufzeitkonfiguration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    site_name: str = "Solar Field A"
    site_code: str = "site-01"
    operator_name: str = "Regional Energy Services"
    hmi_title: str = "Solar Park Operations"
    timezone: str = "Europe/Berlin"
    attacker_ui_locale: str = "en"
    attacker_ui_fallback_locale: str = "en"

    capacity_mw: float = Field(default=6.5, gt=0)
    inverter_block_count: int = Field(default=3, ge=1, le=32)
    enable_tracker: bool = False
    default_power_limit_pct: int = Field(default=100, ge=0, le=100)
    alarm_threshold_low_output_pct: int = Field(default=35, ge=0, le=100)
    weather_provider: Literal["disabled", "deterministic", "open_meteo_forecast", "open_meteo_satellite"] = "disabled"
    weather_latitude: float | None = None
    weather_longitude: float | None = None
    weather_elevation_m: float | None = None
    weather_refresh_seconds: int = Field(default=900, ge=1, le=86400)
    weather_cache_ttl_seconds: int = Field(default=900, ge=0, le=86400)
    weather_request_timeout_seconds: int = Field(default=10, ge=1, le=300)

    modbus_bind_host: str = "127.0.0.1"
    modbus_port: int = Field(default=1502, ge=1, le=65535)
    hmi_bind_host: str = "127.0.0.1"
    hmi_port: int = Field(default=8080, ge=1, le=65535)
    ops_enabled: bool = True
    ops_bind_host: str = "127.0.0.1"
    ops_port: int = Field(default=9090, ge=1, le=65535)
    ops_basic_auth_enabled: bool = False
    ops_basic_auth_username: str | None = None
    ops_basic_auth_password: str | None = None
    allow_nonlocal_bind: bool = False
    exposed_research_enabled: bool = False
    enable_service_login: bool = True
    hmi_cookie_secure: bool = False
    service_cookie_secure: bool = False
    forwarded_header_enabled: bool = False
    trusted_proxy_cidrs: Annotated[tuple[str, ...], NoDecode] = ()

    event_store_backend: Literal["sqlite"] = "sqlite"
    event_store_path: Path = Path("./tmp/honeypot-events.db")
    jsonl_archive_enabled: bool = True
    jsonl_archive_path: Path = Path("./logs/events.jsonl")
    runtime_status_enabled: bool = False
    runtime_status_path: Path = Path("./logs/runtime-status.json")
    runtime_status_interval_seconds: int = Field(default=5, ge=1, le=3600)
    pcap_capture_enabled: bool = False
    pcap_capture_path: Path = Path("./pcap/session.pcapng")
    alert_min_severity: Literal["low", "medium", "high", "critical"] = "medium"
    outbox_batch_size: int = Field(default=50, ge=1, le=1000)
    outbox_retry_backoff_seconds: int = Field(default=30, ge=1, le=86400)

    webhook_exporter_enabled: bool = False
    webhook_exporter_url: AnyUrl | None = None
    smtp_exporter_enabled: bool = False
    smtp_host: str | None = None
    smtp_port: int = Field(default=25, ge=1, le=65535)
    smtp_from: str | None = None
    smtp_to: str | None = None
    telegram_exporter_enabled: bool = False
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    approved_egress_targets: Annotated[tuple[str, ...], NoDecode] = ()
    approved_ingress_bindings: Annotated[tuple[str, ...], NoDecode] = ()
    approved_egress_recipients: Annotated[tuple[str, ...], NoDecode] = ()
    public_ingress_mappings: Annotated[tuple[str, ...], NoDecode] = ()
    watch_officer_name: str | None = None
    duty_engineer_name: str | None = None
    findings_log_path: Path = Path("./logs/findings.md")

    log_level: Literal["debug", "info", "warning", "error", "critical"] = "info"
    trend_window_minutes: int = Field(default=180, ge=1, le=1440)
    alarm_page_size: int = Field(default=25, ge=1, le=500)

    @field_validator(
        "site_name",
        "site_code",
        "operator_name",
        "hmi_title",
        "timezone",
        "modbus_bind_host",
        "hmi_bind_host",
        "ops_bind_host",
        mode="before",
    )
    @classmethod
    def validate_required_strings(cls, value: object) -> str:
        normalized = _normalize_optional_string(value)
        if normalized is None:
            raise ValueError("darf nicht leer sein")
        return normalized

    @field_validator(
        "webhook_exporter_url",
        "smtp_host",
        "smtp_from",
        "smtp_to",
        "telegram_bot_token",
        "telegram_chat_id",
        "ops_basic_auth_username",
        "ops_basic_auth_password",
        "watch_officer_name",
        "duty_engineer_name",
        mode="before",
    )
    @classmethod
    def normalize_optional_strings(cls, value: object) -> str | None:
        return _normalize_optional_string(value)

    @field_validator("weather_latitude", "weather_longitude", "weather_elevation_m", mode="before")
    @classmethod
    def normalize_optional_floats(cls, value: object) -> float | None:
        normalized = _normalize_optional_string(value)
        if normalized is None:
            return None
        try:
            return float(normalized)
        except ValueError as exc:
            raise ValueError("muss numerisch sein") from exc

    @field_validator(
        "approved_egress_targets",
        "approved_ingress_bindings",
        "approved_egress_recipients",
        "public_ingress_mappings",
        "trusted_proxy_cidrs",
        mode="before",
    )
    @classmethod
    def normalize_string_tuple_settings(cls, value: object) -> tuple[str, ...]:
        return _normalize_string_tuple(value)

    @field_validator("attacker_ui_locale", "attacker_ui_fallback_locale")
    @classmethod
    def validate_locale_code(cls, value: str) -> str:
        if not LOCALE_PATTERN.fullmatch(value):
            raise ValueError("muss dem Muster ll oder ll-RR folgen")
        return value

    @model_validator(mode="after")
    def validate_locale_bundles(self) -> "RuntimeConfig":
        fallback_bundle = ATTACKER_UI_LOCALE_DIR / f"{self.attacker_ui_fallback_locale}.json"
        if not fallback_bundle.is_file():
            raise ValueError(
                "ATTACKER_UI_FALLBACK_LOCALE muss auf ein vorhandenes Locale-Paket zeigen"
            )

        resolution_chain = self.attacker_ui_locale_resolution_chain
        if not any((ATTACKER_UI_LOCALE_DIR / f"{locale}.json").is_file() for locale in resolution_chain):
            raise ValueError(
                "ATTACKER_UI_LOCALE muss ueber ll-RR -> ll -> ATTACKER_UI_FALLBACK_LOCALE aufloesbar sein"
            )
        return self

    @model_validator(mode="after")
    def validate_trusted_proxy_settings(self) -> "RuntimeConfig":
        for raw_cidr in self.trusted_proxy_cidrs:
            try:
                network = ip_network(raw_cidr, strict=False)
            except ValueError as exc:
                raise ValueError(f"TRUSTED_PROXY_CIDRS enthaelt ein ungueltiges CIDR: {raw_cidr}") from exc
            if network.prefixlen == 0:
                raise ValueError("TRUSTED_PROXY_CIDRS darf keine Wildcard-Netze wie 0.0.0.0/0 oder ::/0 enthalten")
        if self.forwarded_header_enabled and not self.trusted_proxy_cidrs:
            raise ValueError("TRUSTED_PROXY_CIDRS ist erforderlich, wenn FORWARDED_HEADER_ENABLED aktiv ist")
        return self

    @model_validator(mode="after")
    def validate_ops_auth_requirements(self) -> "RuntimeConfig":
        if self.ops_basic_auth_enabled and (
            self.ops_basic_auth_username is None or self.ops_basic_auth_password is None
        ):
            raise ValueError(
                "OPS_BASIC_AUTH_USERNAME und OPS_BASIC_AUTH_PASSWORD sind erforderlich, "
                "wenn OPS_BASIC_AUTH_ENABLED aktiv ist"
            )
        return self

    @model_validator(mode="after")
    def validate_exporter_requirements(self) -> "RuntimeConfig":
        if self.webhook_exporter_enabled and self.webhook_exporter_url is None:
            raise ValueError("WEBHOOK_EXPORTER_URL ist erforderlich, wenn der Webhook-Exporter aktiv ist")
        if self.smtp_exporter_enabled and (
            self.smtp_host is None or self.smtp_from is None or self.smtp_to is None
        ):
            raise ValueError("SMTP_HOST, SMTP_FROM und SMTP_TO sind erforderlich, wenn der SMTP-Exporter aktiv ist")
        if self.telegram_exporter_enabled and (
            self.telegram_bot_token is None or self.telegram_chat_id is None
        ):
            raise ValueError(
                "TELEGRAM_BOT_TOKEN und TELEGRAM_CHAT_ID sind erforderlich, wenn der Telegram-Exporter aktiv ist"
            )
        return self

    @model_validator(mode="after")
    def validate_weather_settings(self) -> "RuntimeConfig":
        if self.weather_latitude is not None and not -90 <= self.weather_latitude <= 90:
            raise ValueError("WEATHER_LATITUDE muss im Bereich -90..90 liegen")
        if self.weather_longitude is not None and not -180 <= self.weather_longitude <= 180:
            raise ValueError("WEATHER_LONGITUDE muss im Bereich -180..180 liegen")
        if self.weather_elevation_m is not None and not -500 <= self.weather_elevation_m <= 9000:
            raise ValueError("WEATHER_ELEVATION_M muss im Bereich -500..9000 liegen")
        if (self.weather_latitude is None) != (self.weather_longitude is None):
            raise ValueError("WEATHER_LATITUDE und WEATHER_LONGITUDE muessen gemeinsam gesetzt werden")
        if self.weather_provider in {"open_meteo_forecast", "open_meteo_satellite"} and (
            self.weather_latitude is None or self.weather_longitude is None
        ):
            raise ValueError(
                "WEATHER_LATITUDE und WEATHER_LONGITUDE sind erforderlich, wenn ein Open-Meteo-Provider aktiv ist"
            )
        if self.weather_cache_ttl_seconds > self.weather_refresh_seconds:
            raise ValueError("WEATHER_CACHE_TTL_SECONDS darf WEATHER_REFRESH_SECONDS nicht ueberschreiten")
        return self

    @property
    def attacker_ui_locale_resolution_chain(self) -> tuple[str, ...]:
        return _locale_resolution_chain(self.attacker_ui_locale, self.attacker_ui_fallback_locale)


def load_runtime_config(*, env_file: str | Path | None = ".env") -> RuntimeConfig:
    """Laedt die Konfiguration aus `.env` und Umgebungsvariablen."""

    try:
        return RuntimeConfig(_env_file=env_file)
    except ValidationError as exc:  # pragma: no cover - direkte Weitergabe mit klarer Runtime-Message
        raise RuntimeError(f"ungueltige Runtime-Konfiguration: {exc}") from exc
