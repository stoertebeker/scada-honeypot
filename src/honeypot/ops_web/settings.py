"""Persistente Einstellungen fuer das interne Ops-Backend."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Mapping

from honeypot.storage import SQLiteEventStore


@dataclass(frozen=True, slots=True)
class OpsBackendSettings:
    ip_enrichment_enabled: bool = False
    ip_enrichment_rdns_enabled: bool = False
    ip_enrichment_static_map_path: str = ""
    ip_enrichment_country_mmdb_path: str = ""
    ip_enrichment_asn_mmdb_path: str = ""
    ip_enrichment_rdns_timeout_ms: int = 300
    events_default_limit: int = 100
    alerts_default_limit: int = 100
    sources_default_limit: int = 100
    login_campaign_aggregation_enabled: bool = True
    login_credential_capture_enabled: bool = True
    login_password_capture_enabled: bool = True
    login_password_display_enabled: bool = True
    login_credential_export_enabled: bool = True
    login_capture_sample_attempts: int = 5
    login_capture_summary_interval_seconds: int = 60
    login_campaign_idle_timeout_minutes: int = 10
    login_capture_max_unique_passwords: int = 1_000_000
    login_capture_max_credential_length: int = 256

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "OpsBackendSettings":
        defaults = asdict(cls())
        merged = {**defaults, **{key: values[key] for key in defaults.keys() & values.keys()}}
        return cls(
            ip_enrichment_enabled=_bool_value(merged["ip_enrichment_enabled"]),
            ip_enrichment_rdns_enabled=_bool_value(merged["ip_enrichment_rdns_enabled"]),
            ip_enrichment_static_map_path=_text_value(merged["ip_enrichment_static_map_path"]),
            ip_enrichment_country_mmdb_path=_text_value(merged["ip_enrichment_country_mmdb_path"]),
            ip_enrichment_asn_mmdb_path=_text_value(merged["ip_enrichment_asn_mmdb_path"]),
            ip_enrichment_rdns_timeout_ms=_int_value(
                merged["ip_enrichment_rdns_timeout_ms"],
                field_name="ip_enrichment_rdns_timeout_ms",
                minimum=50,
                maximum=5000,
            ),
            events_default_limit=_int_value(
                merged["events_default_limit"],
                field_name="events_default_limit",
                minimum=1,
                maximum=500,
            ),
            alerts_default_limit=_int_value(
                merged["alerts_default_limit"],
                field_name="alerts_default_limit",
                minimum=1,
                maximum=500,
            ),
            sources_default_limit=_int_value(
                merged["sources_default_limit"],
                field_name="sources_default_limit",
                minimum=1,
                maximum=500,
            ),
            login_campaign_aggregation_enabled=_bool_value(merged["login_campaign_aggregation_enabled"]),
            login_credential_capture_enabled=_bool_value(merged["login_credential_capture_enabled"]),
            login_password_capture_enabled=_bool_value(merged["login_password_capture_enabled"]),
            login_password_display_enabled=_bool_value(merged["login_password_display_enabled"]),
            login_credential_export_enabled=_bool_value(merged["login_credential_export_enabled"]),
            login_capture_sample_attempts=_int_value(
                merged["login_capture_sample_attempts"],
                field_name="login_capture_sample_attempts",
                minimum=0,
                maximum=100,
            ),
            login_capture_summary_interval_seconds=_int_value(
                merged["login_capture_summary_interval_seconds"],
                field_name="login_capture_summary_interval_seconds",
                minimum=10,
                maximum=3600,
            ),
            login_campaign_idle_timeout_minutes=_int_value(
                merged["login_campaign_idle_timeout_minutes"],
                field_name="login_campaign_idle_timeout_minutes",
                minimum=1,
                maximum=1440,
            ),
            login_capture_max_unique_passwords=_int_value(
                merged["login_capture_max_unique_passwords"],
                field_name="login_capture_max_unique_passwords",
                minimum=0,
                maximum=1_000_000,
            ),
            login_capture_max_credential_length=_int_value(
                merged["login_capture_max_credential_length"],
                field_name="login_capture_max_credential_length",
                minimum=1,
                maximum=1024,
            ),
        )

    @classmethod
    def from_form(cls, values: Mapping[str, list[str]]) -> "OpsBackendSettings":
        defaults = cls()
        raw = {
            "ip_enrichment_enabled": "ip_enrichment_enabled" in values,
            "ip_enrichment_rdns_enabled": "ip_enrichment_rdns_enabled" in values,
            "ip_enrichment_static_map_path": _first_form_value(values, "ip_enrichment_static_map_path"),
            "ip_enrichment_country_mmdb_path": _first_form_value(values, "ip_enrichment_country_mmdb_path"),
            "ip_enrichment_asn_mmdb_path": _first_form_value(values, "ip_enrichment_asn_mmdb_path"),
            "ip_enrichment_rdns_timeout_ms": _first_form_value(values, "ip_enrichment_rdns_timeout_ms"),
            "events_default_limit": _first_form_value(values, "events_default_limit"),
            "alerts_default_limit": _first_form_value(values, "alerts_default_limit"),
            "sources_default_limit": _first_form_value(values, "sources_default_limit"),
            "login_campaign_aggregation_enabled": "login_campaign_aggregation_enabled" in values,
            "login_credential_capture_enabled": "login_credential_capture_enabled" in values,
            "login_password_capture_enabled": "login_password_capture_enabled" in values,
            "login_password_display_enabled": "login_password_display_enabled" in values,
            "login_credential_export_enabled": "login_credential_export_enabled" in values,
            "login_capture_sample_attempts": _first_form_value(
                values,
                "login_capture_sample_attempts",
                str(defaults.login_capture_sample_attempts),
            ),
            "login_capture_summary_interval_seconds": _first_form_value(
                values,
                "login_capture_summary_interval_seconds",
                str(defaults.login_capture_summary_interval_seconds),
            ),
            "login_campaign_idle_timeout_minutes": _first_form_value(
                values,
                "login_campaign_idle_timeout_minutes",
                str(defaults.login_campaign_idle_timeout_minutes),
            ),
            "login_capture_max_unique_passwords": _first_form_value(
                values,
                "login_capture_max_unique_passwords",
                str(defaults.login_capture_max_unique_passwords),
            ),
            "login_capture_max_credential_length": _first_form_value(
                values,
                "login_capture_max_credential_length",
                str(defaults.login_capture_max_credential_length),
            ),
        }
        return cls.from_mapping(raw)

    def to_mapping(self) -> dict[str, Any]:
        return asdict(self)


def load_ops_settings(store: SQLiteEventStore) -> OpsBackendSettings:
    return OpsBackendSettings.from_mapping(store.fetch_ops_settings())


def save_ops_settings(store: SQLiteEventStore, settings: OpsBackendSettings, *, updated_at: datetime) -> None:
    store.upsert_ops_settings(settings.to_mapping(), updated_at=updated_at)


def changed_settings(before: OpsBackendSettings, after: OpsBackendSettings) -> dict[str, dict[str, Any]]:
    before_values = before.to_mapping()
    after_values = after.to_mapping()
    return {
        key: {"before": before_values[key], "after": after_values[key]}
        for key in before_values
        if before_values[key] != after_values[key]
    }


def _first_form_value(values: Mapping[str, list[str]], key: str, default: str = "") -> str:
    collected = values.get(key)
    if not collected:
        return default
    return collected[0]


def _bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _text_value(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("text settings muessen Strings sein")
    return value.strip()


def _int_value(value: Any, *, field_name: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} muss eine Ganzzahl sein") from exc
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{field_name} muss zwischen {minimum} und {maximum} liegen")
    return parsed
