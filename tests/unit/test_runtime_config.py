from pathlib import Path

import pytest
from pydantic import ValidationError

from honeypot.config_core import RuntimeConfig, load_runtime_config


def write_locale_bundle(root: Path, locale: str) -> None:
    locale_dir = root / "resources" / "locales" / "attacker-ui"
    locale_dir.mkdir(parents=True, exist_ok=True)
    (locale_dir / f"{locale}.json").write_text("{}", encoding="utf-8")


def test_runtime_config_loads_documented_defaults(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    config = RuntimeConfig(_env_file=None)

    assert config.site_name == "Solar Field A"
    assert config.enable_service_login is True
    assert config.enable_tracker is False
    assert config.modbus_port == 1502
    assert config.modbus_response_delay_min_ms == 0
    assert config.modbus_response_delay_max_ms == 0
    assert config.modbus_max_connections == 64
    assert config.modbus_max_connections_per_source == 8
    assert config.modbus_proxy_protocol_enabled is False
    assert config.ops_enabled is True
    assert config.ops_bind_host == "127.0.0.1"
    assert config.ops_port == 9090
    assert config.ops_basic_auth_enabled is False
    assert config.ops_basic_auth_username is None
    assert config.ops_basic_auth_password is None
    assert config.allow_nonlocal_bind is False
    assert config.attacker_ui_locale_resolution_chain == ("en",)
    assert config.event_store_backend == "sqlite"
    assert config.evidence_max_age_days == 30
    assert config.evidence_max_event_rows == 250_000
    assert config.evidence_max_event_rows_per_source == 25_000
    assert config.evidence_max_database_bytes == 512 * 1024 * 1024
    assert config.evidence_reserved_health_bytes == 16 * 1024 * 1024
    assert config.evidence_min_free_bytes == 256 * 1024 * 1024
    assert config.jsonl_archive_max_file_bytes == 64 * 1024 * 1024
    assert config.jsonl_archive_max_total_bytes == 512 * 1024 * 1024
    assert config.runtime_status_enabled is False
    assert config.runtime_status_interval_seconds == 5
    assert config.approved_egress_targets == ()
    assert config.approved_ingress_bindings == ()
    assert config.honeypot_local_debug is False
    assert config.hmi_cookie_secure is False
    assert config.service_cookie_secure is False
    assert config.forwarded_header_enabled is False
    assert config.trusted_proxy_cidrs == ()
    assert config.approved_egress_recipients == ()
    assert config.public_ingress_mappings == ()
    assert config.watch_officer_name is None
    assert config.duty_engineer_name is None
    assert config.weather_provider == "disabled"
    assert config.weather_latitude is None
    assert config.weather_longitude is None
    assert config.weather_elevation_m is None
    assert config.weather_refresh_seconds == 900
    assert config.weather_cache_ttl_seconds == 900
    assert config.weather_request_timeout_seconds == 10


def test_load_runtime_config_reads_env_file(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    env_file = tmp_path / ".env"
    env_file.write_text(
        (
            "SITE_CODE=test-77\n"
            "MODBUS_PORT=1502\n"
            "MODBUS_RESPONSE_DELAY_MIN_MS=25\n"
            "MODBUS_RESPONSE_DELAY_MAX_MS=80\n"
            "MODBUS_PROXY_PROTOCOL_ENABLED=1\n"
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    config = load_runtime_config(env_file=env_file)

    assert config.site_code == "test-77"
    assert config.modbus_port == 1502
    assert config.modbus_response_delay_min_ms == 25
    assert config.modbus_response_delay_max_ms == 80
    assert config.modbus_proxy_protocol_enabled is True


def test_invalid_locale_code_is_rejected(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError):
        RuntimeConfig(_env_file=None, attacker_ui_locale="english")


def test_missing_fallback_locale_bundle_is_rejected(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError):
        RuntimeConfig(_env_file=None)


def test_regional_locale_can_fall_back_to_base_bundle(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    config = RuntimeConfig(_env_file=None, attacker_ui_locale="en-US")

    assert config.attacker_ui_locale_resolution_chain == ("en-US", "en")


def test_disabled_exporters_do_not_require_targets(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    config = RuntimeConfig(
        _env_file=None,
        webhook_exporter_enabled=False,
        webhook_exporter_url="",
        smtp_exporter_enabled=False,
        smtp_host="",
        smtp_from="",
        smtp_to="",
        telegram_exporter_enabled=False,
        telegram_bot_token="",
        telegram_chat_id="",
    )

    assert config.webhook_exporter_url is None
    assert config.smtp_host is None
    assert config.smtp_from is None
    assert config.telegram_bot_token is None


def test_enabled_webhook_exporter_requires_url(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError):
        RuntimeConfig(_env_file=None, webhook_exporter_enabled=True, webhook_exporter_url="")


def test_enabled_ops_basic_auth_requires_credentials(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError):
        RuntimeConfig(_env_file=None, ops_basic_auth_enabled=True)


def test_enabled_smtp_exporter_requires_host_from_and_to(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError):
        RuntimeConfig(
            _env_file=None,
            smtp_exporter_enabled=True,
            smtp_host="",
            smtp_from="alerts@example.invalid",
            smtp_to="soc@example.invalid",
        )


def test_runtime_status_interval_must_be_positive(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError):
        RuntimeConfig(_env_file=None, runtime_status_interval_seconds=0)


@pytest.mark.parametrize(
    ("overrides", "message"),
    (
        (
            {"evidence_max_event_rows": 10, "evidence_max_event_rows_per_source": 11},
            "EVIDENCE_MAX_EVENT_ROWS_PER_SOURCE",
        ),
        (
            {"evidence_max_campaign_rows": 10, "evidence_max_campaign_rows_per_source": 11},
            "EVIDENCE_MAX_CAMPAIGN_ROWS_PER_SOURCE",
        ),
        (
            {
                "evidence_max_unique_usernames": 10,
                "evidence_max_unique_usernames_per_source": 11,
            },
            "EVIDENCE_MAX_UNIQUE_USERNAMES_PER_SOURCE",
        ),
        (
            {
                "jsonl_archive_max_file_bytes": 4096,
                "jsonl_archive_max_total_bytes": 2048,
            },
            "JSONL_ARCHIVE_MAX_FILE_BYTES",
        ),
    ),
)
def test_runtime_config_rejects_inverted_evidence_limits(
    monkeypatch,
    tmp_path: Path,
    overrides: dict[str, int],
    message: str,
) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError, match=message):
        RuntimeConfig(_env_file=None, **overrides)


def test_runtime_config_normalizes_approved_egress_targets(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    config = RuntimeConfig(
        _env_file=None,
        approved_egress_targets="WEBHOOK:example.invalid:443, smtp:mail.example.invalid:25, webhook:example.invalid:443",
    )

    assert config.approved_egress_targets == (
        "webhook:example.invalid:443",
        "smtp:mail.example.invalid:25",
    )


def test_runtime_config_normalizes_approved_ingress_bindings(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    config = RuntimeConfig(
        _env_file=None,
        approved_ingress_bindings="MODBUS:0.0.0.0:1502, hmi:0.0.0.0:8080, modbus:0.0.0.0:1502",
    )

    assert config.approved_ingress_bindings == (
        "modbus:0.0.0.0:1502",
        "hmi:0.0.0.0:8080",
    )


def test_runtime_config_normalizes_exposure_metadata(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    config = RuntimeConfig(
        _env_file=None,
        approved_egress_recipients="WEBHOOK:observer-collector, webhook:observer-collector, smtp:soc-mail",
        public_ingress_mappings="MODBUS:502:1502, hmi:80:8080, modbus:502:1502",
        watch_officer_name="  blue-watch  ",
        duty_engineer_name="  ops-duty  ",
    )

    assert config.approved_egress_recipients == (
        "webhook:observer-collector",
        "smtp:soc-mail",
    )
    assert config.public_ingress_mappings == (
        "modbus:502:1502",
        "hmi:80:8080",
    )
    assert config.watch_officer_name == "blue-watch"
    assert config.duty_engineer_name == "ops-duty"


def test_runtime_config_rejects_local_debug_with_nonlocal_binds(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError, match="HONEYPOT_LOCAL_DEBUG"):
        RuntimeConfig(
            _env_file=None,
            honeypot_local_debug=True,
            modbus_bind_host="0.0.0.0",
        )

    with pytest.raises(ValidationError, match="HONEYPOT_LOCAL_DEBUG"):
        RuntimeConfig(
            _env_file=None,
            honeypot_local_debug=True,
            allow_nonlocal_bind=True,
        )


def test_runtime_config_reads_nonlocal_bind_gate(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    config = RuntimeConfig(_env_file=None, allow_nonlocal_bind=True)

    assert config.allow_nonlocal_bind is True


def test_runtime_config_rejects_invalid_modbus_timing_profile(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError, match="MODBUS_RESPONSE_DELAY_MIN_MS"):
        RuntimeConfig(
            _env_file=None,
            modbus_response_delay_min_ms=80,
            modbus_response_delay_max_ms=25,
        )

    with pytest.raises(ValidationError):
        RuntimeConfig(_env_file=None, modbus_response_delay_max_ms=2001)


def test_runtime_config_rejects_invalid_modbus_connection_limits(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError, match="MODBUS_MAX_CONNECTIONS_PER_SOURCE"):
        RuntimeConfig(
            _env_file=None,
            modbus_max_connections=4,
            modbus_max_connections_per_source=5,
        )

    with pytest.raises(ValidationError):
        RuntimeConfig(_env_file=None, modbus_max_connections=0)


def test_runtime_config_reads_cookie_secure_flags(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    env_file = tmp_path / ".env"
    env_file.write_text(
        "HMI_COOKIE_SECURE=1\nSERVICE_COOKIE_SECURE=1\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    config = load_runtime_config(env_file=env_file)

    assert config.hmi_cookie_secure is True
    assert config.service_cookie_secure is True


def test_runtime_config_normalizes_trusted_proxy_cidrs(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    config = RuntimeConfig(
        _env_file=None,
        forwarded_header_enabled=True,
        trusted_proxy_cidrs="10.14.0.53/32, 127.0.0.1/32, 10.14.0.53/32",
    )

    assert config.forwarded_header_enabled is True
    assert config.trusted_proxy_cidrs == ("10.14.0.53/32", "127.0.0.1/32")


def test_runtime_config_rejects_forwarded_headers_without_trusted_proxies(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError):
        RuntimeConfig(_env_file=None, forwarded_header_enabled=True)


def test_runtime_config_rejects_wildcard_trusted_proxy_cidr(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError):
        RuntimeConfig(_env_file=None, trusted_proxy_cidrs="0.0.0.0/0")


def test_weather_coordinates_require_valid_ranges(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError):
        RuntimeConfig(_env_file=None, weather_latitude=91)
    with pytest.raises(ValidationError):
        RuntimeConfig(_env_file=None, weather_longitude=181)
    with pytest.raises(ValidationError):
        RuntimeConfig(_env_file=None, weather_latitude=52.5, weather_longitude=None)


def test_open_meteo_provider_requires_coordinates_when_enabled(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError):
        RuntimeConfig(_env_file=None, weather_provider="open_meteo_forecast")


def test_deterministic_weather_provider_can_run_without_coordinates(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    config = RuntimeConfig(
        _env_file=None,
        weather_provider="deterministic",
        weather_refresh_seconds=600,
        weather_cache_ttl_seconds=300,
    )

    assert config.weather_provider == "deterministic"
    assert config.weather_latitude is None
    assert config.weather_longitude is None
    assert config.weather_refresh_seconds == 600
    assert config.weather_cache_ttl_seconds == 300
