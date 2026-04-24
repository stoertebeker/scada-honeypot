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
    assert config.allow_nonlocal_bind is False
    assert config.attacker_ui_locale_resolution_chain == ("en",)
    assert config.event_store_backend == "sqlite"
    assert config.runtime_status_enabled is False
    assert config.runtime_status_interval_seconds == 5
    assert config.approved_egress_targets == ()
    assert config.approved_ingress_bindings == ()
    assert config.exposed_research_enabled is False
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
    env_file.write_text("SITE_CODE=test-77\nMODBUS_PORT=1502\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    config = load_runtime_config(env_file=env_file)

    assert config.site_code == "test-77"
    assert config.modbus_port == 1502


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
        exposed_research_enabled=True,
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
    assert config.exposed_research_enabled is True


def test_runtime_config_reads_nonlocal_bind_gate(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    config = RuntimeConfig(_env_file=None, allow_nonlocal_bind=True)

    assert config.allow_nonlocal_bind is True


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
