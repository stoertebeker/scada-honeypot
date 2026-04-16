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
    assert config.attacker_ui_locale_resolution_chain == ("en",)
    assert config.event_store_backend == "sqlite"


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
        smtp_from="",
        smtp_to="",
        telegram_exporter_enabled=False,
        telegram_bot_token="",
        telegram_chat_id="",
    )

    assert config.webhook_exporter_url is None
    assert config.smtp_from is None
    assert config.telegram_bot_token is None


def test_enabled_webhook_exporter_requires_url(monkeypatch, tmp_path: Path) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError):
        RuntimeConfig(_env_file=None, webhook_exporter_enabled=True, webhook_exporter_url="")
