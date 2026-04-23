from pathlib import Path

import pytest

from honeypot.config_core import RuntimeConfig
from honeypot.runtime_ingress import enforce_runtime_ingress_policy, planned_ingress_bindings


def write_locale_bundle(root: Path, locale: str) -> None:
    locale_dir = root / "resources" / "locales" / "attacker-ui"
    locale_dir.mkdir(parents=True, exist_ok=True)
    (locale_dir / f"{locale}.json").write_text("{}", encoding="utf-8")


def test_planned_ingress_bindings_include_only_nonlocal_services() -> None:
    bindings = planned_ingress_bindings(
        modbus_bind_host="0.0.0.0",
        modbus_port=1502,
        hmi_bind_host="127.0.0.1",
        hmi_port=8080,
    )

    assert tuple(binding.spec for binding in bindings) == ("modbus:0.0.0.0:1502",)


def test_enforce_runtime_ingress_policy_rejects_missing_bind_approvals(tmp_path: Path, monkeypatch) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)
    config = RuntimeConfig(
        _env_file=None,
        allow_nonlocal_bind=True,
        modbus_bind_host="0.0.0.0",
        hmi_bind_host="0.0.0.0",
    )

    with pytest.raises(RuntimeError, match="APPROVED_INGRESS_BINDINGS"):
        enforce_runtime_ingress_policy(config=config, modbus_port=1502, hmi_port=8080)


def test_enforce_runtime_ingress_policy_accepts_explicit_bind_approvals(tmp_path: Path, monkeypatch) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)
    config = RuntimeConfig(
        _env_file=None,
        allow_nonlocal_bind=True,
        modbus_bind_host="0.0.0.0",
        hmi_bind_host="0.0.0.0",
        approved_ingress_bindings="modbus:0.0.0.0:1502,hmi:0.0.0.0:8080",
    )

    approved_bindings = enforce_runtime_ingress_policy(
        config=config,
        modbus_port=1502,
        hmi_port=8080,
    )

    assert approved_bindings == ("modbus:0.0.0.0:1502", "hmi:0.0.0.0:8080")
