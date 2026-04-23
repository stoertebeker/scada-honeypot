from pathlib import Path

import pytest

from honeypot.config_core import RuntimeConfig
from honeypot.exporter_runner import WebhookExporter
from honeypot.runtime_exposure import (
    append_exposed_research_finding,
    enforce_exposed_research_policy,
    planned_public_ingress_mappings,
)


def _config(monkeypatch, tmp_path: Path, **kwargs) -> RuntimeConfig:
    locale_dir = tmp_path / "resources" / "locales" / "attacker-ui"
    locale_dir.mkdir(parents=True, exist_ok=True)
    (locale_dir / "en.json").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return RuntimeConfig(_env_file=None, **kwargs)


def test_planned_public_ingress_mappings_normalize_unique_entries(monkeypatch, tmp_path: Path) -> None:
    config = _config(
        monkeypatch,
        tmp_path,
        public_ingress_mappings="MODBUS:502:1502,hmi:80:8080,modbus:502:1502",
    )

    mappings = planned_public_ingress_mappings(config)

    assert tuple(mapping.spec for mapping in mappings) == (
        "modbus:502:1502",
        "hmi:80:8080",
    )


def test_exposed_research_policy_rejects_missing_operator_roles(monkeypatch, tmp_path: Path) -> None:
    config = _config(
        monkeypatch,
        tmp_path,
        exposed_research_enabled=True,
        allow_nonlocal_bind=True,
        modbus_bind_host="0.0.0.0",
        hmi_bind_host="0.0.0.0",
        public_ingress_mappings="modbus:502:1502,hmi:80:8080",
    )

    with pytest.raises(RuntimeError, match="WATCH_OFFICER_NAME"):
        enforce_exposed_research_policy(config=config, exporters={})


def test_exposed_research_policy_rejects_placeholder_webhook_targets(monkeypatch, tmp_path: Path) -> None:
    config = _config(
        monkeypatch,
        tmp_path,
        exposed_research_enabled=True,
        allow_nonlocal_bind=True,
        modbus_bind_host="0.0.0.0",
        hmi_bind_host="0.0.0.0",
        public_ingress_mappings="modbus:502:1502,hmi:80:8080",
        watch_officer_name="blue-watch",
        duty_engineer_name="ops-duty",
        approved_egress_recipients="webhook:observer-collector",
    )

    with pytest.raises(RuntimeError, match="Dokumentations- oder Platzhalterziele"):
        enforce_exposed_research_policy(
            config=config,
            exporters={"webhook": WebhookExporter(url="https://198.51.100.42/honeypot-ingest")},
        )


def test_exposed_research_policy_accepts_named_roles_recipients_and_realistic_targets(
    monkeypatch,
    tmp_path: Path,
) -> None:
    config = _config(
        monkeypatch,
        tmp_path,
        exposed_research_enabled=True,
        allow_nonlocal_bind=True,
        modbus_bind_host="0.0.0.0",
        hmi_bind_host="0.0.0.0",
        modbus_port=1502,
        hmi_port=8080,
        public_ingress_mappings="modbus:502:1502,hmi:80:8080",
        watch_officer_name="blue-watch",
        duty_engineer_name="ops-duty",
        approved_egress_recipients="webhook:observer-collector-live",
    )

    approved = enforce_exposed_research_policy(
        config=config,
        exporters={"webhook": WebhookExporter(url="https://collector.ops.lab/honeypot-ingest")},
    )

    assert approved == (
        "hmi:80:8080",
        "modbus:502:1502",
    )


def test_append_exposed_research_finding_writes_actionable_markdown(monkeypatch, tmp_path: Path) -> None:
    findings_path = tmp_path / "logs" / "findings.md"
    config = _config(
        monkeypatch,
        tmp_path,
        site_code="site-exposed-01",
        findings_log_path=findings_path,
        watch_officer_name="blue-watch",
        duty_engineer_name="ops-duty",
        public_ingress_mappings="modbus:502:1502,hmi:80:8080",
        approved_egress_recipients="webhook:observer-collector-live",
    )

    written_path = append_exposed_research_finding(
        config=config,
        status="passed",
        summary="smoke run ok",
        details=("modbus_address=127.0.0.1:1502",),
    )

    content = written_path.read_text(encoding="utf-8")

    assert written_path == findings_path
    assert "# Exposed Research Findings" in content
    assert "verify-exposed-research passed" in content
    assert "`site-exposed-01`" in content
    assert "`blue-watch`" in content
    assert "`ops-duty`" in content
    assert "modbus:502:1502, hmi:80:8080" in content
    assert "observer-collector-live" in content
