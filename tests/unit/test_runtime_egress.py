from pathlib import Path

import pytest

from honeypot.config_core import RuntimeConfig
from honeypot.exporter_runner import SmtpExporter, TelegramExporter, WebhookExporter
from honeypot.runtime_egress import enforce_runtime_egress_policy, planned_egress_targets


def write_locale_bundle(root: Path, locale: str) -> None:
    locale_dir = root / "resources" / "locales" / "attacker-ui"
    locale_dir.mkdir(parents=True, exist_ok=True)
    (locale_dir / f"{locale}.json").write_text("{}", encoding="utf-8")


def test_planned_egress_targets_normalize_exporter_destinations(tmp_path: Path, monkeypatch) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)

    targets = planned_egress_targets(
        {
            "webhook": WebhookExporter(url="https://example.invalid/hook"),
            "smtp": SmtpExporter(
                host="mail.example.invalid",
                port=2525,
                mail_from="alerts@example.invalid",
                rcpt_to="soc@example.invalid",
            ),
            "telegram": TelegramExporter(bot_token="token-1", chat_id="chat-9"),
        }
    )

    assert tuple(target.spec for target in targets) == (
        "webhook:example.invalid:443",
        "smtp:mail.example.invalid:2525",
        "telegram:api.telegram.org:443",
    )


def test_enforce_runtime_egress_policy_rejects_unapproved_targets(tmp_path: Path, monkeypatch) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)
    config = RuntimeConfig(_env_file=None)

    with pytest.raises(RuntimeError, match="APPROVED_EGRESS_TARGETS"):
        enforce_runtime_egress_policy(
            config=config,
            exporters={"webhook": WebhookExporter(url="https://example.invalid/hook")},
        )


def test_enforce_runtime_egress_policy_accepts_approved_targets(tmp_path: Path, monkeypatch) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)
    config = RuntimeConfig(_env_file=None, approved_egress_targets="webhook:example.invalid:443")

    approved_targets = enforce_runtime_egress_policy(
        config=config,
        exporters={"webhook": WebhookExporter(url="https://example.invalid/hook")},
    )

    assert approved_targets == ("webhook:example.invalid:443",)
