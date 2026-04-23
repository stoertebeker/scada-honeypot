import json
from pathlib import Path
from time import monotonic, sleep
from types import SimpleNamespace

import pytest

from honeypot.main import MODULES, bootstrap_runtime, build_local_runtime, cli, main


def test_bootstrap_runtime_exposes_documented_modules() -> None:
    manifest = bootstrap_runtime()

    assert manifest.components == MODULES
    assert manifest.components[0] == "config_core"
    assert manifest.components[-1] == "exporter_runner"


def test_build_local_runtime_rejects_nonlocal_modbus_bind_host(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"MODBUS_BIND_HOST=0.0.0.0\nEVENT_STORE_PATH={event_store_path}\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="MODBUS_BIND_HOST"):
        build_local_runtime(env_file=str(env_file))


def test_build_local_runtime_rejects_nonlocal_hmi_bind_host(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        f"HMI_BIND_HOST=0.0.0.0\nEVENT_STORE_PATH={event_store_path}\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="HMI_BIND_HOST"):
        build_local_runtime(env_file=str(env_file))


def test_build_local_runtime_wires_jsonl_archive_from_config(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    archive_path = tmp_path / "logs" / "events.jsonl"
    env_file.write_text(
        (
            f"EVENT_STORE_PATH={event_store_path}\n"
            "JSONL_ARCHIVE_ENABLED=1\n"
            f"JSONL_ARCHIVE_PATH={archive_path}\n"
        ),
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)

    assert runtime.event_recorder.archive is not None
    assert runtime.event_recorder.archive.path == archive_path
    assert runtime.event_recorder.rule_engine is not None
    assert runtime.event_recorder.rule_engine.rule_ids == (
        "repeated_service_login_failure",
        "successful_setpoint_change",
        "breaker_open",
        "grid_path_unavailable",
        "low_site_output_unexpected",
        "inverter_comm_loss",
        "multi_block_unavailable",
    )
    assert runtime.hmi_app is not None
    assert runtime.hmi_service.address == ("127.0.0.1", 0)
    assert runtime.exporters == {}
    assert runtime.outbox_runner is None
    assert runtime.outbox_runner_service is None
    assert runtime.runtime_status_service is None


def test_build_local_runtime_wires_webhook_outbox_runner_when_enabled(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        (
            f"EVENT_STORE_PATH={event_store_path}\n"
            "WEBHOOK_EXPORTER_ENABLED=1\n"
            "WEBHOOK_EXPORTER_URL=https://example.invalid/hook\n"
            "OUTBOX_BATCH_SIZE=25\n"
            "OUTBOX_RETRY_BACKOFF_SECONDS=45\n"
        ),
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)

    assert runtime.outbox_runner is not None
    assert runtime.outbox_runner_service is not None
    assert runtime.outbox_runner.batch_size == 25
    assert runtime.outbox_runner.retry_backoff_seconds == 45
    assert tuple(runtime.outbox_runner.exporters) == ("webhook",)


def test_build_local_runtime_wires_smtp_outbox_runner_when_enabled(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        (
            f"EVENT_STORE_PATH={event_store_path}\n"
            "SMTP_EXPORTER_ENABLED=1\n"
            "SMTP_HOST=mail.example.invalid\n"
            "SMTP_PORT=2525\n"
            "SMTP_FROM=alerts@example.invalid\n"
            "SMTP_TO=soc@example.invalid\n"
        ),
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)

    assert runtime.outbox_runner is not None
    assert runtime.outbox_runner_service is not None
    assert tuple(runtime.outbox_runner.exporters) == ("smtp",)


def test_build_local_runtime_wires_telegram_outbox_runner_when_enabled(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    env_file.write_text(
        (
            f"EVENT_STORE_PATH={event_store_path}\n"
            "TELEGRAM_EXPORTER_ENABLED=1\n"
            "TELEGRAM_BOT_TOKEN=token-123\n"
            "TELEGRAM_CHAT_ID=chat-99\n"
        ),
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)

    assert runtime.outbox_runner is not None
    assert runtime.outbox_runner_service is not None
    assert tuple(runtime.outbox_runner.exporters) == ("telegram",)


def test_build_local_runtime_wires_runtime_status_service_when_enabled(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    status_path = tmp_path / "logs" / "runtime-status.json"
    env_file.write_text(
        (
            f"EVENT_STORE_PATH={event_store_path}\n"
            "RUNTIME_STATUS_ENABLED=1\n"
            f"RUNTIME_STATUS_PATH={status_path}\n"
            "RUNTIME_STATUS_INTERVAL_SECONDS=2\n"
            "WEBHOOK_EXPORTER_ENABLED=1\n"
            "WEBHOOK_EXPORTER_URL=https://example.invalid/hook\n"
        ),
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)

    assert runtime.runtime_status_service is not None
    assert runtime.runtime_status_service.writer.path == status_path
    assert runtime.runtime_status_service.interval_seconds == 2
    assert tuple(runtime.exporters) == ("webhook",)


def test_runtime_status_service_writes_local_status_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_path = tmp_path / "events" / "honeypot.db"
    status_path = tmp_path / "logs" / "runtime-status.json"
    env_file.write_text(
        (
            f"EVENT_STORE_PATH={event_store_path}\n"
            "RUNTIME_STATUS_ENABLED=1\n"
            f"RUNTIME_STATUS_PATH={status_path}\n"
            "RUNTIME_STATUS_INTERVAL_SECONDS=1\n"
            "WEBHOOK_EXPORTER_ENABLED=1\n"
            "WEBHOOK_EXPORTER_URL=https://example.invalid/hook\n"
        ),
        encoding="utf-8",
    )

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0, hmi_port=0)
    assert runtime.runtime_status_service is not None

    runtime.start()
    try:
        _wait_for(lambda: status_path.is_file())
        payload = json.loads(status_path.read_text(encoding="utf-8"))
        assert payload["site_code"] == "site-01"
        assert payload["fixture_name"] == "normal_operation"
        assert payload["runtime"]["running"] is True
        assert payload["runtime"]["modbus"]["port"] == runtime.modbus_service.address[1]
        assert payload["runtime"]["hmi"]["port"] == runtime.hmi_service.address[1]
        assert payload["runtime"]["outbox_runner"]["enabled"] is True
        assert payload["exporters"]["webhook"]["status"] == "healthy"
    finally:
        runtime.stop()

    _wait_for(
        lambda: status_path.is_file()
        and json.loads(status_path.read_text(encoding="utf-8"))["runtime"]["running"] is False
    )
    payload = json.loads(status_path.read_text(encoding="utf-8"))
    assert payload["runtime"]["running"] is False


def test_main_returns_success(capsys, monkeypatch, tmp_path: Path) -> None:
    del tmp_path
    fake_runtime = _FakeRuntime()
    stop_called = False

    def fake_build_local_runtime(*, env_file=".env", modbus_port=None, hmi_port=None):
        del env_file, modbus_port, hmi_port
        return fake_runtime

    def fake_stop(runtime) -> None:
        nonlocal stop_called
        assert runtime is fake_runtime
        stop_called = True

    monkeypatch.setattr("honeypot.main.build_local_runtime", fake_build_local_runtime)
    monkeypatch.setattr("honeypot.main._run_until_stopped", fake_stop)

    assert main() == 0
    captured = capsys.readouterr()
    assert stop_called is True
    assert "honeypot runtime ready for site-01" in captured.out
    assert "modbus://127.0.0.1:1502" in captured.out
    assert "http://127.0.0.1:8080/overview" in captured.out


def test_cli_reset_runtime_prints_report(capsys, monkeypatch, tmp_path: Path) -> None:
    del tmp_path

    class _Report:
        site_code = "site-99"
        removed_paths = (Path("/tmp/a"), Path("/tmp/b"))
        missing_paths = (Path("/tmp/c"),)

    monkeypatch.setattr("honeypot.main.reset_local_runtime_artifacts", lambda env_file=".env": _Report())

    assert cli(["--env-file", ".env.test", "--reset-runtime"]) == 0
    captured = capsys.readouterr()
    assert "honeypot runtime artifacts reset for site-99" in captured.out
    assert "removed=2" in captured.out
    assert "missing=1" in captured.out


class _FakeRuntime:
    def __init__(self) -> None:
        self.config = SimpleNamespace(site_code="site-01")
        self.manifest = bootstrap_runtime()
        self.snapshot = SimpleNamespace(fixture_name="normal_operation")
        self.modbus_service = SimpleNamespace(address=("127.0.0.1", 1502))
        self.hmi_service = SimpleNamespace(address=("127.0.0.1", 8080))

    def start(self):
        return self


def _wait_for(predicate, *, timeout: float = 2.0) -> None:
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        if predicate():
            return
        sleep(0.01)
    raise AssertionError("Bedingung wurde nicht rechtzeitig erfuellt")
