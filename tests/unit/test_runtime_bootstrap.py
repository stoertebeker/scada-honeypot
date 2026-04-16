from pathlib import Path
from types import SimpleNamespace

import pytest

from honeypot.main import MODULES, bootstrap_runtime, build_local_runtime, main


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

    runtime = build_local_runtime(env_file=str(env_file), modbus_port=0)

    assert runtime.event_recorder.archive is not None
    assert runtime.event_recorder.archive.path == archive_path


def test_main_returns_success(capsys, monkeypatch, tmp_path: Path) -> None:
    del tmp_path
    fake_runtime = _FakeRuntime()
    stop_called = False

    def fake_build_local_runtime(*, env_file=".env", modbus_port=None):
        del env_file, modbus_port
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


class _FakeRuntime:
    def __init__(self) -> None:
        self.config = SimpleNamespace(site_code="site-01")
        self.manifest = bootstrap_runtime()
        self.snapshot = SimpleNamespace(fixture_name="normal_operation")
        self.modbus_service = SimpleNamespace(address=("127.0.0.1", 1502))

    def start(self):
        return self
