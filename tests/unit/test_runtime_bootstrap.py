from honeypot.main import MODULES, bootstrap_runtime, main


def test_bootstrap_runtime_exposes_documented_modules() -> None:
    manifest = bootstrap_runtime()

    assert manifest.components == MODULES
    assert manifest.components[0] == "config_core"
    assert manifest.components[-1] == "exporter_runner"


def test_main_returns_success(capsys) -> None:
    assert main() == 0

    captured = capsys.readouterr()
    assert "honeypot scaffold ready for site-01" in captured.out
