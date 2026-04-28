from pathlib import Path

from honeypot.config_core import load_runtime_config


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_example_env_files_load_with_inline_comments() -> None:
    base_config = load_runtime_config(env_file=str(REPO_ROOT / ".env.example"))
    assert base_config.exposed_research_enabled is False
    assert base_config.watch_officer_name is None
    assert base_config.duty_engineer_name is None

    exposed_config = load_runtime_config(
        env_file=str(REPO_ROOT / "deploy" / "lab-vm-observer-01.env.example")
    )
    assert exposed_config.exposed_research_enabled is True
    assert exposed_config.watch_officer_name == "blue-watch"
    assert exposed_config.duty_engineer_name == "ops-duty"


def test_compose_profiles_split_normal_and_exposed_runtime() -> None:
    compose_yaml = (REPO_ROOT / "compose.yaml").read_text(encoding="utf-8")
    entrypoint = (REPO_ROOT / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
    healthcheck = (REPO_ROOT / "docker" / "healthcheck.sh").read_text(encoding="utf-8")

    assert "honeypot-exposed:" in compose_yaml
    assert 'HONEYPOT_FORCE_CONTAINER_BINDS: "1"' in compose_yaml
    assert 'HONEYPOT_RUNTIME_MODE: normal' in compose_yaml
    assert 'HONEYPOT_RUNTIME_MODE: exposed' in compose_yaml
    assert "profiles:\n      - exposed" in compose_yaml
    assert "export HMI_BIND_HOST=0.0.0.0" in entrypoint
    assert "export MODBUS_BIND_HOST=0.0.0.0" in entrypoint
    assert "export OPS_BIND_HOST=0.0.0.0" in entrypoint
    assert "ops:0.0.0.0:${OPS_PORT:-9090}" in entrypoint
    assert "127.0.0.1:${OPS_PUBLISHED_PORT:-9090}:${OPS_PORT:-9090}" in compose_yaml
    assert "export EXPOSED_RESEARCH_ENABLED=0" in entrypoint
    assert "export EXPOSED_RESEARCH_ENABLED=1" in entrypoint
    assert "/healthz" in healthcheck
    assert "/overview" not in healthcheck
