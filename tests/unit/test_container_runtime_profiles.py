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

    assert "honeypot-exposed:" in compose_yaml
    assert 'EXPOSED_RESEARCH_ENABLED: "0"' in compose_yaml
    assert 'EXPOSED_RESEARCH_ENABLED: "1"' in compose_yaml
    assert "profiles:\n      - exposed" in compose_yaml
