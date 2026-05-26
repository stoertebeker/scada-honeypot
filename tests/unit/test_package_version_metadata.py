from __future__ import annotations

import json
import tomllib
from pathlib import Path

import honeypot


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_package_version_matches_backend_release_log() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lockfile = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    backend_versions = json.loads((REPO_ROOT / "resources" / "backend_versions.json").read_text(encoding="utf-8"))

    package_version = pyproject["project"]["version"]
    lock_package = next(package for package in lockfile["package"] if package["name"] == "scada-honeypot")

    assert honeypot.__version__ == package_version
    assert lock_package["version"] == package_version
    assert backend_versions[0]["version"] == f"v{package_version}"
