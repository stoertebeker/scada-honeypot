from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DOCUMENTATION_PATHS = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "docs",
    REPO_ROOT / ".schrammns_workflow" / "plans",
)
ATTACKER_RENDERED_PATHS = (
    REPO_ROOT / "src" / "honeypot" / "hmi_web" / "templates",
    REPO_ROOT / "resources" / "locales" / "attacker-ui",
)
ABSOLUTE_PATH_PATTERNS = (
    "/Users/",
    "/home/",
    "file://",
    "vscode://",
    "/private/var/",
)
ATTACKER_DEBUG_PATTERNS = (
    "openapi.json",
    "swagger",
    "redoc",
    "traceback",
    "stack trace",
    "debug toolbar",
    "uvicorn",
    "starlette",
    "fastapi",
    "jinja2",
)
OEM_CLONE_TERMS = (
    "siemens",
    "wincc",
    "schneider electric",
    "rockwell automation",
    "allen-bradley",
    "honeywell",
    "emerson ovation",
    "yokogawa",
    "abb ability",
)
DEPLOYABLE_SECRET_PATTERNS = (
    re.compile(
        r"\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}",
        re.IGNORECASE,
    ),
)


def test_repo_docs_do_not_contain_absolute_path_leaks() -> None:
    checked_files = 0
    violations: list[str] = []

    for path in _iter_documentation_files():
        checked_files += 1
        content = path.read_text(encoding="utf-8")
        for pattern in ABSOLUTE_PATH_PATTERNS:
            if pattern in content:
                violations.append(f"{path.relative_to(REPO_ROOT)} contains forbidden pattern {pattern!r}")

    assert checked_files > 0
    assert violations == []


def test_attacker_rendered_files_do_not_leak_debug_vendor_or_secret_fingerprints() -> None:
    checked_files = 0
    violations: list[str] = []

    for path in _iter_attacker_rendered_files():
        checked_files += 1
        content = path.read_text(encoding="utf-8")
        lowered = content.lower()

        for pattern in ABSOLUTE_PATH_PATTERNS:
            if pattern in content:
                violations.append(f"{path.relative_to(REPO_ROOT)} contains absolute path leak {pattern!r}")
        for pattern in ATTACKER_DEBUG_PATTERNS:
            if pattern in lowered:
                violations.append(f"{path.relative_to(REPO_ROOT)} contains debug/framework fingerprint {pattern!r}")
        for term in OEM_CLONE_TERMS:
            if term in lowered:
                violations.append(f"{path.relative_to(REPO_ROOT)} contains real vendor clone term {term!r}")
        for pattern in DEPLOYABLE_SECRET_PATTERNS:
            if pattern.search(content):
                violations.append(f"{path.relative_to(REPO_ROOT)} contains deployable-looking secret material")

    assert checked_files > 0
    assert violations == []


def _iter_documentation_files() -> tuple[Path, ...]:
    return _iter_files(DOCUMENTATION_PATHS, suffixes={".md", ".json"})


def _iter_attacker_rendered_files() -> tuple[Path, ...]:
    return _iter_files(ATTACKER_RENDERED_PATHS, suffixes={".html", ".json"})


def _iter_files(paths: tuple[Path, ...], *, suffixes: set[str]) -> tuple[Path, ...]:
    files: list[Path] = []
    for path in paths:
        if path.is_file():
            files.append(path)
            continue
        files.extend(
            candidate
            for candidate in sorted(path.rglob("*"))
            if candidate.is_file() and candidate.suffix.lower() in suffixes
        )
    return tuple(files)
