from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DOCUMENTATION_PATHS = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "docs",
    REPO_ROOT / ".schrammns_workflow" / "plans",
)
FORBIDDEN_PATTERNS = (
    "/Users/",
    "/home/",
    "file://",
    "vscode://",
    "/private/var/",
)


def test_repo_docs_do_not_contain_absolute_path_leaks() -> None:
    checked_files = 0
    violations: list[str] = []

    for path in _iter_documentation_files():
        checked_files += 1
        content = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_PATTERNS:
            if pattern in content:
                violations.append(f"{path.relative_to(REPO_ROOT)} contains forbidden pattern {pattern!r}")

    assert checked_files > 0
    assert violations == []


def _iter_documentation_files() -> tuple[Path, ...]:
    files: list[Path] = []
    for path in DOCUMENTATION_PATHS:
        if path.is_file():
            files.append(path)
            continue
        files.extend(
            candidate
            for candidate in sorted(path.rglob("*"))
            if candidate.is_file() and candidate.suffix.lower() in {".md", ".json"}
        )
    return tuple(files)
