"""Lokaler Reset-Pfad fuer reproduzierbare Runtime-Artefakte."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from honeypot.config_core import RuntimeConfig, load_runtime_config


@dataclass(frozen=True, slots=True)
class RuntimeResetReport:
    """Kurzer Bericht ueber entfernte und fehlende Runtime-Artefakte."""

    site_code: str
    removed_paths: tuple[Path, ...]
    missing_paths: tuple[Path, ...]


def reset_local_runtime_artifacts(*, env_file: str | Path | None = ".env") -> RuntimeResetReport:
    """Entfernt lokale Runtime-Artefakte fuer einen frischen Neustart."""

    config = load_runtime_config(env_file=env_file)
    removed_paths: list[Path] = []
    missing_paths: list[Path] = []
    for artifact_path in planned_runtime_artifact_paths(config):
        normalized_path = artifact_path.expanduser()
        if not normalized_path.exists():
            missing_paths.append(normalized_path)
            continue
        if normalized_path.is_symlink():
            raise RuntimeError(f"Reset verweigert symlink-Artefaktpfad: {normalized_path}")
        if normalized_path.is_dir():
            raise RuntimeError(f"Reset verweigert Verzeichnis-Artefaktpfad: {normalized_path}")
        normalized_path.unlink()
        removed_paths.append(normalized_path)

    return RuntimeResetReport(
        site_code=config.site_code,
        removed_paths=tuple(removed_paths),
        missing_paths=tuple(missing_paths),
    )


def planned_runtime_artifact_paths(config: RuntimeConfig) -> tuple[Path, ...]:
    """Liefert alle bekannten lokalen Runtime-Artefakte fuer Reset und Doku."""

    event_store_path = config.event_store_path.expanduser()
    return (
        event_store_path,
        Path(f"{event_store_path}-wal"),
        Path(f"{event_store_path}-shm"),
        config.jsonl_archive_path.expanduser(),
        config.runtime_status_path.expanduser(),
        config.pcap_capture_path.expanduser(),
    )
