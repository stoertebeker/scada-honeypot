"""JSONL-Archiv fuer lokal persistierte Kern-Events."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
import gzip
import json
from pathlib import Path
import shutil
from threading import Lock

from honeypot.event_core.models import EventRecord
from honeypot.storage.retention import JsonlRetentionPolicy


def _filesystem_free_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free


def _utc_now() -> datetime:
    return datetime.now(UTC)


class JsonlEventArchive:
    """Schreibt Events zeilenweise in ein lokales JSONL-Archiv."""

    def __init__(
        self,
        path: str | Path,
        *,
        retention_policy: JsonlRetentionPolicy | None = None,
        free_bytes_provider: Callable[[Path], int] = _filesystem_free_bytes,
        now_provider: Callable[[], datetime] = _utc_now,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.retention_policy = JsonlRetentionPolicy() if retention_policy is None else retention_policy
        self._free_bytes_provider = free_bytes_provider
        self._now_provider = now_provider
        self._lock = Lock()
        self.last_error: str | None = None
        self._dropped_events = 0
        self._rotations = 0
        self._pruned_files = 0
        with self._lock:
            self._enforce_retention_locked()

    def append_event(self, event: EventRecord) -> bool:
        payload = json.dumps(event.model_dump(mode="json"), ensure_ascii=True, sort_keys=True) + "\n"
        payload_size = len(payload.encode("utf-8"))
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if payload_size > self.retention_policy.max_file_bytes:
                    self._dropped_events += 1
                    self.last_error = "event_exceeds_jsonl_file_limit"
                    return False
                if self._free_bytes_provider(self.path.parent) < self.retention_policy.min_free_bytes:
                    self._dropped_events += 1
                    self.last_error = "jsonl_free_space_watermark_reached"
                    return False
                current_size = self.path.stat().st_size if self.path.exists() else 0
                if current_size and current_size + payload_size > self.retention_policy.max_file_bytes:
                    self._rotate_locked()
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(payload)
                self._enforce_retention_locked()
        except OSError as exc:
            self._dropped_events += 1
            self.last_error = str(exc)
            return False

        self.last_error = None
        return True

    def retention_status(self) -> dict[str, int | str | None]:
        with self._lock:
            archive_paths = self._archive_paths_locked()
            retained_bytes = sum(path.stat().st_size for path in archive_paths if path.exists())
            return {
                "retained_files": len(archive_paths),
                "retained_bytes": retained_bytes,
                "dropped_events": self._dropped_events,
                "rotations": self._rotations,
                "pruned_files": self._pruned_files,
                "last_error": self.last_error,
            }

    def _rotate_locked(self) -> None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return
        timestamp = self._now_provider().astimezone(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        rotated_path = self.path.with_name(f"{self.path.stem}.{timestamp}.jsonl.gz")
        try:
            with self.path.open("rb") as source, gzip.open(rotated_path, "wb") as target:
                shutil.copyfileobj(source, target)
            self.path.unlink()
        except OSError:
            if rotated_path.exists():
                rotated_path.unlink()
            raise
        self._rotations += 1

    def _archive_paths_locked(self) -> tuple[Path, ...]:
        compressed = tuple(sorted(self.path.parent.glob(f"{self.path.stem}.*.jsonl.gz")))
        if self.path.exists():
            return (*compressed, self.path)
        return compressed

    def _enforce_retention_locked(self) -> None:
        cutoff = self._now_provider().timestamp() - timedelta(
            days=self.retention_policy.max_age_days
        ).total_seconds()
        compressed = sorted(
            self.path.parent.glob(f"{self.path.stem}.*.jsonl.gz"),
            key=lambda candidate: (candidate.stat().st_mtime, candidate.name),
        )
        for candidate in tuple(compressed):
            if candidate.stat().st_mtime < cutoff:
                candidate.unlink()
                compressed.remove(candidate)
                self._pruned_files += 1

        retained_paths = [*compressed]
        if self.path.exists():
            retained_paths.append(self.path)
        total_bytes = sum(path.stat().st_size for path in retained_paths)
        for candidate in compressed:
            if total_bytes <= self.retention_policy.max_total_bytes:
                break
            candidate_size = candidate.stat().st_size
            candidate.unlink()
            total_bytes -= candidate_size
            self._pruned_files += 1
