"""JSONL-Archiv fuer lokal persistierte Kern-Events."""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock

from honeypot.event_core.models import EventRecord


class JsonlEventArchive:
    """Schreibt Events zeilenweise in ein lokales JSONL-Archiv."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self.last_error: str | None = None

    def append_event(self, event: EventRecord) -> bool:
        payload = json.dumps(event.model_dump(mode="json"), ensure_ascii=True, sort_keys=True)
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(payload)
                    handle.write("\n")
        except OSError as exc:
            self.last_error = str(exc)
            return False

        self.last_error = None
        return True
