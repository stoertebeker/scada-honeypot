"""Zeitquellen fuer Runtime und deterministische Tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol


def ensure_utc_datetime(value: datetime) -> datetime:
    """Normalisiert einen Zeitschnitt auf UTC und verlangt Zeitzonenbezug."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Zeitwerte muessen timezone-aware sein")
    return value.astimezone(UTC)


def parse_utc_timestamp(value: str) -> datetime:
    """Parst ISO-8601-Zeitstempel inklusive `Z`-Suffix in UTC."""

    normalized = value.replace("Z", "+00:00")
    return ensure_utc_datetime(datetime.fromisoformat(normalized))


class Clock(Protocol):
    """Abstrakte Zeitquelle fuer Runtime und Tests."""

    def now(self) -> datetime:
        """Liefert den aktuellen Zeitwert der Quelle."""


@dataclass(slots=True, frozen=True)
class SystemClock:
    """Produktive Zeitquelle auf Basis der Systemuhr."""

    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(slots=True)
class FrozenClock:
    """Deterministische Test-Uhr mit expliziter Fortschaltung."""

    _current: datetime = field(repr=False)

    def __post_init__(self) -> None:
        self._current = ensure_utc_datetime(self._current)

    def now(self) -> datetime:
        return self._current

    def set(self, instant: datetime) -> datetime:
        self._current = ensure_utc_datetime(instant)
        return self._current

    def advance(self, delta: timedelta) -> datetime:
        self._current = ensure_utc_datetime(self._current + delta)
        return self._current
