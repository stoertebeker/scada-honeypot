from datetime import UTC, datetime, timedelta

import pytest

from honeypot.time_core import FrozenClock, SystemClock, ensure_utc_datetime, parse_utc_timestamp


def test_parse_utc_timestamp_supports_z_suffix() -> None:
    instant = parse_utc_timestamp("2026-04-01T10:00:00Z")

    assert instant == datetime(2026, 4, 1, 10, 0, tzinfo=UTC)


def test_ensure_utc_datetime_rejects_naive_values() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ensure_utc_datetime(datetime(2026, 4, 1, 10, 0))


def test_frozen_clock_is_deterministic_and_advances_explicitly() -> None:
    clock = FrozenClock(datetime(2026, 4, 1, 10, 0, tzinfo=UTC))

    assert clock.now() == datetime(2026, 4, 1, 10, 0, tzinfo=UTC)
    assert clock.advance(timedelta(minutes=15)) == datetime(2026, 4, 1, 10, 15, tzinfo=UTC)
    assert clock.set(datetime(2026, 4, 1, 12, 0, tzinfo=UTC)) == datetime(
        2026, 4, 1, 12, 0, tzinfo=UTC
    )


def test_system_clock_returns_timezone_aware_utc_values() -> None:
    instant = SystemClock().now()

    assert instant.tzinfo is UTC
