from __future__ import annotations

from datetime import UTC, datetime

from honeypot.weather_core import DeterministicDiurnalWeatherProvider


def test_deterministic_provider_follows_local_day_night_pattern() -> None:
    provider = DeterministicDiurnalWeatherProvider()

    midday = provider.observe(
        observed_at=datetime(2026, 6, 21, 10, 0, tzinfo=UTC),
        timezone="Europe/Berlin",
        latitude=52.52,
        longitude=13.405,
    )
    night = provider.observe(
        observed_at=datetime(2026, 6, 21, 1, 0, tzinfo=UTC),
        timezone="Europe/Berlin",
        latitude=52.52,
        longitude=13.405,
    )

    assert midday.provider == "deterministic"
    assert midday.confidence_pct_x10 == 1000
    assert midday.irradiance_w_m2 > night.irradiance_w_m2
    assert midday.module_temperature_c > night.module_temperature_c
    assert night.irradiance_w_m2 == 0


def test_deterministic_provider_returns_timezone_aware_local_time() -> None:
    provider = DeterministicDiurnalWeatherProvider()

    observation = provider.observe(
        observed_at=datetime(2026, 12, 1, 11, 30, tzinfo=UTC),
        timezone="Europe/Berlin",
    )

    assert observation.local_time.tzinfo is not None
    assert observation.local_time.utcoffset() is not None
    assert observation.observed_at == datetime(2026, 12, 1, 11, 30, tzinfo=UTC)
    assert observation.quality == "good"
