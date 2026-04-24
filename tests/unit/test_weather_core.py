from __future__ import annotations
from datetime import UTC, datetime

import httpx

from honeypot.weather_core import (
    DeterministicDiurnalWeatherProvider,
    OpenMeteoForecastProvider,
    OpenMeteoSatelliteRadiationProvider,
)


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


def test_open_meteo_forecast_provider_reduces_payload_to_internal_observation() -> None:
    provider = OpenMeteoForecastProvider(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "timezone": "Europe/Berlin",
                    "hourly": {
                        "time": ["2026-06-21T12:00"],
                        "temperature_2m": [24.3],
                        "wind_speed_10m": [4.8],
                        "shortwave_radiation": [812.0],
                        "is_day": [1],
                    },
                },
            )
        )
    )

    observation = provider.observe(
        observed_at=datetime(2026, 6, 21, 10, 0, tzinfo=UTC),
        timezone="Europe/Berlin",
        latitude=52.52,
        longitude=13.405,
    )

    assert observation.provider == "open_meteo_forecast"
    assert observation.quality == "good"
    assert observation.confidence_pct_x10 == 950
    assert observation.irradiance_w_m2 == 812
    assert observation.ambient_temperature_c == 24.3
    assert observation.wind_speed_m_s == 4.8
    assert observation.local_time.isoformat() == "2026-06-21T12:00:00+02:00"


def test_open_meteo_uses_cached_observation_as_estimated_fallback() -> None:
    responses = iter(
        [
            httpx.Response(
                200,
                json={
                    "timezone": "Europe/Berlin",
                    "hourly": {
                        "time": ["2026-06-21T12:00"],
                        "temperature_2m": [21.0],
                        "wind_speed_10m": [5.0],
                        "shortwave_radiation": [700.0],
                        "is_day": [1],
                    },
                },
            ),
            httpx.Response(503, text="upstream temporarily unavailable"),
        ]
    )

    provider = OpenMeteoForecastProvider(
        cache_ttl_seconds=1,
        transport=httpx.MockTransport(lambda request: next(responses)),
    )

    cached = provider.observe(
        observed_at=datetime(2026, 6, 21, 10, 0, tzinfo=UTC),
        timezone="Europe/Berlin",
        latitude=52.52,
        longitude=13.405,
    )
    fallback = provider.observe(
        observed_at=datetime(2026, 6, 21, 10, 2, tzinfo=UTC),
        timezone="Europe/Berlin",
        latitude=52.52,
        longitude=13.405,
    )

    assert cached.quality == "good"
    assert fallback.provider == "open_meteo_forecast"
    assert fallback.quality == "estimated"
    assert fallback.observed_at == datetime(2026, 6, 21, 10, 2, tzinfo=UTC)
    assert fallback.irradiance_w_m2 == cached.irradiance_w_m2
    assert fallback.confidence_pct_x10 == 800


def test_open_meteo_without_cache_falls_back_to_deterministic_estimate() -> None:
    provider = OpenMeteoSatelliteRadiationProvider(
        transport=httpx.MockTransport(lambda request: httpx.Response(502, text="bad gateway"))
    )

    observation = provider.observe(
        observed_at=datetime(2026, 6, 21, 10, 0, tzinfo=UTC),
        timezone="Europe/Berlin",
        latitude=52.52,
        longitude=13.405,
        elevation_m=34,
    )

    assert observation.provider == "open_meteo_satellite"
    assert observation.quality == "estimated"
    assert observation.confidence_pct_x10 == 600
    assert observation.local_time.tzinfo is not None
    assert observation.irradiance_w_m2 >= 0
