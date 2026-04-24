"""Open-Meteo-Adapter mit Cache und Leak-Guards."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import httpx

from honeypot.time_core import ensure_utc_datetime, parse_utc_timestamp
from honeypot.weather_core.models import WeatherObservation
from honeypot.weather_core.provider import DeterministicDiurnalWeatherProvider


@dataclass(frozen=True, slots=True)
class _CachedObservation:
    cache_until: datetime
    observation: WeatherObservation


@dataclass(slots=True)
class OpenMeteoForecastProvider:
    """Forecast-Adapter auf Basis der Open-Meteo-Forecast-API."""

    timeout_seconds: float = 10.0
    cache_ttl_seconds: int = 900
    transport: httpx.BaseTransport | None = None
    base_url: str = "https://api.open-meteo.com/v1/forecast"
    provider_name: str = "open_meteo_forecast"
    fallback_provider: DeterministicDiurnalWeatherProvider = field(default_factory=DeterministicDiurnalWeatherProvider)
    _cache: dict[tuple[str, float, float, str], _CachedObservation] = field(default_factory=dict, init=False, repr=False)

    def observe(
        self,
        *,
        observed_at: datetime,
        timezone: str,
        latitude: float | None = None,
        longitude: float | None = None,
        elevation_m: float | None = None,
    ) -> WeatherObservation:
        if latitude is None or longitude is None:
            raise ValueError("OpenMeteoForecastProvider braucht latitude und longitude")

        observed_at = ensure_utc_datetime(observed_at)
        cache_key = (self.provider_name, round(latitude, 6), round(longitude, 6), timezone)
        cached = self._cache.get(cache_key)
        if cached is not None and observed_at <= cached.cache_until:
            return cached.observation.model_copy(update={"observed_at": observed_at})

        try:
            payload = self._fetch_payload(
                latitude=latitude,
                longitude=longitude,
                timezone=timezone,
            )
            observation = _parse_forecast_payload(
                payload=payload,
                observed_at=observed_at,
                provider_name=self.provider_name,
            )
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError):
            return self._fallback_observation(
                observed_at=observed_at,
                timezone=timezone,
                latitude=latitude,
                longitude=longitude,
                elevation_m=elevation_m,
                cached=cached,
            )

        self._cache[cache_key] = _CachedObservation(
            cache_until=observed_at.replace() + _seconds_delta(self.cache_ttl_seconds),
            observation=observation,
        )
        return observation

    def _fetch_payload(self, *, latitude: float, longitude: float, timezone: str) -> dict[str, Any]:
        params = {
            "latitude": latitude,
            "longitude": longitude,
            "timezone": timezone,
            "hourly": "temperature_2m,wind_speed_10m,shortwave_radiation,is_day",
            "forecast_hours": 1,
            "past_hours": 1,
        }
        with httpx.Client(timeout=self.timeout_seconds, transport=self.transport, trust_env=False) as client:
            response = client.get(self.base_url, params=params)
            response.raise_for_status()
            return response.json()

    def _fallback_observation(
        self,
        *,
        observed_at: datetime,
        timezone: str,
        latitude: float,
        longitude: float,
        elevation_m: float | None,
        cached: _CachedObservation | None,
    ) -> WeatherObservation:
        if cached is not None:
            return cached.observation.model_copy(
                update={
                    "observed_at": observed_at,
                    "quality": "estimated",
                    "confidence_pct_x10": max(0, cached.observation.confidence_pct_x10 - 150),
                }
            )

        fallback = self.fallback_provider.observe(
            observed_at=observed_at,
            timezone=timezone,
            latitude=latitude,
            longitude=longitude,
            elevation_m=elevation_m,
        )
        return fallback.model_copy(
            update={
                "provider": self.provider_name,
                "quality": "estimated",
                "confidence_pct_x10": 600,
            }
        )


@dataclass(slots=True)
class OpenMeteoSatelliteRadiationProvider(OpenMeteoForecastProvider):
    """Satellite-Radiation-Adapter mit gleichem Leak- und Cache-Kurs."""

    base_url: str = "https://api.open-meteo.com/v1/satellite-radiation"
    provider_name: str = "open_meteo_satellite"

    def _fetch_payload(self, *, latitude: float, longitude: float, timezone: str) -> dict[str, Any]:
        params = {
            "latitude": latitude,
            "longitude": longitude,
            "timezone": timezone,
            "hourly": "shortwave_radiation,is_day",
            "forecast_hours": 1,
            "past_hours": 1,
        }
        with httpx.Client(timeout=self.timeout_seconds, transport=self.transport, trust_env=False) as client:
            response = client.get(self.base_url, params=params)
            response.raise_for_status()
            return response.json()


def _parse_forecast_payload(
    *,
    payload: dict[str, Any],
    observed_at: datetime,
    provider_name: str,
) -> WeatherObservation:
    hourly = payload["hourly"]
    timestamps = hourly["time"]
    index = _nearest_index(timestamps, observed_at)
    irradiance = round(_hourly_value(hourly, "shortwave_radiation", index, default=0.0))
    ambient_temperature_c = round(_hourly_value(hourly, "temperature_2m", index, default=15.0), 1)
    module_temperature_c = round(ambient_temperature_c + irradiance * 0.015, 1)
    wind_speed_m_s = round(_hourly_value(hourly, "wind_speed_10m", index, default=3.0), 1)

    return WeatherObservation(
        provider=provider_name,
        observed_at=observed_at,
        local_time=_parse_local_time(payload=payload, raw_time=timestamps[index]),
        quality="good",
        confidence_pct_x10=950,
        irradiance_w_m2=max(0, min(1600, irradiance)),
        ambient_temperature_c=ambient_temperature_c,
        module_temperature_c=module_temperature_c,
        wind_speed_m_s=max(0.0, wind_speed_m_s),
    )


def _nearest_index(timestamps: list[str], observed_at: datetime) -> int:
    target = ensure_utc_datetime(observed_at)
    indexed = [_parse_reference_time(value) for value in timestamps]
    return min(range(len(indexed)), key=lambda index: abs((indexed[index] - target).total_seconds()))


def _hourly_value(hourly: dict[str, Any], key: str, index: int, *, default: float) -> float:
    values = hourly.get(key)
    if values is None:
        return default
    return float(values[index])


def _seconds_delta(value: int) -> timedelta:
    return timedelta(seconds=value)


def _parse_reference_time(value: str) -> datetime:
    try:
        return parse_utc_timestamp(value)
    except ValueError:
        naive = datetime.fromisoformat(value)
        return ensure_utc_datetime(naive.replace(tzinfo=ZoneInfo("UTC")))


def _parse_local_time(*, payload: dict[str, Any], raw_time: str) -> datetime:
    parsed = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
    if parsed.tzinfo is not None and parsed.utcoffset() is not None:
        return parsed
    timezone_name = payload.get("timezone", "UTC")
    return parsed.replace(tzinfo=ZoneInfo(str(timezone_name)))
