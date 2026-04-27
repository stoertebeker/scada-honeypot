"""Provider-Abstraktion und deterministischer Offline-Wetterpfad."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from math import cos, pi, sin
from typing import Protocol
from zoneinfo import ZoneInfo

from honeypot.time_core import ensure_utc_datetime
from honeypot.weather_core.models import WeatherObservation


class WeatherObservationProvider(Protocol):
    """Vertrag fuer interne Wetterquellen."""

    provider_name: str

    def observe(
        self,
        *,
        observed_at: datetime,
        timezone: str,
        latitude: float | None = None,
        longitude: float | None = None,
        elevation_m: float | None = None,
    ) -> WeatherObservation:
        """Liefert eine reduzierte Wetterbeobachtung ohne Standort-Leak."""


@dataclass(frozen=True, slots=True)
class DeterministicDiurnalWeatherProvider:
    """Offline-Provider mit plausibler Tag-/Nacht- und Jahresgang-Simulation."""

    provider_name: str = "deterministic"

    def observe(
        self,
        *,
        observed_at: datetime,
        timezone: str,
        latitude: float | None = None,
        longitude: float | None = None,
        elevation_m: float | None = None,
    ) -> WeatherObservation:
        observed_at = ensure_utc_datetime(observed_at)
        local_time = observed_at.astimezone(ZoneInfo(timezone))
        solar_factor = _solar_factor(local_time=local_time, latitude=latitude)
        seasonal_factor = _seasonal_factor(local_time)
        elevation_factor = 1.0 if elevation_m is None else max(0.9, min(1.1, 1.0 + (elevation_m / 10000)))
        irradiance = round(950 * solar_factor * seasonal_factor * elevation_factor)
        ambient_temperature_c = round(8 + 12 * seasonal_factor + 10 * solar_factor, 1)
        module_temperature_c = round(ambient_temperature_c + irradiance * 0.015, 1)
        wind_speed_m_s = round(2.5 + 1.5 * (1 - solar_factor) + 1.2 * _phase_wave(local_time.hour / 24), 1)

        return WeatherObservation(
            provider="deterministic",
            observed_at=observed_at,
            local_time=local_time,
            quality="good",
            confidence_pct_x10=1000,
            irradiance_w_m2=max(0, min(1600, irradiance)),
            ambient_temperature_c=ambient_temperature_c,
            module_temperature_c=module_temperature_c,
            wind_speed_m_s=max(0.0, wind_speed_m_s),
        )


@dataclass(frozen=True, slots=True)
class PlausibleHistoricalWeatherProvider:
    """Offline-Historienprovider mit deterministischen Wetterlagen statt Idealkurven."""

    provider_name: str = "deterministic"
    clear_sky_provider: DeterministicDiurnalWeatherProvider = DeterministicDiurnalWeatherProvider()

    def observe(
        self,
        *,
        observed_at: datetime,
        timezone: str,
        latitude: float | None = None,
        longitude: float | None = None,
        elevation_m: float | None = None,
    ) -> WeatherObservation:
        clear = self.clear_sky_provider.observe(
            observed_at=observed_at,
            timezone=timezone,
            latitude=latitude,
            longitude=longitude,
            elevation_m=elevation_m,
        )
        if clear.irradiance_w_m2 <= 0:
            return clear.model_copy(update={"quality": "estimated", "confidence_pct_x10": 700})

        local_time = clear.local_time
        cloud_cover_pct = _plausible_cloud_cover_pct(
            local_time=local_time,
            latitude=latitude,
            longitude=longitude,
        )
        haze_factor = 0.92 + 0.08 * _stable_unit("haze", _location_key(latitude, longitude), local_time.strftime("%Y-%m-%d"))
        cloud_transmittance = max(0.08, min(1.0, 1.0 - 0.74 * (cloud_cover_pct / 100) ** 1.35))
        irradiance = round(clear.irradiance_w_m2 * haze_factor * cloud_transmittance)
        ambient_temperature_c = round(clear.ambient_temperature_c - (cloud_cover_pct / 100) * 3.5, 1)
        module_temperature_c = round(ambient_temperature_c + irradiance * 0.015, 1)
        wind_speed_m_s = round(clear.wind_speed_m_s + 0.8 * (cloud_cover_pct / 100), 1)

        return WeatherObservation(
            provider="deterministic",
            observed_at=clear.observed_at,
            local_time=local_time,
            quality="estimated",
            confidence_pct_x10=700,
            irradiance_w_m2=max(0, min(1600, irradiance)),
            ambient_temperature_c=ambient_temperature_c,
            module_temperature_c=module_temperature_c,
            wind_speed_m_s=max(0.0, wind_speed_m_s),
        )


def _solar_factor(*, local_time: datetime, latitude: float | None) -> float:
    hours = local_time.hour + (local_time.minute / 60) + (local_time.second / 3600)
    latitude_scale = 1.0 if latitude is None else max(0.7, min(1.3, 1.0 - abs(latitude) / 180))
    seasonal_daylight_adjustment = sin(((_day_of_year(local_time) - 80) / 365) * 2 * pi) * 1.4 * latitude_scale
    sunrise_hour = 6.0 - seasonal_daylight_adjustment
    sunset_hour = 18.0 + seasonal_daylight_adjustment
    if hours <= sunrise_hour or hours >= sunset_hour:
        return 0.0
    phase = (hours - sunrise_hour) / max(sunset_hour - sunrise_hour, 1e-6)
    return max(0.0, sin(pi * phase))


def _seasonal_factor(local_time: datetime) -> float:
    return max(0.45, min(1.0, 0.72 + 0.28 * sin(((_day_of_year(local_time) - 80) / 365) * 2 * pi)))


def _phase_wave(normalized_hour: float) -> float:
    return (cos((normalized_hour - 0.2) * 2 * pi) + 1) / 2


def _day_of_year(local_time: datetime) -> int:
    return int(local_time.strftime("%j"))


def _plausible_cloud_cover_pct(
    *,
    local_time: datetime,
    latitude: float | None,
    longitude: float | None,
) -> float:
    location_key = _location_key(latitude, longitude)
    day_key = local_time.strftime("%Y-%m-%d")
    ordinal = local_time.toordinal()
    front_offset = _stable_unit("front", location_key) * 2 * pi
    front_wave = (sin((ordinal / 3.8) + front_offset) + 1) / 2
    day_noise = _stable_unit("day", location_key, day_key)
    regime_noise = _stable_unit("regime", location_key, day_key)

    base_cloud = 12 + 58 * front_wave + 28 * day_noise
    if regime_noise < 0.14:
        base_cloud = max(base_cloud, 82)
    elif regime_noise > 0.88:
        base_cloud = min(base_cloud, 18)

    hour = local_time.hour + local_time.minute / 60
    morning_haze = max(0.0, 1.0 - abs(hour - 8.0) / 2.4) * 12
    afternoon_clouds = max(0.0, 1.0 - abs(hour - 15.5) / 3.2) * (8 + 18 * day_noise)
    cloud_pocket = (
        sin((hour * 1.7) + _stable_unit("pocket-a", location_key, day_key) * 2 * pi)
        + sin((hour * 3.1) + _stable_unit("pocket-b", location_key, day_key) * 2 * pi)
        + 2
    ) / 4
    intraday_cloud = cloud_pocket * (6 + 24 * _stable_unit("pocket-scale", location_key, day_key))

    return max(0.0, min(98.0, base_cloud * 0.72 + morning_haze + afternoon_clouds + intraday_cloud))


def _location_key(latitude: float | None, longitude: float | None) -> str:
    if latitude is None or longitude is None:
        return "unknown"
    return f"{latitude:.3f}:{longitude:.3f}"


def _stable_unit(*parts: object) -> float:
    digest = sha256("|".join(str(part) for part in parts).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / ((1 << 64) - 1)
