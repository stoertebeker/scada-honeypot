"""Provider-Abstraktion und deterministischer Offline-Wetterpfad."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
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
