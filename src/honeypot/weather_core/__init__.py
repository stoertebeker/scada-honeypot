"""Interne Wetterabstraktion fuer Runtime und Tests."""

from honeypot.weather_core.models import WeatherObservation, WeatherObservationQuality, WeatherProviderName
from honeypot.weather_core.open_meteo import (
    OpenMeteoForecastProvider,
    OpenMeteoHistoricalArchiveProvider,
    OpenMeteoSatelliteRadiationProvider,
)
from honeypot.weather_core.provider import (
    DeterministicDiurnalWeatherProvider,
    PlausibleHistoricalWeatherProvider,
    WeatherObservationProvider,
)

__all__ = [
    "DeterministicDiurnalWeatherProvider",
    "OpenMeteoForecastProvider",
    "OpenMeteoHistoricalArchiveProvider",
    "OpenMeteoSatelliteRadiationProvider",
    "PlausibleHistoricalWeatherProvider",
    "WeatherObservation",
    "WeatherObservationProvider",
    "WeatherObservationQuality",
    "WeatherProviderName",
]
