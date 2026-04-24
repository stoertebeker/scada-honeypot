"""Interne Wetterbeobachtungen fuer Runtime und Tests."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from honeypot.time_core import ensure_utc_datetime

WeatherProviderName = Literal["disabled", "deterministic", "open_meteo_forecast", "open_meteo_satellite"]
WeatherObservationQuality = Literal["good", "estimated", "stale", "invalid"]


class WeatherObservation(BaseModel):
    """Reduzierte interne Wetterbeobachtung ohne Standort-Leak."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: WeatherProviderName
    observed_at: datetime
    local_time: datetime
    quality: WeatherObservationQuality
    confidence_pct_x10: int = Field(ge=0, le=1000)
    irradiance_w_m2: int = Field(ge=0, le=1600)
    ambient_temperature_c: float = Field(ge=-50, le=70)
    module_temperature_c: float = Field(ge=-40, le=120)
    wind_speed_m_s: float = Field(ge=0, le=100)

    @model_validator(mode="after")
    def validate_times(self) -> "WeatherObservation":
        ensure_utc_datetime(self.observed_at)
        if self.local_time.tzinfo is None or self.local_time.utcoffset() is None:
            raise ValueError("local_time muss timezone-aware sein")
        return self
