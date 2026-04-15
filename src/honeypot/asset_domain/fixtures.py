"""Fixture-System fuer deterministische Startzustaende."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from pydantic import field_validator

from honeypot.time_core import FrozenClock, ensure_utc_datetime

FIXTURE_DIR = Path("fixtures")


class FixtureLoadError(RuntimeError):
    """Signalisiert ungueltige oder fehlende Fixture-Dateien."""


class SiteStateFixture(BaseModel):
    """Globaler Anlagenzustand zum Start eines Tests."""

    model_config = ConfigDict(extra="forbid")

    operating_mode: Literal["normal", "curtailed", "maintenance", "faulted"]
    availability_state: Literal["available", "partially_available", "unavailable"]
    plant_power_mw: float = Field(ge=0)
    plant_power_limit_pct: int = Field(ge=0, le=100)
    reactive_power_setpoint: float = Field(ge=-1.0, le=1.0)
    breaker_state: Literal["closed", "open", "transitioning"]
    communications_health: Literal["healthy", "degraded", "lost"]
    active_alarm_count: int = Field(ge=0)


class WeatherFixture(BaseModel):
    """Deterministische Wetterwerte fuer den Simulationsstart."""

    model_config = ConfigDict(extra="forbid")

    irradiance_w_m2: int = Field(ge=0, le=1600)
    module_temperature_c: float = Field(ge=-40, le=120)
    ambient_temperature_c: float = Field(ge=-50, le=70)
    wind_speed_m_s: float = Field(ge=0, le=100)


class AssetFixture(BaseModel):
    """Einzelner Asset-Zustand innerhalb eines Start-Fixtures."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str
    asset_type: Literal[
        "power_plant_controller",
        "inverter_block",
        "weather_station",
        "revenue_meter",
        "grid_interconnect",
        "tracker_controller",
    ]
    status: Literal["online", "offline", "degraded", "faulted"]
    communication_state: Literal["healthy", "degraded", "lost"]
    quality: Literal["good", "estimated", "stale", "invalid"]
    measurements: dict[str, float | int | str | bool] = Field(default_factory=dict)


class AlarmFixture(BaseModel):
    """Alarmzustand fuer den Teststart."""

    model_config = ConfigDict(extra="forbid")

    alarm_code: str
    category: Literal["communication", "process", "control", "equipment", "site"]
    severity: Literal["low", "medium", "high", "critical"]
    state: Literal["inactive", "active_unacknowledged", "active_acknowledged", "cleared"]


class PlantFixture(BaseModel):
    """Kompletter Startzustand fuer Tests und spaetere Simulation."""

    model_config = ConfigDict(extra="forbid")

    fixture_name: str
    start_time: datetime
    site_state: SiteStateFixture
    weather: WeatherFixture
    assets: list[AssetFixture]
    active_alarms: list[AlarmFixture]

    @field_validator("start_time")
    @classmethod
    def validate_start_time(cls, value: datetime) -> datetime:
        return ensure_utc_datetime(value)

    def build_clock(self) -> FrozenClock:
        """Erzeugt eine deterministische Test-Uhr fuer dieses Fixture."""

        return FrozenClock(self.start_time)


def available_fixture_names(*, fixture_dir: Path = FIXTURE_DIR) -> tuple[str, ...]:
    """Listet alle eingebauten Fixture-Namen ohne Dateiendung."""

    if not fixture_dir.is_dir():
        return ()
    return tuple(sorted(path.stem for path in fixture_dir.glob("*.json")))


def load_plant_fixture(name: str, *, fixture_dir: Path = FIXTURE_DIR) -> PlantFixture:
    """Laedt ein Start-Fixture aus dem Repo-Verzeichnis."""

    fixture_path = fixture_dir / f"{name}.json"
    if not fixture_path.is_file():
        raise FixtureLoadError(f"Fixture '{name}' wurde nicht gefunden: {fixture_path}")

    try:
        payload = json.loads(fixture_path.read_text(encoding="utf-8"))
        fixture = PlantFixture.model_validate(payload)
    except OSError as exc:
        raise FixtureLoadError(f"Fixture '{name}' konnte nicht gelesen werden") from exc
    except json.JSONDecodeError as exc:
        raise FixtureLoadError(f"Fixture '{name}' ist kein gueltiges JSON") from exc
    except ValidationError as exc:
        raise FixtureLoadError(f"Fixture '{name}' ist fachlich ungueltig: {exc}") from exc

    if fixture.fixture_name != name:
        raise FixtureLoadError(
            f"Fixture-Datei '{name}' enthaelt inkonsistenten fixture_name '{fixture.fixture_name}'"
        )
    return fixture
