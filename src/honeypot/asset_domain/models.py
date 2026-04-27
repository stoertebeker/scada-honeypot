"""Typisierte Fachmodelle fuer den statischen Anlagenzustand."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from math import isclose
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from honeypot.asset_domain.fixtures import AssetFixture, PlantFixture

OperatingMode = Literal["normal", "curtailed", "maintenance", "faulted"]
AvailabilityState = Literal["available", "partially_available", "unavailable"]
BreakerState = Literal["closed", "open", "transitioning"]
DcDisconnectState = Literal["closed", "open", "transitioning"]
CommunicationState = Literal["healthy", "degraded", "lost"]
AssetStatus = Literal["online", "offline", "degraded", "faulted"]
DataQuality = Literal["good", "estimated", "stale", "invalid"]
ControlAuthority = Literal["local_auto", "remote_scada", "schedule"]
GridAcceptanceState = Literal["accepted", "limited", "unavailable"]
AlarmCategory = Literal["communication", "process", "control", "equipment", "site"]
AlarmSeverity = Literal["low", "medium", "high", "critical"]
AlarmLifecycleState = Literal["inactive", "active_unacknowledged", "active_acknowledged", "cleared"]


class DomainModelBuildError(ValueError):
    """Signalisiert unvollstaendige oder inkonsistente Fachdaten."""


class SiteState(BaseModel):
    """Globaler Anlagenzustand als gemeinsame Wahrheit fuer V1."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operating_mode: OperatingMode
    availability_state: AvailabilityState
    plant_power_mw: float = Field(ge=0)
    plant_power_limit_pct: float = Field(ge=0, le=100, multiple_of=0.1)
    reactive_power_setpoint: float = Field(ge=-1.0, le=1.0)
    breaker_state: BreakerState
    communications_health: CommunicationState
    active_alarm_count: int = Field(ge=0)


class AssetBase(BaseModel):
    """Gemeinsame Statusbasis fuer fachliche Assets."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    asset_id: str = Field(min_length=1)
    status: AssetStatus
    communication_state: CommunicationState
    quality: DataQuality
    last_update_ts: datetime


class PowerPlantController(AssetBase):
    """Zentrale Setpoint- und Betriebsinstanz des Parks."""

    active_power_limit_pct: float = Field(ge=0, le=100, multiple_of=0.1)
    reactive_power_target: float = Field(ge=-1.0, le=1.0)
    control_authority: ControlAuthority


class InverterBlock(AssetBase):
    """Aggregierter Wechselrichter-Block fuer V1."""

    block_power_kw: float = Field(ge=0)
    availability_pct: int = Field(ge=0, le=100)
    dc_disconnect_state: DcDisconnectState = "closed"
    block_dc_voltage_v: float | None = Field(default=None, ge=0)
    block_dc_current_a: float | None = Field(default=None, ge=0)
    block_ac_voltage_v: float | None = Field(default=None, ge=0)
    block_ac_current_a: float | None = Field(default=None, ge=0)
    internal_temperature_c: float | None = None


class WeatherStation(AssetBase):
    """Wetterstation mit den fuer die Simulation relevanten Umgebungswerten."""

    irradiance_w_m2: int = Field(ge=0, le=1600)
    module_temperature_c: float = Field(ge=-40, le=120)
    ambient_temperature_c: float = Field(ge=-50, le=70)
    wind_speed_m_s: float = Field(ge=0, le=100)


class RevenueMeter(AssetBase):
    """Abrechnungssicht am Netzabgabepunkt."""

    export_power_kw: float = Field(ge=0)
    power_factor: float = Field(ge=-1.0, le=1.0)
    export_energy_mwh_total: float | None = Field(default=None, ge=0)
    grid_voltage_v: float | None = Field(default=None, ge=0)
    grid_frequency_hz: float | None = Field(default=None, ge=0)


class GridInterconnect(AssetBase):
    """Netzuebergabepunkt mit Breaker- und Pfadzustand."""

    breaker_state: BreakerState
    export_path_available: bool
    grid_acceptance_state: GridAcceptanceState


class PlantAlarm(BaseModel):
    """Typisierter Alarmzustand fuer das Fachmodell."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(min_length=1)
    category: AlarmCategory
    severity: AlarmSeverity
    state: AlarmLifecycleState

    @property
    def is_active(self) -> bool:
        return self.state in ("active_unacknowledged", "active_acknowledged")


class PlantSnapshot(BaseModel):
    """Typisierter Startzustand fuer Tests und spaetere Simulation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_name: str = Field(min_length=1)
    start_time: datetime
    observed_at: datetime
    site: SiteState
    power_plant_controller: PowerPlantController
    inverter_blocks: tuple[InverterBlock, ...]
    weather_station: WeatherStation
    revenue_meter: RevenueMeter
    grid_interconnect: GridInterconnect
    alarms: tuple[PlantAlarm, ...] = ()

    @model_validator(mode="after")
    def validate_consistency(self) -> "PlantSnapshot":
        if not self.inverter_blocks:
            raise ValueError("mindestens ein inverter_block ist erforderlich")
        if self.site.breaker_state != self.grid_interconnect.breaker_state:
            raise ValueError("site.breaker_state und grid_interconnect.breaker_state muessen uebereinstimmen")
        if not isclose(
            self.site.plant_power_limit_pct,
            self.power_plant_controller.active_power_limit_pct,
            abs_tol=1e-9,
        ):
            raise ValueError(
                "site.plant_power_limit_pct und power_plant_controller.active_power_limit_pct muessen uebereinstimmen"
            )
        if not isclose(
            self.site.reactive_power_setpoint,
            self.power_plant_controller.reactive_power_target,
            abs_tol=1e-9,
        ):
            raise ValueError(
                "site.reactive_power_setpoint und power_plant_controller.reactive_power_target muessen uebereinstimmen"
            )
        if self.site.active_alarm_count != len(self.active_alarms):
            raise ValueError("site.active_alarm_count muss der Anzahl aktiver Alarmcodes entsprechen")
        return self

    @property
    def active_alarms(self) -> tuple[PlantAlarm, ...]:
        return tuple(alarm for alarm in self.alarms if alarm.is_active)

    @property
    def active_alarm_codes(self) -> tuple[str, ...]:
        return tuple(alarm.code for alarm in self.active_alarms)

    def alarm_by_code(self, code: str) -> PlantAlarm | None:
        for alarm in self.alarms:
            if alarm.code == code:
                return alarm
        return None

    @property
    def total_inverter_power_kw(self) -> float:
        return sum(block.block_power_kw for block in self.inverter_blocks)

    @classmethod
    def from_fixture(cls, fixture: PlantFixture) -> "PlantSnapshot":
        """Uebersetzt ein validiertes Fixture in ein typisiertes Fachmodell."""

        ppc_asset = _require_single_asset(fixture.assets, "power_plant_controller")
        weather_asset = _require_single_asset(fixture.assets, "weather_station")
        meter_asset = _require_single_asset(fixture.assets, "revenue_meter")
        grid_asset = _require_single_asset(fixture.assets, "grid_interconnect")
        inverter_assets = tuple(
            sorted(_assets_of_type(fixture.assets, "inverter_block"), key=lambda asset: asset.asset_id)
        )

        alarms = tuple(
            PlantAlarm(
                code=alarm.alarm_code,
                category=alarm.category,
                severity=alarm.severity,
                state=alarm.state,
            )
            for alarm in fixture.active_alarms
        )

        try:
            return cls(
                fixture_name=fixture.fixture_name,
                start_time=fixture.start_time,
                observed_at=fixture.start_time,
                site=SiteState.model_validate(fixture.site_state.model_dump()),
                power_plant_controller=PowerPlantController(
                    asset_id=ppc_asset.asset_id,
                    status=ppc_asset.status,
                    communication_state=ppc_asset.communication_state,
                    quality=ppc_asset.quality,
                    last_update_ts=fixture.start_time,
                    active_power_limit_pct=_measurement_int(ppc_asset, "active_power_limit_pct"),
                    reactive_power_target=_measurement_float(ppc_asset, "reactive_power_target"),
                    control_authority=_measurement_string(ppc_asset, "control_authority"),
                ),
                inverter_blocks=tuple(
                    InverterBlock(
                        asset_id=asset.asset_id,
                        status=asset.status,
                        communication_state=asset.communication_state,
                        quality=asset.quality,
                        last_update_ts=fixture.start_time,
                        block_power_kw=_measurement_float(asset, "block_power_kw"),
                        availability_pct=_measurement_int(asset, "availability_pct"),
                        dc_disconnect_state=_measurement_string(asset, "dc_disconnect_state", fallback="closed"),
                        block_dc_voltage_v=_optional_measurement_float(asset, "block_dc_voltage_v"),
                        block_dc_current_a=_optional_measurement_float(asset, "block_dc_current_a"),
                        block_ac_voltage_v=_optional_measurement_float(asset, "block_ac_voltage_v"),
                        block_ac_current_a=_optional_measurement_float(asset, "block_ac_current_a"),
                        internal_temperature_c=_optional_measurement_float(asset, "internal_temperature_c"),
                    )
                    for asset in inverter_assets
                ),
                weather_station=WeatherStation(
                    asset_id=weather_asset.asset_id,
                    status=weather_asset.status,
                    communication_state=weather_asset.communication_state,
                    quality=weather_asset.quality,
                    last_update_ts=fixture.start_time,
                    irradiance_w_m2=_measurement_int(
                        weather_asset,
                        "irradiance_w_m2",
                        fallback=fixture.weather.irradiance_w_m2,
                    ),
                    module_temperature_c=_measurement_float(
                        weather_asset,
                        "module_temperature_c",
                        fallback=fixture.weather.module_temperature_c,
                    ),
                    ambient_temperature_c=_measurement_float(
                        weather_asset,
                        "ambient_temperature_c",
                        fallback=fixture.weather.ambient_temperature_c,
                    ),
                    wind_speed_m_s=_measurement_float(
                        weather_asset,
                        "wind_speed_m_s",
                        fallback=fixture.weather.wind_speed_m_s,
                    ),
                ),
                revenue_meter=RevenueMeter(
                    asset_id=meter_asset.asset_id,
                    status=meter_asset.status,
                    communication_state=meter_asset.communication_state,
                    quality=meter_asset.quality,
                    last_update_ts=fixture.start_time,
                    export_power_kw=_measurement_float(meter_asset, "export_power_kw"),
                    power_factor=_measurement_float(meter_asset, "power_factor"),
                    export_energy_mwh_total=_optional_measurement_float(meter_asset, "export_energy_mwh_total"),
                    grid_voltage_v=_optional_measurement_float(meter_asset, "grid_voltage_v"),
                    grid_frequency_hz=_optional_measurement_float(meter_asset, "grid_frequency_hz"),
                ),
                grid_interconnect=GridInterconnect(
                    asset_id=grid_asset.asset_id,
                    status=grid_asset.status,
                    communication_state=grid_asset.communication_state,
                    quality=grid_asset.quality,
                    last_update_ts=fixture.start_time,
                    breaker_state=_measurement_string(grid_asset, "breaker_state"),
                    export_path_available=_measurement_bool(
                        grid_asset,
                        "export_path_available",
                        fallback=fixture.site_state.breaker_state == "closed",
                    ),
                    grid_acceptance_state=_measurement_string(grid_asset, "grid_acceptance_state"),
                ),
                alarms=alarms,
            )
        except ValidationError as exc:
            raise DomainModelBuildError(
                f"Fixture '{fixture.fixture_name}' konnte nicht in das Fachmodell uebersetzt werden"
            ) from exc


def _assets_of_type(assets: Iterable[AssetFixture], asset_type: str) -> tuple[AssetFixture, ...]:
    matching_assets = tuple(asset for asset in assets if asset.asset_type == asset_type)
    if not matching_assets:
        raise DomainModelBuildError(f"kein Asset vom Typ '{asset_type}' im Fixture vorhanden")
    return matching_assets


def _require_single_asset(assets: Iterable[AssetFixture], asset_type: str) -> AssetFixture:
    matching_assets = _assets_of_type(assets, asset_type)
    if len(matching_assets) != 1:
        raise DomainModelBuildError(f"genau ein Asset vom Typ '{asset_type}' erwartet, gefunden: {len(matching_assets)}")
    return matching_assets[0]


_MISSING = object()


def _measurement_value(asset: AssetFixture, name: str, *, fallback: object = _MISSING) -> object:
    if name in asset.measurements:
        return asset.measurements[name]
    if fallback is not _MISSING:
        return fallback
    raise DomainModelBuildError(f"Asset '{asset.asset_id}' fehlt Pflichtmesswert '{name}'")


def _measurement_float(asset: AssetFixture, name: str, *, fallback: object = _MISSING) -> float:
    value = _measurement_value(asset, name, fallback=fallback)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise DomainModelBuildError(f"Messwert '{name}' von Asset '{asset.asset_id}' muss numerisch sein")
    return float(value)


def _optional_measurement_float(asset: AssetFixture, name: str) -> float | None:
    if name not in asset.measurements:
        return None
    return _measurement_float(asset, name)


def _measurement_int(asset: AssetFixture, name: str, *, fallback: object = _MISSING) -> int:
    value = _measurement_value(asset, name, fallback=fallback)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise DomainModelBuildError(f"Messwert '{name}' von Asset '{asset.asset_id}' muss ganzzahlig sein")
    numeric_value = float(value)
    if not numeric_value.is_integer():
        raise DomainModelBuildError(f"Messwert '{name}' von Asset '{asset.asset_id}' muss ganzzahlig sein")
    return int(numeric_value)


def _measurement_string(asset: AssetFixture, name: str, *, fallback: object = _MISSING) -> str:
    value = _measurement_value(asset, name, fallback=fallback)
    if not isinstance(value, str) or not value:
        raise DomainModelBuildError(f"Messwert '{name}' von Asset '{asset.asset_id}' muss ein nichtleerer String sein")
    return value


def _measurement_bool(asset: AssetFixture, name: str, *, fallback: object = _MISSING) -> bool:
    value = _measurement_value(asset, name, fallback=fallback)
    if not isinstance(value, bool):
        raise DomainModelBuildError(f"Messwert '{name}' von Asset '{asset.asset_id}' muss boolesch sein")
    return value
