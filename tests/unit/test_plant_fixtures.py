import json
from pathlib import Path

import pytest

from honeypot.asset_domain import FixtureLoadError, available_fixture_names, load_plant_fixture


def test_available_fixture_names_lists_normal_operation(monkeypatch, tmp_path: Path) -> None:
    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir()
    (fixture_dir / "normal_operation.json").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert available_fixture_names() == ("normal_operation",)


def test_load_normal_operation_fixture(monkeypatch, tmp_path: Path) -> None:
    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir()
    payload = {
        "fixture_name": "normal_operation",
        "start_time": "2026-04-01T10:00:00Z",
        "site_state": {
            "operating_mode": "normal",
            "availability_state": "available",
            "plant_power_mw": 5.8,
            "plant_power_limit_pct": 100,
            "reactive_power_setpoint": 0.0,
            "breaker_state": "closed",
            "communications_health": "healthy",
            "active_alarm_count": 0,
        },
        "weather": {
            "irradiance_w_m2": 840,
            "module_temperature_c": 31.5,
            "ambient_temperature_c": 22.0,
            "wind_speed_m_s": 4.2,
        },
        "assets": [
            {
                "asset_id": "invb-01",
                "asset_type": "inverter_block",
                "status": "online",
                "communication_state": "healthy",
                "quality": "good",
                "measurements": {"block_power_kw": 1935, "availability_pct": 100},
            }
        ],
        "active_alarms": [],
    }
    (fixture_dir / "normal_operation.json").write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    fixture = load_plant_fixture("normal_operation")

    assert fixture.fixture_name == "normal_operation"
    assert fixture.site_state.breaker_state == "closed"
    assert fixture.weather.irradiance_w_m2 == 840
    assert fixture.assets[0].measurements["block_power_kw"] == 1935


def test_load_fixture_raises_for_missing_fixture(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "fixtures").mkdir()
    monkeypatch.chdir(tmp_path)

    with pytest.raises(FixtureLoadError, match="wurde nicht gefunden"):
        load_plant_fixture("normal_operation")


def test_load_fixture_rejects_invalid_payload(monkeypatch, tmp_path: Path) -> None:
    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir()
    payload = {"fixture_name": "normal_operation", "start_time": "2026-04-01T10:00:00Z"}
    (fixture_dir / "normal_operation.json").write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(FixtureLoadError, match="fachlich ungueltig"):
        load_plant_fixture("normal_operation")
