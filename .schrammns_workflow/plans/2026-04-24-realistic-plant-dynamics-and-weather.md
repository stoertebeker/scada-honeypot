# Plan: Realistische Plant-Dynamics und Weather-Provider

**Date:** 2026-04-24
**Source:** `.schrammns_workflow/research/2026-04-24-realistic-plant-dynamics-and-weather.md`

## Context
Der Honeypot ist funktional weit, wirkt im Normalbetrieb aber sichtbar statisch: Die Runtime bootet einen festen Fixture-Snapshot, die HMI zeigt dessen `start_time`, und `/trends` vergleicht nur Baseline gegen aktuellen Snapshot statt echter Zeitverlaeufe. Das ist fuer lokale V1-Tests tragbar, fuer glaubhafte Beobachtung im offenen Netz aber eine erkennbare Schwaeche. `.schrammns_workflow/research/2026-04-24-realistic-plant-dynamics-and-weather.md`, `src/honeypot/main.py:148-167`, `src/honeypot/hmi_web/app.py:2145-2223`

Fuer mehr Realismus braucht der Honeypot drei neue Schichten auf derselben gemeinsamen Wahrheit: (1) tickende Anlagenzeit und Datenfrische, (2) eine interne Wetterquelle per Koordinate, (3) eine daraus abgeleitete Leistungs- und Trenddynamik. Der echte Ort darf dabei intern konfigurierbar sein, aber nirgends in HMI, Modbus, Event-Details, Findings oder Exportern sichtbar werden. `.schrammns_workflow/research/2026-04-24-realistic-plant-dynamics-and-weather.md`, `src/honeypot/protocol_modbus/registers.py:931-942`, `src/honeypot/config_core/settings.py:68-119`

## Files to Modify

| File | Change |
|------|--------|
| `src/honeypot/config_core/settings.py` | interne Geo-/Wetter-Config, Refresh- und Cache-Settings ergaenzen |
| `src/honeypot/asset_domain/models.py` | `observed_at`/`last_update_ts` und ggf. interne Wetterkontext-Felder modellieren |
| `src/honeypot/asset_domain/fixtures.py` | Fixture-Clock weiter nutzbar halten; ggf. Startfelder fuer Evolutionskern vorbereiten |
| `src/honeypot/plant_sim/core.py` | Leistungsableitung von Wetter, Tageszeit und Verfuegbarkeit ausbauen |
| `src/honeypot/protocol_modbus/registers.py` | sicheren Snapshot-Evolutionspfad und ggf. Frische-/Confidence-Ableitung ausbauen |
| `src/honeypot/hmi_web/app.py` | tickende Zeit, echte kleine Trendhistorie, keine Standort-Leaks |
| `src/honeypot/main.py` | Background-Evolution- und Weather-Services verdrahten |
| `src/honeypot/time_core.py` | ggf. Hilfen fuer lokale Zeitzonen-/Ticklogik ergaenzen |
| `src/honeypot/monitoring/runtime_status.py` | optional Weather-/Evolution-Health im Heartbeat sichtbar machen |
| `src/honeypot/weather_core/__init__.py` | **NEW** — Wettermodul exportieren |
| `src/honeypot/weather_core/models.py` | **NEW** — interne `WeatherObservation`-/Cache-Modelle |
| `src/honeypot/weather_core/provider.py` | **NEW** — Provider-Interface und Deterministic-Fallback |
| `src/honeypot/weather_core/open_meteo.py` | **NEW** — Open-Meteo Forecast/Satellite Adapter ohne Leak nach aussen |
| `src/honeypot/runtime_evolution.py` | **NEW** — BackgroundPlantEvolutionService und kleine In-Memory-Historie |
| `tests/unit/test_runtime_config.py` | Config-Validierung fuer Koordinaten, Provider, Refresh, Cache |
| `tests/unit/test_asset_domain_models.py` | neue Zeit-/Frischefelder absichern |
| `tests/unit/test_plant_sim.py` | Leistungsmodell, Tagesgang und Wetterableitung pruefen |
| `tests/unit/test_protocol_modbus_registers.py` | Wetter-/Confidence-/Frische-Abbildung pruefen |
| `tests/integration/test_hmi_web_overview.py` | tickende Snapshot-Zeit und echte kleine Trends absichern |
| `tests/integration/test_runtime_main.py` | Background-Evolution- und Zielhost-Betrieb pruefen |
| `docs/domain-model.md` | `last_update_ts`/`observed_at` und Wetter-/Frischemodell synchronisieren |
| `docs/hmi-concept.md` | kleine Zeitreihen statt Baseline-only dokumentieren |
| `docs/protocol-profile.md` | Modbus-Sicht auf Wetterfrische/Confidence ggf. nachziehen |
| `docs/register-matrix.md` | Registerbedeutung bei Wetterconfidence/Qualitaet aktualisieren |
| `README.md` | neue Wetter-/Realismus-Config und Betriebsmodell erklaeren |

## Boundaries

**Always:** eine gemeinsame Wahrheit fuer HMI, Modbus und Events; Koordinaten nur intern; deterministische Offline-Tests; ruhige Fehlerpfade bei Wetter-API-Ausfall; keine zweite UI- oder Protokollwahrheit.
**Ask First:** Wechsel des externen Wetteranbieters von Open-Meteo; globale Abdeckung ausserhalb Europa mit Satellite-Radiation-Only-Ansatz; neue oeffentliche Angriffsoberflaechen oder Debug-Endpunkte.
**Never:** rohe Geo-Eingaben oder volle Wetterantworten in sichtbaren Pfaden, Findings, internen Telemetrie-Details oder Exporter-Payloads; exakte Ortsdaten in Browser-/Angreifersichten; ungecachte Live-Requests pro Benutzerzugriff.

## Design Decisions

| Decision | Chosen | Rejected Alternatives | Rationale |
|----------|--------|----------------------|-----------|
| Evolutionskern | eigener `BackgroundPlantEvolutionService` in `runtime_evolution.py` | Mutation in HMI-Handlern, Mutation im Modbus-Server | trennt Zeitfortschritt von Zugriffswegen und haelt gemeinsame Wahrheit sauber |
| Wetterintegration | Provider-Interface + Deterministic-Fallback + Open-Meteo Adapter | direkter `httpx`-Call in `main.py`, direkter Call in `plant_sim` | testbar, austauschbar und ohne harte Netzabhaengigkeit in Kernlogik |
| Ortskonfiguration | interne `weather_latitude`/`weather_longitude` in Config | Ortstext, sichtbare Geo-Felder, Ableitung aus `site_name` | erfuellt Nutzerwunsch und minimiert Leckrisiko |
| Zeitdarstellung | `observed_at`/`last_update_ts` im Snapshot-/Asset-Modell | nur UI-seitiger „current time“-Hack | Frische, Trends und Quality lassen sich dann fachlich begruenden |
| Trendmodell | kleine In-Memory-Ringbuffer-Historie mit 5-15min Punkten | Eventstore als primäre Historie, Baseline-vs-Snapshot beibehalten | genug Realismus fuer V1, ohne sofort ein volles Historien-Subsystem zu bauen |
| Wetterquelle | Forecast API zuerst, Satellite Radiation optional priorisiert pro Region | nur synthetischer Sinus, nur Satellite API, fremde Drittanbieter | Forecast ist global robuster; Satellite ist spaeterer Qualitaetsschub |

## Baseline Audit

| Metric | Command | Result |
|--------|---------|--------|
| Gesamttestlauf vor Planung | `uv run pytest -q` | 274 passed |
| Statische Snapshot-Zeit | `rg -n "_snapshot_time|snapshot.start_time|build_trends_view_model" src/honeypot/hmi_web/app.py src/honeypot/main.py fixtures/normal_operation.json` | HMI und Trends haengen am Fixture-Zeitpunkt |
| Fehlende Geo-Config | `rg -n "latitude|longitude|weather_provider|cache_ttl|refresh_seconds" src/honeypot/config_core/settings.py` | keine Wetter-/Geo-Settings vorhanden |
| Fehlende Asset-Frische im Code | `rg -n "last_update_ts|observed_at" src/honeypot docs/domain-model.md` | nur in Doku, nicht im Modell |

## Implementation

### 1. Zeit- und Frischemodell in die gemeinsame Wahrheit ziehen

In `src/honeypot/asset_domain/models.py`:
- **Modify `AssetBase`**: `last_update_ts: datetime` oder aehnlichen Zeitanker aufnehmen.
- **Modify `PlantSnapshot`**: `observed_at: datetime` als globalen Runtime-Zeitpunkt modellieren.
- **Modify `PlantSnapshot.from_fixture()`**: `start_time` als initialen `observed_at` und `last_update_ts` aller Assets setzen.

In `src/honeypot/asset_domain/fixtures.py`:
- **Keep `PlantFixture.start_time` as seed** und dokumentiere/teste sauber, dass daraus die initialen Update-Zeitstempel entstehen.

In `src/honeypot/hmi_web/app.py`:
- **Modify `_snapshot_time()`**: nicht mehr `start_time`, sondern `observed_at` darstellen.
- **Reuse** `_tone_for_quality()` fuer spaetere Frische-/Qualitaetsdarstellung.

In `src/honeypot/protocol_modbus/registers.py`:
- **Add `replace_snapshot()`** oder `evolve_snapshot()`** auf `ReadOnlyRegisterMap`**: atomarer Tausch des Snapshots unter Lock.

In `src/honeypot/time_core.py`:
- **Add helpers only if needed** fuer kontrollierte Tick- und Lokaltime-Abbildung ohne Testinstabilitaet.

### 2. Hintergrund-Evolution statt statischem Snapshot

In `src/honeypot/runtime_evolution.py`:
- **Add `BackgroundPlantEvolutionService`**:
  ```python
  @dataclass(slots=True)
  class BackgroundPlantEvolutionService:
      register_map: ReadOnlyRegisterMap
      clock: Clock
      interval_seconds: int
  ```
- **Add small `TrendHistoryBuffer`** fuer Plant Power, Irradiance, Export Power und Block Power.
- **Add `evolve_once()`**: Zeit fortschreiben, Wetter beobachten, Leistungsmodell anwenden, Historie aktualisieren.

In `src/honeypot/main.py`:
- **Modify `LocalRuntime`**: evolution service optional aufnehmen, starten und stoppen.
- **Modify `build_local_runtime()`**: Weather- und Evolution-Objekte verdrahten.

In `tests/integration/test_runtime_main.py`:
- **Add runtime proofs** fuer laufende Evolution und Zielhost-Sweep mit aktivem Evolutionspfad.

### 3. Wetter-Config und Provider-Abstraktion

In `src/honeypot/config_core/settings.py`:
- **Add fields**:
  - `weather_latitude: float | None`
  - `weather_longitude: float | None`
  - `weather_elevation_m: float | None`
  - `weather_provider: Literal["disabled", "deterministic", "open_meteo_forecast", "open_meteo_satellite"]`
  - `weather_refresh_seconds: int`
  - `weather_cache_ttl_seconds: int`
  - `weather_request_timeout_seconds: int`
- **Add validators** fuer Koordinatenbereich, sinnvolle Defaults und gekoppelte Pflichtfelder.

In `src/honeypot/weather_core/models.py`:
- **Add `WeatherObservation`** mit nur internen, abgeleiteten Wetterfeldern und Frischemetadaten.

In `src/honeypot/weather_core/provider.py`:
- **Add `WeatherObservationProvider` protocol** und `DeterministicDiurnalWeatherProvider` als Offline-/Test-Fallback.

In `src/honeypot/weather_core/__init__.py`:
- **Export** die internen Provider- und Beobachtungsmodelle fuer Runtime-Verdrahtung und Tests.

In `tests/unit/test_runtime_config.py`:
- **Add config proofs** fuer Koordinatenbereich, Providerwahl und Refresh-/Cache-Defaults.

### 4. Open-Meteo-Adapter mit Leak-Schutz

In `src/honeypot/weather_core/open_meteo.py`:
- **Add `OpenMeteoForecastProvider`** fuer Temperatur, Wind, Tagesstatus, Sonnenzeiten und Strahlung.
- **Add optional `OpenMeteoSatelliteRadiationProvider`** fuer realistischere Einstrahlung, mit Forecast-Fallback.
- **Reuse `httpx`** fuer Requests.
- **Never log** rohe URLs mit Koordinaten; nur Provider-Typ, Erfolg/Fehler, Latenz und Datenalter in interne Events/Monitoring schreiben.

### 5. Leistungsmodell aus Wetter ableiten

In `src/honeypot/plant_sim/core.py`:
- **Modify `PlantSimulator.estimate_available_power_kw()`**: nicht nur lineare Skalierung mit GHI, sondern Temperatur- und Verfuegbarkeitsfaktor ergaenzen.
- **Add helper** fuer Blockleistungsverteilung mit kleiner Asymmetrie/Jitter.
- **Add helper** fuer `RevenueMeter.export_power_kw` mit leichten Verlusten gegenüber Blocksumme.
- **Keep** Curtailment, Breaker und Block-Controls als harte fachliche Overrides ueber dem neuen Wetterpfad.

### 6. Sichtbare Trends und Schutz vor Standort-Leaks

In `src/honeypot/hmi_web/app.py`:
- **Modify `build_trends_view_model()`**: statt Baseline-Fixture den Ringbuffer aus `runtime_evolution` lesen.
- **Modify weather/meter pages**: Frische, `quality` und ggf. lokale Zeit glaubhaft darstellen.
- **Never surface** `weather_latitude`, `weather_longitude`, Providerpayload oder Elevation.

In `src/honeypot/monitoring/runtime_status.py`:
- **Add optional health summary**: Weather source healthy/estimated/stale, letztes Update, kein Ort.

In docs:
- **Sync** Domain-, HMI- und Registerkarten auf die neue Frische-/Trendlogik.

## Tests

`tests/unit/test_runtime_config.py` — add:
- `test_weather_coordinates_require_valid_ranges`
- `test_open_meteo_provider_requires_coordinates_when_enabled`
- `test_deterministic_weather_provider_can_run_without_coordinates`

`tests/unit/test_asset_domain_models.py` — add:
- `test_snapshot_from_fixture_sets_observed_at_and_asset_last_update_ts`
- `test_snapshot_consistency_rejects_non_aware_update_timestamps`

`tests/unit/test_plant_sim.py` — add:
- `test_estimate_available_power_reflects_irradiance_and_temperature`
- `test_revenue_meter_tracks_weather_derived_output_with_losses`
- `test_block_distribution_preserves_total_power_under_weather_evolution`

`tests/unit/test_protocol_modbus_registers.py` — add:
- `test_unit_21_confidence_reflects_weather_data_age_not_only_flags`
- `test_register_map_replace_snapshot_is_atomic_and_visible_across_units`

`tests/integration/test_hmi_web_overview.py` — add:
- `test_overview_snapshot_time_advances_with_runtime_clock`
- `test_trends_page_renders_time_series_not_fixture_baseline`
- `test_hmi_never_exposes_weather_coordinates_or_provider_payload`

`tests/integration/test_runtime_main.py` — add:
- `test_runtime_background_evolution_updates_weather_and_power`
- `test_verify_exposed_research_target_host_works_with_weather_provider_enabled`

`tests/unit/test_weather_core.py` — **NEW**:
- `test_deterministic_provider_follows_local_day_night_pattern`
- `test_open_meteo_response_is_reduced_to_internal_observation`
- `test_open_meteo_errors_fall_back_to_cached_or_estimated_quality`

## Verification

```bash
# Plan validation
python3 /Users/schrammn/.codex/skills/set-course/scripts/validate_plan.py \
  .schrammns_workflow/plans/2026-04-24-realistic-plant-dynamics-and-weather.md

# Focused config/domain/weather checks
uv run pytest -q tests/unit/test_runtime_config.py tests/unit/test_asset_domain_models.py tests/unit/test_weather_core.py

# Focused sim/runtime checks
uv run pytest -q tests/unit/test_plant_sim.py tests/unit/test_protocol_modbus_registers.py tests/integration/test_runtime_main.py -k "weather or evolution or exposed_research"

# HMI visibility and leak checks
uv run pytest -q tests/integration/test_hmi_web_overview.py -k "snapshot_time or trends or coordinates"

# Full suite
uv run pytest -q

# Manual local rehearsal
uv run python -m honeypot.main --env-file .env --verify-exposed-research-target-host
```

## Issues

### Issue 1: Zeit- und Frischemodell in Snapshot und Assets verankern
**Size:** M
**Risk:** reversibel / mittel / keine neue Aussenkante
**Dependencies:** None
**Acceptance:** Config-/Modelltests gruen; HMI zeigt fortschreibbaren `observed_at` statt Fixture-Startzeit; siehe Verification-Abschnitt 2 und 4.
**Description:** `src/honeypot/asset_domain/models.py`, `src/honeypot/asset_domain/fixtures.py`, `src/honeypot/time_core.py`, `src/honeypot/hmi_web/app.py`, `src/honeypot/protocol_modbus/registers.py` und `tests/unit/test_asset_domain_models.py` erweitern, damit `observed_at`/`last_update_ts` fachlich vorhanden, testbar und atomar austauschbar sind.

### Issue 2: Background-Evolution-Service fuer gemeinsame Wahrheit und Ringbuffer
**Size:** M
**Risk:** reversibel / mittel / Nebenwirkung auf Runtime-Takt
**Dependencies:** Issue 1
**Acceptance:** Laufende Runtime aendert Wetter-/Leistungswerte ohne Schreibaktion; enge Runtime-Integrationstests gruen; siehe Verification-Abschnitt 3 und 6.
**Description:** `src/honeypot/runtime_evolution.py` neu anlegen, `src/honeypot/main.py` verdrahten, kleine Trendhistorie in Prozessspeicher aufbauen.

### Issue 3: Wetter-Config und deterministischer Provider
**Size:** M
**Risk:** reversibel / gering / keine neue Netzpflicht
**Dependencies:** Issue 1
**Acceptance:** Neue Config-Felder validieren sauber, deterministischer Provider liefert plausible Tag-/Nachtwerte lokal und in Tests; siehe Verification-Abschnitt 2.
**Description:** `src/honeypot/config_core/settings.py`, `src/honeypot/weather_core/models.py`, `src/honeypot/weather_core/provider.py`, `src/honeypot/weather_core/__init__.py`, `tests/unit/test_runtime_config.py` und neue `tests/unit/test_weather_core.py`.

### Issue 4: Open-Meteo-Adapter mit Cache und Standort-Leak-Schutz
**Size:** M
**Risk:** reversibel / mittel / externer Egress-Pfad intern
**Dependencies:** Issue 3
**Acceptance:** Provider reduziert Open-Meteo auf interne Observation, keine Koordinaten in Events/HMI/Status, Fallback bei Fehlern; siehe Verification-Abschnitt 2, 3 und 4.
**Description:** `src/honeypot/weather_core/open_meteo.py`, `src/honeypot/monitoring/runtime_status.py`, `tests/unit/test_weather_core.py` und `tests/integration/test_hmi_web_overview.py`.

### Issue 5: Wettergetriebene Leistungs- und Meterdynamik
**Size:** M
**Risk:** reversibel / mittel / sichtbare Verhaltensaenderung
**Dependencies:** Issue 2, Issue 3
**Acceptance:** Plant power, block power und export power folgen plausibel Wetter und Overrides; Curtailment/Breaker bleiben korrekt; siehe Verification-Abschnitt 3.
**Description:** `src/honeypot/plant_sim/core.py`, `src/honeypot/protocol_modbus/registers.py`, `tests/unit/test_plant_sim.py` und `tests/unit/test_protocol_modbus_registers.py`.

### Issue 6: Echte Mini-Historie fuer `/trends` und Doku-Sync
**Size:** M
**Risk:** reversibel / gering / UI-only plus docs
**Dependencies:** Issue 2, Issue 5
**Acceptance:** `/trends` zeigt kleine echte Zeitreihen statt Baseline-Vergleich; Doku und Leak-Tests gruen; siehe Verification-Abschnitt 4 und 5.
**Description:** `src/honeypot/hmi_web/app.py`, `docs/domain-model.md`, `docs/hmi-concept.md`, `docs/protocol-profile.md`, `docs/register-matrix.md`, `README.md`, passende Integrations- und Doku-Tests.

## Invalidation Risks

| Assumption | If Wrong, Impact | Affected Issues |
|------------|-----------------|-----------------|
| Open-Meteo bleibt als primaere Wetterquelle zulaessig | Externer Provider-Pfad muss ausgetauscht oder abgeschaltet werden | 3, 4 |
| Kleine In-Memory-Historie reicht fuer HMI-Realismus | Es waere spaeter ein persistenter Historienpfad noetig | 2, 6 |
| Temperatur-/GHI-basiertes empirisches Leistungsmodell reicht | Es waere ein detaillierteres Ertragsmodell mit Tilt/Azimuth noetig | 5 |
| Koordinaten duerfen intern in `.env` stehen | Sonst waere ein separater Secret-/Vault-Pfad noetig | 3, 4 |

## Execution Order

**Wave 1**: Issue 1, Issue 3
**Wave 2** (after Wave 1): Issue 2
**Wave 3** (after Wave 2): Issue 4, Issue 5
**Wave 4** (after Wave 3): Issue 6

## Rollback Strategy

**Git checkpoint:** Vor Umsetzung einen Rollback-Branch erstellen:
`git branch rollback/2026-04-24-realistic-plant-dynamics-and-weather`

**Per-wave rollback:** Nach jeder Wave bleibt ein atomarer Commit-Schnitt. Bei Fehlkurs:
`git revert --no-commit <wave-commit>`

**Per-issue rollback notes:**
- Issue 1: Modell-/View-Rollback problemlos, wenn neue Zeitfelder noch nicht von anderen Wellen genutzt werden
- Issue 2: Background-Service komplett entfernbar, solange Weather/Trends noch nicht darauf aufsetzen
- Issue 3: Deterministic Provider kann ohne Open-Meteo bestehen bleiben
- Issue 4: Open-Meteo-Adapter notfalls ganz deaktivierbar, wenn Leak-/Egress-Bedenken bleiben
- Issue 5: Leistungsmodell separat revertierbar, wenn Wetterpfad bleiben soll
- Issue 6: Trends koennen notfalls auf Baseline-Modell zurueckgesetzt werden

## Next Steps
- **Nach Freigabe direkt umsetzbar:** Issue 1 als erster atomarer Schlag
- **Parallel organisatorisch:** neue Realismus-Epic in `bd` anlegen und die sechs Issues spiegeln
- **Wichtigster Sicherheitscheck vor Implementierung:** klare Regel, dass Geo-Config und rohe Weather-Payloads nie in sichtbare Pfade gelangen
