# Agent-Handoff

## Zwischenfazit

Das Repo ist nicht mehr nur in Dokumentationsnaehe. Die Deckscrew hat **Phase A
praktisch abgeschlossen**:

- Projektgeruest unter `src/`, `tests/`, `fixtures/`, `tools/` steht
- `uv`-Setup mit `pyproject.toml`, `.python-version` und `uv.lock` steht
- `config_core` laedt und validiert Runtime-Konfiguration aus `.env` und
  Umgebungsvariablen
- erstes mitgeliefertes Locale-Paket liegt unter
  `resources/locales/attacker-ui/en.json`
- erstes ladbares Start-Fixture `fixtures/normal_operation.json` ist vorhanden
- Zeitabstraktion fuer deterministische Tests ist vorhanden
- das Repo ist lokal startbar und die Unit-Tests laufen gruen

Wichtiger Kurs:

- **Nicht** mit Modbus oder HMI anfangen, bevor Phase B sauber steht
- naechster echter Bauabschnitt ist `asset_domain` plus `plant_sim`
- Ziel bleibt eine gemeinsame Wahrheit fuer Anlage, Zustaende, Setpoints und
  Alarme

## Letzte Commits

- `56e1f98` `feat: add typed asset domain snapshot`
- `cd18d1b` `feat: add deterministic test clock`
- `1ac917e` `feat: add loadable plant fixture`
- `2e294f1` `feat: add validated runtime config core`
- `9d4de02` `chore: ignore finder metadata`
- `80f4538` `docs: sync readme with phase-a scaffold`
- `9a8c35b` `chore: bootstrap phase-a project scaffold`

## Aktueller Implementierungsstand

### 1. Tooling und Einstiegspunkt

- `Python 3.12` und `uv` sind verdrahtet
- zentrale Paketdefinition in `pyproject.toml`
- minimaler Prozesseinstieg in `src/honeypot/main.py`
- Startkommando funktioniert:
  `uv run python -m honeypot.main`

### 2. Konfiguration

Dateien:

- `src/honeypot/config_core/__init__.py`
- `src/honeypot/config_core/settings.py`

Vorhanden:

- `RuntimeConfig`
- `load_runtime_config()`
- generische Defaults aus `.env.example`
- Validierung fuer:
  - Locale-Format `ll` oder `ll-RR`
  - vorhandenes Fallback-Locale-Bundle
  - Ports und numerische Schwellwerte
  - exporter-bezogene Pflichtfelder nur bei aktivierten Exportern

Wichtige Regel:

- `ATTACKER_UI_FALLBACK_LOCALE` muss auf ein mitgeliefertes Locale-Paket
  zeigen

### 3. Fixture-System

Dateien:

- `src/honeypot/asset_domain/fixtures.py`
- `fixtures/normal_operation.json`

Vorhanden:

- `PlantFixture` und Teilmodelle fuer Site, Weather, Assets und Alarme
- `load_plant_fixture()`
- `available_fixture_names()`
- klarer Fehlerpfad ueber `FixtureLoadError`
- erstes kanonisches Start-Fixture `normal_operation`

Wichtige Regel:

- Fixtures werden fachlich validiert und nicht stillschweigend akzeptiert

### 4. Zeitabstraktion

Datei:

- `src/honeypot/time_core.py`

Vorhanden:

- `SystemClock`
- `FrozenClock`
- UTC-Normalisierung ueber `ensure_utc_datetime()`
- ISO-Zeitstempel-Parsing ueber `parse_utc_timestamp()`
- `PlantFixture.build_clock()` fuer deterministische Teststarts

Wichtige Regel:

- Zeitwerte muessen timezone-aware und auf UTC normalisierbar sein

### 5. Fachmodell-Start fuer Phase B

Dateien:

- `src/honeypot/asset_domain/models.py`
- `src/honeypot/asset_domain/__init__.py`
- `tests/unit/test_asset_domain_models.py`

Vorhanden:

- typisierte Modelle fuer:
  - `SiteState`
  - `PowerPlantController`
  - `InverterBlock`
  - `WeatherStation`
  - `RevenueMeter`
  - `GridInterconnect`
  - `PlantSnapshot`
- Fixture-zu-Domaenen-Mapping ueber `PlantSnapshot.from_fixture()`
- Konsistenzchecks fuer:
  - Breaker-Zustand Site gegen Grid
  - Power-Limit Site gegen PPC
  - Blindleistungs-Setpoint Site gegen PPC
  - aktive Alarmanzahl gegen aktive Alarmcodes
- erster Unit-Test fuer `normal_operation`

## Teststand

Aktuell gruen:

- `uv run pytest`

Letzter bekannter Lauf:

- `18 passed`

Abgedeckt sind bisher:

- Scaffold und Prozesseinstieg
- Konfigurationsdefaults und Fehlkonfiguration
- Fixture-Laden und Fehlerpfade
- Zeitabstraktion und deterministische Uhr
- typisiertes Asset-Domain-Snapshot aus `normal_operation`

## Sicherheitsplanken

Weiter verbindlich:

- keine reale OEM-Kopie
- keine echten Orts-, Firmen- oder Zugangsdaten
- keine Shell- oder Host-Zugriffspfade
- keine echte Fernsteuerung externer Systeme
- Logging bleibt Kernfunktion
- nur die angreiferzugewandte HMI ist lokalisierbar
- Admin-Sicht und Logs bleiben deutsch

Bereits implizit abgesichert:

- Konfiguration weist ungueltige Locale- und Exporter-Einstellungen frueh ab
- Fixtures weisen fachlich schiefe Startdaten frueh ab
- Zeitwerte sind fuer Tests kontrollierbar und UTC-konsistent

## Offene Luecken

Noch **nicht** vorhanden:

- Simulationskern fuer normale Erzeugung, Curtailment, Breaker offen,
  Kommunikationsverlust
- Alarmzustandslogik jenseits des Fixture-Snapshots
- Event-Core, Storage, Outbox
- Modbus-Server
- HMI
- Exporter-Implementierung

Operative Hinweise:

- Git-Remote ist derzeit nicht konfiguriert; `push` ist also nicht moeglich
- Arbeitsbaum war beim letzten Handoff sauber

## Naechster Schritt

### Phase B beginnen

Direkter Kurs fuer den naechsten Agenten:

1. `plant_sim` fuer die Kernszenarien aufziehen
2. zuerst nur fachlich und testbar, noch ohne Modbus oder HMI
3. danach Event-Core, Storage und Outbox anschliessen

Empfohlener erster atomarer Fix in Phase B:

- deterministische Simulationslogik fuer:
  - `normal`
  - `curtailed`
  - `breaker_open`
  - `comm_loss_single_block`
- plus fokussierte Unit-Tests fuer Ursache/Wirkung im Fachmodell

Nicht als naechstes tun:

- keinen Modbus-Vertical-Slice vorziehen
- keine HMI vorziehen
- keine Storage- oder Exporter-Pfade anfassen, bevor das Fachmodell steht

## Vor dem Weiterbauen lesen

- `docs/v1-decisions.md`
- `docs/implementation-roadmap.md`
- `docs/domain-model.md`
- `docs/protocol-profile.md`
- `docs/register-matrix.md`
- `docs/hmi-concept.md`
- `docs/logging-and-events.md`
- `docs/testing-strategy.md`
- `docs/security-operations.md`
