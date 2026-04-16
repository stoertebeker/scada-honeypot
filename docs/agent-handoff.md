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
- `asset_domain`, `plant_sim` und der Start von `event_core` stehen jetzt als
  gemeinsamer Fachkern
- Ziel bleibt die lueckenlose Eventspur fuer jede fachliche Schreibwirkung,
  bevor Modbus oder HMI drankommen

## Letzte Commits

- `cd25146` `feat: add event recorder and sqlite store`
- `6dc38a9` `feat: add alarm lifecycle to plant sim`
- `a7f5954` `feat: add deterministic plant simulation scenarios`
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

### 6. Deterministische Simulationsszenarien

Dateien:

- `src/honeypot/plant_sim/core.py`
- `src/honeypot/plant_sim/__init__.py`
- `tests/unit/test_plant_sim.py`

Vorhanden:

- `PlantSimulator.from_snapshot()` leitet eine nominale Parkleistung aus dem Referenzzustand ab
- `estimate_available_power_kw()` skaliert Leistung plausibel mit der Einstrahlung
- deterministische Szenariofunktionen fuer:
  - `simulate_normal_operation()`
  - `apply_curtailment()`
  - `open_breaker()`
  - `lose_block_communications()`
- Szenario-spezifische Alarme:
  - `PLANT_CURTAILED`
  - `BREAKER_OPEN`
  - `COMM_LOSS_INVERTER_BLOCK`
- Unit-Tests fuer Ursache/Wirkung von Curtailment, Breaker offen und Kommunikationsverlust

### 7. Alarmlebenszyklus und Datenqualitaet

Dateien:

- `src/honeypot/asset_domain/models.py`
- `src/honeypot/plant_sim/core.py`
- `src/honeypot/plant_sim/__init__.py`
- `tests/unit/test_plant_sim.py`

Vorhanden:

- `PlantAlarm` als typisiertes Alarmobjekt im Fachmodell
- `PlantSnapshot.alarms`, `active_alarms`, `active_alarm_codes` und `alarm_by_code()`
- deterministische Alarmzustaende fuer:
  - `inactive`
  - `active_unacknowledged`
  - `active_acknowledged`
  - `cleared`
- `PlantSimulator.acknowledge_alarm()` fuer Quittierung ohne Loeschung
- fachliche Qualitaetsableitung ueber `determine_data_quality()` fuer:
  - `good`
  - `estimated`
  - `stale`
  - `invalid`
- Unit-Tests fuer `acknowledged != cleared` und fuer alle vier Qualitaetszustaende

### 8. Event-Core, Storage und Outbox-Grundlage

Dateien:

- `src/honeypot/event_core/models.py`
- `src/honeypot/event_core/recorder.py`
- `src/honeypot/event_core/__init__.py`
- `src/honeypot/storage/sqlite_store.py`
- `src/honeypot/storage/__init__.py`
- `tests/unit/test_event_core.py`

Vorhanden:

- kanonische Pydantic-Modelle fuer:
  - `EventRecord`
  - `AlertRecord`
  - `OutboxEntry`
  - `RecordedArtifacts`
- strikte Normalisierung fuer Pflichtfelder, UTC-Zeitstempel und optionale
  Metadaten
- `EventRecorder.build_event()` mit generierten `event_id`- und
  `correlation_id`-Ketten
- `EventRecorder.build_alert()` zur Ableitung lokaler Alerts aus Kern-Events
- `EventRecorder.record()` fuer:
  - `event_log`
  - `current_state`
  - `alert_log`
  - optionale Outbox-Auftraege fuer spaetere Exporter
- `SQLiteEventStore` im `WAL`-Modus fuer:
  - `current_state`
  - `event_log`
  - `alert_log`
  - `outbox`
- Guardrails gegen leere `state_key`- und `target_type`-Werte
- Unit-Tests fuer:
  - kanonische Feldnormalisierung
  - Korrelation ueber `correlation_id` plus `causation_id`
  - Persistenz von Event, State, Alert und Outbox
  - lokale Wahrheit ohne erzwungene Outbox-Ziele

## Teststand

Aktuell gruen:

- `uv run pytest`

Letzter bekannter Lauf:

- `28 passed`

Abgedeckt sind bisher:

- Scaffold und Prozesseinstieg
- Konfigurationsdefaults und Fehlkonfiguration
- Fixture-Laden und Fehlerpfade
- Zeitabstraktion und deterministische Uhr
- typisiertes Asset-Domain-Snapshot aus `normal_operation`
- deterministische Simulationsszenarien fuer Kernszenarien aus Phase B
- Alarmlebenszyklus und Qualitaetslogik auf dem Simulationskern
- Eventvertrag, lokale Persistenz und Outbox-Grundlage im `SQLite`-Store

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

- Verdrahtung des Simulationskerns auf `event_core` bei fachlichen
  Schreibwirkungen
- JSONL-Archivpfad
- Rule-Engine und eventgetriebene Alarmableitung
- Modbus-Server
- HMI
- Exporter-Implementierung

Operative Hinweise:

- Git-Remote ist derzeit nicht konfiguriert; `push` ist also nicht moeglich
- Arbeitsbaum war beim letzten Handoff sauber

## Naechster Schritt

### Phase C fortsetzen

Direkter Kurs fuer den naechsten Agenten:

1. `plant_sim`-Schreibpfade ueber `EventRecorder` auf `current_state`,
   `event_log` und bei Bedarf `alert_log` verdrahten
2. zuerst weiter nur fachlich und testbar, noch ohne Modbus oder HMI
3. danach JSONL-Archivpfad und minimale Rule-Engine-Schnittstelle nachziehen
4. erst dann Modbus- und HMI-Slices anschliessen

Empfohlener naechster atomarer Fix in Phase C:

- `PlantSimulator`-Schreiboperationen mit `EventRecorder` koppeln
- pro fachlicher Wirkung `EventRecord` plus `current_state`-Update erzeugen
- fokussierte Unit-Tests fuer Eventspur bei Curtailment, Breaker offen und
  Kommunikationsverlust

Nicht als naechstes tun:

- keinen Modbus-Vertical-Slice vorziehen
- keine HMI vorziehen
- keine Exporter oder externe Auslieferung vorziehen, bevor Eventspur und
  JSONL/Rule-Engine-Basis sauber stehen

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
