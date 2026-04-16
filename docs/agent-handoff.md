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

- `asset_domain`, `plant_sim`, `event_core` und der erste schreibbare
  `protocol_modbus`-Slice fuer `Unit 1` stehen jetzt als gemeinsamer Fachkern
- erste read-only HMI fuer `/overview` steht jetzt als App auf derselben
  Snapshot-Wahrheit; keine zweite Wahrheit neben Modbus bauen
- Ziel bleibt die lueckenlose Eventspur fuer Schreib- und jetzt auch
  Modbus- und HMI-Lesezugriffe

## Letzte Commits

- `9d4c92a` `feat: add fc16 ppc setpoint writes`
- `114c271` `feat: boot local modbus runtime`
- `0be087b` `feat: add fc06 curtailment write path`
- `9f0b0a3` `feat: add read-only modbus slice`
- `04ebab8` `feat: record plant sim state transitions`
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
- lokaler Prozesseinstieg in `src/honeypot/main.py`
- Startkommando funktioniert:
  `uv run python -m honeypot.main`
- `build_local_runtime()` bootstrapt aktuell:
  - `RuntimeConfig`
  - `PlantSnapshot(normal_operation)`
  - `SQLiteEventStore`
  - `EventRecorder`
  - `ReadOnlyRegisterMap`
  - `ReadOnlyModbusTcpService`
- `LocalHmiHttpService`
- `main()` startet jetzt lokalen Modbus-Listener und lokalen HMI-HTTP-Dienst
  und bleibt bis `KeyboardInterrupt` aktiv
- Sicherheitsregel im Startpfad:
  - `MODBUS_BIND_HOST` muss derzeit `127.0.0.1` bleiben
  - `HMI_BIND_HOST` muss derzeit `127.0.0.1` bleiben
  - Design-Local-Default fuer `MODBUS_PORT` ist `1502`
  - Design-Local-Default fuer `HMI_PORT` ist `8080`

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
- `src/honeypot/rule_engine/engine.py`
- `src/honeypot/rule_engine/__init__.py`
- `src/honeypot/storage/sqlite_store.py`
- `src/honeypot/storage/__init__.py`
- `tests/unit/test_event_core.py`
- `tests/unit/test_rule_engine.py`

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
  - optionales `JSONL`-Archiv
  - optionale Rule-basierte Alert-Ableitung
  - `current_state`
  - `alert_log`
  - optionale Outbox-Auftraege fuer spaetere Exporter
- `SQLiteEventStore` im `WAL`-Modus fuer:
  - `current_state`
  - `event_log`
  - `alert_log`
  - `outbox`
- `JsonlEventArchive` als zeilenweiser Event-Sink an `JSONL_ARCHIVE_PATH`
- `RuleEngine` mit:
  - Registry fuer deterministische Regelreihenfolge
  - Severity-Gate ueber `ALERT_MIN_SEVERITY`
  - erstem V1-Rule-Slice fuer erfolgreiche Setpoint-Aenderungen
- best-effort Verhalten fuer Archivfehler: `SQLite` bleibt Primärwahrheit und
  wird bei Archivproblemen nicht blockiert
- Guardrails gegen leere `state_key`- und `target_type`-Werte
- Unit-Tests fuer:
  - kanonische Feldnormalisierung
  - Korrelation ueber `correlation_id` plus `causation_id`
  - Persistenz von Event, State, Alert und Outbox
  - Rule-Registrierung und Severity-Gate
  - Rule-Ableitung fuer erfolgreiche Setpoint-Aenderung
  - JSONL-Schreibpfad
  - best-effort Verhalten bei JSONL-Archivfehlern
  - lokale Wahrheit ohne erzwungene Outbox-Ziele

### 9. Plant-Sim-Eventspur auf dem lokalen Wahrheitskern

Dateien:

- `src/honeypot/plant_sim/core.py`
- `src/honeypot/plant_sim/__init__.py`
- `src/honeypot/storage/sqlite_store.py`
- `tests/unit/test_plant_sim.py`

Vorhanden:

- optionaler `EventRecorder` an `PlantSimulator.from_snapshot()`
- `SimulationEventContext` fuer uebergebene Metadaten wie `source_ip`,
  `actor_type`, `correlation_id`, `protocol` und `service`
- Eventspur fuer fachliche Schreibpfade:
  - `apply_curtailment()`
  - `open_breaker()`
  - `close_breaker()`
  - `lose_block_communications()`
  - `acknowledge_alarm()`
- lokale Persistenz der resultierenden Wahrheit in:
  - `event_log`
  - `current_state`
  - `alert_log`
- fokussierte Eventtypen fuer:
  - Curtailment
  - Breaker-Zustandswechsel
  - Kommunikationsverlust eines Inverter-Blocks
- kleine Store-Lesehilfen fuer Tests:
  - `fetch_events()`
  - `fetch_alerts()`
  - `fetch_current_state()`
- Unit-Tests fuer:
  - uebergebene `correlation_id` und Quellmetadaten
  - Eventspur und Alert fuer Curtailment
  - Eventspur und Null-Export bei offenem Breaker
  - Alarm-Clear und Wiederherstellung nach `close_breaker()`
  - Eventspur und degradierte Blockdaten bei Kommunikationsverlust

### 10. Modbus Vertical Slices fuer Unit 1, Unit 11-13, Unit 21, Unit 31 und Unit 41

Dateien:

- `src/honeypot/protocol_modbus/registers.py`
- `src/honeypot/protocol_modbus/server.py`
- `src/honeypot/protocol_modbus/__init__.py`
- `tests/unit/test_protocol_modbus_registers.py`
- `tests/contract/test_protocol_modbus_read_only.py`

Vorhanden:

- `ReadOnlyRegisterMap` fuer:
  - Identitaetsblock `40001-40049`
  - Unit-spezifische Status-, Setpoint- und Alarmbloecke
- `Unit 1`-Sicht fuer `site / power_plant_controller`
- `Unit 11-13`-Sicht fuer `inverter_block_*`
- `Unit 21`-Sicht fuer `weather_station`
- `Unit 31`-Sicht fuer `revenue_meter`
- `Unit 41`-Sicht fuer `grid_interconnect`
- `ReadOnlyModbusTcpService` mit:
  - stabilem MBAP-Header
  - `Transaction ID`-Echo
  - `Protocol Identifier = 0`
  - `FC03` fuer Holding Registers
  - `FC06` fuer `40200 active_power_limit_pct_x10`
  - `FC16` fuer den PPC-Setpoint-Block `40200-40202`
- `Unit 41` bildet zusaetzlich ab:
  - Identitaetsblock mit `device_class_code = 1401`
  - Status `40100-40104`
  - self-clearing Pulsregister `40200 breaker_open_request` und
    `40201 breaker_close_request`
  - Alarmdiagnose `40300-40303`
- `Unit 31` bildet zusaetzlich ab:
  - Identitaetsblock mit `device_class_code = 1301`
  - Status `40100-40110`
  - `export_power_kw` als `s32`
  - `export_energy_kwh_total` als `u32`
  - `export_path_available` als abgeleitete Breaker-Sicht
  - Alarmdiagnose `40300-40303`
- `Unit 21` bildet zusaetzlich ab:
  - Identitaetsblock mit `device_class_code = 1201`
  - Status `40100-40107`
  - Fallback der Wetterwerte auf `fixture.weather`, wenn Asset-Messwerte fehlen
  - `weather_confidence_pct_x10` als abgeleitete Qualitaetssicht
  - Alarmdiagnose `40300-40302`
- `Unit 11-13` bilden zusaetzlich ab:
  - Identitaetsbloecke mit `device_class_code = 1101`
  - Status `40100-40111`
  - saubere Differenzierung ueber `unit_id_echo`, `asset_instance` und
    `asset_tag_ascii`
  - `block_power_kw` als `s32` und `availability_pct_x10`
  - lokale Alarmdiagnose `40300-40305`
  - bewusst noch keine verdrahteten Inverter-Write-Pfade
- dokumentiertes Fehlerverhalten im Slice:
  - `FC04` -> `01 Illegal Function`
  - Wert ausserhalb `0..1000` auf `40200` -> `03 Illegal Data Value`
  - Wert ausserhalb `-1000..1000` auf `40201` -> `03 Illegal Data Value`
  - Wert ausserhalb `0..2` auf `40202` -> `03 Illegal Data Value`
  - jeder Write auf `Unit 11-13 / 40200-40249` -> `02 Illegal Data Address`
  - jeder Write auf `Unit 21 / 40200-40249` -> `02 Illegal Data Address`
  - jeder Write auf `Unit 31 / 40200-40249` -> `02 Illegal Data Address`
  - Wert ausserhalb `0..1` auf `Unit 41 / 40200-40201` -> `03 Illegal Data Value`
  - gleichzeitiges `breaker_open_request=1` und `breaker_close_request=1` in
    derselben `FC16`-Anfrage -> `03 Illegal Data Value`
  - Bereich ausserhalb aktiver Bloecke -> `02 Illegal Data Address`
- Event-Logging fuer Modbus-Lesezugriffe, akzeptierte `FC06`-/`FC16`-Writes und
  abgelehnte Requests in den bestehenden `SQLite`-Eventstore
- gemeinsame `correlation_id` ueber Modbus-Write und nachgelagerte
  `plant_sim`-Prozesswirkung
- erste fachliche Registerabbildung fuer:
  - `operating_mode`
  - `communications_health`
  - `plant_power_kw`
  - `active_power_limit_pct_x10`
  - `reactive_power_target_pct_x10`
  - `plant_mode_request`
  - `block_power_kw`
  - `availability_pct_x10`
  - `local_alarm_count`
  - `irradiance_w_m2`
  - `module_temperature_c_x10`
  - `ambient_temperature_c_x10`
  - `wind_speed_m_s_x10`
  - `weather_confidence_pct_x10`
  - `export_power_kw`
  - `export_energy_kwh_total`
  - `power_factor_x1000`
  - `export_path_available`
  - `breaker_state`
  - `active_alarm_count`
  - primaere Alarmdiagnose
- `active_power_limit_pct` hat im Fachkern jetzt `x10`-Granularitaet bis auf
  Zehntel-Prozent
- `reactive_power_target` wird im Fachkern ueber `FC16` jetzt fachlich in
  Site und PPC synchron gehalten
- `plant_mode_request` ist im aktuellen Slice als latched Bedienwunsch
  sichtbar, ohne dem eigentlichen `operating_mode` eine zweite Wahrheit
  aufzuzwingen
- `breaker_open_request` und `breaker_close_request` greifen direkt auf
  `plant_sim.open_breaker()` und `plant_sim.close_breaker()` zu
- `FC06`-Antworten spiegeln jetzt den angeforderten Pulswert korrekt, waehrend
  die Register intern self-clearen
- Contract-Tests auf echter Socket-Ebene fuer:
  - MBAP
  - `FC03`
  - `FC06` mit sichtbarer Curtailment-Wirkung
  - `FC16` mit Mehrregister-Header, reaktiver Setpoint-Wirkung und latched
    `plant_mode_request`
  - `Unit 11`- und `Unit 13`-Identity/Status-Lesezugriffe
  - read-only Ablehnung fuer `Unit 12 / FC06`
  - `Unit 12`-Kommunikationsverlust mit lokaler Alarmdiagnose
  - `Unit 21`-Identity/Status-Lesezugriffe
  - read-only Ablehnung fuer `Unit 21 / FC06`
  - `Unit 31`-Identity/Status-Lesezugriffe
  - read-only Ablehnung fuer `Unit 31 / FC06`
  - konsistente `Unit 31`-Reaktion auf `Unit 41`-Breaker Open
  - `Unit 41`-Identity/Status-Lesezugriffe
  - `Unit 41`-Breaker Open/Close mit selbstloeschenden Pulsregistern
  - Konfliktablehnung fuer `Unit 41 / FC16`
  - `reserved -> 0x0000`
  - `FC04 -> 01`
  - Adressfehler -> `02`
  - ungueltige `FC06`-/`FC16`-Werte -> `03`

### 11. Erste Read-only HMI fuer `/overview`

Dateien:

- `src/honeypot/hmi_web/app.py`
- `src/honeypot/hmi_web/__init__.py`
- `src/honeypot/hmi_web/server.py`
- `src/honeypot/hmi_web/templates/overview.html`
- `resources/locales/attacker-ui/en.json`
- `src/honeypot/main.py`
- `tests/integration/test_hmi_web_overview.py`
- `tests/integration/test_runtime_main.py`
- `tests/unit/test_runtime_bootstrap.py`

Vorhanden:

- `create_hmi_app()` erzeugt eine erste `FastAPI`-/`Jinja2`-App fuer:
  - `/`
  - `/overview`
- `LocalHmiHttpService` startet diese App als echten lokalen HTTP-Dienst auf
  `HMI_BIND_HOST/HMI_PORT`
- die HMI liest pro Request dieselbe Snapshot-Wahrheit wie Modbus ueber einen
  `snapshot_provider`
- `build_local_runtime()` verdrahtet die HMI intern bereits an
  `register_map.snapshot`
- `runtime.start()` bootstrapt jetzt Modbus und HMI gemeinsam; `runtime.stop()`
  stoppt beide Pfade sauber
- `overview` zeigt sichtbar:
  - Parkleistung
  - aktuelle Leistungsbegrenzung
  - Blindleistungsziel
  - Breaker-Zustand
  - Anzahl aktiver Alarme
  - Kommunikationszustand
  - Kurzstatus der drei Inverter-Bloecke
  - Wetter-Kurzwerte
  - die bis zu drei wichtigsten aktiven Alarme
- sichtbare HMI-Texte kommen aus dem ersten Locale-Paket
  `resources/locales/attacker-ui/en.json`
- `overview` nutzt keine UI-Schattenwerte:
  - Curtailment aus Modbus ist direkt in der HMI sichtbar
  - Inverter-Comm-Loss aus `plant_sim` ist direkt in der HMI sichtbar
- HMI-Aufrufe schreiben jetzt HTTP-Eventspur in den lokalen Store mit:
  - `component = hmi-web`
  - `service = web-hmi`
  - `endpoint_or_register`
  - `requested_value.http_method`
  - `requested_value.http_path`
  - `resulting_value.http_status`
  - `session_id`
- Anti-Fingerprint-Minimum:
  - `FastAPI`-Docs/OpenAPI sind deaktiviert
  - `uvicorn`-`Server`- und `Date`-Header sind im lokalen HMI-Dienst
    deaktiviert
- lokaler Runtime-Smoke-Test prueft jetzt:
  - echter `GET /overview` auf localhost
  - HTTP-Eventspur aus dem Runtime-Pfad
  - sauber geschlossene Modbus- und HTTP-Ports nach `runtime.stop()`

Noch bewusst **nicht** enthalten:

- weitere Seiten wie `single-line`, `inverters`, `weather`, `meter`, `alarms`
- Service-Login oder schreibende HMI-Pfade
- eigene HMI-Fehlerseiten fuer `404/500`

## Teststand

Aktuell gruen:

- `uv run pytest`

Letzter bekannter Lauf:

- `86 passed`

Abgedeckt sind bisher:

- Scaffold und Prozesseinstieg
- Konfigurationsdefaults und Fehlkonfiguration
- Fixture-Laden und Fehlerpfade
- Zeitabstraktion und deterministische Uhr
- typisiertes Asset-Domain-Snapshot aus `normal_operation`
- deterministische Simulationsszenarien fuer Kernszenarien aus Phase B
- Alarmlebenszyklus und Qualitaetslogik auf dem Simulationskern
- Eventvertrag, lokale Persistenz und Outbox-Grundlage im `SQLite`-Store
- `JSONL`-Archivpfad fuer Eventanalyse
- minimale Rule-Engine mit lokaler Event-zu-Alert-Ableitung fuer erfolgreiche
  Setpoint-Aenderungen
- Eventspur fuer fachliche `plant_sim`-Schreibwirkungen im lokalen Store
- Modbus-Slice mit `FC03`/`FC06`/`FC16`, Contract-Tests und korrelierter
  Eventspur
- `inverter_block`-Slices mit gemeinsamer read-only Status-/Alarmmatrix,
  korrekter Unit-Differenzierung und lokaler Comm-Loss-Sicht
- `weather_station`-Slice mit Fallback auf `fixture.weather`, abgeleiteter
  Confidence-Sicht und strikt read-only Verhalten
- `revenue_meter`-Slice mit read-only Verhalten, Export-/Qualitaetssicht und
  konsistenter Breaker-Ableitung
- `grid_interconnect`-Slice mit sichtbarer Breaker-Wirkung, Exportverlust,
  Wiederherstellung und Alarm-Clear
- erste read-only HMI fuer `/overview`, HTTP-Eventspur und Shared-Truth-Test
  gegen Modbus-Curtailment
- lokaler Runtime-Startpfad mit `build_local_runtime()`, echtem Modbus-Socket,
  echtem HMI-HTTP-Socket und sauberem Stoppen beider Dienste

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

- weitere Rule-Engine-Regeln, Dedupe/Suppression und mehrstufige Alarmfolgen
- restliche Modbus-Write-Pfade fuer weitere Setpoints und weitere aktive Units
- weitere HMI-Seiten und HMI-Fehlerseiten
- Exporter-Implementierung

Operative Hinweise:

- Arbeitsbaum war beim letzten Handoff sauber

## Naechster Schritt

### Phase D/E fortsetzen

Direkter Kurs fuer den naechsten Agenten:

1. jetzt weitere read-only HMI-Seiten auf dieselbe Snapshot-Wahrheit setzen
2. danach HMI-Servicepfade und restliche Modbus-Write-Pfade nachziehen
3. Rule-Engine/Exporter entlang der sichtbaren Bedienpfade erweitern

Empfohlener naechster atomarer Fix in Phase D/E:

- naechste read-only HMI-Seite auf dieselbe Snapshot-Wahrheit setzen,
  bevorzugt `single-line` oder `inverters`
- fokussierte Tests fuer sichtbare Zustandskonsistenz zu Modbus und
  fehlerarme lokale Renderpfade
- keine Service-Login- oder Schreibpfade vorziehen, bevor die HMI
  beobachtend lokal sauber erreichbar ist

Nicht als naechstes tun:

- keine schreibenden HMI-Pfade vorziehen
- keine Exporter oder externe Auslieferung vorziehen, bevor die
  Rule-Engine-Grundlage steht

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
