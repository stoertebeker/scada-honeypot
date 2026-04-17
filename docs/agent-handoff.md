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
- HMI fuer `/overview`, `/single-line`, `/inverters`, `/weather`, `/meter`,
  `/alarms`, `/trends` sowie den ersten schreibenden Service-Pfad auf
  derselben Snapshot-Wahrheit steht jetzt als App; keine zweite Wahrheit
  neben Modbus bauen
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
  - V1-Regeln fuer:
    - wiederholte Login-Fehlschlaege ab Schwellwert
    - erfolgreiche Setpoint-Aenderungen
    - `BREAKER_OPEN`
    - `COMM_LOSS_INVERTER_BLOCK`
- `EventRecorder.record()` fuehrt explizite Prozess-Alerts und Rule-basierte
  Alerts jetzt dedupliziert zusammen, ohne doppelte Eintraege im `alert_log`
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
  - Setpoints `40200 block_enable_request`, `40201 block_power_limit_pct_x10`
    und `40202 block_reset_request`
  - lokale Alarmdiagnose `40300-40305`
- dokumentiertes Fehlerverhalten im Slice:
  - `FC04` -> `01 Illegal Function`
  - Wert ausserhalb `0..1000` auf `40200` -> `03 Illegal Data Value`
  - Wert ausserhalb `-1000..1000` auf `40201` -> `03 Illegal Data Value`
  - Wert ausserhalb `0..2` auf `40202` -> `03 Illegal Data Value`
  - Wert ausserhalb `0..1` auf `Unit 11-13 / 40200` oder `40202` -> `03 Illegal Data Value`
  - Wert ausserhalb `0..1000` auf `Unit 11-13 / 40201` -> `03 Illegal Data Value`
  - `Unit 11-13 / FC16` ausserhalb `40200-40202` -> `02 Illegal Data Address`
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

### 11. HMI fuer `/overview`, `/single-line`, `/inverters`, `/weather`, `/meter`, `/alarms`, `/trends` und den erweiterten Service-Control-Pfad

Dateien:

- `src/honeypot/hmi_web/app.py`
- `src/honeypot/hmi_web/__init__.py`
- `src/honeypot/hmi_web/server.py`
- `src/honeypot/hmi_web/templates/overview.html`
- `src/honeypot/hmi_web/templates/single_line.html`
- `src/honeypot/hmi_web/templates/inverters.html`
- `src/honeypot/hmi_web/templates/weather.html`
- `src/honeypot/hmi_web/templates/meter.html`
- `src/honeypot/hmi_web/templates/alarms.html`
- `src/honeypot/hmi_web/templates/trends.html`
- `src/honeypot/hmi_web/templates/error_page.html`
- `src/honeypot/hmi_web/templates/service_login.html`
- `src/honeypot/hmi_web/templates/service_panel.html`
- `resources/locales/attacker-ui/en.json`
- `src/honeypot/main.py`
- `tests/integration/test_hmi_web_overview.py`
- `tests/integration/test_runtime_main.py`
- `tests/unit/test_runtime_bootstrap.py`

Vorhanden:

- `create_hmi_app()` erzeugt eine erste `FastAPI`-/`Jinja2`-App fuer:
  - `/`
  - `/overview`
  - `/single-line`
  - `/inverters`
  - `/weather`
  - `/meter`
  - `/alarms`
  - `/trends`
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
- `single-line` zeigt sichtbar:
  - PV-Park als Sammelsicht
  - PPC
  - die drei Inverter-Bloecke
  - Revenue Meter
  - Grid Interconnect / Breaker
  - einfachen Leistungsfluss
  - Breaker- und Exportpfad-Zustand
- `inverters` zeigt sichtbar:
  - die drei Inverter-Bloecke im Direktvergleich
  - Status, Comms und Datenqualitaet je Block
  - Blockleistung und Verfuegbarkeit
  - optionale AC-/DC-nahe Werte und Temperatur
  - lokale Alarmanzahl je Block
- `weather` zeigt sichtbar:
  - Einstrahlung
  - Modul- und Umgebungstemperatur
  - Windgeschwindigkeit
  - Wetterqualitaet und Kommunikationszustand
  - den Leistungskontext zur aktuellen Parkleistung
- `meter` zeigt sichtbar:
  - Exportleistung
  - Exportpfad und Breaker-Zustand
  - Datenqualitaet und Kommunikationszustand des Revenue Meters
  - Exportenergie, Netzspannung, Netzfrequenz und Leistungsfaktor
  - den Netz-/Exportkontext zur aktuellen Breaker-Lage
- `alarms` zeigt sichtbar:
  - Alarmcode und Alarmname
  - Kategorie, Severity und Asset-Bezug
  - Zustand und Ack-Status klar getrennt
  - First-Seen- und Last-Changed-Zeit aus der lokalen Alert-Spur
  - Filter fuer Severity, State und Sortierung
- `trends` zeigt sichtbar:
  - kurze Verlaufsspuren fuer Parkleistung, Leistungslimit, Einstrahlung und Exportleistung
  - Blockleistungs-Traces fuer alle drei Inverter-Bloecke
  - Baseline-gegen-Current-Sicht ohne zweite Wahrheit
  - Trendkontext fuer Curtailment, Breaker-Offen und degradierte Kommunikation
- eigene Fehlerseiten zeigen sichtbar:
  - `404` ohne Framework-Defaultbild
  - `500` ohne technische Fehltexte
  - dieselbe Navigations- und HMI-Sprache wie die uebrigen Seiten
- `service/login` und `service/panel` zeigen sichtbar:
  - Login-Formular ohne Framework-Standardformular
  - ruhige Fehlermeldung bei Login-Fehlschlag
  - serverseitige Session mit `20` Minuten Idle-Timeout
  - geschuetzten Service-Bereich mit `401` fuer unauthentifiziert und `403` bei deaktiviertem Login
  - schreibende Bedienungen fuer `active_power_limit_pct`, `reactive_power_target`, `plant_mode_request`, `block_enable_request`, `block_power_limit_pct_x10`, `block_reset_request` sowie `breaker_open_request` / `breaker_close_request`
  - ruhige Statusrueckmeldung nach akzeptierten oder abgelehnten Bedienungen
- sichtbare HMI-Texte kommen aus dem ersten Locale-Paket
  `resources/locales/attacker-ui/en.json`
- `overview`, `single-line`, `inverters`, `weather`, `meter`, `alarms` und `trends` nutzen keine
  UI-Schattenwerte:
  - Curtailment aus Modbus ist direkt in der HMI sichtbar
  - Breaker-Offen aus `Unit 41` ist direkt im Einlinienschema sichtbar
  - Inverter-Comm-Loss aus `plant_sim` ist direkt in der HMI sichtbar
  - Wetterwerte aus `Unit 21` sind direkt in der HMI sichtbar
  - Revenue-Meter-Werte und Breaker-Wirkung aus `Unit 31`/`Unit 41` sind direkt in der HMI sichtbar
  - Alarm-Historie und Ack-Zustand lesen dieselbe Alert-Spur wie `plant_sim` und Modbus-Schreibpfade
  - Trenddaten leiten sich aus derselben Baseline-Fixture und dem aktuellen Snapshot ab
- HMI-Aufrufe schreiben jetzt HTTP-Eventspur in den lokalen Store mit:
  - `component = hmi-web`
  - `service = web-hmi`
  - `endpoint_or_register`
  - `requested_value.http_method`
  - `requested_value.http_path`
  - `resulting_value.http_status`
  - `session_id`
- `404`- und `500`-Seiten schreiben jetzt zusaetzlich eigene Fehler-Events mit
  kontrolliertem `error_code`
- Service-Login schreibt jetzt:
  - `hmi.auth.service_login_attempt`
  - `hmi.page.service_login_viewed`
  - `hmi.page.service_panel_viewed`
  - `hmi.action.service_control_submitted`
- Anti-Fingerprint-Minimum:
  - `FastAPI`-Docs/OpenAPI sind deaktiviert
  - `uvicorn`-`Server`- und `Date`-Header sind im lokalen HMI-Dienst
    deaktiviert
- lokaler Runtime-Smoke-Test prueft jetzt:
  - echter `GET /overview` auf localhost
  - echter `GET /single-line` ueber denselben Runtime-Pfad
  - echter `GET /inverters` ueber denselben Snapshot-Pfad
  - echter `GET /weather` ueber denselben Snapshot-Pfad
  - echter `GET /meter` ueber denselben Snapshot-Pfad
  - echter `GET /alarms` ueber denselben Snapshot-/Alert-Store-Pfad
  - echter `GET /trends` ueber denselben Baseline-/Snapshot-Pfad
  - echter `GET` auf unbekannte HMI-Routen mit eigener `404`-Seite
  - interner Renderfehler mit eigener `500`-Seite
  - echter `/service/login`-Pfad mit Erfolgs- und Fehlversuch
  - Session-Ablauf nach `20` Minuten Idle-Zeit
  - geschuetztes `/service/panel` mit `401/403`
  - echte `POST /service/panel/power-limit`-Wirkung mit sichtbarem Curtailment
  - echte `POST /service/panel/reactive-power`-Wirkung mit sichtbarem Blindleistungsziel
  - echte `POST /service/panel/plant-mode`-Wirkung mit gelatchtem `plant_mode_request`
  - echte `POST /service/panel/inverter-block`-Wirkung mit sichtbarem Disable/Limit je Block
  - echte `POST /service/panel/inverter-block/reset`-Wirkung mit sichtbarer Comm-Loss-Wiederherstellung
  - echte `POST /service/panel/breaker`-Wirkung mit sichtbarem Exportverlust und Wiederherstellung
  - HTTP-Eventspur aus dem Runtime-Pfad
  - sauber geschlossene Modbus- und HTTP-Ports nach `runtime.stop()`

Noch bewusst **nicht** enthalten:

- weitere schreibende HMI-Pfade jenseits des aktuellen PPC-/Inverter-/Breaker-Slices

### 12. Exporter-SDK-Grundlage

Dateien:

- `src/honeypot/exporter_sdk/contracts.py`
- `src/honeypot/exporter_sdk/local_test_exporter.py`
- `src/honeypot/exporter_sdk/__init__.py`
- `tests/unit/test_exporter_sdk.py`

Vorhanden:

- `HoneypotExporter` als minimaler Vertrag fuer:
  - `capabilities()`
  - `validate_config(config)`
  - `health()`
  - `deliver_event_batch(batch)`
  - `deliver_alert_batch(batch)`
- leichte Vertragsmodelle fuer:
  - `ExporterCapabilities`
  - `ExporterHealth`
  - `ExportDelivery`
- `LocalTestExporter` ohne Netzwerkpfad:
  - nimmt Event- und Alert-Batches lokal im Speicher an
  - kann kontrolliert `retry_later` fuer Runner- und Fehlerpfadtests erzwingen
  - meldet Health/Capture-Zustand sauber fuer spaetere Runner
- Unit-Tests fuer:
  - Delivery-Vertrag und Retry-Semantik
  - Capabilities-/Health-Meldung
  - lokale Batch-Erfassung fuer Events und Alerts
  - Konfigurationsvalidierung ohne echte Zielparameter

### 13. Outbox-Runner und Webhook-Exporter

Dateien:

- `src/honeypot/exporter_runner/runner.py`
- `src/honeypot/exporter_runner/webhook_exporter.py`
- `src/honeypot/exporter_runner/__init__.py`
- `src/honeypot/storage/sqlite_store.py`
- `src/honeypot/main.py`
- `tests/unit/test_exporter_runner.py`
- `tests/unit/test_runtime_bootstrap.py`

Vorhanden:

- `OutboxRunner.drain_once()` mit:
  - Leasing faelliger Outbox-Eintraege
  - Payload-Aufloesung fuer `alert` und `event`
  - Zustandswechsel `pending -> leased -> delivered`
  - Retry-Backoff fuer `retry_later`
  - `failed` bei fehlendem Exporter oder fehlender Payload-Aufloesung
- `WebhookExporter` als erster echter technischer Kanal:
  - liefert Event- und Alert-Batches per `POST`
  - meldet `retry_later` bei Transport- oder HTTP-Fehlern
  - blockiert den Kernpfad nicht
- `SQLiteEventStore` kann jetzt:
  - einzelne Events/Alerts ueber Referenzen aufloesen
  - Outbox-Eintraege leasen
  - Outbox-Eintraege als `delivered`, `pending` mit Backoff oder `failed` markieren
- `BackgroundOutboxRunnerService` fuehrt denselben Outbox-Drain jetzt lokal im
  Thread aus und bleibt strikt im selben Prozess
- `build_local_runtime()` verdrahtet jetzt optional Outbox-Runner **und**
  Hintergrunddienst fuer `webhook`, sobald `WEBHOOK_EXPORTER_ENABLED=1` gesetzt
  ist
- Unit-Tests fuer:
  - Webhook-Batch-POST
  - Retry-Backoff bei HTTP-Fehlern
  - `failed` bei fehlendem Exporter
  - Hintergrund-Drain ohne manuellen `drain_once()`
  - Runtime-Verdrahtung des Webhook-Runners

### 14. Release-Gate- und Hardening-Suite

Dateien:

- `tests/integration/test_release_gates.py`

Vorhanden:

- Release-Gates fuer:
  - ruhige `401`, `403` und `404`
  - fehlende `Server`-/`Date`-Header im lokalen HMI-Dienst
  - keine sichtbaren Framework-Signaturen in Fehlerseiten
  - Exporter-Ausfall ohne sichtbare Client-Seiteneffekte
  - stabilen lokalen Modbus-/HMI-Betrieb trotz Outbox-Retry
- Die Gates pruefen echte localhost-Pfade, nicht nur ASGI-Shortcuts

## Teststand

Aktuell gruen:

- `uv run pytest`

Letzter bekannter Lauf:

- `151 passed`

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
- minimale Rule-Engine mit lokaler Event-zu-Alert-Ableitung fuer wiederholte
  Login-Fehlschlaege, erfolgreiche Setpoint-Aenderungen, `BREAKER_OPEN` und
  `COMM_LOSS_INVERTER_BLOCK`
- Eventspur fuer fachliche `plant_sim`-Schreibwirkungen im lokalen Store
- Modbus-Slice mit `FC03`/`FC06`/`FC16`, Contract-Tests und korrelierter
  Eventspur
- `inverter_block`-Slices mit Status-/Alarmmatrix, Write-Pfaden fuer
  `block_enable_request`, `block_power_limit_pct_x10`, `block_reset_request`,
  korrekter Unit-Differenzierung und lokaler Comm-Loss-Sicht
- `weather_station`-Slice mit Fallback auf `fixture.weather`, abgeleiteter
  Confidence-Sicht und strikt read-only Verhalten
- `revenue_meter`-Slice mit read-only Verhalten, Export-/Qualitaetssicht und
  konsistenter Breaker-Ableitung
- `grid_interconnect`-Slice mit sichtbarer Breaker-Wirkung, Exportverlust,
  Wiederherstellung und Alarm-Clear
- HMI fuer `/overview`, `/single-line`, `/inverters`, `/weather`, `/meter`,
  `/alarms` und `/trends`, HTTP-Eventspur und Shared-Truth-Tests gegen
  Modbus-Curtailment, Breaker-Offen, Inverter-Blockwerte, Unit-21-Wetterdaten,
  Unit-31-Meterwerte, die lokale Alert-Spur und die synthetische
  Trendableitung aus Baseline plus Snapshot
- eigene HMI-Fehlerseiten fuer `404/500` mit Fehler-Events statt
  Framework-Standardbildern
- `/service/login` und `/service/panel` mit serverseitiger Session-Grundlogik,
  `20` Minuten Idle-Timeout, ruhigem `401/403`-Verhalten, Auth-Events und
  schreibenden Service-Bedienungen fuer Leistungsbegrenzung,
  Blindleistungsziel, `plant_mode_request` und Breaker inklusive korrelierter
  Eventspur zum Fachkern
- `exporter_sdk` mit lokalem Test-Exporter als Vertragsschicht fuer kommende
  Outbox-Runner und Ziel-Exporter
- `exporter_runner` mit Webhook-Exporter, Outbox-Leasing und Retry-Backoff auf
  dem lokalen SQLite-Store
- lokaler Runner-Hintergrundbetrieb fuer den Webhook-Pfad ohne manuelles
  `drain_once()` im Runtime-Slice
- Release-Gate- und Hardening-Suite fuer ruhige Fehlerbilder, Header-Armut und
  Exporter-Ausfall ohne sichtbare Seiteneffekte
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

- Rule-Engine-Feinschliff fuer Dedupe/Suppression und mehrstufige Alarmfolgen
- restliche Modbus-Write-Pfade fuer weitere Setpoints und weitere aktive Units
- weitere HMI-Seiten und HMI-Fehlerseiten
- weitere Ziel-Exporter, Rule-Engine-Feinschliff und restliche Servicepfade

Operative Hinweise:

- Arbeitsbaum war beim letzten Handoff sauber

## Naechster Schritt

### Phase D/E fortsetzen

Direkter Kurs fuer den naechsten Agenten:

1. jetzt weitere Ziel-Exporter auf den bestehenden Outbox-Pfad ziehen
2. danach Rule-Engine-Feinschliff entlang der sichtbaren Bedienpfade erweitern
3. erst danach weitere V1-Erweiterungen jenseits des aktuellen Service-Slices ansetzen

Empfohlener naechster atomarer Fix in Phase D/E:

- einen weiteren Ziel-Exporter auf dieselbe Outbox-Wahrheit setzen
- fokussierte Tests fuer Konsistenz zwischen Outbox, Retry-Verhalten, Eventspur und bestehender Release-Gate-Suite
- keine weitere Exponierung oder Runner-Daemonisierung vorziehen, bevor diese Gates dauerhaft gruen bleiben

Nicht als naechstes tun:

- keine neue Aussenkante vorziehen
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
