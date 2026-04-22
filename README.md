# SCADA Honeypot: Fiktiver Solarpark

## Ziel

Dieses Projekt beschreibt und spaeter implementiert einen interaktiven
SCADA-Honeypot fuer einen fiktiven Solarpark im einstelligen MW-Bereich.

Die Anlage soll:
- fuer Angreifer glaubhaft und navigierbar sein
- standardnahe `Modbus/TCP`- und Web-HMI-Pfade bieten
- die angreiferzugewandte HMI pro Deployment sprachlich anpassbar machen
- sauber und vollstaendig loggen
- kontrollierte Prozesswirkung zeigen
- keine reale Anlage, keinen realen Betreiber und keine reale Vendor-Identitaet
  nachbilden

## Aktueller Stand

Das Projekt befindet sich aktuell im **fruehen Implementierungsstand von
Phase D/E bei offenem Rest aus Phase C**.

Vorhanden sind:
- Scope
- Architektur
- Domaenenmodell
- Logging-/Event-Modell
- Protokollprofil
- Registermatrix
- HMI-Konzept
- Teststrategie
- Implementierungs-Roadmap
- Security-/Operations-Leitfaden
- Beispielkonfiguration
- Projektgeruest unter `src/`, `tests/`, `fixtures/` und `tools/`
- `uv`-basiertes Projektsetup mit `pyproject.toml` und `uv.lock`
- `config_core` mit `.env`-/Umgebungs-Laden, generischen Defaults und frueher Validierung
- erstes mitgeliefertes Locale-Paket unter `resources/locales/attacker-ui/en.json`
- Fixture-System mit erstem ladbaren Startzustand `normal_operation`
- typisiertes Fachmodell fuer Site, PPC, Inverter-Bloecke, Wetter, Meter und Grid
- Fixture-zu-Domaenen-Mapping ueber `PlantSnapshot.from_fixture()`
- deterministischer `plant_sim`-Kern fuer `normal`, `curtailed`, `breaker_open` und `comm_loss_single_block`
- `plant_sim` schreibt fachliche Schreibwirkungen fuer Curtailment, Breaker und Kommunikationsverlust ueber `EventRecorder` in `event_log`, `current_state` und `alert_log`
- Alarmlebenszyklus fuer `inactive`, `active_unacknowledged`, `active_acknowledged` und `cleared`
- fachliche Qualitaetsregeln fuer `good`, `estimated`, `stale` und `invalid`
- kanonischer `event_core` mit `EventRecord`, `AlertRecord`, `OutboxEntry` und `EventRecorder`
- lokaler `SQLiteEventStore` im `WAL`-Modus fuer `current_state`, `event_log`, `alert_log` und `outbox`
- optionaler `JsonlEventArchive`-Sink, der Events zeilenweise nach `JSONL_ARCHIVE_PATH` spiegelt und bei Archivfehlern den lokalen SQLite-Kern nicht blockiert
- lokale `RuleEngine`, die jetzt wiederholte Login-Fehler, erfolgreiche Setpoint-Aenderungen, `BREAKER_OPEN`, den kritischen Grid-Folge-Alert `GRID_PATH_UNAVAILABLE`, den hohen Folge-Alert `LOW_SITE_OUTPUT_UNEXPECTED` bei deutlicher Minderleistung ohne Breaker-/Curtailment-Erklaerung, `COMM_LOSS_INVERTER_BLOCK` und den kritischen Folge-Alert `MULTI_BLOCK_UNAVAILABLE` beim zweiten unterschiedlichen aktiven Block-Comm-Loss abdeckt, aktive `REPEATED_LOGIN_FAILURE` nach erfolgreichem Login sauber auf `cleared` setzt, explizite Prozessalarme priorisiert und identische aktive Rule-Alerts bis `cleared` unterdrueckt
- `exporter_sdk` mit stabilem Exporter-Vertrag fuer Capabilities, Health und Batch-Delivery sowie einem lokalen `LocalTestExporter` ohne Netzwerkpfad fuer spaetere Runner-/Outbox-Tests
- `exporter_runner` mit leased Outbox-Drain, `WebhookExporter`, `SmtpExporter`, `TelegramExporter`, Retry-Backoff und einem lokalen Hintergrunddienst; Export-Ausfaelle landen kontrolliert in `outbox.retry_count`, `next_attempt_at` und `last_error`, ohne den Kernpfad zu blockieren
- Release-Gate- und Hardening-Tests pruefen jetzt ruhige `401/403/404`-Seiten, fehlende `Server`-/`Date`-Header, lokale Bindings, Suppression gegen Folge-Alert-Flooding sowie Webhook-/SMTP-Ausfall ohne sichtbare Client-Seiteneffekte; der Webhook-Hintergrundrunner liefert dabei auch den rule-basierten Folge-Alert `MULTI_BLOCK_UNAVAILABLE` kontrolliert aus
- `Modbus/TCP`-Vertical-Slices fuer `Unit 1`, `Unit 11-13`, `Unit 21`, `Unit 31` und `Unit 41` mit MBAP-Handling, `FC03`, `FC06` und dem ersten gezielten `FC16`-Pfad
- `FC06` und `FC16` auf `40200` koppeln Modbus-Write, `plant_sim.apply_curtailment()`, sichtbaren Leistungsabfall, Alarm `PLANT_CURTAILED` und korrelierte Eventspur
- `FC16` auf `40201` aktualisiert jetzt das Blindleistungsziel fachlich konsistent, und `40202 plant_mode_request` bleibt als latched Bedienwunsch sichtbar
- `Unit 11-13` bilden jetzt die drei `inverter_block_*` mit gemeinsamer Status-/Alarmmatrix, verdrahteten Setpoints `block_enable_request`, `block_power_limit_pct_x10`, `block_reset_request` und korrekten Unit-IDs, Asset-Tags sowie lokaler Alarmdiagnose ab
- `Unit 12` spiegelt Kommunikationsverlust, Disable/Enable, Blockleistungsbegrenzung und Reset jetzt sichtbar in `communication_state`, `data_quality`, `local_alarm_count`, `block_power_kw` und der korrelierten Eventspur
- read-only HMI fuer `/`, `/overview`, `/single-line`, `/inverters`, `/weather`, `/meter`, `/alarms` und `/trends` steht als `FastAPI`-/`Jinja2`-App auf derselben Snapshot-Wahrheit wie Modbus
- `overview` zeigt Parkleistung, Leistungsbegrenzung, Blindleistungsziel, Breaker-Zustand, Kommunikationslage, Blockstatus, Wetterwerte und die wichtigsten aktiven Alarme
- `/single-line` zeigt jetzt das einfache Einlinienschema fuer PV-Park, PPC, Inverter-Bloecke, Revenue Meter und Grid Interconnect mitsamt Breaker- und Leistungsflusszustand
- `/inverters` zeigt jetzt die drei Blockaggregate im direkten Vergleich mit Status, Comms, Leistung, Verfuegbarkeit, optionalen AC/DC-nahen Werten, Temperatur und lokaler Alarmzahl
- `/weather` zeigt jetzt Einstrahlung, Temperaturen, Wind, Wetterqualitaet, Kommunikationszustand und einen plausiblen Leistungskontext auf derselben Snapshot-Wahrheit wie `Unit 21`
- `/meter` zeigt jetzt Exportleistung, Exportpfad, Breaker-Zustand, Meter-Qualitaet sowie Netzkennwerte auf derselben Snapshot-Wahrheit wie `Unit 31`
- `/alarms` zeigt jetzt Alarmcode, Kategorie, Severity, Asset-Bezug, Zustand, Ack-Status sowie First-Seen/Last-Changed aus derselben lokalen Eventspur wie die Fachlogik und fuehrt dabei auch history-only Rule-Alerts wie wiederholte Service-Login-Fehler sichtbar mit
- `/trends` zeigt jetzt kurze synthetische Verlaufsspuren fuer Parkleistung, Leistungslimit, Einstrahlung, Exportleistung und Blockleistung je Inverter auf Basis derselben Baseline- und Snapshot-Wahrheit
- eigene HMI-Fehlerseiten fuer `404` und `500` sind jetzt aktiv; sie zeigen keine Framework-Standardbilder und schreiben denselben Fehlerpfad in die lokale Eventspur
- `/service/login` und `/service/panel` stehen jetzt mit serverseitiger Service-Session, `20` Minuten Idle-Timeout, ruhigem `401/403`-Verhalten und schreibenden Bedienungen fuer Leistungsbegrenzung, Blindleistungsziel, `plant_mode_request`, Inverter-Block-Enable/Limit/Reset sowie Breaker Open/Close auf derselben Fachwirkung wie Modbus
- Service-Bedienungen im Panel schreiben jetzt korrelierte HMI-Control-Events und triggern ueber denselben Shared-Truth-Pfad sichtbare Curtailment-, Blindleistungs-, Inverter-Block- und Breaker-Wirkung; `plant_mode_request` bleibt dabei bewusst ein gelatchter Bedienwunsch wie in `Unit 1 / 40202`, Block-Reset bleibt ein self-clearing Puls wie in `Unit 11-13 / 40202`, und mehrere gelatchte Block-Enable-/Limit-Requests wirken jetzt kumulativ ueber mehrere Units
- HMI-Aufrufe und Service-Bedienungen schreiben jetzt eine saubere HTTP-/HMI-Eventspur mit `component=hmi-web`, `service=web-hmi`, Pfad, HTTP-Status und `session_id` in den lokalen Eventstore
- browserbasierte `Playwright`-Smokes unter `tests/e2e/test_hmi_service_playwright.py` pruefen jetzt `/service/login -> /service/panel -> breaker open -> /alarms`, `breaker open -> /single-line`, `/weather` als read-only Shared-Truth-Seite gegen `Unit 21`, `power_limit -> /overview -> /trends`, `reactive_power_target -> /service/panel -> /overview`, `plant_mode_request` als gelatchten Bedienwunsch ohne heimlichen `operating_mode`-Wechsel, `breaker open -> breaker close -> /meter -> /alarms`, `inverter block control -> /inverters`, `block reset after COMM_LOSS_INVERTER_BLOCK -> /inverters -> /alarms`, fehlgeschlagenen Service-Login plus `401` auf `/service/panel`, Session-Ablauf nach Idle-Timeout, deaktiviertes Service-Login mit ruhigem `403`, wiederholte Fehl-Logins mit sichtbarem Rule-Alert in `/alarms`, weitere Fehlversuche ohne duplizierten Login-Fehler-Alert, erfolgreichen Login mit sichtbarem `cleared` fuer `REPEATED_LOGIN_FAILURE`, `GRID_PATH_UNAVAILABLE` als zweiten history-only Rule-Alert mitsamt unterdruecktem Folge-Duplikat, `MULTI_BLOCK_UNAVAILABLE` bei doppeltem Block-Comm-Loss mitsamt sichtbarem `cleared` nach Reset eines Blocks und ohne duplizierten Folge-Alert bei weiterem Blockverlust sowie `LOW_SITE_OUTPUT_UNEXPECTED` nach mehrfachen Block-Ausfaellen inklusive unterdruecktem Folge-Duplikat und sichtbarem `cleared` nach Erholung gegen den echten lokalen Runtime-Pfad
- lokaler Prozesseinstieg ueber `uv run python -m honeypot.main` bootstrapt jetzt `normal_operation`, `SQLiteEventStore`, den Modbus-Listener auf `127.0.0.1:1502` und die HMI auf `127.0.0.1:8080`
- der HMI-Dienst laeuft als echter lokaler HTTP-Server; `GET /overview`, `GET /single-line`, `GET /inverters`, `GET /weather`, `GET /meter`, `GET /alarms` und `GET /trends` sind damit nicht mehr nur im ASGI-Testpfad, sondern im Runtime-Slice erreichbar
- `Unit 21` bildet jetzt `weather_station` mit eigenem Identitaetsblock, Status-/Alarmregistern, Fallback auf `fixture.weather` und einer aus `quality` abgeleiteten `weather_confidence_pct_x10` ab
- `Unit 21` bleibt strikt read-only; Setpoint-Zugriffe auf `40200-40249` werden sauber als `02 Illegal Data Address` abgewiesen
- `Unit 31` bildet jetzt `revenue_meter` mit eigenem Identitaetsblock, Status-/Alarmregistern und read-only Ablehnung fuer Setpoint-Schreibzugriffe ab
- `Unit 31` spiegelt Breaker-Wirkungen aus `Unit 41` konsistent in `export_power_kw`, `export_path_available` und der Alarmdiagnose
- `Unit 41` bildet jetzt `grid_interconnect` mit eigenem Identitaetsblock, Status-/Alarmregistern sowie `breaker_open_request` und `breaker_close_request` als self-clearing Puls-Schreibpfaden ab
- `plant_sim.close_breaker()` stellt Export und Normalzustand nach einem offenen Breaker wieder her und schreibt die Alarm-Clear-Spur fuer `BREAKER_OPEN`
- Zeitabstraktion mit kontrollierbarer Test-Uhr
- Runtime-Guardrails im Startpfad, die `MODBUS_BIND_HOST` und `HMI_BIND_HOST` im aktuellen Laborstand auf `127.0.0.1` festhalten
- lokaler Modbus-Default auf `1502/tcp`, damit `uv run python -m honeypot.main` ohne privilegierte Ports laeuft; `502/tcp` bleibt fachlicher Standard fuer bewusste Deployments
- Unit-, Contract- und erste Integrations-Tests fuer Konfiguration, Fixtures, Asset-Domain-Snapshot, Zeitkern, Simulationsszenarien, Event-/Persistenzvertrag, den erweiterten Rule-Engine-Kern, die ersten `FC03`/`FC06`/`FC16`-Modbus-Slices und den lokalen Runtime-Startpfad

Noch nicht vorhanden:
- weiterer Rule-Engine-Feinschliff fuer mehrstufige Alert-Kaskaden und spaetere Suppression-Strategien jenseits identischer aktiver Alerts
- restliche Modbus-Write-Pfade fuer weitere Setpoints und weitere aktive Units
- weitere HMI-Seiten jenseits von `overview`, `single-line`, `inverters`, `weather`, `meter`, `alarms` und `trends`
- weitere Ziel-Exporter, Rule-Engine-Feinschliff und restliche Servicepfade

## Leitplanken

Dieses Projekt folgt diesen Grundsaetzen:

- keine reale OEM-Kopie
- keine echten Standort- oder Firmendaten
- keine echte Fernsteuerung externer Systeme
- keine Shell- oder Host-Zugriffspfade
- Logging ist Kernfunktion, nicht Zusatz
- nur die angreiferzugewandte HMI ist lokalisierbar
- Admin-Sicht und Logs bleiben deutsch
- jede sichtbare Fehlersituation braucht spaeter einen Test

## Doku-Landkarte

Die wichtigsten Dokumente:

- [docs/v1-decisions.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/v1-decisions.md)
  - verbindlicher V1-Entscheidungsstand fuer Defaults, Technikgrundkurs und Startkommandos
- [docs/solarpark-honeypot-scope.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/solarpark-honeypot-scope.md)
  - Projektziel, Scope, Nicht-Ziele, Grundannahmen
- [docs/architecture.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/architecture.md)
  - modularer Monolith, Hauptmodule, Datenfluss
- [docs/domain-model.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/domain-model.md)
  - fachliche Assets, Zustaende, Setpoints, Alarme
- [docs/logging-and-events.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/logging-and-events.md)
  - Event-Schema, Eventstore, Outbox, Exporter-Modell
- [docs/protocol-profile.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/protocol-profile.md)
  - Modbus-/HTTP-Aussenwirkung, Fehlerverhalten
- [docs/register-matrix.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/register-matrix.md)
  - konkrete V1-Registerabbildung
- [docs/hmi-concept.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/hmi-concept.md)
  - Seitenbaum, Login, Fehlerbilder, HMI-Regeln
- [docs/testing-strategy.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/testing-strategy.md)
  - Testpyramide, Gates, Anti-Fingerprint
- [docs/implementation-roadmap.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/implementation-roadmap.md)
  - Reihenfolge der Umsetzung
- [docs/agent-handoff.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/agent-handoff.md)
  - kurzer Einsatzbrief fuer neue Agenten oder neue Umsetzungsrunden
- [docs/security-operations.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/security-operations.md)
  - Isolation, Exposure-Gates, Reset, Betrieb

## Empfohlener naechster Baukurs

Die Deckscrew ist jetzt sauber in Phase D/E angekommen. Der naechste konkrete
Schlag sollte innerhalb der Roadmap-Reihenfolge sein:

1. Rule-Engine-Feinschliff und weitere Exporter-Ziele auf die jetzt geschlossenen Servicepfade ziehen

Danach bleibt der weitere Baukurs laut Roadmap:

1. Rule-Engine-Feinschliff entlang der sichtbaren Bedienpfade
2. weitere Ziel-Exporter
3. restliche Servicepfade und spaetere V1-Erweiterungen

## Beispielkonfiguration

Eine Beispielkonfiguration liegt in
[.env.example](/Users/schrammn/Documents/VSCodium/scada-honeypot/.env.example).

Wichtige Konfigurationsprinzipien:

- Defaults bleiben generisch
- keine realen Firmen-, Orts- oder Produktdaten im Repo
- Exporter sind standardmaessig aus
- `ENABLE_TRACKER` bleibt in der V1-Default-Konfiguration aus
- `ENABLE_SERVICE_LOGIN` ist in der V1-Default-Konfiguration aktiv und kann fuer
  strengere Deployments bewusst deaktiviert werden

Wichtige Variablengruppen:

- Identitaet:
  - `SITE_NAME`
  - `SITE_CODE`
  - `OPERATOR_NAME`
  - `HMI_TITLE`

- Anlagenmodell:
  - `CAPACITY_MW`
  - `INVERTER_BLOCK_COUNT`
  - `ENABLE_TRACKER`
  - `DEFAULT_POWER_LIMIT_PCT`

- HMI und Protokoll:
  - `ENABLE_SERVICE_LOGIN`
  - `MODBUS_BIND_HOST`
  - `MODBUS_PORT`
  - `HMI_BIND_HOST`
  - `HMI_PORT`
  - `TIMEZONE`
  - `ATTACKER_UI_LOCALE`
  - `ATTACKER_UI_FALLBACK_LOCALE`

Fuer lokale Entwicklung und Tests binden `MODBUS_BIND_HOST` und
`HMI_BIND_HOST` standardmaessig an `127.0.0.1`. Eine Bindung an `0.0.0.0`
oder andere Interfaces ist eine bewusste Deployment-Entscheidung und darf erst
nach den Security-Gates erfolgen.

Der Design-Local-Default fuer `MODBUS_PORT` liegt bei `1502`, damit der lokale
Prozesseinstieg ohne privilegierte Ports laeuft. Fuer spaetere Lab-/Exposure-
Deployments kann bewusst auf `502` gewechselt werden.

- Logging und Events:
  - `EVENT_STORE_BACKEND`
  - `EVENT_STORE_PATH`
  - `JSONL_ARCHIVE_ENABLED`
  - `PCAP_CAPTURE_ENABLED`
  - `ALERT_MIN_SEVERITY`

- Exporter:
  - `WEBHOOK_EXPORTER_ENABLED`
  - `WEBHOOK_EXPORTER_URL`
  - `SMTP_EXPORTER_ENABLED`
  - `SMTP_HOST`
  - `SMTP_PORT`
  - `SMTP_FROM`
  - `SMTP_TO`
  - `TELEGRAM_EXPORTER_ENABLED`
  - `TELEGRAM_BOT_TOKEN`
  - `TELEGRAM_CHAT_ID`

## Security-Hinweis

Diese Anlage darf **nicht** ins Netz exponiert werden, bevor mindestens die
Gates aus
[docs/security-operations.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/security-operations.md)
und
[docs/testing-strategy.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/testing-strategy.md)
erfuellt sind.

Besonders wichtig:

- Egress-Kontrolle aktiv
- Debug-/Development-Pfade aus
- Logging-Completeness nachgewiesen
- Reset und Snapshot-Strategie vorhanden
- keine echten Secrets oder Betreiberdaten

## Sprachregel

Fuer die Sprachsicht gilt im Projekt bewusst eine harte Trennung:

- nur die angreiferzugewandte Web-HMI ist pro Deployment lokalisierbar
- Modbus, Register, Event-Typen und interne Codes bleiben sprachneutral
- Admin-Sicht, Betriebsdiagnose und Logs bleiben deutsch
- neue Angreifer-Sprachen wie `uk` werden ueber zusaetzliche Locale-Pakete
  ergaenzt, nicht ueber neue Fachlogik
- die HMI zeigt keinen sichtbaren Sprachumschalter

Diese Trennung ist sicherheitsrelevant. Gemischte oder halb uebersetzte
Oberflaechen sind ein Fingerprint-Risiko und verraten schnell eine Attrappe.

Fuer die Benennung der Angreifer-Sprachen gilt:

- Locale-Bezeichner folgen dem Muster `ll` oder `ll-RR`
- Beispiele: `en`, `uk`, `en-US`, `uk-UA`
- V1 sollte einfache Basis-Sprachen wie `en` oder `uk` bevorzugen
- wenn eine regionsspezifische Variante spaeter genutzt wird, faellt die HMI
  zuerst auf die Basissprache und danach auf
  `ATTACKER_UI_FALLBACK_LOCALE` zurueck
- `ATTACKER_UI_FALLBACK_LOCALE` muss immer auf ein mitgeliefertes
  Locale-Paket zeigen

Empfohlene Ablagekonvention:

- angreiferzugewandte Sprachpakete liegen logisch unter
  `resources/locales/attacker-ui/`
- pro Locale gibt es genau eine Hauptdatei, z. B. `en.json`, `uk.json`,
  `en-US.json`
- nur sichtbare HMI-Texte gehoeren in diese Pakete
- Admin-Texte, Logs und interne Codes gehoeren ausdruecklich nicht in diese
  Locale-Dateien

## Fuer Nicht-Programmierer

Diese Fragen kann der Kapitaen spaeter gut selbst zur Abnahme nutzen:

- zeigt die HMI denselben Zustand wie Modbus?
- fuehrt ein Curtailment sichtbar zu sinkender Leistung?
- fuehrt `breaker open` sichtbar zu Exportverlust?
- bleiben Fehlermeldungen ruhig und glaubhaft?
- tauchen Aktionen spaeter in den Logs wieder auf?
- bleiben Namen, Orte und Betreiber generisch?

## Mini-Status

Das Projekt ist dokumentarisch sauber abgesteckt. Der naechste echte Schritt
waere nicht noch mehr Doku, sondern der Wechsel in den Umsetzungsmodus entlang
der Roadmap.
