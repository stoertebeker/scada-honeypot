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
- `Modbus/TCP`-Vertical-Slices fuer `Unit 1` und `Unit 41` mit MBAP-Handling, `FC03`, `FC06` und dem ersten gezielten `FC16`-Pfad
- `FC06` und `FC16` auf `40200` koppeln Modbus-Write, `plant_sim.apply_curtailment()`, sichtbaren Leistungsabfall, Alarm `PLANT_CURTAILED` und korrelierte Eventspur
- `FC16` auf `40201` aktualisiert jetzt das Blindleistungsziel fachlich konsistent, und `40202 plant_mode_request` bleibt als latched Bedienwunsch sichtbar
- `Unit 41` bildet jetzt `grid_interconnect` mit eigenem Identitaetsblock, Status-/Alarmregistern sowie `breaker_open_request` und `breaker_close_request` als self-clearing Puls-Schreibpfaden ab
- `plant_sim.close_breaker()` stellt Export und Normalzustand nach einem offenen Breaker wieder her und schreibt die Alarm-Clear-Spur fuer `BREAKER_OPEN`
- Zeitabstraktion mit kontrollierbarer Test-Uhr
- lokaler Prozesseinstieg ueber `uv run python -m honeypot.main`, der `normal_operation`, `SQLiteEventStore` und den Modbus-Listener auf `127.0.0.1` bootstrapt
- Runtime-Guardrails im Startpfad, die `MODBUS_BIND_HOST` im aktuellen Laborstand auf `127.0.0.1` festhalten
- lokaler Modbus-Default auf `1502/tcp`, damit `uv run python -m honeypot.main` ohne privilegierte Ports laeuft; `502/tcp` bleibt fachlicher Standard fuer bewusste Deployments
- Unit-, Contract- und erste Integrations-Tests fuer Konfiguration, Fixtures, Asset-Domain-Snapshot, Zeitkern, Simulationsszenarien, Event-/Persistenzvertrag, die ersten `FC03`/`FC06`/`FC16`-Modbus-Slices und den lokalen Runtime-Startpfad

Noch nicht vorhanden:
- JSONL-Archivpfad fuer Eventexport
- Rule-Engine und eventgetriebene Alarmableitung
- restliche Modbus-Write-Pfade fuer weitere Setpoints und weitere aktive Units
- Web-HMI
- Exporter-Implementierung

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

Die Deckscrew ist jetzt am Uebergang von Phase C zu D/E unterwegs. Der
naechste konkrete Schlag sollte innerhalb der Roadmap-Reihenfolge sein:

1. den noch offenen `JSONL`-Archivpfad fuer Events einziehen und direkt an den lokalen Eventstore ankoppeln
2. danach die minimale Rule-Engine-Schnittstelle aufsetzen, damit Alerts nicht nur aus dem Simulationskern kommen

Danach bleibt der weitere Baukurs laut Roadmap:

1. restliche Registermatrix und weitere aktive Units fuer Modbus
2. read-only HMI
3. HMI-Servicepfade
4. Alerts und Exporter
5. Hardening und Anti-Fingerprint

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
  - `TELEGRAM_EXPORTER_ENABLED`

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
