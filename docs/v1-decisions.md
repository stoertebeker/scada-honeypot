# V1-Entscheidungsstand: Baubare Grundlage

## 1. Zweck dieses Dokuments

Dieses Dokument haelt die verbindlichen Entscheidungen fest, die fuer die erste
baubare V1 nicht mehr offen bleiben sollen. Es ist die zentrale Karte fuer
Defaults, Technikgrundkurs, Event-Vertrag und Startkommandos.

## 2. Verbindliche V1-Defaults

Fuer V1 gelten verbindlich:

- `ENABLE_TRACKER=0`
- `ENABLE_SERVICE_LOGIN=1`
- `FC04 Read Input Registers` bleibt in der Default-Konfiguration deaktiviert
- kein sichtbarer Logout-Link in der HMI
- Exporter laufen in V1 im selben Prozess, aber nur ueber entkoppelte
  Outbox-/Runner-Logik
- `MODBUS_BIND_HOST=127.0.0.1`
- `HMI_BIND_HOST=127.0.0.1`
- `PCAP_CAPTURE_ENABLED=0`

## 3. Technischer Grundkurs fuer V1

Fuer die erste baubare Version wird festgelegt:

- Hauptsprache: `Python 3.12`
- Paket-, Venv- und Startwerkzeug: `uv`
- Web-Stack: `FastAPI` mit serverseitig gerenderten `Jinja2`-Templates
- Modbus-Stack: `pymodbus`
- Persistenz: lokales `SQLite` im `WAL`-Modus
- Teststack: `pytest`, `pytest-asyncio`, `httpx`, `Playwright`

Wichtige V1-Regeln:

- OpenAPI-/Swagger-Routen bleiben deaktiviert
- HMI und Modbus werden ueber einen gemeinsamen Prozesseinstieg gestartet
- Debug- und Development-Endpunkte werden nicht exponiert

## 4. Startkommandos fuer die erste Umsetzung

Bis echte Repo-Hilfskommandos vorliegen, gilt fuer die Deckscrew dieser
verbindliche Arbeitskurs:

- Bootstrap: `uv sync --dev`
- Lokaler Start: `uv run python -m honeypot.main`
- Testgesamtlauf: `uv run pytest`
- Contract-Tests: `uv run pytest tests/contract`
- Integrations-Tests: `uv run pytest tests/integration`
- HMI-End-to-End: `uv run playwright test`

Die erste Geruest-Implementierung soll diese Befehle spaeter ueber schlanke
Repo-Wrapper oder Make-Targets kapseln, ohne die Semantik zu aendern.

## 5. HMI-Login- und Session-Kurs

Fuer V1 gilt:

- `/service/login` ist in der V1-Default-Konfiguration aktiv
- `anonymous_view` sieht alle read-only Betriebsseiten
- `service_view` schaltet nur die dokumentierten V1-Bedienhandlungen frei
- Sessions laufen serverseitig mit signiertem Cookie-Handle
- Idle-Timeout fuer Sessions: `20` Minuten
- ein Prozessneustart invalidiert bestehende Sessions

## 6. Kanonischer Event-Vertrag

Pflichtfelder fuer jedes Event:

- `timestamp`
- `event_id`
- `correlation_id`
- `event_type`
- `category`
- `severity`
- `source_ip`
- `actor_type`
- `component`
- `asset_id`
- `action`
- `result`

Stark empfohlene Zusatzfelder:

- `session_id`
- `causation_id`
- `protocol`
- `service`
- `endpoint_or_register`
- `requested_value`
- `previous_value`
- `resulting_value`
- `resulting_state`
- `alarm_code`
- `error_code`
- `message`
- `tags`

Feldregeln fuer V1:

- `component` ist immer der stabile Modulname wie `protocol-modbus` oder
  `hmi-web`
- `service` beschreibt die logische Oberflaeche wie `holding-registers` oder
  `web-hmi`
- `endpoint_or_register` enthaelt je nach Protokoll die Registeradresse oder
  den HTTP-Pfad
- pro Protokoll duplizierte Detailfelder wie `http_path` oder `register_start`
  sind zulaessig, ersetzen aber nicht die kanonischen Event-Felder

## 7. Persistenz- und Alert-Kurs fuer V1

Fuer V1 wird festgelegt:

- der lokale Eventstore ist `SQLite`
- die logischen Persistenzbereiche bleiben `current_state`, `event_log`,
  `alert_log` und `outbox`
- erste aktive Alert-Regeln sind:
  - wiederholte Login-Fehler
  - erfolgreiche Setpoint-Aenderung
  - `BREAKER_OPEN`
  - `GRID_PATH_UNAVAILABLE` als kritischer Folge-Alert bei sichtbarem
    Exportpfadverlust
  - `LOW_SITE_OUTPUT_UNEXPECTED` als hoher Folge-Alert, wenn die Parkleistung
    trotz geschlossenem Breaker, verfuegbarem Exportpfad und ohne aktive
    Curtailment deutlich unter der Einstrahlungserwartung liegt
  - `COMM_LOSS_INVERTER_BLOCK`
  - `MULTI_BLOCK_UNAVAILABLE` als kritischer Folge-Alert beim zweiten
    gleichzeitigen Block-Kommunikationsverlust
- `LOW_SITE_OUTPUT_UNEXPECTED` nutzt als Startschwelle
  `ALARM_THRESHOLD_LOW_OUTPUT_PCT=35`

## 8. Spaetere Erweiterungen ausserhalb dieser Bauvorlage

Nicht blockierend fuer V1, aber spaeter vertiefbar:

- Containerisierung oder Prozessmanager fuer exponierte Deployments
- Nightly- gegen PR-Testverteilung
- feinere Dedupe- und Suppression-Regeln fuer Alerts
- weitere Protokolle und Exportkanaele
