# Agent-Handoff

## Kurzlage

Das Repo ist kein Geruest mehr, sondern ein weitgehend fertiger lokaler
SCADA-Honeypot fuer einen fiktiven Solarpark.

Aktueller Kurs:

- lokaler V1-Release: `GO`
- `pre-exposure`: `GO`
- `exposed-research`: technisch vorbereitet, aber deployment-spezifisch
  freizugeben
- Gesamtteststand: `285 passed`
- Trends und sichtbare Snapshot-Zeit laufen inzwischen ueber eine kleine
  Runtime-Historie und `observed_at`, nicht mehr nur ueber den Fixture-Start

Wichtige Grundregel:
- HMI, Modbus und Eventspur laufen auf derselben Fachwahrheit.
- Keine zweite Wahrheit neben Snapshot, Eventstore und Alarmhistorie bauen.

## Schnellstart

### Lokaler Start

```bash
uv run python -m honeypot.main
```

### Lokaler Reset

```bash
uv run python -m honeypot.main --reset-runtime
```

### Exposure-Sweep

```bash
uv run python -m honeypot.main --verify-exposed-research
uv run python -m honeypot.main --verify-exposed-research-target-host
```

### Gesamttestlauf

```bash
uv run pytest -q
```

## Was an Deck steht

### Fachkern

- `config_core`
  - `.env`-Laden, Defaults, Validierung, Locale- und Exposure-Gates
- `asset_domain`
  - typisiertes Modell fuer Site, PPC, Inverter, Wetter, Meter, Grid, Alarme
- `plant_sim`
  - Prozesswirkung fuer Curtailment, Breaker, Blockverluste, Reset, Alarmfluss
- `event_core`
  - Event-/Alert-/Outbox-Modelle und Recorder
- `storage`
  - `SQLite` im `WAL`-Modus plus optionales JSONL-Archiv
- `rule_engine`
  - Folge-Alerts, Dedupe, Suppression, `cleared`-Logik

### Angreiferpfade

- `protocol_modbus`
  - aktive Units `1`, `11-13`, `21`, `31`, `41`
  - `FC03`, `FC06`, `FC16`
- `hmi_web`
  - `/overview`
  - `/single-line`
  - `/inverters`
  - `/weather`
  - `/meter`
  - `/alarms`
  - `/trends`
  - `/service/login`
  - `/service/panel`

### Betrieb und Ausleitung

- `monitoring`
  - Heartbeat nach `RUNTIME_STATUS_PATH`
- `runtime_evolution`
  - tickende Snapshot-Zeit plus kleine In-Memory-Trendhistorie fuer `/trends`
- `weather_core`
  - interne Wetterabstraktion mit deterministischem Offline-Provider, Open-Meteo-Adaptern und Geo-Config
- `exporter_sdk`
  - gemeinsamer Exporter-Vertrag
- `exporter_runner`
  - Background-Runner fuer Webhook, SMTP und Telegram
- `runtime_reset`
  - definierter Reset von Laufartefakten
- `runtime_egress`
  - Gate fuer aktive Exportziele
- `runtime_ingress`
  - Gate fuer externe Bindings
- `runtime_exposure`
  - Exposure-Gates, Findings-Log und Exposure-Sweep
- `main`
  - gemeinsamer Runtime-Einstieg

## Sichtbare Wirkung in V1

Wichtige End-to-End-Pfade, die schon stehen:

- Curtailment ueber HMI und Modbus
- Blindleistungsziel ueber HMI und Modbus
- `plant_mode_request` als gelatchter Bedienwunsch
- Breaker Open/Close mit sichtbarer Meter- und Alarmwirkung
- Inverter-Block Enable/Disable, Limit und Reset
- Folge-Alerts:
  - `REPEATED_LOGIN_FAILURE`
  - `GRID_PATH_UNAVAILABLE`
  - `LOW_SITE_OUTPUT_UNEXPECTED`
  - `MULTI_BLOCK_UNAVAILABLE`
- Webhook-, SMTP- und Telegram-Ausleitung ueber die Outbox

## Wichtige Runtime-Gates

### Ingress

- `ALLOW_NONLOCAL_BIND=1`
- `APPROVED_INGRESS_BINDINGS`

### Egress

- `APPROVED_EGRESS_TARGETS`

### Exposed Research

- `EXPOSED_RESEARCH_ENABLED=1`
- `PUBLIC_INGRESS_MAPPINGS`
- `APPROVED_EGRESS_RECIPIENTS`
- `WATCH_OFFICER_NAME`
- `DUTY_ENGINEER_NAME`
- `FINDINGS_LOG_PATH`

Wichtige Regel:
- Platzhalter- oder Doku-Ziele fuer aktive Exporter sind im
  `exposed-research`-Modus verboten.

## Relevante Doku zuerst lesen

### Fuer Nicht-SCADA-Menschen

1. [docs/scada-primer-and-module-guide.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/scada-primer-and-module-guide.md)
2. [docs/test-attacker-guide.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/test-attacker-guide.md)

### Fuer Architektur und Fachmodell

1. [docs/architecture.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/architecture.md)
2. [docs/domain-model.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/domain-model.md)
3. [docs/protocol-profile.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/protocol-profile.md)
4. [docs/register-matrix.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/register-matrix.md)
5. [docs/hmi-concept.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/hmi-concept.md)
6. [docs/logging-and-events.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/logging-and-events.md)

### Fuer Betrieb und Freigabe

1. [docs/testing-strategy.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/testing-strategy.md)
2. [docs/release-checklist.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/release-checklist.md)
3. [docs/security-operations.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/security-operations.md)
4. [docs/pre-exposure-decision.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/pre-exposure-decision.md)
5. [docs/exposed-research-checklist.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/exposed-research-checklist.md)
6. [docs/exposed-research-runbook.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/exposed-research-runbook.md)

## Letzte relevante Commits

- `c330cc7` `docs: simplify readme structure`
- `db75ea2` `docs: add scada primer and attacker runbooks`
- `44470a1` `feat: record exposed research sweep findings`
- `90cdb90` `feat: gate exposed research deployments`
- `8ee4865` `feat: gate nonlocal ingress approvals`
- `d66c41e` `feat: gate exporter egress targets`
- `0c3a6cd` `feat: add local runtime reset path`
- `47dab3c` `feat: add local runtime status heartbeat`

## Offene Luecken

Repo-seitig ist der Grundbau weitgehend geschlossen. Die groessten offenen
Punkte liegen jetzt nicht mehr im Kern, sondern im echten Einsatz:

1. deployment-spezifische `.env` fuer den Zielhost
2. reale Firewall-/NAT-Validierung
3. reale Egress-Empfaenger statt Doku-Ziele
4. echter Zielhost-Lauf von `--verify-exposed-research-target-host`

## Naechster sinnvoller Schritt

Wenn lokal weitergearbeitet wird:

1. keine neue Grundmechanik vorziehen
2. nur gezielte Härtung, Test- oder Doku-Schlaege

Wenn echte Exponierung vorbereitet wird:

1. Zielhost-`.env` setzen
2. `uv run python -m honeypot.main --verify-exposed-research-target-host` auf dem Zielhost fahren
3. Findings, Runtime-Status und Eventspur gegenlesen
4. erst danach Ingress wirklich nach aussen oeffnen
