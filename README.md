# SCADA Honeypot: Fiktiver Solarpark

Dieses Repo enthaelt einen interaktiven SCADA-Honeypot fuer einen fiktiven
Solarpark. Der Fokus liegt auf einer glaubhaften, kontrolliert bedienbaren
OT-Oberflaeche mit gemeinsamer Fachlogik fuer:

- `Modbus/TCP`
- Web-HMI
- Event-/Alert-Spur
- regelbasierte Folge-Alerts
- kontrollierte Exportpfade

Der aktuelle Stand ist **lokal release-faehig**, `pre-exposure` ist
abgenommen, und `exposed-research` ist technisch vorbereitet, bleibt aber ein
bewusst freizugebender Sicherheitskurs.

## Betrieb

### Lokaler Start

```bash
uv run python -m honeypot.main
```

Standardpfade im lokalen Designbetrieb:

- HMI: `http://127.0.0.1:8080/overview`
- Modbus/TCP: `127.0.0.1:1502`

### Lokaler Reset

```bash
uv run python -m honeypot.main --reset-runtime
```

Entfernt reproduzierbar lokale Runtime-Artefakte wie Eventstore, JSONL,
Runtime-Status und SQLite-`-wal`/`-shm`-Sidecars.

### Exposed-Research-Sweep

```bash
uv run python -m honeypot.main --verify-exposed-research
uv run python -m honeypot.main --verify-exposed-research-target-host
```

Prueft auf demselben Runtime-Pfad:

- Start im freigegebenen Exponierungsmodus
- Modbus-Read
- HMI-Read auf `/overview`
- Alert-Lebenszyklus fuer `BREAKER_OPEN`
- sauberen Stop
- Findings-Eintrag nach `FINDINGS_LOG_PATH`

Fuer den echten Zielhost ist der bevorzugte Befehl:

```bash
uv run python -m honeypot.main --env-file .env --verify-exposed-research-target-host
```

Er fuehrt denselben Sweep aus und gibt danach die relevanten Artefaktpfade fuer
Findings, Runtime-Status, Eventstore und JSONL kompakt aus.

Wichtige Sicherheitsregel:
- Dieser Sweep ist Pflicht vor echter Exponierung.
- Non-Local-Bind und Egress bleiben `deny-by-default`, bis sie explizit
  freigegeben werden.

## Installation

### Voraussetzungen

- `Python 3.12`
- `uv`

### Projekt aufsetzen

```bash
uv sync --dev
```

Deployment-spezifische Beispielkarte fuer den ersten kontrollierten
`exposed-research`-Zielhost:

- [deploy/lab-vm-observer-01.env.example](/Users/schrammn/Documents/VSCodium/scada-honeypot/deploy/lab-vm-observer-01.env.example)

### Tests

```bash
uv run pytest -q
```

Weitere sinnvolle Läufe:

```bash
uv run pytest tests/contract
uv run pytest tests/integration
uv run pytest tests/e2e
```

Fuer Browser-Smokes bei Bedarf einmalig:

```bash
uv run python -m playwright install chromium
```

## Bestandteile

### Fachkern

- `config_core`
  - laedt `.env`, validiert Defaults, Ports, Exporter und Exposure-Gates
- `asset_domain`
  - typisiertes Modell fuer Site, PPC, Inverter-Bloecke, Wetter, Meter und Grid
- `plant_sim`
  - simuliert Prozesswirkung wie Curtailment, Breaker Open/Close und Blockverlust
- `event_core`
  - erzeugt, korreliert und persistiert Events, Alerts und Outbox-Eintraege
- `storage`
  - SQLite-Eventstore plus optionales JSONL-Archiv
- `rule_engine`
  - leitet Folge-Alerts wie `GRID_PATH_UNAVAILABLE` oder
    `LOW_SITE_OUTPUT_UNEXPECTED` ab

### Angreiferpfade

- `protocol_modbus`
  - Modbus-Sicht mit aktiven Units `1`, `11-13`, `21`, `31`, `41`
- `hmi_web`
  - HMI fuer `/overview`, `/single-line`, `/inverters`, `/weather`, `/meter`,
    `/alarms`, `/trends`, `/service/login`, `/service/panel`

### Betrieb und Ausleitung

- `monitoring`
  - lokaler Heartbeat nach `RUNTIME_STATUS_PATH`
- `runtime_evolution`
  - tickende `observed_at`-Zeit und kleine In-Memory-Trendhistorie fuer `/trends`
- `exporter_sdk`
  - gemeinsamer Vertrag fuer Exporter
- `exporter_runner`
  - Hintergrundrunner fuer Webhook, SMTP und Telegram
- `runtime_reset`
  - definierter Reset fuer Runtime-Artefakte
- `runtime_egress`
  - Gate fuer aktive Exportziele
- `runtime_ingress`
  - Gate fuer externe Bindings
- `runtime_exposure`
  - zusaetzliche Gates und Findings-Log fuer `exposed-research`
- `time_core`
  - kontrollierbare Zeitbasis fuer deterministische Tests
- `main`
  - gemeinsamer Einstiegspunkt fuer Start, Reset und Exposure-Sweep

## Doku-Landkarte

### Einstieg fuer Nicht-SCADA-Menschen

- [docs/scada-primer-and-module-guide.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/scada-primer-and-module-guide.md)
  - erklaert Komponenten, SCADA-Begriffe und Repo-Module in Klartext
- [docs/test-attacker-guide.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/test-attacker-guide.md)
  - zeigt, wie man HMI, Service-Panel und Modbus als Testangreifer bedient

### Architektur und Fachmodell

- [docs/architecture.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/architecture.md)
- [docs/domain-model.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/domain-model.md)
- [docs/protocol-profile.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/protocol-profile.md)
- [docs/register-matrix.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/register-matrix.md)
- [docs/hmi-concept.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/hmi-concept.md)
- [docs/logging-and-events.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/logging-and-events.md)

### Tests, Release und Betrieb

- [docs/testing-strategy.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/testing-strategy.md)
- [docs/release-checklist.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/release-checklist.md)
- [docs/security-operations.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/security-operations.md)
- [docs/pre-exposure-decision.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/pre-exposure-decision.md)
- [docs/exposed-research-checklist.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/exposed-research-checklist.md)
- [docs/exposed-research-runbook.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/exposed-research-runbook.md)
- [deploy/lab-vm-observer-01.env.example](/Users/schrammn/Documents/VSCodium/scada-honeypot/deploy/lab-vm-observer-01.env.example)

## Sicherheitsleitplanken

- keine reale OEM-Kopie
- keine echten Orts-, Firmen- oder Zugangsdaten im Repo
- keine Shell- oder Host-Zugriffspfade
- keine echte Fernsteuerung externer Systeme
- Logging ist Kernfunktion
- sichtbare Fehlersituationen brauchen Tests

Wichtige Runtime-Gates:

- `ALLOW_NONLOCAL_BIND=1`
- `APPROVED_INGRESS_BINDINGS`
- `APPROVED_EGRESS_TARGETS`
- `EXPOSED_RESEARCH_ENABLED=1`
- `PUBLIC_INGRESS_MAPPINGS`
- `APPROVED_EGRESS_RECIPIENTS`
- `WATCH_OFFICER_NAME`
- `DUTY_ENGINEER_NAME`

## Status

- lokaler V1-Release: `GO`
- `pre-exposure`: `GO`
- `exposed-research`: technisch vorbereitet, aber deployment-spezifisch
  freizugeben
- Gesamtteststand aktuell: `280 passed`
