# Agent-Handoff

## Kurzlage

Das Repo ist kein Geruest mehr, sondern ein weitgehend fertiger lokaler
SCADA-Honeypot fuer einen fiktiven Solarpark.

Aktueller Kurs:

- lokaler V1-Release: `GO`
- `pre-exposure`: `GO`
- `exposed-research`: `GO` fuer den validierten Docker-Compose-Produktionspfad
  auf `scada.stoerte.net` und `scada-admin.stoerte.net`
- Release-Version: `v1.3.2`
- Gesamtteststand: `374 passed`
- Trends und sichtbare Snapshot-Zeit laufen inzwischen ueber eine persistente
  30-Tage-Erzeugungshistorie und `observed_at`, nicht mehr nur ueber den
  Fixture-Start
- der Docker-/Compose-Kurs ist auf einen Produktionsdienst reduziert,
  inklusive Healthcheck, `read_only`-Rootfs und einem Entry-Point, der
  Container-Binds bewusst auf den intern/proxyfaehigen Runtime-Pfad zieht
- `./data/geoip` wird nach `/app/data/geoip` gemountet; der Entry-Point kann
  DB-IP-Lite-Country-/ASN-MMDBs automatisch aktualisieren und schreibt
  CC-BY-Attributionsmetadata fuer das Ops-Backend
- der HMI-Service-Login-Koeder nutzt standardmaessig `admin` / `sunshine` und
  ist im geschuetzten Ops-Backend unter `/settings` aenderbar

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

### Containerbetrieb

```bash
docker compose up --build -d
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
  - `/robots.txt`
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
  - tickende Snapshot-Zeit plus wettergetriebene Leistungs-/Meterfortschreibung und persistente 30-Tage-Erzeugungshistorie fuer `/trends`, inklusive Tagesenergie-Balken
- `weather_core`
  - interne Wetterabstraktion mit deterministischem Offline-Provider, Open-Meteo-Adaptern, Geo-Config und Leak-Guards
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
- `ops_web`
  - Source-IP-Anreicherung mit Static Map, Country-MMDB, ASN-MMDB und rDNS-
    Fallback; GeoIP-MMDB-Dateien liegen im Compose-Pfad unter `/app/data/geoip`
    und werden bei ueblichen Dateinamen automatisch erkannt
  - DB-IP-Lite-Attribution aus `metadata.json` wird in der geschuetzten
    Ops-Oberflaeche angezeigt, sobald die Auto-Aktualisierung Daten geladen hat
- `geoip_update`
  - fester DB-IP-Lite-Downloader fuer Country und ASN, keine freie URL-Eingabe
- `main`
  - gemeinsamer Runtime-Einstieg

## Sichtbare Wirkung in V1

Wichtige End-to-End-Pfade, die schon stehen:

- Curtailment ueber HMI und Modbus
- Blindleistungsziel ueber HMI und Modbus
- `plant_mode_request` als gelatchter Bedienwunsch
- Breaker Open/Close mit sichtbarer Meter- und Alarmwirkung
- Inverter-Block Enable/Disable, Limit, PV-/DC-Disconnect und Reset
- `/single-line` zeigt Inverter-Schalter als anonyme Koederpfade oder, mit
  Service-Login, als CSRF-geschuetzte Service-Control-Bedienung
- `/robots.txt` markiert `/service/login` als disallowed und bleibt dabei
  bewusst ein leiser Koeder ohne Session- oder Eventspur
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
- im Compose-Kurs gibt es nur noch den Produktionsdienst `honeypot`; der
  Entry-Point aktiviert die Exposure-Gates fuer diesen Containerpfad
- bind-relevante Containerwerte werden im Entry-Point erzwungen, damit eine
  lokale `.env` mit `127.0.0.1` den Host-Zugriff nicht wieder still auf
  Loopback drueckt
- das Ops-Backend bleibt hostseitig per Default auf `127.0.0.1` veroeffentlicht
  und wird nur ueber `OPS_PUBLISHED_HOST` bewusst auf andere Interfaces gelegt

## Relevante Doku zuerst lesen

### Fuer Nicht-SCADA-Menschen

1. [docs/scada-primer-and-module-guide.md](scada-primer-and-module-guide.md)
2. [docs/test-attacker-guide.md](test-attacker-guide.md)

### Fuer Architektur und Fachmodell

1. [docs/architecture.md](architecture.md)
2. [docs/domain-model.md](domain-model.md)
3. [docs/protocol-profile.md](protocol-profile.md)
4. [docs/register-matrix.md](register-matrix.md)
5. [docs/hmi-concept.md](hmi-concept.md)
6. [docs/logging-and-events.md](logging-and-events.md)

### Fuer Betrieb und Freigabe

1. [docs/testing-strategy.md](testing-strategy.md)
2. [docs/release-checklist.md](release-checklist.md)
3. [docs/security-operations.md](security-operations.md)
4. [docs/pre-exposure-decision.md](pre-exposure-decision.md)
5. [docs/exposed-research-checklist.md](exposed-research-checklist.md)
6. [docs/exposed-research-runbook.md](exposed-research-runbook.md)

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

Repo-seitig ist der Grundbau fuer `v1.0.0` geschlossen. Der validierte
Einsatzpfad umfasst Caddy vor HMI und Ops, public Modbus `1502`,
Trusted-Proxy-Source-IP, leise `HEAD`-Probes und die geschuetzte Ops-Oberflaeche.

Offen fuer Produktpflege nach `v1.0.0`:

1. Admin-Passwort nach Release-Rollout rotieren
2. Egress-Empfaenger je Deployment regelmaessig pruefen
3. weitere HMI-/Modbus-Slices nur mit passender Testabdeckung ergaenzen

## Naechster sinnvoller Schritt

Wenn lokal weitergearbeitet wird:

1. keine neue Grundmechanik vorziehen
2. nur gezielte Härtung, Test- oder Doku-Schlaege

Wenn der Release neu ausgerollt wird:

1. Zielhost per `git pull` aktualisieren
2. Compose-Image neu bauen und den einzigen Produktionsdienst starten:
   `docker compose up --build -d`
3. HMI, Ops, optionale Proxy-/TLS-Header, Source-IP und Modbus kurz
   extern gegenpruefen
