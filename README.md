# SCADA Honeypot: Fiktiver Solarpark

Dieses Repo enthaelt einen interaktiven SCADA-Honeypot fuer einen fiktiven
Solarpark. Der Fokus liegt auf einer glaubhaften, kontrolliert bedienbaren
OT-Oberflaeche mit gemeinsamer Fachlogik fuer:

- `Modbus/TCP`
- Web-HMI
- Event-/Alert-Spur
- regelbasierte Folge-Alerts
- kontrollierte Exportpfade

Der aktuelle Stand ist **v1.3.1**. Der lokale Release, `pre-exposure` und der
deployment-spezifische Betriebskurs sind abgenommen; `v1.3.1` ergaenzt eine
leise `robots.txt` als Service-Login-Koeder und behaelt die DB-IP-Lite-
Beschaffung aus `v1.3.0` bei.

## Betrieb

### Lokaler Start

```bash
uv run python -m honeypot.main
```

Standardpfade im lokalen Designbetrieb:

- HMI: `http://127.0.0.1:8080/overview`
- HMI robots lure: `http://127.0.0.1:8080/robots.txt`
- Ops-Backend: `http://127.0.0.1:9090/`
- Modbus/TCP: `127.0.0.1:1502`

Das Ops-Backend fuehrt eigene persistente Einstellungen unter `/settings`.
IP-Anreicherung fuer die Source-Uebersicht wird dort aktiviert; rDNS bleibt
standardmaessig aus, weil es aktiven DNS-Egress erzeugt. Laender werden in der
Tabelle als kurze Codes wie `GER` angezeigt. Wenn keine ASN-MMDB konfiguriert
ist, nutzt die ISP-Spalte bei aktivem rDNS einen kompakten Domain-Fallback.

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

### Basis-Container bauen

Erster Docker-Schlag fuer den Runtime-Pfad:

```bash
docker build -t scada-honeypot:base .
docker run --rm \
  -p 127.0.0.1:9090:9090 \
  -p 8080:8080 \
  -p 1502:1502 \
  -e ALLOW_NONLOCAL_BIND=1 \
  -e MODBUS_BIND_HOST=0.0.0.0 \
  -e HMI_BIND_HOST=0.0.0.0 \
  -e OPS_BIND_HOST=0.0.0.0 \
  -e APPROVED_INGRESS_BINDINGS=modbus:0.0.0.0:1502,hmi:0.0.0.0:8080,ops:0.0.0.0:9090 \
  scada-honeypot:base
```

Hinweis:
- dieser Basiscontainer ist bewusst noch **nicht** der volle
  `production-ready`-Kurs
- die expliziten Laufzeitvariablen oben oeffnen nur den Container-Bind-Pfad;
  die sicheren Defaults im Repo bleiben unveraendert `deny-by-default`
- `compose`, `healthcheck`, `read_only`-Dateisystem und weitere
  Laufzeithärtung folgen als eigene Schläge

### Compose-Betrieb

Der produktive Docker-Kurs laeuft ueber genau einen Dienst in `compose.yaml`.
Eine `.env` ist weiter der Konfigurationsort, Compose braucht aber keine
zusaetzlichen Parameter oder Profilnamen:

```bash
cp .env.example .env
docker compose up --build -d
docker compose logs -f honeypot
```

Wichtige Defaults:
- HMI wird hostseitig auf `${HMI_PUBLISHED_HOST:-0.0.0.0}:${HMI_PUBLISHED_PORT:-8080}`
  veroeffentlicht
- Modbus wird hostseitig auf `${MODBUS_PUBLISHED_HOST:-0.0.0.0}:${MODBUS_PUBLISHED_PORT:-1502}`
  veroeffentlicht
- das interne Ops-Backend wird hostseitig nur auf
  `${OPS_PUBLISHED_HOST:-127.0.0.1}:${OPS_PUBLISHED_PORT:-9090}` veroeffentlicht
- im Container lauschen HMI, Modbus und Ops auf `0.0.0.0`, damit spaetere
  Compose-Services wie Caddy, Cloudflared, WireGuard oder Tailscale das Ops-
  Backend intern ueber `http://honeypot:9090` erreichen koennen
- der Hauptdienst laeuft mit `read_only`, `tmpfs` fuer `/tmp`,
  `restart: unless-stopped` und `no-new-privileges`
- der Healthcheck prueft den nicht-loggenden HMI-Endpunkt `/healthz` plus
  einen Modbus-Socket auf dem internen Runtime-Pfad
- DB-IP-Lite-GeoIP-Datenbanken werden bei Compose-Starts standardmaessig nach
  `./data/geoip` aktualisiert; der Hauptprozess liest sie im Container unter
  `/app/data/geoip`

Security-Hinweis:
- `OPS_PUBLISHED_HOST=127.0.0.1` ist der sichere Default. Setze fuer direkten
  Backend-Zugriff nur bewusst eine andere Host-IP oder `0.0.0.0` und kombiniere
  das mit Firewall, VPN, Tunnel oder Basic Auth.
- Caddy ist optional. Ohne Caddy kann der Honeypot direkt per VM-IP erreicht
  werden; mit Caddy oder Tunnel bleibt das Ops-Backend im Docker-Netz intern
  erreichbar.

### GeoIP-MMDB fuer Source-Anreicherung

Fuer belastbare Laender- und ISP-/Provider-Namen in der geschuetzten
Source-Uebersicht aktualisiert der Docker-Compose-Start standardmaessig die
freien DB-IP-Lite-MMDBs. Die Dateien werden nicht ins Repo oder Image
gebundled.

```bash
mkdir -p data/geoip
docker compose up --build -d
ls -lh data/geoip
```

Der Updater schreibt:

- `data/geoip/dbip-country-lite.mmdb`
- `data/geoip/dbip-asn-lite.mmdb`
- `data/geoip/metadata.json`

Im Ops-Backend unter `/settings`:

- `Enable IP enrichment` aktivieren
- `Country MMDB path` kann leer bleiben oder auf
  `/app/data/geoip/dbip-country-lite.mmdb` zeigen
- `ASN MMDB path` kann leer bleiben oder auf
  `/app/data/geoip/dbip-asn-lite.mmdb` zeigen
- bei ueblichen Dateinamen mit `country`, `asn` oder `isp` funktioniert auch
  Auto-Erkennung, wenn die Felder leer bleiben

Hinweise:
- DB-IP Lite steht unter `Creative Commons Attribution 4.0 International
  (CC BY 4.0)`. Das Ops-Backend zeigt bei vorhandener `metadata.json` den
  erforderlichen Link `IP Geolocation by DB-IP`.
- `GEOIP_DBIP_AUTO_UPDATE=0` deaktiviert den automatischen Download.
- `GEOIP_DBIP_RELEASE=YYYY-MM` pinnt eine konkrete DB-IP-Monatsversion.
- Der Updater nutzt fest verdrahtete DB-IP-HTTPS-URLs und ist kein frei
  konfigurierbarer Downloader.
- Download-Ausfaelle blockieren den Honeypot-Start nicht; fehlende Daten
  fuehren nur zu `UNK` oder rDNS-Fallback.
- MaxMind GeoLite2-Country und GeoLite2-ASN passen direkt.
- DB-IP Country Lite und ASN Lite funktionieren ebenfalls, sind aber
  attributionpflichtig.
- `Country = UNK` bedeutet: keine Country-MMDB gefunden oder kein Treffer.
- `ISP = example.net`-artige Werte bedeuten: ASN-MMDB lieferte keinen Treffer,
  daher wurde rDNS als Fallback genutzt.

Bezugsquellen:
- MaxMind GeoLite2 ASN: `https://dev.maxmind.com/geoip/docs/databases/asn/`
- MaxMind GeoLite2 Country: `https://dev.maxmind.com/geoip/docs/databases/country/`
- DB-IP ASN Lite: `https://db-ip.com/db/download/ip-to-asn-lite`
- DB-IP Country Lite: `https://db-ip.com/db/download/ip-to-country-lite`

Manueller Update-Lauf ausserhalb von Compose:

```bash
uv run honeypot-geoip-update --provider dbip-lite
```

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
  - SQLite-Eventstore, persistente `plant_history` fuer Erzeugungstrends plus
    optionales JSONL-Archiv
- `rule_engine`
  - leitet Folge-Alerts wie `GRID_PATH_UNAVAILABLE` oder
    `LOW_SITE_OUTPUT_UNEXPECTED` ab

### Angreiferpfade

- `protocol_modbus`
  - Modbus-Sicht mit aktiven Units `1`, `11-13`, `21`, `31`, `41`
- `hmi_web`
  - HMI fuer `/overview`, `/single-line`, `/inverters`, `/weather`, `/meter`,
    `/alarms`, `/trends`, `/service/login`, `/service/panel`, `/robots.txt`

### Betrieb und Ausleitung

- `monitoring`
  - lokaler Heartbeat nach `RUNTIME_STATUS_PATH`
- `ops_web`
  - internes read-only Backend fuer Events, Alerts und Source-Aktivitaet auf
    separatem Port
  - persistente Backend-Settings, Source-IP-Anreicherung und Audit-Events fuer
    Settings-Aenderungen
  - geschuetzte Credential-Analyse fuer Service-Login-Kampagnen mit
    All-Time-/Kampagnen-Toplisten und CSV-Export
  - Backend-Version-Log unter `/versions` mit nachvollziehbaren Feature- und
    Fix-Staenden
  - Wartungsaktion zum Loeschen der Anlagenhistorie, auditierbar ueber
    `ops.history.deleted`
- `runtime_evolution`
  - tickende `observed_at`-Zeit, wettergetriebene Anlagenleistung und
    persistente 30-Tage-Erzeugungshistorie fuer `/trends`, inklusive
    Tagesenergie-Balken aus dem Export-Energy-Zaehler
- `weather_core`
  - interne Wetterabstraktion mit deterministischem Offline-Provider, Open-Meteo-Adaptern, Geo-Config und Leak-Guards
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

- [docs/scada-primer-and-module-guide.md](docs/scada-primer-and-module-guide.md)
  - erklaert Komponenten, SCADA-Begriffe und Repo-Module in Klartext
- [docs/test-attacker-guide.md](docs/test-attacker-guide.md)
  - zeigt, wie man HMI, Service-Panel und Modbus als Testangreifer bedient

### Architektur und Fachmodell

- [docs/architecture.md](docs/architecture.md)
- [docs/domain-model.md](docs/domain-model.md)
- [docs/protocol-profile.md](docs/protocol-profile.md)
- [docs/register-matrix.md](docs/register-matrix.md)
- [docs/hmi-concept.md](docs/hmi-concept.md)
- [docs/logging-and-events.md](docs/logging-and-events.md)

### Tests, Release und Betrieb

- [docs/testing-strategy.md](docs/testing-strategy.md)
- [docs/release-checklist.md](docs/release-checklist.md)
- [docs/security-operations.md](docs/security-operations.md)
- [docs/pre-exposure-decision.md](docs/pre-exposure-decision.md)
- [docs/exposed-research-checklist.md](docs/exposed-research-checklist.md)
- [docs/exposed-research-runbook.md](docs/exposed-research-runbook.md)
- [deploy/lab-vm-observer-01.env.example](deploy/lab-vm-observer-01.env.example)

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
- `FORWARDED_HEADER_ENABLED=1` und enge `TRUSTED_PROXY_CIDRS`, wenn HMI
  oder Ops hinter einem Reverse Proxy laufen
- `WATCH_OFFICER_NAME`
- `DUTY_ENGINEER_NAME`

## Status

- lokaler V1-Release: `GO`
- `pre-exposure`: `GO`
- `exposed-research`: `GO` fuer den validierten Docker-Compose-Produktionspfad
  auf `scada.stoerte.net` und `scada-admin.stoerte.net`
- Release-Version: `v1.3.1`
- Gesamtteststand aktuell: `372 passed`
