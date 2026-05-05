# SCADA Honeypot: Fiktiver Solarpark

Kontrollierter SCADA-Honeypot fuer einen fiktiven Solarpark. Das System bietet
eine Web-HMI, einen Modbus/TCP-Endpunkt, realistisch driftende Anlagenwerte,
Event-/Alert-Logging und optionale Exporter. Es ist fuer Forschungsbetrieb in
einer bewusst exponierten Umgebung gebaut, nicht fuer echte Anlagensteuerung.

## Betrieb

Production laeuft per Docker Compose. Default: HMI auf Host-Port `8080`,
Modbus auf `1502`, Ops-Backend nur auf Host-Loopback `127.0.0.1:9090`.

```bash
cp .env.example .env
docker compose pull
docker compose up -d
docker compose logs -f honeypot
```

Aufruf:

- HMI: `http://<host>:8080/overview`
- Modbus/TCP: `<host>:1502`
- Ops-Backend: `http://127.0.0.1:9090/`

Soll die HMI direkt auf Port `80` lauschen:

```env
HMI_PUBLISHED_PORT=80
```

Der Container mapped diesen Host-Port intern fest auf `8080`. Interne Ports
sind absichtlich keine Konfigurationsparameter.

## Installation

Voraussetzungen fuer Production:

- Docker mit Compose-Plugin
- geklonte Repo-Dateien oder ein eigenes Compose-Bundle mit `.env`
- Firewall, DNS, TLS-Proxy und Host-Hardening liegen beim Betreiber

Lokale Entwicklung und Tests:

```bash
uv sync --dev
HONEYPOT_LOCAL_DEBUG=1 uv run python -m honeypot.main
uv run pytest
```

`HONEYPOT_LOCAL_DEBUG=1` ist nur fuer lokale Loopback-Starts gedacht. Sobald
ein Dienst nicht-lokal gebunden wird, greifen die Production-Gates.

## Konfiguration

Die zentrale Vorlage ist `.env.example`. Fuer den normalen Docker-Betrieb
sollten nur wenige Werte angepasst werden:

- `HMI_PUBLISHED_PORT`: oeffentlicher Host-Port fuer die HMI, default `8080`
- `MODBUS_PUBLISHED_PORT`: oeffentlicher Host-Port fuer Modbus, default `1502`
- `OPS_PUBLISHED_PORT`: lokaler Host-Port fuer Ops, default `9090`
- `WEATHER_PROVIDER`: `disabled`, `deterministic`, `open_meteo_forecast`,
  `open_meteo_satellite`
- `WEATHER_LATITUDE` / `WEATHER_LONGITUDE`: echte Koordinaten fuer Wetterdaten,
  werden in der Honeypot-UI nicht angezeigt
- `OPS_BASIC_AUTH_ENABLED`: optionaler Basic-Auth-Schutz fuer das Ops-Backend
- `APPROVED_EGRESS_TARGETS` und `APPROVED_EGRESS_RECIPIENTS`: erforderlich,
  wenn Webhook, SMTP oder Telegram aktiviert werden

Ops Basic Auth wird durch die FastAPI-App des Ops-Backends erzwungen. Es ist
kein Reverse-Proxy-Feature und schuetzt nur das Ops-Backend, nicht die HMI.
Die HMI-Service-Login-Credentials sind ein Koeder und werden im Ops-Backend
unter `/settings` im Abschnitt `Service Login Lure` eingestellt.

## Bestandteile

- `config_core`: Runtime-Konfiguration und Sicherheitsvalidierung
- `asset_domain` / `plant_sim`: Anlagenmodell, Alarme, Setpoints, Wetter- und Zeitverlauf
- `protocol_modbus`: Modbus/TCP-Profil auf derselben Anlagenwahrheit wie die HMI
- `hmi_web`: attacker-facing Web-HMI mit Service-Login-Koeder und Audit-Spur
- `event_core` / `storage`: SQLite/WAL-Eventstore, JSONL-Archiv, Alerts
- `runtime_ingress` / `runtime_exposure` / `runtime_egress`: Bind-, Exposure- und Egress-Gates
- `ops_web`: lokales Betriebsbackend fuer Status, Reset und Settings
- `exporter_runner`: entkoppelte Webhook-, SMTP- und Telegram-Exporter

## Tests

```bash
uv run pytest
docker compose config --quiet
```

Vor echter Exponierung zusaetzlich:

```bash
docker compose run --rm honeypot python -m honeypot.main --verify-exposed-research-target-host
```

## Sicherheitskurs

- Keine echten OEM-Namen, Zugangsdaten, Anlagenpfade oder Standorte eintragen.
- Docker Compose ist der Production-Pfad; eine Exponierung wird nicht per
  optionalem Schalter versteckt.
- HMI und Modbus sind die gewollte Angriffsoberflaeche; Ops bleibt lokal.
- Exporter sind deny-by-default und brauchen Ziel- sowie Empfaengerfreigaben.
- Wetter-Koordinaten duerfen intern echt sein, werden aber nicht in der UI gezeigt.
- Der Honeypot darf keine realen OT-Systeme steuern oder erreichen.

## Weiterfuehrende Doku

- [SCADA-Modulguide](docs/scada-primer-and-module-guide.md)
- [Angreifer-Testguide](docs/test-attacker-guide.md)
- [Security Operations](docs/security-operations.md)
- [Exposed-Research-Runbook](docs/exposed-research-runbook.md)
