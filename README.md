# SCADA Honeypot: Fictional Solar Plant

This project is a controlled SCADA honeypot for a fictional solar plant. It exposes a
Human-Machine Interface (HMI), meaning the attacker-facing honeypot frontend that
looks like an operator screen, plus a Modbus/TCP endpoint, realistic plant drift,
event and alert logging, and optional exporters. A separate Ops backend is the
protected operator backend for configuration, observation, reset, and maintenance.

The honeypot is built for exposed research. It must never control or reach real
operational technology.

## Operation

Production runs through Docker Compose. Defaults:

- HMI frontend on host port `8080`
- Modbus/TCP on host port `1502`
- Ops backend on host-loopback only at `127.0.0.1:9090`

```bash
cp .env.example .env
docker compose pull
docker compose up -d
docker compose logs -f honeypot
```

Entrypoints:

- HMI frontend: `http://<host>:8080/overview`
- Modbus/TCP: `<host>:1502`
- Ops backend: `http://127.0.0.1:9090/`

To publish the HMI frontend directly on port `80`, set only this host-port value:

```env
HMI_PUBLISHED_PORT=80
```

Container-internal ports are fixed by design. They are not deployment knobs.

## Installation

Production prerequisites:

- Docker with the Compose plugin
- this repository or a deployment bundle with `compose.yaml` and `.env`
- firewall, DNS, TLS proxy, and host hardening handled by the operator

Local development:

```bash
uv sync --dev
HONEYPOT_LOCAL_DEBUG=1 uv run python -m honeypot.main
uv run pytest
```

`HONEYPOT_LOCAL_DEBUG=1` is only for local loopback starts. As soon as a service
binds non-locally, production exposure gates apply.

## Configuration

The main template is `.env.example`. For a normal Docker deployment, only a few
values usually need changes:

- `HMI_PUBLISHED_PORT`: public host port for the HMI frontend, default `8080`
- `MODBUS_PUBLISHED_PORT`: public host port for Modbus, default `1502`
- `OPS_PUBLISHED_PORT`: local host port for Ops, default `9090`
- `WEATHER_PROVIDER`: `disabled`, `deterministic`, `open_meteo_forecast`, or `open_meteo_satellite`
- `WEATHER_LATITUDE` / `WEATHER_LONGITUDE`: real weather coordinates, never shown in the HMI
- `OPS_BASIC_AUTH_ENABLED`: optional Basic Auth for the Ops backend
- `APPROVED_EGRESS_TARGETS` and `APPROVED_EGRESS_RECIPIENTS`: required when exporters are enabled

Ops Basic Auth is enforced by the FastAPI Ops backend. It protects only the Ops
backend, not the attacker-facing HMI.

The HMI service-login credentials are lure credentials. Set them in the Ops
backend under `/settings`, section `Service Login Lure`; do not put real
passwords there.

## Components

- `config_core`: runtime configuration and safety validation
- `asset_domain` / `plant_sim`: plant model, alarms, setpoints, weather, and time evolution
- `protocol_modbus`: Modbus/TCP profile backed by the same plant truth as the HMI
- `hmi_web`: attacker-facing HMI frontend, service-login lure, and audit trail
- `event_core` / `storage`: SQLite/WAL event store, JSONL archive, alerts, and outbox
- `runtime_ingress` / `runtime_exposure` / `runtime_egress`: bind, exposure, and egress gates
- `ops_web`: protected local operator backend for status, reset, settings, sources, and versions
- `exporter_runner`: decoupled Webhook, SMTP, and Telegram exporters

## Tests

```bash
uv run pytest
docker compose config --quiet
```

Before real exposure, run a production-path sweep:

```bash
docker compose run --rm honeypot python -m honeypot.main --verify-exposed-research-target-host
```

## Security Course

- Do not enter real OEM names, real credentials, real plant paths, or real site names.
- Docker Compose is the production path; exposure is not hidden behind an optional switch.
- HMI and Modbus are the intended attack surface; Ops stays local.
- Exporters are deny-by-default and need approved targets and recipients.
- Weather coordinates may be real internally but are never shown in the HMI.
- The honeypot must not control or contact real OT systems.

## Further Reading

- [SCADA primer and module guide](docs/scada-primer-and-module-guide.md)
- [Attacker test guide](docs/test-attacker-guide.md)
- [Security operations](docs/security-operations.md)
- [Exposed research runbook](docs/exposed-research-runbook.md)
