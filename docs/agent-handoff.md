# Agent Handoff

## Current State

The repository is a working SCADA honeypot for a fictional solar plant. The
production path is Docker Compose with one service named `honeypot`.

Current baseline:

- attacker-facing HMI frontend: host port `8080` by default
- Modbus/TCP: host port `1502` by default
- protected Ops backend: host-loopback only, port `9090`
- Docker image: `stoertebeker2k/scada-honeypot:latest`
- latest full local test status before this documentation sync: `378 passed`
- Docker publish workflow runs on pushes to `main`

The HMI service-login lure defaults to `admin` / `sunshine` and can be changed
in the protected Ops backend under `/settings`.
Bounded Modbus response timing is also controlled in Ops `/settings`; `.env`
values remain only as boot fallback before Ops settings are saved.

## Start Commands

Production:

```bash
cp .env.example .env
docker compose pull
docker compose up -d
docker compose logs -f honeypot
```

Local development:

```bash
uv sync --dev
HONEYPOT_LOCAL_DEBUG=1 uv run python -m honeypot.main
uv run pytest
```

Target-host sweep:

```bash
docker compose run --rm honeypot python -m honeypot.main --verify-exposed-research-target-host
```

## Important Runtime Rules

- HMI, Modbus, alerts, trends, and Ops all use the same plant truth.
- Docker Compose forces container-internal binds required for exposure.
- Ops stays published only on host loopback.
- `HONEYPOT_LOCAL_DEBUG=1` is a development-only loopback bypass.
- Production sweeps reject local debug mode.
- Exporters require approved egress targets and named recipients.

## Main Modules

- `config_core`: settings and validation
- `asset_domain`: typed plant state
- `plant_sim`: state transitions and process effects
- `runtime_evolution`: clock-driven plant history and weather effects
- `weather_core`: deterministic and Open-Meteo weather adapters
- `protocol_modbus`: Modbus/TCP server and register map
- `hmi_web`: attacker-facing HMI frontend and service panel
- `ops_web`: protected operator backend
- `event_core` and `storage`: events, alerts, SQLite/WAL, JSONL, outbox
- `runtime_ingress`, `runtime_exposure`, `runtime_egress`: safety gates
- `exporter_runner`: Webhook, SMTP, and Telegram delivery

## Tracker State

Use `bd ready` before starting the next work item. At this handoff, the
low-change `.env` defaults task has been implemented for the safe runtime
surface, and additional candidates must remain in `.env` until a safe runtime
refresh path exists.

Keep `.beads/issues.jsonl` in sync with `bd export --no-memories -o .beads/issues.jsonl`
before committing tracker changes.
