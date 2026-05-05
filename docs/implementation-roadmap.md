# Implementation Roadmap

## Completed Baseline

The project has moved beyond initial scaffolding. The current baseline includes:

- Python 3.12 and `uv`
- FastAPI/Jinja2 HMI
- Modbus/TCP server
- shared plant model
- SQLite/WAL event store
- JSONL archive
- runtime evolution and plant history
- deterministic and Open-Meteo weather providers
- Ops backend
- Docker Compose production path
- Docker Hub publishing workflow

## Current Production Path

Production is Docker Compose first:

```bash
docker compose pull
docker compose up -d
```

Local development still uses:

```bash
HONEYPOT_LOCAL_DEBUG=1 uv run python -m honeypot.main
```

## Future Work

1. Migrate low-change `.env` defaults into the Ops settings UI where safe.
2. Keep `.env.example` focused on initial deployment requirements.
3. Add more HMI/Modbus slices only when shared-truth tests exist.
4. Expand realistic plant behavior without leaking real location data.
5. Improve operator runbooks as deployments become repeatable.

## Rule For New Work

Every new visible behavior needs:

- domain-state impact, if applicable
- event coverage
- HMI and/or Modbus consistency tests
- documentation update
- security review for misuse and data leakage
