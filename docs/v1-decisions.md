# V1 Decisions

## Defaults

- `ENABLE_TRACKER=0`
- `ENABLE_SERVICE_LOGIN=1`
- `FC04` disabled by default
- Service logout is visible in the service panel and uses CSRF-protected `POST`
- exporters run in-process through the decoupled outbox/runner path
- native local binds default to `127.0.0.1`
- `PCAP_CAPTURE_ENABLED=0`

## Runtime Course

- production path: Docker Compose
- local development path: `HONEYPOT_LOCAL_DEBUG=1 uv run python -m honeypot.main`
- production sweep: `docker compose run --rm honeypot python -m honeypot.main --verify-exposed-research-target-host`

## Technology

- Python 3.12
- `uv`
- FastAPI
- Jinja2 templates
- `pymodbus`
- SQLite/WAL
- pytest, pytest-asyncio, httpx, Playwright

## Configuration Direction

`.env` should stay small and focused on initial deployment. Low-change defaults
should move to the protected Ops settings UI when this is safe and does not
affect boot-time security.

Current boundary: deployment, ingress, egress, evidence paths, exporter targets,
weather startup tuning, and boot-only services remain in `.env`. Service-login
lure settings, source enrichment, table limits, credential capture, and bounded
Modbus response timing are Ops settings.
