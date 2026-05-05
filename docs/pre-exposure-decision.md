# Pre-Exposure Decision

## Decision

The repository is ready for controlled target-host validation, not automatically
ready for any arbitrary internet exposure.

## Evidence Required

- full tests pass locally
- Docker Compose config is valid
- HMI and Modbus share the same state
- Ops remains host-loopback only
- exporter egress is approved
- target-host sweep passes
- findings log is written

## Current Production Course

Use Docker Compose:

```bash
docker compose pull
docker compose run --rm honeypot python -m honeypot.main --verify-exposed-research-target-host
docker compose up -d
```

## Stop Conditions

- public Ops exposure
- HMI and Modbus inconsistency
- missing events for visible actions
- exporter traffic to unapproved targets
- real OT access from the honeypot path
