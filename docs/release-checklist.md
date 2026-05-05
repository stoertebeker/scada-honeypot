# Release Checklist

## Local Checks

```bash
uv run pytest
docker compose config --quiet
```

## Docker Checks

```bash
docker compose pull
docker compose up -d
docker compose logs --tail 50 honeypot
```

Expected:

- HMI responds on the configured host port
- Modbus accepts a socket connection on the configured host port
- Ops is reachable only through host loopback
- healthcheck becomes healthy

## Exposure Checks

```bash
docker compose run --rm honeypot python -m honeypot.main --verify-exposed-research-target-host
```

Review:

- findings log
- event store
- JSONL archive
- exporter approval config
- firewall/NAT mapping

## Documentation Checks

- README describes HMI and Ops boundaries
- attacker guide starts with Docker Compose
- docs do not mention the removed exposure toggle
- docs do not contain outdated logout assumptions
- docs do not contain private host paths or concrete personal device paths

## NO-GO Conditions

- failing tests
- public Ops backend
- real OT credentials or names
- unapproved egress
- HMI/Modbus inconsistency
