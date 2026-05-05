# Attacker Test Guide

## Start The Honeypot

Use Docker Compose for the current production-like path:

```bash
cp .env.example .env
docker compose pull
docker compose up -d
```

Open:

- HMI frontend: `http://<host>:8080/overview`
- Modbus/TCP: `<host>:1502`
- Ops backend for the operator: `http://127.0.0.1:9090/`

For local development only:

```bash
HONEYPOT_LOCAL_DEBUG=1 uv run python -m honeypot.main
```

## HMI Recon

Recommended path:

1. `/overview`
2. `/robots.txt`
3. `/single-line`
4. `/inverters`
5. `/weather`
6. `/meter`
7. `/alarms`
8. `/trends`
9. `/service/login`

The service-login lure defaults to `admin` / `sunshine` unless changed in the
Ops backend under `/settings`.

After successful login, use `/service/panel`. A visible `Log Out` button ends
the service session.

## Service Actions To Try

- apply active-power limit
- apply reactive-power target
- latch plant-mode request
- open and close breaker
- disable and enable an inverter block
- set inverter block power limit
- toggle PV/DC disconnect
- request block reset

Check effects in HMI pages, Modbus reads, and Ops events.

## Modbus Recon

Read Unit `1` first, then Units `11` to `13`, `21`, `31`, and `41`.

Useful expectations:

- plant-controller values are on Unit `1`
- inverter blocks are on Units `11` to `13`
- weather is on Unit `21`
- meter values are on Unit `31`
- grid and breaker state are on Unit `41`

## Operator Review

After tests, the operator should review:

- Ops events
- alerts
- sources
- credential aggregates
- findings log, if a sweep was run

An HMI action without a matching event trail is a defect.
