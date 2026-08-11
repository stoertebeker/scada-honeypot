# Exposed Research Runbook

## Purpose

This runbook describes the current Docker production path for a controlled
internet-facing honeypot deployment.

## Prepare

```bash
cp .env.example .env
docker compose config --quiet
docker compose pull
```

Edit `.env` only for deployment-specific values:

- public HMI host port
- public Modbus host port
- finite honeypot container resource limits, when the deployment needs values
  other than the safe defaults
- the patch-pinned `MODBUS_GATEWAY_IMAGE`, when updating HAProxy deliberately
- weather provider and coordinates
- optional Ops Basic Auth
- optional exporter targets and recipients

## Verify Before Exposure

Run the target-host sweep before opening public ingress:

```bash
docker compose run --rm honeypot python -m honeypot.main --verify-exposed-research-target-host
```

The sweep checks:

- runtime build
- egress approvals
- exposure metadata
- Modbus read
- HMI `/overview` read
- breaker alert lifecycle
- findings log write

## Start

```bash
docker compose up -d
docker compose logs -f honeypot modbus-gateway
```

Expected:

- HMI frontend reachable on the configured public host port
- Modbus reachable on the configured public host port through `modbus-gateway`
- no host port published for the Python Modbus listener in `honeypot`
- Ops reachable only on host loopback

## Operate

- watch logs and findings
- watch gateway rejection/connection logs for sustained rate-limit pressure
- review Ops events, alerts, sources, credentials, and versions
- keep exporter targets under change control
- do not expose Ops directly to the internet

## Stop And Reset

```bash
docker compose down
```

For a fresh artifact set, reset through the Ops backend or run the documented
runtime reset on a local/dev path. Do not delete evidence before collection.
