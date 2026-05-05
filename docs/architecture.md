# Architecture

## Goal

The system is a controlled SCADA honeypot for a fictional solar plant. It offers
two attacker-facing surfaces and one protected operator surface:

- HMI frontend over HTTP
- Modbus/TCP endpoint
- Ops backend on host loopback only

All visible state comes from one domain model. There is no separate HMI truth or
Modbus truth.

## Runtime Shape

Production uses Docker Compose with a single service:

```bash
docker compose up -d
```

The container uses fixed internal ports:

- HMI: `8080`
- Modbus: `1502`
- Ops: `9090`

Only host-published ports are deployment parameters. Ops is bound to
`127.0.0.1` on the host.

## Data Flow

1. A client reads or writes through HMI or Modbus.
2. The protocol layer validates and normalizes the action.
3. The plant simulator updates the shared domain state.
4. Events, alerts, and plant-history samples are persisted.
5. HMI, Modbus, Ops, and exporters observe the same result.

## Persistence

SQLite in WAL mode stores:

- events
- current state
- alerts
- outbox entries
- plant history
- Ops settings
- credential-capture aggregates

JSONL archiving can mirror events for offline analysis.

## Safety Gates

- `runtime_ingress`: non-loopback binds require explicit approval.
- `runtime_exposure`: production exposure requires public ingress metadata,
  named operators, and non-placeholder exporter targets.
- `runtime_egress`: exporters are deny-by-default.
- `config_core`: validates coordinates, ports, cookies, proxies, exporters, and
  local debug constraints.

## Operator Boundary

The HMI is the honeypot frontend. The Ops backend is the protected operator
backend. Ops contains reset, settings, source enrichment, credential analysis,
runtime status, and version information.

Ops must remain local, tunneled, VPN-protected, or otherwise explicitly
protected by the deployment operator.
