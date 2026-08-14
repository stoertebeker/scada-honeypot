# Logging And Events

## Purpose

Logging is a core honeypot function. The system records attacker activity,
process effects, alerts, exporter attempts, and operator-visible state changes.

## Event Store

SQLite/WAL stores structured events and current state. JSONL archiving can be
enabled for offline review.

Persistent attacker evidence has mandatory retention controls:

- age and row limits for events, alerts, outbox, campaigns, and credentials
- global and per-source event, campaign, and username-cardinality limits
- a SQLite byte ceiling plus WAL checkpointing
- a free-space watermark with a separate reserve for trusted system-health events
- gzip JSONL rotation with file, total-byte, and age ceilings

When ordinary evidence reaches a quota or watermark, it is rejected instead of
consuming the health reserve. Current-state updates remain bounded and continue
independently. Runtime status exposes retained rows/bytes and cumulative dropped
or pruned counters. JSONL remains best-effort; an archive failure never rolls
back SQLite truth.

## Main Event Families

- `protocol.modbus.*`
- `hmi.page.*`
- `hmi.auth.*`
- `hmi.action.*`
- `process.*`
- `alert.*`
- `ops.*`
- `exporter.*`

## Service Login

The HMI service-login lure records:

- login page views
- failed login attempts
- successful login attempts
- repeated-failure alerts
- credential aggregates, depending on Ops settings
- service logout events

Credential display and export are available only in the protected Ops backend.
Do not use real passwords as lure credentials.

## Alerts

The rule engine derives alerts from event and state chains. Examples:

- repeated service-login failures
- breaker open
- grid path unavailable
- unexpected low output
- inverter communication loss
- multiple blocks unavailable

Event-time rule evaluation reads a bounded rule-specific alert context from
SQLite instead of loading the full alert log. This preserves active and cleared
transitions while keeping attacker-triggered HMI and Modbus event recording from
amplifying storage I/O as alert history grows.

## Exporter Outbox

Exporter delivery is decoupled through the outbox. A failed exporter must not
break HMI, Modbus, or core event recording. Oldest outbox rows, including
undelivered rows, may be pruned when retention limits are reached; this is
reported by the evidence-retention counters.

## Language

Events and logs stay stable and English even when attacker-facing HMI locale
changes.
