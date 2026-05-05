# Logging And Events

## Purpose

Logging is a core honeypot function. The system records attacker activity,
process effects, alerts, exporter attempts, and operator-visible state changes.

## Event Store

SQLite/WAL stores structured events and current state. JSONL archiving can be
enabled for offline review.

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

## Exporter Outbox

Exporter delivery is decoupled through the outbox. A failed exporter must not
break HMI, Modbus, or core event recording.

## Language

Events and logs stay stable and English even when attacker-facing HMI locale
changes.
