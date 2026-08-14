# Exposed Research Checklist Example

This file is an example only. Do not copy it as a live approval.

## Example Decision

Status: `NO-GO`

Reason:

- target-host values are not confirmed
- exporter targets are placeholders
- production sweep has not been run
- public ingress mapping is not confirmed by the operator

## Minimum Evidence Required For GO

- Docker Compose service starts cleanly
- HMI is reachable on the intended public host port
- Modbus is reachable on the intended public host port
- Ops remains reachable only from the operator path
- `--verify-exposed-research-target-host` completes
- event store, JSONL archive, and findings log are persisted
- exporter targets, CIDRs, recipients, and TLS are approved and non-placeholder
- rollback and reset procedure is known

## Security Reminder

A GO decision is deployment-specific. A successful local run is not a blanket
approval for internet exposure.
