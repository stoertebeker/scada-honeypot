# Target-Host Exposed Research Checklist

This checklist captures the intended production posture for a generic target
host. Replace values only in a non-versioned `.env` on the host.

## Exposure Scope

- HMI frontend: public HTTP port selected by `HMI_PUBLISHED_PORT`, default `8080`
- Modbus/TCP: public port selected by `MODBUS_PUBLISHED_PORT`, default `1502`
- Ops backend: host loopback only, default `127.0.0.1:9090`

## Required Checks

- `.env` does not contain real company names, real plant names, or real OT
  credentials
- HMI weather coordinates, if configured, are not visible in the HMI
- Ops Basic Auth is enabled if the operator exposes Ops through a tunnel or proxy
- `APPROVED_EGRESS_TARGETS` covers every active exporter
- `APPROVED_EGRESS_CIDRS` covers every resolved exporter A/AAAA address and the
  same CIDRs are enforced by the host or perimeter firewall
- `PROHIBITED_OT_CIDRS` contains every real OT route visible from the host
- `APPROVED_EGRESS_RECIPIENTS` names every active recipient
- `PUBLIC_INGRESS_MAPPINGS` matches the intended public Modbus and HMI ports
- `WATCH_OFFICER_NAME` and `DUTY_ENGINEER_NAME` are set in the real deployment

## Sweep

Run before opening public ingress:

```bash
docker compose run --rm honeypot python -m honeypot.main --verify-exposed-research-target-host
```

GO only if the sweep completes and the findings log is written.

## Stop Conditions

- HMI and Modbus disagree
- Ops is reachable publicly by accident
- exporter traffic goes to an unapproved target
- logs, event store, or findings are not persisted
- any real OT endpoint is reachable from the honeypot path
