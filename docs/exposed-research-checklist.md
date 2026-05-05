# Exposed Research Checklist

Use this checklist before any internet-facing deployment.

## 1. Configuration

- `.env` is based on `.env.example`
- only host-published ports are changed for Docker deployment
- `HONEYPOT_LOCAL_DEBUG` is not used in production
- `HMI_PUBLISHED_PORT` and `MODBUS_PUBLISHED_PORT` match firewall/NAT rules
- `OPS_PUBLISHED_PORT` remains host-loopback only
- weather coordinates, if used, are not identifying the operator

## 2. Identity Hygiene

- no real company names
- no real plant names
- no real usernames or passwords
- no OEM branding
- no host filesystem paths in public documentation

## 3. Ingress And Egress

- HMI public mapping is intentional
- Modbus public mapping is intentional
- Ops is not public
- every active exporter has an approved target
- every active exporter has a named recipient
- no exporter uses `.example`, `.invalid`, `.test`, or documentation IP ranges

## 4. Verification

```bash
docker compose config --quiet
docker compose run --rm honeypot python -m honeypot.main --verify-exposed-research-target-host
```

Review:

- findings log
- event store
- JSONL archive
- runtime status, if enabled
- host firewall and container port mappings

## 5. GO / NO-GO

GO only when the sweep passes and the operator can explain how to stop, reset,
and collect evidence.
