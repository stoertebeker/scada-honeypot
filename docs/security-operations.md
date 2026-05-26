# Security Operations

## Boundaries

- HMI and Modbus are the intended exposed surfaces.
- Ops is the protected operator backend and must stay local or protected.
- The honeypot must never control or contact real OT systems.
- Do not store real credentials, real plant names, or real OEM branding.

## Production Mode

Production is always the exposed-research path. The previous explicit exposure
toggle has been removed. Local development uses `HONEYPOT_LOCAL_DEBUG=1` and
only with loopback binds.

## Ingress

Docker Compose publishes:

- HMI on `0.0.0.0:${HMI_PUBLISHED_PORT:-8080}`
- Modbus on `0.0.0.0:${MODBUS_PUBLISHED_PORT:-1502}`
- Ops on `127.0.0.1:${OPS_PUBLISHED_PORT:-9090}`

## Egress

Exporters are deny-by-default. Active exporters require:

- `APPROVED_EGRESS_TARGETS`
- `APPROVED_EGRESS_RECIPIENTS`

Documentation-only hostnames and documentation IP ranges are rejected for active
exporters during production exposure checks.

## Ops Backend

Ops contains:

- settings
- source enrichment
- credential analysis
- runtime status
- event and alert views
- version log, including the read-only `/api/versions` JSON surface
- reset and maintenance controls

Protect Ops with loopback, VPN, SSH tunnel, or a hardened proxy path.

Only bounded runtime-safe defaults belong in Ops settings. Bind hosts, ports,
trusted proxies, egress approvals, exporter endpoints, evidence paths, and
boot-only service toggles remain `.env` decisions.

## Weather Privacy

Weather coordinates may be real internally. They must not appear in HMI pages,
events, findings, or public documentation.

## Fingerprint Hygiene

The hardening gate checks public documentation and attacker-facing HMI
templates/locales for private path leaks, framework/debug fingerprints, real
vendor clone terms, and deployable-looking secret material.

Do not add background network traffic, extra listeners, or outbound synthetic OT
peers for realism. HMI and Modbus remain the intended exposed surfaces. A
backend-only simulated local source marker needs an explicit design decision
before implementation.

## Incident Triggers

- public Ops exposure
- HMI/Modbus disagreement
- missing event trail for visible action
- exporter traffic to unapproved targets
- evidence persistence failure
- any sign of real OT reachability
