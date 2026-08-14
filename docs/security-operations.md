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
- the HAProxy Modbus gateway on `0.0.0.0:${MODBUS_PUBLISHED_PORT:-1502}`
- Ops on `127.0.0.1:${OPS_PUBLISHED_PORT:-9090}`

Only the gateway publishes Modbus. It caps concurrent connections globally at
`64`, concurrent connections per source at `8`, and new connections per source
at `20` per `10s`. It forwards the original address using mandatory PROXY v1;
the private Python listener rejects missing, malformed, oversized, or nested
metadata before parsing Modbus or writing an event.

The Modbus listener also rejects MBAP lengths outside `2..254` before reading
the PDU and retains an application-level global handler ceiling. Compose caps
both containers' PIDs, memory, CPU, and open file descriptors; deployment
overrides must retain finite ceilings.

`MODBUS_PROXY_PROTOCOL_ENABLED=1` creates a trust boundary: never publish the
Python listener directly or connect an untrusted service to its private port.
NATed clients share one per-source gateway quota by design.

## Egress

Exporters are deny-by-default. Active exporters require:

- `APPROVED_EGRESS_TARGETS`
- `APPROVED_EGRESS_RECIPIENTS`

Documentation-only hostnames and documentation IP ranges are rejected for active
exporters during production exposure checks.

## GeoIP Maintenance

Automatic DB-IP updates are disabled by default. Enable them only with a pinned
`YYYY-MM` release and independently controlled SHA-256 pins for both compressed
archives. Do not derive the runtime pins from the same download transaction.

The container invokes the updater as the unprivileged `honeypot` user. Each run
has compressed and decompressed byte ceilings, a maximum gzip expansion ratio,
a total deadline, MMDB structural validation, and a `256 MiB` application-level
directory budget. A failed candidate is deleted and never replaces the last
valid database. Retain a host/filesystem quota as an outer containment layer;
the application budget is not a substitute for one.

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

## Evidence Storage

Do not disable or inflate evidence quotas without a volume-capacity review.
SQLite events, alerts, outbox rows, login campaigns, and credential aggregates
have age/row limits; events, campaigns, and usernames also have per-source
ceilings. The database and WAL use a byte budget, and ordinary attacker writes
stop at `EVIDENCE_MIN_FREE_BYTES + EVIDENCE_RESERVED_HEALTH_BYTES`. Only trusted
events with both `category=system` and `actor_type=system` may consume the
reserve down to the minimum-free watermark.

JSONL is secondary evidence. It stops before the same health reserve, rotates
to gzip, and enforces independent file, total-byte, and age bounds. Monitor
`store.evidence_retention` and `store.jsonl_retention` in runtime status,
especially dropped/pruned counters and `last_error`. Host or volume quotas are
still required as an outer containment layer.

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
- sustained evidence drops, retention pruning, or reserve-watermark use
- any sign of real OT reachability
