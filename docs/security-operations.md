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

Exporters and auxiliary weather/GeoIP traffic are deny-by-default. Active
network paths require:

- `APPROVED_EGRESS_TARGETS`
- `APPROVED_EGRESS_CIDRS`
- `APPROVED_EGRESS_RECIPIENTS` for exporter deliveries

Documentation-only hostnames and documentation IP ranges are rejected for active
exporters during production exposure checks.

Webhook, Telegram, and Open-Meteo URLs use HTTPS without userinfo. The runtime
resolves all A and AAAA answers, rejects every non-global/special address and
any address outside `APPROVED_EGRESS_CIDRS`, then pins the vetted addresses at
the actual HTTP socket boundary. TLS still verifies the original hostname
through SNI, so a later DNS answer cannot redirect delivery to a sensitive
network. Open-Meteo requires the live and historical target specs before any
history seeding occurs.
Known routed OT ranges, including public allocations, must be entered in
`PROHIBITED_OT_CIDRS`; this denylist overrides all approvals.

SMTP uses certificate-verified implicit TLS from connection start; plaintext
SMTP and opportunistic STARTTLS are unsupported. `APPROVED_EGRESS_CIDRS` is the
application's independent socket allowlist, but it does not replace a host,
VPC, or perimeter firewall allowlist. That outer firewall must permit only the
same collector/mail CIDRs and must deny every real OT route.

## GeoIP Maintenance

Automatic DB-IP updates are disabled by default. Enable them only with a pinned
`YYYY-MM` release and independently controlled SHA-256 pins for both compressed
archives. Do not derive the runtime pins from the same download transaction.
The entrypoint also requires `geoip-dbip:download.db-ip.com:443` in
`APPROVED_EGRESS_TARGETS`; every resolved address must fit
`APPROVED_EGRESS_CIDRS` and remain outside `PROHIBITED_OT_CIDRS`. Missing policy
approval fails container startup even though download availability is optional.
The updater ignores environment proxies and rejects redirects so the approved
DB-IP hostname cannot silently delegate the request to another target.

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

## HMI Service Sessions

Keep `SERVICE_SESSION_MAX_ACTIVE`, `SERVICE_SESSION_MAX_ACTIVE_PER_USER`, and
the `SERVICE_SESSION_MAX_ADMISSIONS_PER_USER` per
`SERVICE_SESSION_ADMISSION_WINDOW_SECONDS` budget finite. Expired sessions are
swept during create, touch, and monitoring; full stores evict the least recently
used eligible session deterministically. Admission-limit responses return HTTP
`429` without allocating a new service session.

Monitor `runtime.hmi.service_sessions` in runtime status. `active` is a gauge;
`expired`, `evicted`, and `rejected` are cumulative process-lifetime counters.
Unexpected growth in the latter two indicates login pressure or limits that are
too tight for the intended lab workflow.

## HMI Forensic Session Attribution

The anonymous `hmi_session` cookie is a versioned HMAC token. Only a verified,
server-issued `hmi_<uuid>` identifier is written to events and used by Ops
source analytics. Invalid, malformed, oversized, future-dated, or expired
cookies are replaced and are never treated as authoritative session IDs.

Set `HMI_SESSION_SIGNING_KEY` to a deployment-specific value of at least 32
bytes when attribution must survive restarts. If it is empty, startup generates
an ephemeral key; this is safe for a single process but intentionally invalidates
all pre-restart cookies and is unsuitable for multiple independent workers.
`HMI_SESSION_MAX_AGE_SECONDS` defaults to `86400` and accepts values from 60
seconds through 30 days.

Rotate without losing attribution continuity:

1. Copy the old current key to `HMI_SESSION_PREVIOUS_SIGNING_KEY`.
2. Install a newly generated value as `HMI_SESSION_SIGNING_KEY` and restart.
3. Keep the previous key for at least `HMI_SESSION_MAX_AGE_SECONDS`; accepted
   old cookies are immediately reissued under the current key.
4. Clear `HMI_SESSION_PREVIOUS_SIGNING_KEY` and restart after the overlap.

Generate and transport these keys through the deployment secret mechanism; do
not commit populated values to the repository. Setting only a previous key,
using keys shorter than 32 bytes, or reusing the same key in both slots fails
configuration validation.

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
