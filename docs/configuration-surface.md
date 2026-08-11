# Configuration Surface

## Purpose

This project keeps `.env` focused on initial deployment and security-critical
boot decisions. Low-change values move to the protected Ops settings UI only
when they can be applied safely at runtime.

## Ops Settings

These values are safe to manage through the protected Ops backend under
`/settings`:

- service-login lure username and password
- source-enrichment toggles, local lookup paths, and rDNS timeout
- Events, Alerts, and Sources default table limits
- bounded Modbus response timing, `0..2000` ms with `0/0` disabled
- credential-capture aggregation, display, export, and retention limits

The Modbus timing `.env` keys remain supported as boot fallback values. As soon
as Ops settings are saved, the persisted Ops values take precedence.

## Remain In `.env`

These settings stay in `.env` because they affect deployment safety, startup
wiring, or evidence paths:

- public host ports, bind hosts, and nonlocal-bind approvals
- Modbus global/per-source connection ceilings and container resource limits
- Ops enablement, Ops Basic Auth, secure-cookie flags, and trusted proxies
- weather provider, coordinates, and provider startup tuning
- event store, JSONL archive, findings, runtime-status, and PCAP paths
- exporter enablement, endpoints, tokens, and explicit egress approvals
- image source and GeoIP updater inputs
- plant capacity and alert thresholds used to construct the rule engine
- outbox runner batch and retry timing
- process log level

## Migration Plan

Safe runtime migration is allowed only when all of these are true:

- the setting is bounded by server-side validation
- changing it cannot expose a new listener, route, credential, host path, or
  outbound target
- the running component can read the setting without restart or has an explicit
  refresh path
- tests prove both the runtime effect and the `.env` fallback behavior

Settings that fail one of these checks remain in `.env` until the runtime has a
safe refresh mechanism.
