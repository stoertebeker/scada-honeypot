# Testing Strategy

## Test Layers

- unit tests for settings, domain logic, storage, exporters, and rules
- integration tests for HMI, runtime, ingress, egress, exposure, and release gates
- contract tests for Modbus read/write behavior
- Playwright tests for browser-level HMI flows

## Main Commands

```bash
uv run pytest
uv run pytest tests/unit/test_repo_hardening.py
uv run pytest tests/contract
uv run pytest tests/integration
uv run pytest tests/e2e
docker compose config --quiet
```

## Production Sweep

```bash
docker compose run --rm honeypot python -m honeypot.main --verify-exposed-research-target-host
```

The sweep verifies runtime startup, Modbus read, HMI read, breaker alert
lifecycle, stop behavior, and findings output.

## Critical Guarantees

- HMI and Modbus use the same plant truth.
- Service controls require a valid service session and CSRF token.
- Service logout clears server-side session state and cookie.
- Local debug cannot be combined with non-loopback binds.
- Exporter failures do not break core runtime behavior.
- Weather provider failures degrade safely.
- Docker Compose keeps Ops on host loopback.
- Attacker-facing templates/locales do not expose debug/framework fingerprints,
  real vendor clone terms, private paths, or deployable-looking secrets.

## Documentation Checks

Docs should be checked for:

- old local-only startup instructions
- obsolete exposure switches
- missing HMI/Ops boundary explanation
- private or absolute host paths
- outdated logout assumptions
- missing statement that background network realism is out of scope
