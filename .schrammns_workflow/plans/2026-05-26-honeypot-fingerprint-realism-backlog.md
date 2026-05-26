# Plan: Honeypot Fingerprint Realism Backlog

**Date:** 2026-05-26
**Source:** `.schrammns_workflow/research/2026-05-26-honeypot-detection-countermeasures.md`

## Context

The supplied SCADA/HMI forum article highlights the same tells attackers use when probing OT honeypots: generic identities, too-perfect responses, lack of process logic, static operation, and clean fingerprints. The current project already has strong shared-truth and process-effect foundations: HMI and Modbus share the same plant model, FC04 is disabled, and writes create visible effects.

The selected backlog follows the approved course: no background network realism. The only future-adjacent idea is a backend-only simulated local source marker, but it is excluded from this first plan.

## Files to Modify

| File | Change |
|------|--------|
| `tests/unit/test_repo_hardening.py` | Extend hardening tests to scan attacker-facing files for prohibited leak patterns and debug surfaces. |
| `docs/security-operations.md` | Document the leakage gate and the no-background-network decision. |
| `docs/testing-strategy.md` | Add the fingerprint-realism release gate and verification commands. |
| `README.md` | Summarize the new exposed-research hardening checks. |
| `tests/contract/test_honeypot_fingerprint_realism.py` | **NEW** - Contract tests for function-code matrix, identity consistency, write persistence, and HMI/Modbus invariants. |
| `src/honeypot/protocol_modbus/registers.py` | Introduce a fictional identity profile and use it in identity register construction. |
| `tests/contract/test_protocol_modbus_read_only.py` | Update identity expectations and protect documented exception behavior. |
| `docs/register-matrix.md` | Document the fictional identity block layout and reserved fields. |
| `src/honeypot/protocol_modbus/server.py` | Add bounded optional Modbus response timing profile. |
| `src/honeypot/config_core/settings.py` | Add and validate protocol timing settings. |
| `.env.example` | Document default-off or low-impact timing knobs. |
| `tests/unit/test_runtime_config.py` | Cover timing setting validation. |
| `tests/contract/test_protocol_modbus_timing.py` | **NEW** - Verify timing bounds without creating flaky tests. |
| `src/honeypot/asset_domain/models.py` | Add bounded maintenance/shift fields if needed by the visible state. |
| `src/honeypot/plant_sim/core.py` | Model scheduled maintenance effects and degraded/stale transitions. |
| `src/honeypot/runtime_evolution.py` | Drive maintenance windows from clock/timezone without extra services. |
| `src/honeypot/hmi_web/app.py` | Surface maintenance/shift state in existing HMI view models. |
| `resources/locales/attacker-ui/en.json` | Add attacker-facing labels for maintenance/shift context. |
| `tests/unit/test_plant_sim.py` | Cover maintenance process effects and edge cases. |
| `tests/integration/test_hmi_web_overview.py` | Prove HMI reflects the same maintenance state as Modbus/domain state. |
| `docs/domain-model.md` | Document maintenance and shift fields as part of shared truth. |
| `docs/hmi-concept.md` | Document visible HMI behavior for maintenance windows. |

## Boundaries

**Always:** Keep changes atomic, testable, and tied to the shared plant model. Preserve existing HMI/Modbus consistency. Keep FC04 disabled by default.

**Ask First:** Any non-default timing above one second, any change to published ports, any use of a backend-only simulated local source marker, and any new attacker-facing route.

**Never:** New public ports; vendor clone; live secrets; payload hosting.

## Design Decisions

| Decision | Chosen | Rejected Alternatives | Rationale |
|----------|--------|----------------------|-----------|
| Background realism | Exclude from implementation | Synthetic traffic or extra listeners | Avoids added attack surface and keeps the project within current safety boundaries. |
| Identity realism | Fictional, internally consistent profile | Specific OEM mimicry | Plausibility improves without copying a real device family. |
| Timing realism | Bounded optional jitter with deterministic test mode | Unbounded sleeps or random failures | Reduces perfect-response signal without harming reliability. |
| Operations rhythm | Model local maintenance/shift state in existing domain and HMI paths | Separate fake subsystem | Keeps one shared truth and avoids inconsistent surfaces. |
| QA first | Add release-gate tests before behavior changes where possible | Manual-only review | Makes fingerprint regressions visible and repeatable. |

## Baseline Audit

| Metric | Command | Result |
|--------|---------|--------|
| Issue database | `bd status` | 26 total, 1 open, 0 in progress, 1 ready. |
| Worktree | `git status --short` | No tracked changes reported before this plan. |
| Existing hardening test | `nl -ba tests/unit/test_repo_hardening.py` | Current gate checks documentation path leaks only. |
| Existing Modbus identity | `rg -n "PROFILE_VERSION|DEVICE_CLASS_CODE|ASSET_TAG|_build_identity_registers" src/honeypot/protocol_modbus/registers.py` | Identity values are static constants. |
| Existing source-IP handling | `nl -ba src/honeypot/http_source.py` | Trusted-proxy logic exists; backend-only simulated source marker not implemented. |

## Implementation

### 1. Leakage Gate

In `tests/unit/test_repo_hardening.py`:

- Extend `DOCUMENTATION_PATHS` or add a new `ATTACKER_FACING_PATHS` tuple that includes `src/honeypot/hmi_web/templates`, `resources/locales/attacker-ui`, `docs`, and `README.md`.
- Add `test_attacker_facing_files_do_not_contain_prohibited_leaks`.
- Check for path leaks, debug route hints, framework fingerprints, vendor clone terms, and placeholder credentials that look deployable.
- Keep the checks explicit and low-noise. Use allowlists for documentation examples where needed.

In `docs/security-operations.md`, `docs/testing-strategy.md`, and `README.md`:

- Document the gate and the reason it exists.
- State that background network realism is excluded.

### 2. Fingerprint Contract QA

Add `tests/contract/test_honeypot_fingerprint_realism.py`:

- `test_modbus_function_code_matrix_is_intentional`: FC03/FC06/FC16 behave as documented; FC04 and unsupported codes return Modbus exceptions.
- `test_identity_blocks_are_consistent_across_units`: identity version, class, unit, instance, and ASCII tags agree with the configured profile.
- `test_write_readback_has_visible_effect`: a write changes the expected register, plant snapshot, event trail, and related HMI-visible value.
- `test_unknown_registers_and_units_are_quiet`: gaps and unknown units return generic Modbus exceptions and record rejected protocol events.

Reuse helpers from `tests/contract/test_protocol_modbus_read_only.py`, or extract small request helpers only if it reduces duplication.

Update `docs/testing-strategy.md` with the new contract command.

### 3. Fictional Identity Profile

In `src/honeypot/protocol_modbus/registers.py`:

- Add a frozen `ModbusIdentityProfile` dataclass or equivalent constants near `PROFILE_VERSION`.
- Replace scattered `DEVICE_CLASS_CODE`, `ASSET_INSTANCE`, and `ASSET_TAG` lookups with profile accessors.
- Expand `_build_identity_registers(unit_id)` to include stable reserved fields for firmware-like revision, lifecycle state, profile checksum, and site-local unit family. Keep values fictional.
- Preserve existing address ranges and exception behavior.

In `tests/contract/test_protocol_modbus_read_only.py` and `tests/contract/test_honeypot_fingerprint_realism.py`:

- Update expected identity tuples.
- Add tests that reserved fields are stable and non-conflicting.

In `docs/register-matrix.md`:

- Document the identity block layout, reserved fields, and no-OEM rule.

### 4. Bounded Protocol Timing

In `src/honeypot/config_core/settings.py`:

- Add settings such as `modbus_response_delay_min_ms`, `modbus_response_delay_max_ms`, and `modbus_response_delay_seed`.
- Validate `0 <= min <= max <= 1000`.
- Default to `0` min and a conservative max only if product decision approves nonzero default; otherwise keep disabled by default.

In `src/honeypot/protocol_modbus/server.py`:

- Add a `response_timing` dependency to `ReadOnlyModbusTcpService`.
- Delay immediately before `sendall` using a bounded deterministic/random strategy.
- Do not delay malformed frames that cause connection close before response unless explicitly covered.

Add `tests/contract/test_protocol_modbus_timing.py`:

- Test disabled timing has no configured delay object.
- Test configured timing stays within bounds using a deterministic seed or injected sleeper.
- Avoid wall-clock flaky assertions by injecting a fake sleeper where possible.

Update `.env.example`, `docs/protocol-profile.md`, and `docs/testing-strategy.md`.

### 5. Maintenance And Shift Rhythm

In `src/honeypot/asset_domain/models.py`:

- Add minimal shared-truth fields only if existing `operating_mode`, `quality`, and alarms are insufficient.
- Prefer reusing `operating_mode="maintenance"` and existing quality states before adding fields.

In `src/honeypot/plant_sim/core.py`:

- Add functions such as `apply_planned_maintenance_window` and `clear_planned_maintenance_window`.
- Effects should be bounded: visible status changes, lower output, stale/estimated quality, and reversible alarms.

In `src/honeypot/runtime_evolution.py`:

- Add a scheduler function based on configured timezone and clock.
- Keep it deterministic in tests.

In `src/honeypot/hmi_web/app.py` and `resources/locales/attacker-ui/en.json`:

- Surface maintenance context in existing pages without adding a route.
- Show consistent state on overview, alarms, trends, and service panel where already relevant.

In `tests/unit/test_plant_sim.py` and `tests/integration/test_hmi_web_overview.py`:

- Cover entering and leaving maintenance.
- Verify HMI and Modbus/domain state agree.

Update `docs/domain-model.md` and `docs/hmi-concept.md`.

## Tests

`tests/unit/test_repo_hardening.py`:
- `test_attacker_facing_files_do_not_contain_prohibited_leaks`: attacker-facing templates/locales/docs do not contain prohibited leakage patterns.

`tests/contract/test_honeypot_fingerprint_realism.py`:
- `test_modbus_function_code_matrix_is_intentional`
- `test_identity_blocks_are_consistent_across_units`
- `test_write_readback_has_visible_effect`
- `test_unknown_registers_and_units_are_quiet`

`tests/contract/test_protocol_modbus_read_only.py`:
- Update identity expectations and add regression for new identity fields.

`tests/unit/test_runtime_config.py`:
- `test_modbus_response_delay_bounds_are_validated`
- `test_modbus_response_delay_defaults_are_safe`

`tests/contract/test_protocol_modbus_timing.py`:
- `test_modbus_timing_profile_uses_injected_sleeper`
- `test_modbus_timing_profile_never_exceeds_configured_bounds`

`tests/unit/test_plant_sim.py`:
- `test_planned_maintenance_window_changes_visible_state`
- `test_planned_maintenance_window_clears_reversibly`

`tests/integration/test_hmi_web_overview.py`:
- `test_hmi_reflects_planned_maintenance_shared_truth`

## Verification

```bash
# Focused hardening gate
uv run pytest tests/unit/test_repo_hardening.py

# Contract fingerprint checks
uv run pytest tests/contract/test_honeypot_fingerprint_realism.py tests/contract/test_protocol_modbus_read_only.py

# Timing checks
uv run pytest tests/unit/test_runtime_config.py tests/contract/test_protocol_modbus_timing.py

# Maintenance checks
uv run pytest tests/unit/test_plant_sim.py tests/integration/test_hmi_web_overview.py

# Full regression
uv run pytest
```

## Issues

### Issue 1: Add Attacker-Facing Leakage Gate
**Size:** S
**Risk:** Low / reversible / no authorization change
**Dependencies:** None
**Acceptance:** `uv run pytest tests/unit/test_repo_hardening.py` passes and docs mention the gate.
**Description:** Extend `tests/unit/test_repo_hardening.py`; update `docs/security-operations.md`, `docs/testing-strategy.md`, and `README.md` with the leakage gate and excluded background-realism decision.

### Issue 2: Add Fingerprint Contract QA
**Size:** M
**Risk:** Low / reversible / test-only behavior
**Dependencies:** Issue 1
**Acceptance:** `uv run pytest tests/contract/test_honeypot_fingerprint_realism.py tests/contract/test_protocol_modbus_read_only.py` passes.
**Description:** Add `tests/contract/test_honeypot_fingerprint_realism.py`; reuse request helpers from `tests/contract/test_protocol_modbus_read_only.py`; update `docs/testing-strategy.md`.

### Issue 3: Implement Fictional Modbus Identity Profile
**Size:** M
**Risk:** Medium / reversible / protocol contract change
**Dependencies:** Issue 2
**Acceptance:** Contract tests pass and `docs/register-matrix.md` documents the identity block.
**Description:** Modify `src/honeypot/protocol_modbus/registers.py`, `tests/contract/test_protocol_modbus_read_only.py`, `tests/contract/test_honeypot_fingerprint_realism.py`, and `docs/register-matrix.md`.

### Issue 4: Add Bounded Modbus Timing Profile
**Size:** M
**Risk:** Medium / reversible / latency behavior change
**Dependencies:** Issue 2
**Acceptance:** Timing tests pass without wall-clock flakiness; defaults remain safe in `.env.example`.
**Description:** Modify `src/honeypot/config_core/settings.py`, `src/honeypot/protocol_modbus/server.py`, `.env.example`, `tests/unit/test_runtime_config.py`, `tests/contract/test_protocol_modbus_timing.py`, `docs/protocol-profile.md`, and `docs/testing-strategy.md`.

### Issue 5: Model Maintenance And Shift Rhythm
**Size:** L
**Risk:** Medium / reversible / visible state change
**Dependencies:** Issue 2
**Acceptance:** Unit and integration tests prove entering/leaving maintenance and HMI/domain agreement.
**Description:** Modify `src/honeypot/asset_domain/models.py`, `src/honeypot/plant_sim/core.py`, `src/honeypot/runtime_evolution.py`, `src/honeypot/hmi_web/app.py`, `resources/locales/attacker-ui/en.json`, `tests/unit/test_plant_sim.py`, `tests/integration/test_hmi_web_overview.py`, `docs/domain-model.md`, and `docs/hmi-concept.md`.

## Invalidation Risks

| Assumption | If Wrong, Impact | Affected Issues |
|------------|-----------------|-----------------|
| Existing Modbus helpers can be reused cleanly | QA issue may require helper extraction first | Issue 2 |
| Identity register expansion can stay inside the existing 0-49 block | Address layout may need a docs-first decision | Issue 3 |
| Bounded timing can be injected without brittle tests | Timing work may need a small abstraction layer | Issue 4 |
| Maintenance can reuse `operating_mode` and existing alarm states | Domain model change grows larger | Issue 5 |

## Execution Order

**Wave 1** (parallel): Issue 1, Issue 2
**Wave 2** (after Wave 1): Issue 3, Issue 4
**Wave 3** (after Wave 1): Issue 5

Issue 3 and Issue 4 can run independently after the QA baseline. Issue 5 should be reviewed carefully because it changes visible process behavior.

## Rollback Strategy

**Git checkpoint:** Before execution, create a rollback branch:
`git branch rollback/2026-05-26-honeypot-fingerprint-realism-backlog`

**Per-wave rollback:** Revert the atomic commit for the failed issue with `git revert <commit>`.

**Per-issue rollback notes:**
- Issue 1: Remove added hardening checks and doc paragraphs.
- Issue 2: Remove the new contract test file and docs entry.
- Issue 3: Revert identity profile code and expected identity tuples.
- Issue 4: Revert timing settings and server timing injection.
- Issue 5: Revert maintenance model/runtime/HMI additions together.

## Next Steps

- Review this plan with the captain.
- If approved, create `bd` issues mirroring Issues 1-5 and export `.beads/issues.jsonl`.
- Then implement each issue atomically: describe, get approval, read, implement, review, test, report, commit, push.
