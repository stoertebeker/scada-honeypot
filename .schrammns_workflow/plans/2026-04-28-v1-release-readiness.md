# Plan: V1.0 Release Readiness

**Date:** 2026-04-28
**Source:** External deployment retest on `scada.stoerte.net` / `scada-admin.stoerte.net`, `docs/release-checklist.md`, `bd status`

**Completion:** Completed on 2026-04-28 with `v1.0.0`. `HEAD` handling,
`/inverters` layout, external Caddy/HMI/Ops/Modbus validation, Beads closeout
and release documentation are done. Historical baseline notes below describe
the state before the final release fixes.

## Context

Der aktuelle Stand ist funktional nahe an V1.0: HMI, Ops-Backend, Trusted-Proxy-Source-IP, Credential-Capture, historische Erzeugungsdaten und Container-Healthcheck laufen im externen Deployment. Der letzte verifizierte Stand zeigt `v0.9.6` im Backend-Version-Log.

Vor einem sauberen V1.0-Tag bleiben drei technische No-Go-/Go-Check-Punkte: HMI-`HEAD`-Requests liefern noch `500`, `/inverters` ist bei Desktop-Breite sichtbar abgeschnitten, und die Target-Host-Exposed-Research-Validation ist im Beads-Board noch nicht abgeschlossen. Danach braucht der Release nur noch Dokumentations-/Versionierungsabschluss, Deployment-Sweep und eine letzte Sicherheitsfreigabe.

## Files to Modify

| File | Change |
|------|--------|
| `src/honeypot/hmi_web/app.py` | `HEAD`-fähige HMI-Routen oder Middleware/Handler ergänzen; `/healthz` muss auch per `HEAD` ohne Event funktionieren. |
| `src/honeypot/hmi_web/templates/inverters.html` | Tabelle/Layout so anpassen, dass Inhalte bei 1440px und Mobile nicht abgeschnitten werden. |
| `tests/integration/test_hmi_web_overview.py` | Regressionstests für `HEAD`-Routen und Inverter-Layout-Marker ergänzen. |
| `tests/e2e/test_hmi_service_playwright.py` | Optionalen Screenshot-/Viewport-Test für `/inverters` ergänzen, wenn Layout-Fix riskant ist. |
| `resources/backend_versions.json` | Abschlussversion `v1.0.0` mit Release-Scope und Sicherheitsnotizen hinzufügen. |
| `README.md` | Release-Status von release-fähig auf `v1.0.0` aktualisieren. |
| `docs/release-checklist.md` | Checkliste auf den realen Exposed-Research-Betrieb und die V1.0-Abnahme aktualisieren. |
| `docs/exposed-research-runbook.md` | Nach Zielhost-Sweep ggf. bestätigte Kommandos/Artefakte ergänzen. |
| `.beads/issues.jsonl` | Nach Beads-Abschluss per `bd export --no-memories -o .beads/issues.jsonl` aktualisieren. |

## Boundaries

**Always:** Jede Änderung atomar umsetzen, testen, committen und pushen. Keine Events oder Source-Statistiken durch interne Healthchecks verfälschen. HMI darf keine Tracebacks, Framework-Fehlerseiten oder Backend-Details leaken.

**Ask First:** Ob `HEAD` als `200` mit leerem Body oder als `405` ohne Fehler-Event behandelt werden soll. Empfehlung: `200` für `GET`-äquivalente Read-only-Routen und `/healthz`.

**Never:** Kein `down -v` auf dem Produktivhost ohne ausdrückliche Datenlöschfreigabe. Keine echten Zugangsdaten in Repo-Dateien. Keine öffentliche Ops-Oberfläche ohne vorgeschaltete Auth/VPN/Tunnel-Kontrolle.

## Design Decisions

| Decision | Chosen | Rejected Alternatives | Rationale |
|----------|--------|----------------------|-----------|
| HMI `HEAD` handling | Explizit `HEAD` für Read-only-Routen und `/healthz` bedienen | `HEAD` weiter als Fehler loggen; pauschale Exception-Unterdrückung | Scanner und Monitore nutzen `HEAD`; `500` erzeugt unnötige High-Severity-Events und sieht unprofessionell aus. |
| `/inverters` layout | Tabelle in klare Responsive-Spalten oder echte Scroll-Region bringen | Noch kleinere Schrift; Inhalte abschneiden | Ziel ist Bedienbarkeit und glaubhafte HMI, nicht nur kosmetisches Kaschieren. |
| V1.0 versioning | `v1.0.0` als Backend-Version-Log-Eintrag nach Fixes und Sweeps | Weiter `v0.9.x` trotz Deployment | Nach stabiler Exposed-Research-Validierung ist ein klarer Release-Anker sinnvoll. |
| Target-host validation | Beads `scada-honeypot-qrq.2` und `.3` vor Release schließen | Nur lokale Tests akzeptieren | V1.0 soll den realen Caddy/NAT/Compose-Pfad abdecken, nicht nur die Entwickler-Maschine. |

## Baseline Audit

| Metric | Command | Result |
|--------|---------|--------|
| Issue status | `bd status` | 12 total, 2 open, 1 in progress, 1 blocked; ready work: target-host validation. |
| External HMI GET | `curl https://scada.stoerte.net/{overview,single-line,inverters,weather,meter,alarms,trends,service/login}` | Alle geprüften GET-Routen liefern `200`. |
| External HMI HEAD | `curl -I https://scada.stoerte.net/overview` | `500`, erzeugt `hmi.error.internal`. |
| Healthcheck behavior | `/api/summary` vor/nach Wartefenster | Keine neuen `127.0.0.1`-Pageviews nach `v0.9.6`. |
| Trusted proxy | Ops Events/Sources | Externe HMI-Events erscheinen mit echter Client-IP statt Caddy-IP. |
| Inverter page screenshot | Playwright Desktop 1440px | `/inverters`-Tabelle rechts abgeschnitten; Header brechen unsauber. |

## Implementation

### 1. Fix HMI HEAD Handling

In `src/honeypot/hmi_web/app.py`:

- **Add HEAD handlers for `/healthz`**: Return an empty response with `200`, no cookie, no event.
- **Add HEAD handlers for read-only HMI pages**: Cover `/`, `/overview`, `/single-line`, `/inverters`, `/weather`, `/meter`, `/alarms`, `/trends`, `/service/login`.
- **Avoid event recording for HEAD** unless the request is intentionally suspicious or invalid. If logging is desired, use low-severity operational telemetry outside attacker page-view counts.

Key functions to reuse:
- `_record_page_view()` at `src/honeypot/hmi_web/app.py`
- `_render_error_page()` at `src/honeypot/hmi_web/app.py`
- `create_hmi_app()` route definitions at `src/honeypot/hmi_web/app.py`

### 2. Fix `/inverters` Layout

In `src/honeypot/hmi_web/templates/inverters.html`:

- **Modify `.layout` and `.table-scroll`** so the table never disappears under the side panel.
- **Reduce or reshape table columns**: Prefer fewer high-value columns in the main comparison plus details below/side, or make horizontal scroll visually explicit and contained.
- **Keep labels inside cells**: Avoid `overflow: hidden` on panels that clips scrollable table content.

Acceptance visual target:
- Desktop 1440px: full table affordance visible, no cut-off text at right edge.
- Mobile width: no incoherent overlap; horizontal scroll if needed.

### 3. Version and Documentation Closeout

In `resources/backend_versions.json`:

- Add `v1.0.0 / Initial exposed-research release` after Issues 1-2 and target-host validation.

In `README.md` and `docs/release-checklist.md`:

- Update current status to V1.0 only after all tests and target-host sweeps pass.
- Document remaining known limitations if they are accepted, but do not hide `HEAD` or layout defects as limitations if they are fixable before release.

### 4. Target-Host Validation and Beads Closeout

In `docs/exposed-research-runbook.md`:

- Nach erfolgreicher Zielhostfahrt nur dann anpassen, wenn die tatsächlich
  verwendeten Kommandos oder Artefaktpfade vom dokumentierten Kurs abweichen.

Commands on the Debian target host:

```bash
HONEYPOT_ENV_FILE=.env docker compose --profile exposed ps
HONEYPOT_ENV_FILE=.env docker compose --profile exposed logs --tail 120 honeypot-exposed
HONEYPOT_ENV_FILE=.env docker compose --profile verify run --rm honeypot-sweep
```

External probes:

```bash
curl -I https://scada.stoerte.net/healthz
curl -I https://scada.stoerte.net/overview
curl -sS https://scada.stoerte.net/overview >/dev/null
curl -sS --user "$OPS_AUTH" https://scada-admin.stoerte.net/api/summary
```

Beads:

```bash
bd close scada-honeypot-qrq.2 --reason "target-host sweep passed"
bd close scada-honeypot-qrq.3 --reason "findings reviewed and ingress approved"
bd export --no-memories -o .beads/issues.jsonl
```

## Tests

`tests/integration/test_hmi_web_overview.py` - add:
- `test_hmi_healthz_head_is_quiet`: `HEAD /healthz` returns `200`, no cookie, no event.
- `test_hmi_readonly_head_routes_do_not_raise_500`: read-only HMI `HEAD` routes do not hit the internal error handler.
- `test_inverters_page_layout_contains_scroll_region`: page includes stable wrapper/classes that prevent table clipping.

`tests/e2e/test_hmi_service_playwright.py` - optional:
- `test_playwright_inverters_layout_does_not_clip_table_desktop`: screenshot or DOM box check at 1440px.
- `test_playwright_inverters_layout_mobile_scrolls_cleanly`: mobile viewport has no overlap.

`tests/integration/test_ops_web.py` - update:
- `test_ops_versions_page_renders_backend_change_log`: assert `v1.0.0` only after final release entry.

## Verification

```bash
# Focused
uv run pytest tests/integration/test_hmi_web_overview.py::test_hmi_healthz_head_is_quiet
uv run pytest tests/integration/test_hmi_web_overview.py::test_hmi_readonly_head_routes_do_not_raise_500
uv run pytest tests/integration/test_ops_web.py::test_ops_versions_page_renders_backend_change_log

# Full suite
uv run pytest

# Container smoke
HONEYPOT_ENV_FILE=.env.example docker compose down -v --remove-orphans
HONEYPOT_ENV_FILE=.env.example docker compose up --build -d honeypot
curl -I http://127.0.0.1:8080/healthz
curl -I http://127.0.0.1:8080/overview
curl -sS http://127.0.0.1:9090/versions | rg 'v1.0.0|v0.9'
HONEYPOT_ENV_FILE=.env.example docker inspect --format '{{json .State.Health}}' scada-honeypot-honeypot-1
HONEYPOT_ENV_FILE=.env.example docker compose down -v --remove-orphans

# External post-deploy
curl -I https://scada.stoerte.net/healthz
curl -I https://scada.stoerte.net/overview
uv run playwright screenshot --full-page --viewport-size=1440,1200 https://scada.stoerte.net/inverters /tmp/scada-v1-inverters.png
```

## Issues

### Issue 1: Quiet HEAD Handling for HMI
**Size:** M
**Risk:** Low reversibility / medium observability impact / no extra authorization
**Dependencies:** None
**Acceptance:** Focused `HEAD` tests pass; external `curl -I /overview` and `/healthz` no longer return `500`; no high-severity internal error event for normal `HEAD`.
**Description:** Implement section "Fix HMI HEAD Handling" in `src/honeypot/hmi_web/app.py` and add regression tests in `tests/integration/test_hmi_web_overview.py`.

### Issue 2: Repair Inverter Page Layout
**Size:** M
**Risk:** Low reversibility / medium UX impact / no extra authorization
**Dependencies:** None
**Acceptance:** Desktop screenshot at 1440px shows no clipped right-side table; mobile remains readable; tests pass.
**Description:** Implement section "Fix `/inverters` Layout" in `src/honeypot/hmi_web/templates/inverters.html`, add integration coverage in `tests/integration/test_hmi_web_overview.py`, and add Playwright coverage in `tests/e2e/test_hmi_service_playwright.py` if the layout risk warrants it.

### Issue 3: Target-Host Sweep and Findings Review
**Size:** S
**Risk:** No code risk / high release confidence impact / requires target host access
**Dependencies:** Issues 1-2 deployed
**Acceptance:** `honeypot-sweep` passes on Debian host; Ops sources show real client IP; no new `127.0.0.1` healthcheck pageviews; Beads `qrq.2` and `qrq.3` closed.
**Description:** Run target-host validation commands, review Ops events, update `docs/exposed-research-runbook.md` if the deployed command path differs, close Beads, export `.beads/issues.jsonl`.

### Issue 4: V1.0 Version and Release Docs
**Size:** S
**Risk:** Low reversibility / release communication impact / no extra authorization
**Dependencies:** Issues 1-3
**Acceptance:** `v1.0.0` visible in Ops Versions; README/release checklist match deployment reality; docs contain no stale healthcheck or release-gate statements.
**Description:** Add V1.0 entry in `resources/backend_versions.json`, update `README.md`, `docs/release-checklist.md` and `docs/exposed-research-runbook.md` as needed, then run doc-sync-check.

### Issue 5: Final Release Tag
**Size:** S
**Risk:** Medium reversibility / release artifact impact / ask before tagging
**Dependencies:** Issues 1-4
**Acceptance:** Git tree clean, `uv run pytest` passed, Docker smoke passed, external retest passed; annotated tag pushed only after explicit approval.
**Description:** Verify `resources/backend_versions.json`, `README.md` and `docs/release-checklist.md` already contain the final V1.0 state, then create and push `v1.0.0` tag after final sign-off.

## Invalidation Risks

| Assumption | If Wrong, Impact | Affected Issues |
|------------|-----------------|-----------------|
| Starlette/FastAPI can serve explicit `HEAD` routes cleanly for these endpoints | Need middleware-level handling instead of per-route handlers | Issue 1 |
| `/inverters` can be fixed with CSS/template only | View model may need fewer or reorganized fields | Issue 2 |
| Target host has the latest pushed commit and no local uncommitted config drift | External validation may show old behavior | Issue 3 |
| Existing event history can remain in SQLite | Source statistics still contain historical `127.0.0.1` rows, though no new ones appear | Issue 3 |

## Execution Order

**Wave 1** (parallel-capable): Issue 1, Issue 2
**Wave 2** (after Wave 1): Issue 3
**Wave 3** (after Wave 2): Issue 4
**Wave 4** (after explicit approval): Issue 5

## Rollback Strategy

**Git checkpoint:** Before execution, create:
`git branch rollback/2026-04-28-v1-release-readiness`

**Per-wave rollback:** Revert the last atomic commit if a wave fails:
`git revert --no-commit HEAD`

**Per-issue rollback notes:**
- Issue 1: Revert route/handler changes and tests.
- Issue 2: Revert template/CSS changes and screenshots/tests.
- Issue 3: No code rollback; reopen Beads if findings fail.
- Issue 4: Revert version/docs commit before tagging.
- Issue 5: If tag was pushed incorrectly, coordinate before deleting remote tag.

## Next Steps

- Start with Issue 1: quiet `HEAD` handling for HMI.
- Then Issue 2: `/inverters` layout.
- After both are deployed, run Issue 3 on the Debian target host.
