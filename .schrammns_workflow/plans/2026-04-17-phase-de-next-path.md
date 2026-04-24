# Plan: Phase D/E Next Path

**Date:** 2026-04-17
**Source:** `.schrammns_workflow/research/2026-04-15-projekt-status-und-baukurs.md`

## Context
Der lokale V1-Prototyp ist nicht mehr nur Geruest: Fachmodell, Simulationskern,
Eventstore, Outbox, lokaler Modbus-Slice, HMI, Service-Panel und zwei echte
Exporter laufen bereits auf einer gemeinsamen Wahrheit. Der aktuelle
Repo-Stand ist in `README.md`, `docs/agent-handoff.md` und dem letzten
gruenen Testlauf mit `163 passed` sichtbar.

Die offenen Luecken liegen jetzt nicht mehr im Fundament, sondern an den
Rändern der Glaubhaftigkeit und Beobachtbarkeit: weitere mehrstufige
Alert-Folgen im `rule_engine`, der bereits vorbereitete aber noch fehlende
`SMTP`-Exporter und haertere Release-Gates gegen Alert-/Exporter-Rauschen.
Der Plan bleibt bewusst lokal und sicherheitsdiszipliniert: keine neue
Aussenkante, keine Umgehung der Outbox, keine zweite Wahrheit neben Fachkern,
Modbus und HMI.

## Files to Modify

| File | Change |
|------|--------|
| `src/honeypot/rule_engine/engine.py` | Weitere mehrstufige Folge-Regeln fuer `GRID_PATH_UNAVAILABLE` und `LOW_SITE_OUTPUT_UNEXPECTED` ergaenzen |
| `src/honeypot/event_core/recorder.py` | Falls noetig Kontext-/Asset-Aufloesung fuer weitere Rule-Ableitungen praezisieren |
| `src/honeypot/config_core/settings.py` | Vorhandene `SMTP`-Konfiguration fuer den echten Exportpfad absichern, ohne neue Default-Exponierung |
| `src/honeypot/exporter_runner/smtp_exporter.py` | **NEW** — lokaler SMTP-Exporter auf derselben Outbox-Wahrheit einfuehren |
| `src/honeypot/exporter_runner/__init__.py` | `SmtpExporter` exportieren |
| `src/honeypot/main.py` | `SMTP`-Exporter opt-in in `_build_exporters()` verdrahten |
| `tests/unit/test_rule_engine.py` | Regeln fuer `GRID_PATH_UNAVAILABLE` und `LOW_SITE_OUTPUT_UNEXPECTED` auf Rule-Ebene beweisen |
| `tests/unit/test_event_core.py` | Event-/Outbox-Ableitung fuer neue Folge-Alerts pruefen |
| `tests/unit/test_exporter_runner.py` | SMTP-Delivery, Retry und Alert-only-Verhalten pruefen |
| `tests/unit/test_runtime_bootstrap.py` | Runtime-Bootstrap fuer `SMTP`-Exporter absichern |
| `tests/integration/test_runtime_main.py` | Echter Runtime-Pfad fuer `SMTP`-Outbox-Drain pruefen |
| `tests/integration/test_release_gates.py` | Release-Gates fuer Alert-Suppression und ruhige Exporter-Fehler erweitern |
| `README.md` | Fortschritt und neue Rule-/Exporter-Faehigkeiten synchronisieren |
| `docs/agent-handoff.md` | Teststand, neuer Baukurs und naechste Luecken aktualisieren |

## Boundaries

**Always:** Gemeinsame Wahrheit zwischen `plant_sim`, `protocol_modbus`, `hmi_web` und `event_core` behalten; neue Alerts nur aus kanonischen Events ableiten; Export immer ueber `outbox` und Runner; lokale Defaults und ruhige Fehlerbilder bewahren.
**Ask First:** Ob nach den vier Issues noch ein weiterer HMI-Ausbau oder bereits Exposure-/Operations-Themen priorisiert werden sollen.
**Never:** Keine neue Bindung ausserhalb `127.0.0.1`; keine direkte externe Fernsteuerung; keine blockierende Auslieferung im Anfragepfad; keine OEM-/Betreiberdaten oder Shell-/Host-Pfade.

## Design Decisions

| Decision | Chosen | Rejected Alternatives | Rationale |
|----------|--------|----------------------|-----------|
| Naechster Schwerpunkt | Erst `rule_engine`, dann Exporter, dann Gates | Sofort weitere HMI-Seiten oder neue Protokolle | Die glaubhafte Reaktion auf Bedienung und Fehler ist aktuell wertvoller als noch mehr Oberflaeche |
| `GRID_PATH_UNAVAILABLE` | Als Folge-Alert aus bestehendem Grid-/Breaker-Kontext | Direkt im `plant_sim` als eigener Szenario-Alarm | Die Folgelogik gehoert in den Regelkern und bleibt dort besser suppressible |
| `LOW_SITE_OUTPUT_UNEXPECTED` | Schwellwertbasiert aus vorhandener Site-/Weather-Wahrheit | Neue eigene Simulationsschicht nur fuer Alarmbildung | `alarm_threshold_low_output_pct` existiert bereits in `settings.py` |
| `SMTP`-Exporter | Opt-in, alert-only, ueber Outbox und Runner | Direkter Versand aus `EventRecorder` oder HMI-Pfad | Entkoppelt Delivery von Bedienpfaden und erhaelt denselben Retry-/Quiet-Failure-Kurs |

## Baseline Audit

| Metric | Command | Result |
|--------|---------|--------|
| Voller Teststand | `uv run pytest -q` | `163 passed in 15.46s` |
| Sichtbare Moduldateien | `find src/honeypot -maxdepth 2 -type f \| wc -l` | `34` |
| Sichtbare Testdateien | `find tests -maxdepth 2 -type f \| wc -l` | `20` |

## Implementation

### 1. Rule-Folgen fuer Grid und Low Output

In `src/honeypot/rule_engine/engine.py`:

- **Add `GridPathUnavailableRule`**:
  Aus Grid-/Breaker-Ereignissen einen kritischen Folge-Alert `GRID_PATH_UNAVAILABLE`
  ableiten, wenn der Exportpfad nicht verfuegbar ist und die bestehende
  Signatur noch nicht `cleared` wurde.

- **Add `LowSiteOutputUnexpectedRule`**:
  Aus vorhandener Site-/Weather-Wahrheit einen `LOW_SITE_OUTPUT_UNEXPECTED`
  ableiten, wenn `plant_power_mw` deutlich unter der erwarteten Verfuegbarkeit
  liegt und kein offensichtlicher erklaerender Zustand wie Breaker-offen oder
  aktive Curtailment greift.

In `src/honeypot/event_core/recorder.py`:

- **Reuse `RuleContext`-Aufbau**:
  Falls fuer die Regelableitung noetig, bestehende `current_state`-/`alert_history`-
  Verdrahtung so erweitern, dass die neuen Regeln ohne zweite Wahrheit arbeiten.

Key functions to reuse:
- `RuleEngine.evaluate()` in `src/honeypot/rule_engine/engine.py`
- `EventRecorder._derive_rule_alerts()` in `src/honeypot/event_core/recorder.py`

### 2. SMTP-Exporter auf bestehender Outbox

In `src/honeypot/exporter_runner/smtp_exporter.py`:

- **Add `SmtpExporter`**:
  Ein lokaler Exporter, der nur Alert-Batches akzeptiert, ruhige Fehlerbilder
  liefert und denselben Delivery-Vertrag wie `WebhookExporter` und
  `TelegramExporter` einhaelt.

In `src/honeypot/exporter_runner/__init__.py` und `src/honeypot/main.py`:

- **Export and wire `SmtpExporter`**:
  `SMTP` opt-in in `_build_exporters()` verdrahten, ohne bestehende Webhook- und
  Telegram-Pfade zu brechen.

In `src/honeypot/config_core/settings.py`:

- **Keep existing SMTP config authoritative**:
  Keine neuen Defaults, nur sicherstellen, dass die vorhandenen Felder sauber
  zum echten Exportpfad passen.

### 3. Release-Gates fuer Alert-Rauschen und Exporter-Ruhe

In `tests/integration/test_release_gates.py`:

- **Extend release gates**:
  Neue Folge-Alerts und `SMTP`-Fehler muessen dieselben Quiet-Failure- und
  Anti-Noise-Gates erfuellen wie bestehende Exporter.

In `tests/integration/test_runtime_main.py` und `tests/unit/test_runtime_bootstrap.py`:

- **Verify runtime wiring**:
  Der Runtime-Pfad muss `SMTP` korrekt bootstrappen, ohne lokale Dienste oder
  Startpfad zu verrauschen.

## Tests

`tests/unit/test_rule_engine.py` — add:
- `test_grid_path_unavailable_rule_derives_follow_up_alert`
- `test_low_site_output_rule_derives_threshold_alert_without_breaker_or_curtailment`

`tests/unit/test_event_core.py` — add:
- `test_record_derives_grid_path_follow_up_alert_once`
- `test_record_derives_low_output_alert_without_outbox_flood`

`tests/unit/test_exporter_runner.py` — add:
- `test_smtp_exporter_accepts_alert_batch`
- `test_smtp_exporter_rejects_event_batch`
- `test_smtp_exporter_failure_sets_retry_metadata`

`tests/unit/test_runtime_bootstrap.py` — add:
- `test_build_local_runtime_wires_smtp_exporter_when_enabled`

`tests/integration/test_runtime_main.py` — add:
- `test_runtime_background_runner_drains_smtp_outbox`

`tests/integration/test_release_gates.py` — add:
- `test_release_gates_suppress_duplicate_grid_path_follow_up_alerts`
- `test_release_gates_keep_smtp_failure_quiet_from_client_paths`

## Verification

```bash
# Rule and recorder focus
uv run pytest -q tests/unit/test_rule_engine.py tests/unit/test_event_core.py

# Exporter and runtime focus
uv run pytest -q tests/unit/test_exporter_runner.py tests/unit/test_runtime_bootstrap.py tests/integration/test_runtime_main.py

# Release gates
uv run pytest -q tests/integration/test_release_gates.py

# Full suite
uv run pytest -q
```

## Issues

### Issue 1: Grid-Path-Folgeregel
**Size:** S
**Risk:** low / medium / no new authorization
**Dependencies:** None
**Acceptance:** `uv run pytest -q tests/unit/test_rule_engine.py tests/unit/test_event_core.py`
**Description:** In `src/honeypot/rule_engine/engine.py` und `tests/unit/test_rule_engine.py` die Folge-Regel `GRID_PATH_UNAVAILABLE` sauber auf bestehende Grid-/Breaker-Ereignisse setzen; `tests/unit/test_event_core.py` muss beweisen, dass `event_core/recorder.py` denselben Alert nur einmal ableitet.

### Issue 2: Low-Output-Folgeregel
**Size:** M
**Risk:** medium / medium / no new authorization
**Dependencies:** Issue 1
**Acceptance:** `uv run pytest -q tests/unit/test_rule_engine.py tests/unit/test_event_core.py`
**Description:** In `src/honeypot/rule_engine/engine.py`, optional `src/honeypot/event_core/recorder.py` und `tests/unit/test_rule_engine.py` den Schwellwert-Alert `LOW_SITE_OUTPUT_UNEXPECTED` aus vorhandener Site-/Weather-Wahrheit und `config_core/settings.py` ableiten, ohne Breaker- oder Curtailment-Faelle falsch zu alarmieren.

### Issue 3: SMTP-Exporter
**Size:** M
**Risk:** low / medium / no new authorization
**Dependencies:** None
**Acceptance:** `uv run pytest -q tests/unit/test_exporter_runner.py tests/unit/test_runtime_bootstrap.py tests/integration/test_runtime_main.py`
**Description:** `src/honeypot/exporter_runner/smtp_exporter.py` neu anlegen, in `src/honeypot/exporter_runner/__init__.py` exportieren und in `src/honeypot/main.py` auf vorhandene `RuntimeConfig` aus `src/honeypot/config_core/settings.py` verdrahten; `tests/unit/test_exporter_runner.py`, `tests/unit/test_runtime_bootstrap.py` und `tests/integration/test_runtime_main.py` pruefen Delivery, Retry und Runtime-Wiring.

### Issue 4: Release-Gates nachziehen
**Size:** S
**Risk:** low / high / no new authorization
**Dependencies:** Issue 1, Issue 2, Issue 3
**Acceptance:** `uv run pytest -q tests/integration/test_release_gates.py && uv run pytest -q`
**Description:** In `tests/integration/test_release_gates.py` die Ruheanforderungen fuer neue Alerts und den `SMTP`-Pfad absichern; danach `README.md` und `docs/agent-handoff.md` auf den neuen Teststand und die geschlossenen Luecken synchronisieren.

## Invalidation Risks

| Assumption | If Wrong, Impact | Affected Issues |
|------------|-----------------|-----------------|
| Grid-/Breaker-Ereignisse liefern genug Kontext fuer `GRID_PATH_UNAVAILABLE` | Regel muss zusaetzliche `current_state`-Felder auswerten | Issue 1 |
| `LOW_SITE_OUTPUT_UNEXPECTED` laesst sich ohne neue Simulationsschicht sauber ableiten | Regel wird groesser oder muss auf spaeter verschoben werden | Issue 2 |
| Vorhandene `SMTP`-Konfigurationsfelder reichen fuer einen minimalen Exporter | `config_core/settings.py` braucht weitere Felder und Tests | Issue 3 |

## Execution Order

**Wave 1** (parallel faehig inhaltlich, seriell wegen atomarer Commits): Issue 1, Issue 3
**Wave 2** (nach Wave 1): Issue 2
**Wave 3** (nach Wave 2): Issue 4

## Rollback Strategy

**Git checkpoint:** Vor Ausfuehrung einen Rollback-Zweig setzen:
`git branch rollback/2026-04-17-phase-de-next-path`

**Per-wave rollback:** Wenn eine Welle kippt, auf den letzten gruenen Commit
dieser Welle mit `git revert --no-commit HEAD~N` zurueckgehen.

**Per-issue rollback notes:**
- Issue 1: Regel und Tests zusammen revertieren; keine Persistenzmigration noetig
- Issue 2: Bei Fehlalarmen nur Regel und Tests zuruecknehmen
- Issue 3: `SMTP`-Exporter und `_build_exporters()` gemeinsam revertieren
- Issue 4: N/A — reine Gate-/Doku-Nachzuege

## Next Steps
- **If inline-eligible:** Nach Freigabe mit Issue 1 beginnen
- **Otherwise:** Diesen Plan als Commit-Wellenliste fuer die naechste Ausfuehrungsrunde nutzen
