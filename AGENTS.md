# Projekt-Handoff fuer den naechsten Coding-Agenten

## Zweck

Dieses Repo ist jetzt dokumentarisch weit genug vorbereitet, um mit der
Implementierung von V1 zu beginnen. Der verbindliche Entscheidungsstand liegt in
`docs/v1-decisions.md`.

## Baukurs fuer V1

Arbeite in dieser Reihenfolge:

1. Phase A: Grundgeruest und Testharness
   - Projektgeruest unter `src/`, `tests/`, `fixtures/` anlegen
   - `uv`-Setup aufsetzen
   - Konfigurationsladen mit Validierung implementieren
   - Testharness vorbereiten
   - erste Fixtures fuer Startzustaende anlegen
   - Zeitabstraktion fuer deterministische Tests einbauen

2. Phase B: Fachmodell und Simulationskern
   - gemeinsame Wahrheit fuer Anlage, Zustaende, Setpoints und Alarme bauen
   - noch keine vorgezogenen UI- oder Protokoll-Sonderwege

3. Erst danach Protokoll- und HMI-Slices
   - zuerst read-only `Modbus/TCP` Vertical Slice
   - danach read-only HMI Vertical Slice
   - Modbus und HMI muessen auf dasselbe Fachmodell zeigen
   - nicht mit Modbus oder HMI anfangen, bevor Phase A und B sauber stehen

## Verbindliche V1-Defaults

- `ENABLE_TRACKER=0`
- `ENABLE_SERVICE_LOGIN=1`
- `FC04` bleibt in der Default-Konfiguration deaktiviert
- kein sichtbarer Logout-Link in V1
- Exporter laufen im selben Prozess ueber entkoppelte Outbox-/Runner-Logik
- `MODBUS_BIND_HOST=127.0.0.1`
- `HMI_BIND_HOST=127.0.0.1`
- `PCAP_CAPTURE_ENABLED=0`

## Technischer Grundkurs fuer V1

- `Python 3.12`
- `uv`
- `FastAPI` plus serverseitige `Jinja2`-Templates
- `pymodbus`
- `SQLite` im `WAL`-Modus
- `pytest`, `pytest-asyncio`, `httpx`, `Playwright`

## Startkommandos

- Bootstrap: `uv sync --dev`
- Lokaler Start: `uv run python -m honeypot.main`
- Testgesamtlauf: `uv run pytest`
- Contract-Tests: `uv run pytest tests/contract`
- Integrations-Tests: `uv run pytest tests/integration`
- HMI-End-to-End: `uv run playwright test`

## Vor dem ersten Code lesen

- `docs/v1-decisions.md`
- `docs/implementation-roadmap.md`
- `docs/domain-model.md`
- `docs/protocol-profile.md`
- `docs/register-matrix.md`
- `docs/hmi-concept.md`
- `docs/logging-and-events.md`
- `docs/testing-strategy.md`
- `docs/security-operations.md`

## Sicherheitsplanken

- keine reale OEM-Kopie
- keine echten Orts-, Firmen- oder Zugangsdaten
- keine Shell- oder Host-Zugriffspfade
- keine echte Fernsteuerung externer Systeme
- Logging ist Kernfunktion
- jede sichtbare Fehlersituation braucht spaeter einen Test
