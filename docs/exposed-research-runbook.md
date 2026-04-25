# Exposed-Research-Runbook

## 1. Zweck dieses Dokuments

Dieses Runbook beschreibt den operativen Kurs fuer den ersten kontrollierten
`exposed-research`-Einsatz.

Es ist bewusst **kein** Ersatz fuer die Checklisten, sondern die Schrittfolge
fuer die Deckscrew:

1. `.env` setzen
2. Runtime pruefen
3. Sweep fahren
4. Artefakte bewerten
5. erst danach Ingress oeffnen

## 2. Vorbedingungen

Vor dem ersten Zielhost-Lauf muessen diese Karten sauber vorbereitet sein:

- [docs/exposed-research-checklist.md](exposed-research-checklist.md)
- [docs/exposed-research-profile-lab-vm-observer-01.md](exposed-research-profile-lab-vm-observer-01.md)
- [docs/exposed-research-checklist-lab-vm-observer-01.md](exposed-research-checklist-lab-vm-observer-01.md)

Wichtige Mindestpunkte:

- `ALLOW_NONLOCAL_BIND=1`
- `APPROVED_INGRESS_BINDINGS` gesetzt
- `EXPOSED_RESEARCH_ENABLED=1`
- `PUBLIC_INGRESS_MAPPINGS` gesetzt
- `APPROVED_EGRESS_TARGETS` gesetzt
- `APPROVED_EGRESS_RECIPIENTS` gesetzt
- `WATCH_OFFICER_NAME` gesetzt
- `DUTY_ENGINEER_NAME` gesetzt

## 3. Zielhost vorbereiten

### 3.1 `.env` anlegen

Empfohlener Startpunkt:
- `.env.example`
- [deploy/lab-vm-observer-01.env.example](../deploy/lab-vm-observer-01.env.example)
- danach deployment-spezifisch ausfuellen

Die Werte muessen **echt** sein:

- keine `.example`-, `.invalid`-, `.test`- oder Doku-IP-Ziele
- keine Platzhalter fuer aktive Exporter
- keine ungeklaerten Rollenfelder

Wichtige Regel:
- die Datei unter `deploy/` ist eine **versionierte Zielhost-Vorlage**
- fuer den echten Einsatz wird sie auf dem Zielhost in eine **nicht
  versionierte** `.env` ueberfuehrt

### 3.2 Pakete und Projektstand

```bash
uv sync --dev
```

Optionaler Containerkurs statt Direktlauf:

```bash
HONEYPOT_ENV_FILE=.env docker compose up --build -d honeypot
HONEYPOT_ENV_FILE=.env docker compose --profile verify run --rm honeypot-sweep
```

Dabei gilt weiter:
- `.env` enthaelt die echten Zielwerte
- benannte Docker-Volumes tragen Eventstore, Logs und PCAP
- der Hauptdienst bleibt im Compose-Kurs mit `read_only` Root-Filesystem und
  echtem HMI-/Modbus-Healthcheck gehaertet
- die Sweep-Fahrt bleibt Pflicht vor oeffentlichem Ingress

### 3.3 Noch keine oeffentliche Freigabe

Vor dem Sweep:
- Firewall/NAT noch nicht nach aussen oeffnen
- nur den Zielhost selbst oder einen eng kontrollierten Laborkorridor nutzen

## 4. Trockenlauf auf dem Zielhost

### 4.1 Runtime lokal pruefen

```bash
uv run python -m honeypot.main --env-file .env
```

Kurz pruefen:
- Modbus-Port bindet wie erwartet
- HMI oeffnet `/overview`
- Runtime-Status-Datei wird geschrieben, falls aktiviert

Dann sauber stoppen.

### 4.2 Exposure-Sweep fahren

```bash
uv run python -m honeypot.main --env-file .env --verify-exposed-research
```

Bevorzugt fuer den echten Zielhost:

```bash
uv run python -m honeypot.main --env-file .env --verify-exposed-research-target-host
```

Der Sweep prueft aktuell:

1. Start der Runtime im freigegebenen Exposure-Modus
2. Modbus-Read ueber den echten Runtime-Pfad
3. HMI-Read auf `/overview`
4. Alert-Lebenszyklus fuer `BREAKER_OPEN`
5. sauberen Stop
6. Eintrag nach `FINDINGS_LOG_PATH`

Der Zielhost-Wrapper gibt danach zusaetzlich direkt aus:

- `FINDINGS_LOG_PATH`
- `RUNTIME_STATUS_PATH` oder `disabled`
- `EVENT_STORE_PATH`
- `JSONL_ARCHIVE_PATH` oder `disabled`

## 5. Was danach geprueft werden muss

### 5.1 Findings

Datei:
- `FINDINGS_LOG_PATH`

Erwartet:
- neuer Eintrag `verify-exposed-research passed`
- `site_code`
- `watch_officer`
- `duty_engineer`
- `public_ingress_mappings`
- `approved_egress_recipients`
- Kurzsummary des Sweeps

### 5.2 Runtime-Heartbeat

Datei:
- `RUNTIME_STATUS_PATH`

Erwartet:
- Dienst-Adressen
- Exporter-Health
- Alert- und Outbox-Zaehler
- nach Stop `running=false`

### 5.3 Eventspur

Relevante Artefakte:

- `EVENT_STORE_PATH`
- optional `JSONL_ARCHIVE_PATH`

Erwartet:
- HMI-/HTTP-Ereignisse
- Modbus-Read
- Breaker-Open/Close-Spur
- passende Alerts

## 6. Erst danach Ingress freigeben

Die Reihenfolge ist verbindlich:

1. Sweep auf dem Zielhost gruen
2. Findings und Heartbeat gegenlesen
3. erst dann Firewall/NAT/Ingress oeffnen

Nicht andersherum. Sonst laeuft die Anlage schon offen, bevor die Deckscrew
ueberhaupt weiss, ob die Runtime sauber auf Kurs ist.

## 7. Erste Beobachtungsphase nach dem Oeffnen

Die ersten Stunden nach Oeffnung sind keine Routine, sondern Pilotfahrt.

Eng beobachten:

- `FINDINGS_LOG_PATH`
- `RUNTIME_STATUS_PATH`
- `EVENT_STORE_PATH`
- `JSONL_ARCHIVE_PATH`
- Outbox- und Exporter-Zustand

Watch-Officer und Duty-Engineer muessen in dieser Phase wirklich besetzt sein.

## 8. Wann `NO-GO` gilt

Kein Internetkurs, wenn eines davon zutrifft:

- Sweep faellt rot
- Findings werden nicht geschrieben
- Heartbeat fehlt oder zeigt falsche Bindings
- aktive Exporter nutzen Platzhalter- oder Doku-Ziele
- `watch_officer` oder `duty_engineer` sind nur Platzhalter auf Papier
- Ingress ist weiter unklar oder weicht von `PUBLIC_INGRESS_MAPPINGS` ab

## 9. Verweise

- [docs/security-operations.md](security-operations.md)
- [docs/release-checklist.md](release-checklist.md)
- [docs/exposed-research-checklist.md](exposed-research-checklist.md)
