# Testangreifer-Guide

## 1. Zweck dieses Dokuments

Dieses Dokument beschreibt, wie du den Honeypot **kontrolliert** wie ein
Testangreifer bedienst:

1. ueber die HMI
2. ueber `Modbus/TCP`
3. ueber den lokalen oder spaeter bewusst freigegebenen Exponierungsmodus

Wichtige Sicherheitsregel:
- Das ist ein Bedienguide fuer Test- und Forschungszwecke im eigenen
  Laborkurs.
- Vor echter Exponierung muessen die Gates aus
  [docs/security-operations.md](security-operations.md),
  [docs/exposed-research-checklist.md](exposed-research-checklist.md)
  und [docs/exposed-research-runbook.md](exposed-research-runbook.md)
  erfuellt sein.

## 2. Schnellstart lokal

### 2.1 Runtime starten

```bash
uv run python -m honeypot.main
```

Standardpfade im lokalen Designbetrieb:

- HMI: `http://127.0.0.1:8080/overview`
- Modbus/TCP: `127.0.0.1:1502`

### 2.2 Service-Zugang

Wenn `ENABLE_SERVICE_LOGIN=1` aktiv ist, liegt der Service-Zugang aktuell auf:

- Benutzer: `field.service`
- Passwort: `Solar-Field-2026`

Wichtiger Sicherheitshinweis:
- Das sind die aktuellen Test-Defaults im Code.
- Fuer einen echten Exponierungskurs darfst du diese Werte nicht als
  "automatisch akzeptabel" behandeln. Die Freigabe von `/service/login` ist ein
  bewusster Deployment-Entscheid.

## 3. Sinnvolle Recon-Reihenfolge in der HMI

### 3.1 `/overview`

Erster Blick auf:
- Parkleistung
- Wirkleistungslimit
- Blindleistungsziel
- Breaker-Zustand
- Alarmanzahl
- Kommunikationslage

Wenn diese Seite schon unplausibel wirkt, lohnt sich der Rest kaum.

### 3.2 `/single-line`

Hier pruefst du:
- ist der Netzpfad offen oder geschlossen?
- welche Blocke wirken online oder degradet?
- laufen die PV-/DC-Zweige zuerst in die Inverter und erst danach auf den AC-Bus?
- geht Leistung Richtung Grid?
- welche Flusslinie wird beim Hover/Fokus eines Knotens hervorgehoben?
- steht der Breaker im Single-Line-Schema plausibel zu Export und Meterwert?

Die Seite ist die schnellste Gegenprobe nach Breaker-Aktionen. Der Breaker im
Schema ist klickbar, aber vor Login kein echter Schaltpfad: ein Klick fuehrt
nach `/service/login`, laesst den Anlagenzustand unveraendert und schreibt
`hmi.action.unauthenticated_control_attempt` in das Eventlog.

### 3.3 `/inverters`

Hier suchst du:
- Block mit Comm-Loss
- Block mit `Offline by request` oder `Stale telemetry`
- Block mit reduzierter Leistung
- lokale Alarmanzahl

Diese Seite ist die beste Gegenprobe fuer `Unit 11-13`.

### 3.4 `/weather`

Diese Seite beantwortet:
- ist niedrige Leistung plausibel?
- oder ist sie trotz guter Einstrahlung verdaechtig?

### 3.5 `/meter`

Hier pruefst du:
- kommt wirklich Export am Netzpunkt an?
- ist der Exportpfad verfuegbar?
- was sagt der Breaker aus Sicht des Netzanschlusspunkts?

### 3.6 `/alarms`

Das ist die wichtigste Auswertungsseite nach Bedienhandlungen.

Hier siehst du:
- aktive Alarme
- `cleared`-Historie
- Folge-Alerts aus der `rule_engine`

### 3.7 `/trends`

Hier pruefst du, ob eine Aktion nur ein Schnappschuss oder ein sichtbarer
Verlauf ist.

## 4. Service-Panel: was man dort tun kann

### 4.1 Login

Pfad:
- `/service/login`

Danach:
- `/service/panel`

Der Service-Bereich ist serverseitig sessionsbasiert. Idle-Timeout aktuell:
- `20` Minuten

Mehrfach falsche Logins koennen:
- `REPEATED_LOGIN_FAILURE` ausloesen
- auf `/alarms` sichtbar werden

### 4.2 Power Limit

Aktion:
- Wirkleistungslimit setzen

Erwartete Wirkung:
- Parkleistung sinkt
- `PLANT_CURTAILED` wird sichtbar
- `/overview`, `/trends` und `Unit 1` spiegeln den neuen Zustand

### 4.3 Reactive Power

Aktion:
- Blindleistungsziel setzen

Erwartete Wirkung:
- PPC-Sollwert aendert sich
- keine harte Stoerwirkung wie beim offenen Breaker

### 4.4 Plant Mode Request

Aktion:
- `plant_mode_request` setzen

Erwartete Wirkung:
- der Bedienwunsch wird sichtbar gelatcht
- der echte `operating_mode` springt nicht still und heimlich um

### 4.5 Inverter Block Control

Aktionen:
- Block `enable/disable`
- Blockleistungslimit setzen
- Block-Reset ausloesen

Erwartete Wirkung:
- `/inverters` zeigt Status-, Leistungs- und Qualitaetsaenderungen
- Folge-Alerts sind moeglich, wenn mehrere Blocke betroffen sind

### 4.6 Breaker Open / Close

Aktion:
- Breaker oeffnen oder schliessen

Erwartete Wirkung:
- offener Breaker trennt Exportpfad
- `/single-line` und `/meter` zeigen Null-Export
- `/alarms` zeigt `BREAKER_OPEN`
- beim Schliessen muss derselbe Alert sauber auf `cleared` gehen

## 5. Modbus: wie du ihn sinnvoll bedienst

## 5.1 Adressregel

Die Doku verwendet menschenlesbare Register wie `40200`.

Viele Clients erwarten aber nullbasierte Offsets. Dann gilt:

- interner Offset = Registeradresse - `40001`

Beispiele:

- `40100` -> Offset `99`
- `40200` -> Offset `199`
- `40300` -> Offset `299`

Wenn dein Client also "Adresse 199" will, meint die Doku dazu `40200`.

## 5.2 Aktive Unit-IDs in V1

| Unit | Asset | Typischer Zweck |
| --- | --- | --- |
| `1` | `site / ppc-01` | Parkzustand und zentrale Setpoints |
| `11` | `invb-01` | Inverter-Block 1 |
| `12` | `invb-02` | Inverter-Block 2 |
| `13` | `invb-03` | Inverter-Block 3 |
| `21` | `wx-01` | Wetterstation, read-only |
| `31` | `meter-01` | Revenue Meter, read-only |
| `41` | `grid-01` | Breaker und Netzpfad |

## 5.3 Erstes Read-Muster

Ein typischer Recon-Kurs:

1. Identitaetsblock `40001-40049`
2. Statusblock `40100-40199`
3. danach gezielte Setpoints in `40200-40249`

Wichtige Funktionscodes in V1:

- `FC03` lesen
- `FC06` einzelnes Register schreiben
- `FC16` mehrere Register schreiben

Nicht als Standardpfad aktiv:

- `FC04`
  - fuehrt in der Default-Konfiguration zu `01 Illegal Function`

## 5.4 Die wichtigsten Write-Punkte

### Unit `1` / PPC

- `40200 active_power_limit_pct_x10`
  - Beispiel `750` = `75.0 %`
- `40201 reactive_power_target_pct_x10`
  - Beispiel `-150` = `-15.0 %`
- `40202 plant_mode_request`
  - `0=normal`
  - `1=curtailed`
  - `2=maintenance`

### Unit `11-13` / Inverter-Bloecke

- `40200 block_enable_request`
  - `0=disable`
  - `1=enable`
- `40201 block_power_limit_pct_x10`
  - Beispiel `655` = `65.5 %`
- `40202 block_reset_request`
  - `1` loest den self-clearing Reset-Puls aus

### Unit `41` / Grid Interconnect

- `40200 breaker_open_request`
  - `1` oeffnet
- `40201 breaker_close_request`
  - `1` schliesst

### Read-only-Units

Bei diesen Units sind `40200-40249` bewusst nicht bedienbar:

- `21` Wetterstation
- `31` Revenue Meter

Schreibversuche dort fuehren zu:
- `02 Illegal Data Address`

## 6. Drei einfache Testangreifer-Szenarien

### 6.1 Szenario A: Curtailment pruefen

1. `overview` und `trends` merken
2. HMI oder Modbus:
   - Unit `1`, `40200 = 750`
3. Wirkung pruefen:
   - Parkleistung sinkt
   - `PLANT_CURTAILED` wird sichtbar
   - Trendlinie aendert sich

### 6.2 Szenario B: Breaker-Reaktion pruefen

1. `/meter` und `/single-line` merken
2. HMI oder Modbus:
   - Unit `41`, `40200 = 1`
3. Wirkung pruefen:
   - Breaker offen
   - Export faellt weg
   - `BREAKER_OPEN` wird aktiv
4. Rueckbau:
   - Unit `41`, `40201 = 1`
5. Gegenprobe:
   - Export kommt wieder
   - Alert steht als `cleared` in `/alarms`

### 6.3 Szenario C: Inverter-Block-Verlust pruefen

1. `/inverters` und `/alarms` merken
2. HMI oder Modbus:
   - Unit `12`, `40200 = 0`
   - optional zusaetzlich `40201 = 500`
3. Wirkung pruefen:
   - Block wirkt `Offline by request`, `Stale telemetry` oder leistungsgedrosselt
   - Parkleistung kann sinken
4. Rueckbau:
   - Unit `12`, `40200 = 1`
   - wenn noetig `40202 = 1` fuer Reset

## 7. Wo du die Wirkung deiner Aktionen nachverfolgst

Wenn du nicht nur die UI, sondern auch die forensische Spur sehen willst,
sind diese Artefakte relevant:

- `EVENT_STORE_PATH`
  - SQLite mit `event_log`, `alert_log`, `outbox`
- `JSONL_ARCHIVE_PATH`
  - optionaler Event-Spiegel
- `RUNTIME_STATUS_PATH`
  - Heartbeat mit Dienst-Adressen, Alert- und Outbox-Zaehlern
- `FINDINGS_LOG_PATH`
  - Exposure-Sweeps und deren Ergebnis

Wichtige Sicherheitsregel:
- Eine HMI-Aktion ohne passende Eventspur ist verdachtig.
- Ein Alert ohne sichtbare Ursache in UI oder Modbus sollte ebenso als
  Inkonsistenz behandelt werden.

## 8. Typische Stolperfallen

1. Falsche Modbus-Adressbasis
   - dein Client nutzt Offsets, die Doku zeigt `4xxxx`
2. Falsche Unit-ID
   - unbekannte Units liefern keine sinnvollen Daten
3. `FC04` statt `FC03`
   - in V1 standardmaessig nicht aktiv
4. Read-only-Unit beschreiben
   - Wetter und Meter nehmen keine Setpoints an
5. Wirkung nur auf einer Seite pruefen
   - immer mindestens eine zweite Gegenprobe machen, z. B. `meter` plus
     `alarms`

## 9. Weiterfuehrende Karten

- [docs/scada-primer-and-module-guide.md](scada-primer-and-module-guide.md)
  - SCADA-Begriffe und Moduluebersicht
- [docs/register-matrix.md](register-matrix.md)
  - genaue Registermatrix
- [docs/protocol-profile.md](protocol-profile.md)
  - Protokollregeln und Fehlerverhalten
- [docs/exposed-research-runbook.md](exposed-research-runbook.md)
  - Zielhost-Kurs fuer spaetere echte Exponierung
