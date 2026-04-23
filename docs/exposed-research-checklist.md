# Exposed-Research Checkliste

## Zweck

Diese Karte ist die deployment-spezifische Abnahme fuer den Schritt von
`pre-exposure` zu `exposed-research`.

Sie ist erst gueltig, wenn sie fuer das konkrete Zielumfeld ausgefuellt und
abgezeichnet ist.

Vorbedingung:

- [pre-exposure-decision.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/pre-exposure-decision.md)
  steht auf `GO`
- eine ausgefuellte Beispielkarte liegt in
  [exposed-research-checklist-example.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/exposed-research-checklist-example.md)
  und zeigt den aktuellen Projektstand bewusst als `NO-GO`
- ein konkretes Referenzprofil liegt in
  [exposed-research-profile-lab-vm-observer-01.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/exposed-research-profile-lab-vm-observer-01.md)
  und definiert die erste freizugebende Zielkonfiguration

## 1. Einsatzdaten

- Deployment-Name:
- Datum:
- Verantwortliche Person:
- Umgebung:
  - isolierte VM / isoliertes VLAN / sonstige Isolation
- Zweck der Exponierung:
- geplante Dauer:

## 2. Ingress-Entscheidung

Verbindlich festzuhalten:

- offene Ports:
- offene Protokolle:
- Bind-Interfaces:
- freigegebene Runtime-Bindings in `APPROVED_INGRESS_BINDINGS`:
- oeffentliche Port-Abbildung in `PUBLIC_INGRESS_MAPPINGS`:
- vorgeschaltete NAT-/Firewall-Regeln:
- externe Erreichbarkeit:
  - nein / ja, bewusst dokumentiert

Pflichtchecks:

- nur benoetigte Ports freigegeben
- keine unbewusste Bindung auf Management- oder Produktivnetze
- Non-Local-Bind ist bewusst ueber `ALLOW_NONLOCAL_BIND=1` aktiviert
- die freigegebenen Bindings entsprechen den geplanten offenen Ports
- Modbus- und HMI-Pfade entsprechen dem geplanten Scope

## 3. Entscheidung zu `/service/login`

Verbindlich festzuhalten:

- `ENABLE_SERVICE_LOGIN`:
  - an / aus
- Begruendung:
- erwartete Nutzung im Beobachtungsszenario:

Pflichtchecks:

- Entscheidung ist dokumentiert und bewusst
- Browser- und Fehlerpfade fuer den gewaehlten Zustand sind getestet
- kein versteckter zweiter Service-Pfad bleibt offen

## 4. Egress-Entscheidung

Verbindlich festzuhalten:

- aktive Exportkanaele:
  - webhook / smtp / telegram / sonstige
- freigegebene Ziele in `APPROVED_EGRESS_TARGETS`:
- benannte Empfaenger in `APPROVED_EGRESS_RECIPIENTS`:
- verantwortete Empfaenger:
- welche Daten den Host verlassen duerfen:

Pflichtchecks:

- nur benoetigte Ziele freigegeben
- keine produktiven Betreiber- oder OEM-Ziele
- Failure- und Retry-Pfade fuer die aktiven Kanaele getestet
- keine unbeabsichtigte Datenweitergabe

## 5. Monitoring und Artefakte

Verbindlich festzuhalten:

- `RUNTIME_STATUS_ENABLED=1`:
  - ja / nein
- Pfad fuer Heartbeat:
- Eventstore-Pfad:
- optionale Artefakte:
  - `JSONL`
  - `PCAP`
- Aufbewahrungsdauer:

Pflichtchecks:

- Heartbeat wird aktiv beobachtet
- Alert-/Outbox-Stau ist operativ erkennbar
- Artefakte wachsen nicht unkontrolliert

## 6. Incident- und Reset-Prozess

Verbindlich festzuhalten:

- wer beobachtet den Honeypot aktiv:
- wer trifft Stop-/Reset-Entscheidungen:
- wo werden Findings dokumentiert:
- gesetzte Rollenwerte:
  - `WATCH_OFFICER_NAME`
  - `DUTY_ENGINEER_NAME`
- Findings-Pfad:
  - `FINDINGS_LOG_PATH`
- wann wird `--reset-runtime` gezogen:

Pflichtchecks:

- Reset-Pfad ist bekannt und geuebt
- `uv run python -m honeypot.main --verify-exposed-research` ist fuer dieses
  Zielprofil erfolgreich gelaufen
- Artefakte werden vor Reset gesichert, wenn noetig
- unerwarteter Egress oder HMI-/Modbus-Inkonsistenz fuehrt zu klarer Aktion

## 7. Go/No-Go fuer dieses Deployment

`GO` nur wenn:

- Ingress-Entscheidung dokumentiert und technisch kontrolliert ist
- `/service/login` bewusst entschieden wurde
- Egress-Ziele bewusst freigegeben und verantwortet sind
- Monitoring aktiv beobachtet wird
- Incident- und Reset-Prozess klar benannt sind
- der Exposure-Sweep erfolgreich gelaufen ist

`NO-GO` wenn mindestens eines davon auftritt:

- unklare offene Ports oder Interfaces
- unklare Entscheidung zu `/service/login`
- unklare oder unbewusste Egress-Ziele
- kein beobachteter Heartbeat
- kein benannter Incident-/Reset-Prozess
- kein erfolgreicher Exposure-Sweep

## 8. Freigabe

- Urteil:
  - `GO` / `NO-GO`
- Datum:
- verantwortliche Freigabe:
- offene Restrisiken:
