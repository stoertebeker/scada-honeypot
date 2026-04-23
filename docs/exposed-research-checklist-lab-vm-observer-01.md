# Exposed-Research Checkliste: `lab-vm-observer-01`

## Zweck

Diese Karte ist die **deployment-spezifisch ausgefuellte Einsatzkarte** fuer
das erste kontrollierte `exposed-research`-Zielprofil
`lab-vm-observer-01`.

Sie uebernimmt die festen technischen Leitplanken aus
[exposed-research-profile-lab-vm-observer-01.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/exposed-research-profile-lab-vm-observer-01.md)
und macht daraus eine konkrete Freigabepruefung fuer den ersten echten
Internet-Kurs.

## 1. Einsatzdaten

- Deployment-Name: `lab-vm-observer-01`
- Datum: `2026-04-23`
- Verantwortliche Person:
  - operative Deckscrew `watch_officer`
  - technische Freigabe `duty_engineer`
- Umgebung:
  - isolierte VM hinter vorgeschaltetem NAT-/Firewall-Gate
- Zweck der Exponierung:
  - kontrollierte Beobachtung von Modbus-/HMI-Zugriffen im offenen Netz
- geplante Dauer:
  - erster Pilotlauf `72h`, danach erneute Lagebewertung

## 2. Ingress-Entscheidung

- offene Ports:
  - extern `tcp/502`
  - extern `tcp/80`
- offene Protokolle:
  - `Modbus/TCP`
  - `HTTP`
- Bind-Interfaces:
  - `MODBUS_BIND_HOST=0.0.0.0`
  - `HMI_BIND_HOST=0.0.0.0`
- freigegebene Runtime-Bindings in `APPROVED_INGRESS_BINDINGS`:
  - `modbus:0.0.0.0:1502`
  - `hmi:0.0.0.0:8080`
- vorgeschaltete NAT-/Firewall-Regeln:
  - `tcp/502` extern -> `tcp/1502` Honeypot-VM
  - `tcp/80` extern -> `tcp/8080` Honeypot-VM
  - keine weiteren eingehenden Ports
- externe Erreichbarkeit:
  - ja, bewusst dokumentiert

Bewertung:

- der geplante Ingress ist technisch kontrollierbar und entspricht dem
  Referenzprofil
- offen bleibt die deployment-seitige Verifikation, dass auf der echten
  Firewall nur genau diese zwei Regeln aktiv sind

## 3. Entscheidung zu `/service/login`

- `ENABLE_SERVICE_LOGIN`:
  - an
- Begruendung:
  - Login-Versuche, Fehl-Logins und zugehoerige Rule-Alerts sind Teil des
    gewuenschten Beobachtungsbilds
  - der Pfad ist fuer `401`, `403`, Session-Ablauf und wiederholte Fehlversuche
    bereits tief getestet
- erwartete Nutzung im Beobachtungsszenario:
  - opportunistische Bedienversuche ueber `/service/login` und
    `/service/panel` sollen sichtbar bleiben

Bewertung:

- die Entscheidung ist bewusst und sicherheitlich vertretbar
- vor Live-Betrieb darf daran nichts ohne neuen Gate-Check geaendert werden

## 4. Egress-Entscheidung

- aktive Exportkanaele:
  - `webhook`
- freigegebene Ziele in `APPROVED_EGRESS_TARGETS`:
  - `webhook:198.51.100.42:443`
- verantwortete Empfaenger:
  - vorgesehenes Research-Ingest `observer-collector`
- welche Daten den Host verlassen duerfen:
  - Event-/Alert-Payloads aus Outbox und Exporter-Runner

Bewertung:

- der Ausleitungspfad ist technisch am tiefsten getestet und fuer dieses
  Deployment auf genau einen Kanal begrenzt
- offen bleibt die operative Bestaetigung, dass `198.51.100.42:443` im
  konkreten Einsatz wirklich der verantwortete Empfaenger ist

## 5. Monitoring und Artefakte

- `RUNTIME_STATUS_ENABLED=1`:
  - ja
- Pfad fuer Heartbeat:
  - `./logs/runtime-status.json`
- Eventstore-Pfad:
  - `./data/events.sqlite3`
- optionale Artefakte:
  - `JSONL`: an unter `./logs/events.jsonl`
  - `PCAP`: aus
- Aufbewahrungsdauer:
  - Eventstore `14 Tage`
  - `JSONL` `14 Tage`
  - Runtime-Status `7 Tage`

Bewertung:

- Heartbeat, Outbox-Stau und Exporter-Health sind operativ sichtbar
- vor Live-Betrieb muss die Deckscrew bestaetigen, dass diese Pfade auf dem
  Zielhost wirklich gesichert und gesichtet werden

## 6. Incident- und Reset-Prozess

- wer beobachtet den Honeypot aktiv:
  - `watch_officer`
- wer trifft Stop-/Reset-Entscheidungen:
  - `duty_engineer`
- wo werden Findings dokumentiert:
  - `./logs/findings.md`
- wann wird `--reset-runtime` gezogen:
  - nach unerwartetem Egress
  - nach HMI-/Modbus-Inkonsistenz
  - nach Debug-/Leak-Indiz
  - nach beendetem Pilotlauf

Bewertung:

- der Reset-Pfad ist technisch validiert
- vor Live-Betrieb muessen `watch_officer` und `duty_engineer` konkret besetzt
  sein und der Findings-Pfad auf dem Zielsystem tatsaechlich existieren

## 7. Go/No-Go fuer dieses Deployment

**Urteil:** `NO-GO`

Begruendung:

- die technische Zielkonfiguration ist jetzt dokumentiert und geschlossen
- offen sind aber noch die deployment-seitige Firewall-/NAT-Bestaetigung,
  der reale benannte Webhook-Empfaenger und die konkret besetzten
  Betriebsrollen

Ein `GO` fuer dieses Deployment ist erst erreicht, wenn:

1. die echte Ingress-Regelung auf dem Zielsystem gegen diese Karte verifiziert
   wurde
2. `observer-collector` als realer Webhook-Empfaenger bestaetigt ist
3. `watch_officer` und `duty_engineer` personell besetzt und benannt sind
4. ein letzter Start-/Stop-/Alert-Sweep auf dem Zielhost erfolgreich gelaufen
   ist

## 8. Offene Restrisiken

- Fehlkonfiguration auf NAT-/Firewall-Ebene koennte zusaetzliche Dienste
  mitfreigeben
- ein falscher Webhook-Empfaenger wuerde trotz Egress-Gate kontrolliert, aber
  an das falsche Ziel exportieren
- unbesetzte Beobachtungsrolle wuerde den operativen Sicherheitsgewinn des
  Heartbeats entwerten

## 9. Bezug

- [exposed-research-checklist.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/exposed-research-checklist.md)
- [exposed-research-profile-lab-vm-observer-01.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/exposed-research-profile-lab-vm-observer-01.md)
- [security-operations.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/security-operations.md)
- [pre-exposure-decision.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/pre-exposure-decision.md)
