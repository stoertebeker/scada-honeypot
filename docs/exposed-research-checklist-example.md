# Exposed-Research Checkliste: Beispielbewertung

## Zweck

Diese Karte zeigt eine **konkret ausgefuellte Beispielbewertung** fuer den
aktuellen Projektstand.

Sie ersetzt keine echte Deployment-Freigabe, zeigt aber klar, wie die
Checkliste auszufuellen ist und warum der Stand heute fuer
`exposed-research` noch auf `NO-GO` bleibt.

## 1. Einsatzdaten

- Deployment-Name: `lab-vm-observer-01`
- Datum: `2026-04-23`
- Verantwortliche Person: lokal betreibende Deckscrew
- Umgebung:
  - isolierte VM
- Zweck der Exponierung:
  - Vorbereitung einer spaeteren kontrollierten Angreiferbeobachtung
- geplante Dauer:
  - noch nicht freigegeben

## 2. Ingress-Entscheidung

- offene Ports:
  - aktuell keine extern freigegeben
- offene Protokolle:
  - aktuell keine extern freigegeben
- Bind-Interfaces:
  - `MODBUS_BIND_HOST=127.0.0.1`
  - `HMI_BIND_HOST=127.0.0.1`
- vorgeschaltete NAT-/Firewall-Regeln:
  - keine
- externe Erreichbarkeit:
  - nein

Bewertung:

- Ingress ist technisch derzeit **nicht** fuer Exponierung freigezogen
- der aktuelle Runtime-Pfad blockiert bewusst unkontrollierte externe Bindung

## 3. Entscheidung zu `/service/login`

- `ENABLE_SERVICE_LOGIN`:
  - an
- Begruendung:
  - der Pfad ist Teil des Forschungsbilds und fuer Fehler- und Alert-Verhalten
    breit getestet
- erwartete Nutzung im Beobachtungsszenario:
  - Login-Versuche, Fehl-Logins und sichtbare Rule-Alerts sollen beobachtbar
    bleiben

Bewertung:

- die Entscheidung ist fachlich vertretbar
- sie ist aber erst fuer echte Exponierung tragfaehig, wenn Ingress und
  Beobachtungsprozess ebenfalls sauber festgezogen sind

## 4. Egress-Entscheidung

- aktive Exportkanaele:
  - im Beispiel nur `webhook`
- freigegebene Ziele in `APPROVED_EGRESS_TARGETS`:
  - `webhook:example.invalid:443`
- verantwortete Empfaenger:
  - noch nicht deployment-spezifisch benannt
- welche Daten den Host verlassen duerfen:
  - nur Alert-/Event-Payloads gemaess lokalem Testpfad

Bewertung:

- technisches Egress-Gate ist vorhanden
- fuer echte Exponierung fehlen noch verantwortete Zielsysteme und
  Empfaengerentscheid

## 5. Monitoring und Artefakte

- `RUNTIME_STATUS_ENABLED=1`:
  - vorgesehen
- Pfad fuer Heartbeat:
  - `./logs/runtime-status.json`
- Eventstore-Pfad:
  - deployment-spezifisch festzulegen
- optionale Artefakte:
  - `JSONL`: bewusst je Einsatz zu entscheiden
  - `PCAP`: standardmaessig aus
- Aufbewahrungsdauer:
  - noch nicht deployment-spezifisch festgelegt

Bewertung:

- lokaler Monitoring-Pfad ist vorhanden und getestet
- fuer echte Exponierung fehlt noch die dokumentierte Aufbewahrungs- und
  Sichtungsregel

## 6. Incident- und Reset-Prozess

- wer beobachtet den Honeypot aktiv:
  - noch nicht deployment-spezifisch benannt
- wer trifft Stop-/Reset-Entscheidungen:
  - noch nicht deployment-spezifisch benannt
- wo werden Findings dokumentiert:
  - noch nicht deployment-spezifisch benannt
- wann wird `--reset-runtime` gezogen:
  - nach Testlauf, bei Inkonsistenz oder bei unerwartetem Egress

Bewertung:

- technischer Reset-Pfad ist vorhanden und validiert
- der operative Incident-Kurs ist fuer echte Exponierung noch nicht
  konkret besetzt

## 7. Go/No-Go fuer dieses Beispieldeployment

**Urteil:** `NO-GO`

Begruendung:

- Ingress ist nicht deployment-spezifisch freigezogen
- Modbus und HMI bleiben aktuell bewusst auf `127.0.0.1`
- verantwortete Egress-Ziele sind nicht benannt
- beobachtende und freigebende Rollen sind nicht konkret festgelegt

## 8. Offene Restrisiken und naechster Schlag

Vor einem echten `GO` fuer `exposed-research` muessen mindestens folgen:

1. bewusste Ingress-Entscheidung fuer Ports, Interfaces und Firewall
2. benannte Verantwortliche fuer Beobachtung, Stop und Reset
3. echte, verantwortete Egress-Empfaenger statt Platzhalterzielen
4. Entscheidung, ob `/service/login` fuer genau dieses Deployment an bleibt

## 9. Bezug

Verwendete Hauptkarten:

- [exposed-research-checklist.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/exposed-research-checklist.md)
- [pre-exposure-decision.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/pre-exposure-decision.md)
- [security-operations.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/security-operations.md)
