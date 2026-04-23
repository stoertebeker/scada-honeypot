# Exposed-Research Deployment-Profil: `lab-vm-observer-01`

## Zweck

Diese Karte beschreibt das **erste konkrete Referenzprofil** fuer eine
kontrollierte `exposed-research`-Exponierung.

Sie ist bewusst technisch konkret, verwendet aber nur Dokumentationswerte und
Rollenbezeichnungen. Vor echtem Einsatz muss sie deployment-spezifisch
kopiert, mit realen Zielwerten versehen und final abgezeichnet werden.

## 1. Profilstatus

- Profilname: `lab-vm-observer-01`
- Status: freizugebendes Referenzprofil
- Einsatzmodus: `exposed-research`
- Umgebung: isolierte VM hinter vorgeschaltetem NAT/Firewall-Gate

## 2. Verbindliche Laufzeitwerte

```env
MODBUS_BIND_HOST=0.0.0.0
MODBUS_PORT=1502
HMI_BIND_HOST=0.0.0.0
HMI_PORT=8080
ALLOW_NONLOCAL_BIND=1
EXPOSED_RESEARCH_ENABLED=1
APPROVED_INGRESS_BINDINGS=modbus:0.0.0.0:1502,hmi:0.0.0.0:8080
PUBLIC_INGRESS_MAPPINGS=modbus:502:1502,hmi:80:8080

ENABLE_SERVICE_LOGIN=1

RUNTIME_STATUS_ENABLED=1
RUNTIME_STATUS_PATH=./logs/runtime-status.json
JSONL_ARCHIVE_ENABLED=1
JSONL_ARCHIVE_PATH=./logs/events.jsonl
PCAP_CAPTURE_ENABLED=0
FINDINGS_LOG_PATH=./logs/findings.md

WEBHOOK_EXPORTER_ENABLED=1
WEBHOOK_EXPORTER_URL=https://collector.ops.lab/honeypot-ingest
APPROVED_EGRESS_TARGETS=webhook:collector.ops.lab:443
APPROVED_EGRESS_RECIPIENTS=webhook:observer-collector-live
SMTP_EXPORTER_ENABLED=0
TELEGRAM_EXPORTER_ENABLED=0
WATCH_OFFICER_NAME=blue-watch
DUTY_ENGINEER_NAME=ops-duty
```

## 3. Ingress-Profil

### 3.1 Laufzeit-Binding

- Modbus lauscht intern auf `0.0.0.0:1502`
- HMI lauscht intern auf `0.0.0.0:8080`
- Non-Local-Bind ist bewusst ueber `ALLOW_NONLOCAL_BIND=1` freigegeben
- konkrete Bindings sind ueber `APPROVED_INGRESS_BINDINGS` explizit erlaubt

### 3.2 Vorgeschaltete Port-Freigabe

Empfohlenes externes Mapping:

- `tcp/502` extern -> `tcp/1502` auf der Honeypot-VM
- `tcp/80` extern -> `tcp/8080` auf der Honeypot-VM

Pflicht:

- keine weiteren Ports auf dieselbe VM oeffnen
- kein Management-Zugang auf derselben oeffentlichen Adresse terminieren
- NAT-/Firewall-Regeln muessen exakt den zwei freigegebenen Ports entsprechen

## 4. Entscheidung zu `/service/login`

- Wert: `ENABLE_SERVICE_LOGIN=1`
- Begruendung:
  - Login-Versuche, Fehl-Logins und Folge-Alerts sind Teil des gewuenschten
    Beobachtungsbilds
  - die HMI-/Service-Fehlerpfade fuer `401`, `403`, Session-Ablauf und
    wiederholte Fehlversuche sind bereits tief getestet

Operative Folge:

- Bedienhandlungen ueber `/service/panel` sind im Honeypot erlaubt
- die Wirkung bleibt simuliert und schreibt dieselbe Event-/Alert-Spur wie
  Modbus

## 5. Egress-Profil

- aktiver Kanal: `webhook`
- Ziel: `collector.ops.lab:443`
- `APPROVED_EGRESS_TARGETS=webhook:collector.ops.lab:443`
- `APPROVED_EGRESS_RECIPIENTS=webhook:observer-collector-live`
- SMTP und Telegram bleiben fuer dieses Referenzprofil deaktiviert

Begruendung:

- ein einzelner Zielkanal reduziert operative Komplexitaet
- der Webhook-Pfad ist im aktuellen Stand am tiefsten auf Erfolgs-, Retry- und
  Release-Gate-Ebene belegt

Pflicht:

- das reale Zielsystem muss vor Live-Betrieb verantwortet benannt werden
- Exporter-Failure-Path muss vor Exponierung nochmals gegen das echte Ziel
  geprueft werden

## 6. Monitoring und Artefakte

- Runtime-Heartbeat: aktiv
- Heartbeat-Pfad: `./logs/runtime-status.json`
- Event-Archiv: `JSONL` aktiv unter `./logs/events.jsonl`
- `PCAP`: aus

Aufbewahrung fuer dieses Referenzprofil:

- Eventstore: 14 Tage
- `JSONL`: 14 Tage
- Runtime-Status: 7 Tage

Pflicht:

- Heartbeat mindestens alle 5 Minuten aktiv sichten
- Outbox-Stau, Exporter-Health und Alert-Anzahl muessen operativ beobachtet
  werden

## 7. Incident- und Reset-Kurs

Rollenmodell:

- `watch_officer`: beobachtet Heartbeat, Alerts und sichtbare HMI-/Modbus-Lage
- `duty_engineer`: entscheidet ueber Stop, Isolation und Reset
- konkrete Referenz-Besetzung:
  - `WATCH_OFFICER_NAME=blue-watch`
  - `DUTY_ENGINEER_NAME=ops-duty`

Pflichtreaktion bei:

- unerwartetem Egress
- HMI-/Modbus-Inkonsistenz
- Debug-/Leak-Indiz
- Alert-/Outbox-Stau

Mindestablauf:

1. Ereignis markieren
2. Eventstore und `JSONL` sichern
3. externe Verbindungen pruefen
4. Instanz bei Bedarf isolieren
5. `uv run python -m honeypot.main --reset-runtime`
6. Findings dokumentieren

Pflicht-Sweep vor Live-Betrieb:

- `uv run python -m honeypot.main --verify-exposed-research`
- erwartet danach einen neuen Eintrag unter `FINDINGS_LOG_PATH`

## 8. Go/No-Go fuer dieses Referenzprofil

Dieses Profil ist **freizugebend**, aber noch nicht automatisch live freigegeben.

`GO` fuer ein echtes Deployment nur wenn:

- NAT-/Firewall-Regeln exakt dem Profil entsprechen
- Webhook-Empfaenger `observer-collector-live` auf `collector.ops.lab:443`
  deployment-seitig bestaetigt ist
- `blue-watch` und `ops-duty` fuer diesen Pilotlauf tatsaechlich besetzt sind
- die deployment-spezifische Kopie dieser Karte abgezeichnet wurde
- der Sweep `--verify-exposed-research` auf dem Zielhost erfolgreich laeuft

`NO-GO` wenn:

- zusaetzliche Ports aufgehen
- `/service/login` ungeprueft umkonfiguriert wird
- weitere Exportkanaele ohne neuen Gate-Check zugeschaltet werden
- Beobachtung und Reset nicht personell besetzt sind
- `--verify-exposed-research` fehlschlaegt

## 9. Bezug

- [exposed-research-checklist.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/exposed-research-checklist.md)
- [exposed-research-checklist-lab-vm-observer-01.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/exposed-research-checklist-lab-vm-observer-01.md)
- [security-operations.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/security-operations.md)
- [pre-exposure-decision.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/pre-exposure-decision.md)
