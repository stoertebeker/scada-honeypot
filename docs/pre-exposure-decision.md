# Pre-Exposure Go/No-Go Entscheidung

## Stand vom 23. April 2026

Diese Karte dokumentiert die formale Entscheidung fuer den Betriebsmodus
`pre-exposure`.

Sie ist **keine** Freigabe fuer `exposed-research` oder fuer eine echte
Internet-Exponierung.

Update vom 28. April 2026: Die spaetere, deployment-spezifische Freigabe fuer
`v1.0.0` und den validierten `exposed-research`-Pfad ist in
[release-checklist.md](release-checklist.md) dokumentiert. Diese Karte bleibt
als historische Pre-Exposure-Entscheidung bestehen.

## Entscheidung

**Urteil:** `GO` fuer `pre-exposure`

Das gilt nur unter den folgenden Betriebsgrenzen:

- isolierte Labor- oder VM-Umgebung
- bewusste Egress-Freigaben ueber `APPROVED_EGRESS_TARGETS`
- aktives Runtime-Monitoring ueber `RUNTIME_STATUS_ENABLED=1`
- bekannter und geuebter Reset-Pfad ueber
  `uv run python -m honeypot.main --reset-runtime`
- keine echten Betreiberdaten, Secrets oder OEM-Kennungen

## Belegte Gates

Die Entscheidung stuetzt sich auf folgende gruene Nachweise:

1. Fehlerpfade von HMI und Modbus sind getestet:
   - ruhige `401/403/404`
   - keine `FastAPI`-/`Starlette`-/`Traceback`-Leckage
   - Modbus-Fehlerverhalten und Registergrenzen per Contract-Tests abgesichert

2. Logging- und Alert-Pfad sind fuer Kernfaelle nachgewiesen:
   - Eventstore, Alert-Log und Outbox schreiben auf derselben Wahrheit
   - history-only Rule-Alerts sind sichtbar, dedupliziert und clearbar

3. Exporter-Ausfallpfade sind getestet:
   - Webhook, SMTP und Telegram liefern kontrolliert oder fallen ruhig in Retry
   - Mehrkanal-Recovery und Ziel-Backoff sind ueber mehrere Zyklen belegt

4. Debug- und Development-Pfade sind geschlossen:
   - OpenAPI- und ReDoc-Routen deaktiviert
   - keine `Server`-/`Date`-Header im lokalen HMI-Dienst

5. `pre-exposure`-Pflichtgates sind technisch vorhanden und getestet:
   - lokaler Heartbeat ueber `RUNTIME_STATUS_PATH`
   - Reset validiert
   - Egress-Gate im echten Startpfad aktiv
   - kombinierter Runtime-Sweep fuer Monitoring, freigegebenes Ziel,
     erfolgreiche Ausleitung, Reset und Fresh-Start belegt

## Bewusste Grenzen

Dieses `GO` bedeutet nur:

- der Stand ist fuer einen letzten technischen Vorlauf vor kontrollierter
  Exponierung geeignet
- die Sicherheitsplanken fuer Isolation, Monitoring, Reset und Egress sind
  technisch belegt

Dieses `GO` bedeutet **nicht**:

- Freigabe fuer Bindung auf unkontrollierte Interfaces
- Freigabe fuer offene Internet-Exponierung
- Freigabe fuer reale Betreiber-, OEM- oder Cloud-Bezuege

## Weiterhin `NO-GO`

`exposed-research` bleibt weiter `NO-GO`, bis deployment-spezifisch geklaert
und dokumentiert ist:

- Ingress-Freigabe und konkrete offene Ports
- Entscheidung zu `/service/login` fuer das jeweilige Deployment
- operative Egress-Ziele und verantwortete Empfaenger
- Incident- und Beobachtungsprozess fuer den laufenden Betrieb

## Empfohlener naechster Kurs

Vor einer echten Exponierung jetzt **nicht** sofort weiterziehen. Ich empfehle
stattdessen:

1. deployment-spezifische Ingress-Entscheidung dokumentieren
2. `/service/login` bewusst auf `an` oder `aus` festzurren
3. [exposed-research-checklist.md](exposed-research-checklist.md)
   fuer genau dieses Zielumfeld abzeichnen
