# Security und Betrieb V1

## 1. Zweck dieses Dokuments

Dieses Dokument beschreibt die Sicherheits- und Betriebsregeln fuer den
Solarpark-Honeypot. Es legt fest:

- unter welchen Bedingungen die Anlage betrieben werden darf
- welche technischen Sicherheitsgrenzen gelten
- wie Logging, Alerts und Artefakte behandelt werden
- welche Schritte vor einer Exponierung zwingend erledigt sein muessen
- wie Reset, Vorfallbehandlung und Abschaltung ablaufen sollen

Diese Karte ist bewusst operativ. Sie ergaenzt Scope, Architektur und Testplan
um den praktischen Betriebsrahmen.

## 2. Grundsatz

Der Honeypot darf nie vom Beobachtungsobjekt zum realen Risiko werden.

Darum gelten immer:

- kein produktiver OT-Bezug
- kein produktiver IT-Bezug
- kein echter Betreiberbezug
- keine ungepruefte Exponierung
- keine ausgehende Kommunikation ohne bewusste Freigabe

## 3. Betriebsmodi

### 3.1 `design-local`

Zweck:
- Entwicklung und lokale Tests

Eigenschaften:
- nur lokal erreichbar
- Exporter aus oder lokal emuliert
- keine echten Internetziele

### 3.2 `lab-isolated`

Zweck:
- Integrations- und Realismus-Tests

Eigenschaften:
- isoliertes VLAN oder isolierte VM-Umgebung
- kontrollierter Zugriff
- voller Logging-Pfad
- Egress standardmaessig blockiert

### 3.3 `pre-exposure`

Zweck:
- letzter technischer Check vor kontrollierter Exponierung

Eigenschaften:
- Release-Gates aus Test- und Security-Doku muessen gruen sein
- Reset-Mechanismus validiert
- Monitoring aktiv; aktuell steht dafuer ein lokaler Heartbeat unter
  `RUNTIME_STATUS_PATH` bereit, ohne neue Netzwerkflaeche zu oeffnen
- internes Ops-Backend laeuft getrennt von der Angreifer-HMI auf eigenem Port;
  Remote-Zugriff nur ueber Tunnel/VPN oder vergleichbare Zugriffsschicht
- ein kombinierter Runtime-Sweep fuer Monitoring, freigegebenes Exportziel,
  Reset und Fresh-Start ist jetzt im Testharness belegt
- Stand 23. April 2026: formales `GO` fuer `pre-exposure`, siehe
  [pre-exposure-decision.md](pre-exposure-decision.md)

### 3.4 `exposed-research`

Zweck:
- kontrollierte Angreiferbeobachtung

Eigenschaften:
- nur nach expliziter Freigabe
- nur mit aktivem Logging
- nur mit Egress-Kontrolle
- nur mit definiertem Incident- und Reset-Prozess
- nur mit explizitem Exposure-Start-Gate:
  `EXPOSED_RESEARCH_ENABLED=1`, `PUBLIC_INGRESS_MAPPINGS`,
  `APPROVED_EGRESS_RECIPIENTS`, `WATCH_OFFICER_NAME`,
  `DUTY_ENGINEER_NAME`
- Stand 23. April 2026 technisch deutlich weiter; die Runtime erzwingt jetzt
  benannte Rollen, benannte Egress-Empfaenger und verbietet Platzhalterziele
  fuer aktive Exporter im `exposed-research`-Modus
- fuer diese deployment-spezifische Freigabe ist
  [exposed-research-checklist.md](exposed-research-checklist.md)
  verbindlich zu fuehren
- eine ausgefuellte Beispielbewertung des heutigen Stands liegt in
  [exposed-research-checklist-example.md](exposed-research-checklist-example.md)
  und endet bewusst auf `NO-GO`

## 4. Harte Sicherheitsgrenzen

Diese Grenzen sind verbindlich:

- keine Verbindung zu realen OT-Systemen
- keine Verbindung zu realen Cloud-Management-Pfaden
- keine echten OEM-Zugangsdaten
- keine echten Betreiber- oder Standortdaten
- keine Shell fuer Angreifer
- keine Datei-Uploads
- keine generischen Debug-Endpunkte
- keine echten Fernwartungspfade
- interne Wetterkoordinaten duerfen weder in HMI noch in Events, Findings oder
  Exporter-Payloads sichtbar werden

Wenn eine dieser Grenzen verletzt waere, darf die Anlage nicht betrieben
werden.

## 5. Netzwerkisolation

### 5.1 Pflichtkurs

Die Anlage soll in einer isolierten Umgebung laufen:

- dedizierte VM, Container-Host oder isoliertes Netzsegment
- keine Seitverbindungen zu produktiven Netzen
- kein Routing in bestehende Unternehmens- oder OT-Netze

### 5.2 Egress-Kontrolle

Standardregel:

- `deny-all egress`

Ausnahmen nur bewusst fuer:

- lokales Logging-Ziel
- emulierte Exporter-Ziele
- explizit freigegebene Testkanale

Wichtige Regel:
- Exporter duerfen technisch moeglich sein
- ausgehender Traffic muss operativ trotzdem kontrolliert bleiben
- der aktuelle lokale Startpfad erzwingt dafuer eine explizite
  Ziel-Freigabe ueber `APPROVED_EGRESS_TARGETS` im Format
  `target_type:host:port`
- im `exposed-research`-Modus muessen aktive Ausleitungsziele zusaetzlich
  ueber `APPROVED_EGRESS_RECIPIENTS` als benannte Empfaenger dokumentiert sein
- Dokumentations- und Platzhalterziele wie `.invalid` oder Test-Netze bleiben
  in diesem Modus verboten

### 5.3 Ingress-Kontrolle

Vor Exponierung definieren:

- welche Ports offen sind
- welche HMI-Pfade aktiv sind
- ob `service/login` fuer das jeweilige Deployment aktiv bleibt
- ob der Tracker in V1 ueberhaupt sichtbar ist
- fuer Non-Local-Bind im aktuellen Runtime-Pfad ist bewusst
  `ALLOW_NONLOCAL_BIND=1` erforderlich
- die konkreten externen Runtime-Bindings muessen zusaetzlich ueber
  `APPROVED_INGRESS_BINDINGS` im Format `service:host:port` freigegeben sein
- fuer echten `exposed-research`-Betrieb muessen oeffentliche Port-Abbildungen
  zusaetzlich ueber `PUBLIC_INGRESS_MAPPINGS` im Format
  `service:public_port:internal_port` dokumentiert sein
- wenn die HMI browserseitig ueber HTTPS hinter einem TLS-Proxy wie Caddy
  erreichbar ist, muessen `HMI_COOKIE_SECURE=1` und
  `SERVICE_COOKIE_SECURE=1` gesetzt werden; bei direktem HTTP-Labbetrieb
  bleiben beide Werte `0`, sonst senden Browser die Cookies nicht zurueck
- der interne HTTP-Port der App darf bei TLS-Proxy-Betrieb nicht parallel
  oeffentlich erreichbar sein, weil Proxy-Header sonst keine Sicherheitsgrenze
  bilden

## 6. Systemhygiene

### 6.1 Secrets

Pflicht:

- keine echten Secrets im Repo
- keine echten API-Tokens in `.env.example`
- Secrets nur ueber lokale Konfiguration

### 6.2 Identitaetsdaten

Pflicht:

- keine echten Firmennamen
- keine echten Ortsdaten
- keine echten Ansprechpartner
- keine realen OEM-Kennungen

### 6.3 Artefakte

Nicht versionieren:

- echte `.env`
- Logs
- PCAPs
- Mitschnitte echter Sessions

## 7. Logging im Betrieb

### 7.1 Pflichtartefakte

Im aktiven Betrieb muessen mindestens verfuegbar sein:

- Eventstore
- strukturierte Events
- Session- und Protokollereignisse
- Prozess- und Alarmereignisse

### 7.2 Optionale Artefakte

Nur kontrolliert aktivieren:

- `JSONL`-Archiv
- `PCAP`
- HTTP-Rohtranskripte

### 7.3 Warum das wichtig ist

Ohne diese Artefakte verliert Ihr:

- forensische Nachvollziehbarkeit
- Sequenzanalyse
- Korrelation zwischen Modbus, HMI und Prozesswirkung

## 8. Alerting und Exporter im Betrieb

### 8.1 Standardregel

Exporter sind nachgelagert. Sie duerfen:

- nie den Anfragepfad blockieren
- nie sichtbare Fehler in HMI oder Modbus erzeugen

### 8.2 Empfohlene Aktivierung

Zuerst aktivieren:

- lokaler Test-Exporter
- lokaler Webhook-Double

Danach optional:

- echter Webhook
- SMTP
- Telegram

### 8.3 Betriebsgate

Vor Aktivierung eines echten Exportkanals pruefen:

- Ziel ist gewollt
- Rate-Limits sind bekannt
- Failure-Path ist getestet
- keine sensiblen Daten verlassen unbeabsichtigt die Umgebung

## 9. Reset und Wiederherstellung

Ein Honeypot ohne schnellen Reset ist betrieblich unsauber.

### 9.1 Pflichtmechanismus

Es muss einen klaren Ruecksetzpfad geben:

- Snapshot
- frischer Containerzustand
- oder reproduzierbare Neuinitialisierung

Aktueller lokaler V1-Pfad:

- `uv run python -m honeypot.main --reset-runtime`
- entfernt `EVENT_STORE_PATH`, SQLite-`-wal`/`-shm`, `JSONL_ARCHIVE_PATH`,
  `RUNTIME_STATUS_PATH` und `PCAP_CAPTURE_PATH`
- verweigert Verzeichnis- oder Symlink-Artefaktpfade, um keine unsauberen
  Reset-Loeschpfade zu oeffnen

### 9.4 Zielhost-Sweep vor Exponierung

Vor echtem Internetbetrieb ausfuehren:

- `uv run python -m honeypot.main --verify-exposed-research`
- bevorzugt auf dem echten Zielhost:
  `uv run python -m honeypot.main --env-file .env --verify-exposed-research-target-host`

Der Sweep prueft auf demselben Runtime-Pfad:

- Start mit freigegebenem `exposed-research`-Profil
- lesbaren Modbus-Pfad
- lesbare HMI unter `/overview`
- Alert-Lebenszyklus fuer `BREAKER_OPEN`
- sauberen Stop
- schreibt einen dokumentierten Sweep-Eintrag nach `FINDINGS_LOG_PATH`
- der Zielhost-Wrapper gibt danach die relevanten Artefaktpfade kompakt aus

### 9.2 Reset-Ausloeser

Reset soll mindestens moeglich sein nach:

- Testlauf
- auffaelligem Angreiferverhalten
- HMI-/Modbus-Inkonsistenz
- Speicher- oder Loggingproblemen

### 9.3 Nach dem Reset pruefen

- definierter Startzustand geladen
- Logging aktiv
- HMI und Modbus konsistent
- keine Exporter-Staus

## 10. Vorfallbehandlung

### 10.1 Ziel

Ein Incident im Honeypot ist nicht automatisch ein Sicherheitsvorfall im
Unternehmen. Er muss aber sauber behandelt werden.

### 10.2 Mindestablauf

1. Session oder Ereignis markieren
2. Artefakte sichern
3. Egress- und Seitverbindungen pruefen
4. falls noetig Instanz isolieren
5. Reset oder Neuaufsetzen
6. Findings auswerten

### 10.3 Kritische Trigger

Sofort handeln bei:

- unerwartetem ausgehenden Traffic
- Speicher-/CPU-Entgleisung
- HMI-/Modbus-Inkonsistenz
- Hinweisen auf Debug- oder Developer-Spuren
- Konfigurationsleck oder Secret-Leak

## 11. Aufbewahrung und Datenhygiene

Vor aktivem Forschungseinsatz festlegen:

- wie lange Eventdaten aufbewahrt werden
- ob `PCAP` ueberhaupt noetig ist
- wann alte Artefakte geloescht oder archiviert werden

Pflicht:

- keine unendliche Aufbewahrung ohne Plan
- keine unkontrolliert wachsenden Capture-Verzeichnisse
- keine Vermischung von Test- und Beobachtungsdaten

## 12. Exposure-Gates

Die Anlage darf nicht kontrolliert exponiert werden, bevor alle folgenden
Gates erfuellt sind:

- Modbus-Fehlerpfade getestet
- HMI-Fehlerpfade getestet
- Logging-Completeness fuer Kernpfade nachgewiesen
- Exporter-Ausfallpfade getestet
- Debug- und Development-Pfade deaktiviert
- Egress-Kontrolle aktiv
- Reset-Mechanismus validiert
- keine echten Betreiberdaten
- keine echten Secrets

Ich empfehle ausdruecklich, diese Gates als verbindlich zu behandeln und nicht
nur als Wunschliste.

## 13. Kurze Betriebs-Checkliste

Vor Start:

- richtige `.env` geladen
- generische Identitaetsdaten gesetzt
- Logging aktiv
- Exporter-Konfiguration geprueft
- Egress-Regeln aktiv
- Reset-Mechanismus bekannt

Vor Exponierung:

- Test-Gates gruen
- Fehlerpfade pruefen
- HMI und Modbus vergleichen
- Exporter-Ausfall simulieren
- Entscheidung zu `/service/login` dokumentieren

Nach Stop oder Incident:

- Artefakte sichern
- Laufzustand dokumentieren
- Instanz zuruecksetzen
- Review der Events und Alerts

## 14. Bezug zur restlichen Doku

Dieses Dokument arbeitet zusammen mit:

- [README.md](../README.md)
- [v1-decisions.md](v1-decisions.md)
- [testing-strategy.md](testing-strategy.md)
- [implementation-roadmap.md](implementation-roadmap.md)
- [logging-and-events.md](logging-and-events.md)

## 15. Kurzfazit

Die Anlage darf klein und generisch wirken, aber der Betrieb muss hart
kontrolliert sein. Isolation, Egress-Sperre, Logging, Reset und getestete
Fehlerpfade sind keine Option, sondern der sichere Kiel des ganzen Vorhabens.
