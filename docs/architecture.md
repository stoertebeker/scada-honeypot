# Architektur: Modularer Monolith fuer den Solarpark-Honeypot

## 1. Zweck dieses Dokuments

Dieses Dokument beschreibt die Zielarchitektur des Projekts auf hoher Ebene.
Es soll auch fuer Nicht-Programmierer verstaendlich bleiben und erklaeren,
welche Bausteine es gibt, wie sie zusammenarbeiten und warum diese Aufteilung
fuer einen glaubhaften, testbaren und erweiterbaren Honeypot sinnvoll ist.

Das Dokument ist bewusst konzeptionell. Es legt noch keine konkrete Sprache,
kein Framework und keine technische Detailimplementierung fest.

## 2. Architekturentscheidung

Das Projekt wird als **modularer Monolith** geplant.

Das bedeutet:
- Es gibt zunaechst **eine Anwendung** und **ein gemeinsames Projekt**.
- Innerhalb dieser Anwendung wird die Logik in klar getrennte Module zerlegt.
- Die Module haben definierte Verantwortungen und Schnittstellen.
- Benachrichtigungen und externe Ziele werden spaeter ueber eine
  Plugin-/Exporter-Schnittstelle angebunden.

### Warum kein Microservice-Ansatz?

Ein verteiltes System mit vielen Einzelservices wuerde den Betriebsaufwand,
die Komplexitaet und die Fehleroberflaeche zu frueh erhoehen.

Fuer dieses Projekt ist wichtiger:
- klare Fachgrenzen
- gute Testbarkeit
- konsistentes Logging
- einfache lokale Entwicklung
- spaetere Erweiterbarkeit ohne Komplettumbau

## 3. Architekturprinzipien

Die Zielarchitektur folgt diesen Grundsaetzen:

1. **Standardnahe Aussenwirkung**
   - Angreifer sollen sich schnell zurechtfinden.
   - Die Anlage soll sich an gaengigen OT-/SCADA-Mustern orientieren.
   - Fuer V1 ist eine Modbus/TCP- und SunSpec-nahe Sicht der Hauptanker.

2. **Logging ist Kernfunktion, nicht Nebensache**
   - Jede relevante Aktion erzeugt strukturierte Events.
   - Logging darf nicht nur in einzelnen Modulen versteckt sein.
   - Die Event-Pipeline ist ein eigener Architekturbaustein.

3. **Glaubhafte Fehlerbilder**
   - Fehlermeldungen, Timeouts, Alarme und Zustandswechsel muessen konsistent
     und nachvollziehbar wirken.
   - Sichtbare Fehlersituationen brauchen eigene Tests.

4. **Isolation und Sicherheit**
   - Kein Modul darf reale OT-, IT- oder Cloud-Systeme voraussetzen.
   - Ausgehende Kommunikation muss kontrolliert und optional bleiben.
   - Exporter-Ausfaelle duerfen den Honeypot nicht blockieren.

5. **Erweiterbarkeit ueber klare Schnittstellen**
   - Neue Protokolle, Exporter oder HMI-Seiten sollen spaeter hinzufuegbar sein.
   - Das Kernsystem darf dabei nicht unkontrolliert wachsen.

## 4. Uebersicht der Hauptbausteine

Die V1-Architektur besteht aus den folgenden logischen Modulen:

- `config-core`
- `asset-domain`
- `plant-sim`
- `protocol-modbus`
- `hmi-web`
- `event-core`
- `rule-engine`
- `exporter-sdk`
- `exporter-runner`
- `storage`
- `test-harness`

## 5. Grober Systemfluss

Der Datenfluss laeuft konzeptionell so:

```text
Angreifer / Client
        |
        v
+-------------------+
| protocol-modbus   |
| hmi-web           |
+-------------------+
        |
        v
+-------------------+
| asset-domain      |
| plant-sim         |
+-------------------+
        |
        +----------------------+
        |                      |
        v                      v
+-------------------+   +-------------------+
| event-core        |   | storage           |
| correlation       |   | state + events    |
+-------------------+   +-------------------+
        |
        v
+-------------------+
| rule-engine       |
+-------------------+
        |
        v
+-------------------+
| exporter-runner   |
| outbox            |
+-------------------+
        |
        v
+-------------------+
| Exporter Plugins  |
| Mail/Webhook/etc. |
+-------------------+
```

Wichtiger Grundsatz:
- Die Aussenwelt spricht mit Protokoll- oder HMI-Modulen.
- Die Fachlogik lebt in `asset-domain` und `plant-sim`.
- Alle beobachtbaren Aktionen muessen ueber `event-core` erfasst werden.
- Externe Weiterleitung geschieht nur ueber den entkoppelten Exporter-Pfad.

## 6. Modulbeschreibung

### 6.1 `config-core`

**Zweck**
- Laedt und validiert Konfiguration aus `.env` oder aequivalenten Quellen.

**Eingaben**
- Umgebungsvariablen
- optionale Konfigurationsdateien

**Ausgaben**
- normalisierte Laufzeitkonfiguration fuer alle anderen Module

**Wichtige Regeln**
- Keine realen Orts-, Firmen- oder Herstellerdaten als Standardwerte
- Sichere und generische Defaults
- Fruehe Validierung statt spaeter Laufzeitfehler
- Validierung von `ATTACKER_UI_LOCALE` und `ATTACKER_UI_FALLBACK_LOCALE`
- klare Trennung zwischen lokalisierbarer Angreifer-HMI und deutscher
  Betreiber-/Log-Sicht

### 6.2 `asset-domain`

**Zweck**
- Beschreibt die logischen Assets der Anlage und ihre Beziehungen.

**Beispiele fuer Assets**
- Power Plant Controller
- Wechselrichter-Block
- Wetterstation
- Revenue Meter
- Uebergabefeld / Breaker
- Tracker-Controller

**Ausgaben**
- fachliches Modell der Anlage
- Zustandsobjekte, Alarmklassen, Abhaengigkeiten

**Wichtige Regeln**
- Keine Protokolldetails in diesem Modul
- Keine UI-Details in diesem Modul

### 6.3 `plant-sim`

**Zweck**
- Simuliert das Verhalten des Solarparks.

**Verantwortung**
- berechnet Zustandsaenderungen
- modelliert Rueckkopplung nach Schreiboperationen
- erzeugt plausible Prozessreaktionen

**Typische Eingaben**
- Schreibbefehle aus Protokollmodulen
- Zeitverlauf
- Wetteraenderungen
- interne Stoerungen oder Simulationsereignisse

**Typische Ausgaben**
- aktualisierte Messwerte
- Alarmwechsel
- Zustandsaenderungen

**Wichtige Regeln**
- Keine echte Prozessgefaehrdung
- Keine direkte Kenntnis ueber SMTP, Webhooks oder andere Exportziele
- Reproduzierbares Verhalten fuer Tests, aber nicht voellig unnatuerlich

### 6.4 `protocol-modbus`

**Zweck**
- Stellt die standardnahe OT-Schnittstelle bereit.

**Verantwortung**
- beantwortet Leseanfragen
- nimmt schreibbare Befehle entgegen
- uebersetzt Protokollzugriffe in fachliche Operationen

**Wichtige Regeln**
- Protokollfehler muessen konsistent und plausibel sein
- Keine internen Stacktraces oder Framework-Fehler
- Klare Trennung zwischen Protokollabbildung und Fachlogik

### 6.5 `hmi-web`

**Zweck**
- Stellt die Bedien- und Beobachtungsoberflaeche bereit.

**Verantwortung**
- Uebersicht ueber Parkzustand
- Trend- und Alarmansichten
- begrenzte Interaktion mit Betriebswerten
- optionale Login- oder Service-Oberflaechen

**Wichtige Regeln**
- Keine reale Herstelleroptik
- Konsistente Fehlerseiten und Session-Flows
- Keine verratenden Debug- oder Development-Header
- Lokalisierung nur fuer sichtbare Angreifer-HMI-Texte
- Locale-Aufloesung nach Kette `ll-RR -> ll -> ATTACKER_UI_FALLBACK_LOCALE`
- logische Ressourcenkonvention `resources/locales/attacker-ui/<locale>.json`

### 6.6 `event-core`

**Zweck**
- Zentraler Baustein fuer Event-Erzeugung, Korrelation und Persistenz.

**Verantwortung**
- vergibt oder uebernimmt `event_id` und `correlation_id`
- normalisiert Ereignisse aus allen Modulen
- schreibt Events in den Eventspeicher
- fuellt die Outbox fuer nachgelagerte Exporter

**Wichtige Regeln**
- Kein stilles Verwerfen relevanter Ereignisse
- Strukturiertes, durchsuchbares Format
- Export-Fehler duerfen Event-Erfassung nicht verhindern

### 6.7 `rule-engine`

**Zweck**
- Bewertet Events und Zustandsfolgen, um Alarme und Benachrichtigungen
  abzuleiten.

**Beispiele**
- zu viele Login-Versuche in kurzer Zeit
- Sequenz aus Setpoint-Aenderung und Leistungseinbruch
- Breaker-Wechsel mit nachfolgender Alarmkaskade

**Wichtige Regeln**
- Regeldefinitionen muessen transparent und testbar sein
- Keine direkte Kenntnis ueber Versandkanaele

### 6.8 `exporter-sdk`

**Zweck**
- Definiert den stabilen Vertrag fuer externe Exporter.

**Ziel**
- Exporter sollen in separaten Projekten entstehen koennen, ohne den Kern zu
  veraendern.

**Ein Exporter sollte mindestens koennen**
- Konfiguration pruefen
- Health-/Bereitschaftszustand melden
- Event-Batches empfangen
- Alert-Batches empfangen
- Fehler kontrolliert zurueckmelden

### 6.9 `exporter-runner`

**Zweck**
- Fuehrt konfigurierte Exporter kontrolliert aus.

**Verantwortung**
- liest aus der Outbox
- uebergibt Events oder Alerts an Exporter
- protokolliert Erfolg, Fehler und Retry-Zustaende

**Wichtige Regeln**
- asynchron und entkoppelt vom Anfragepfad
- Retries mit Backoff
- keine Blockade des Honeypots bei Zielausfaellen

### 6.10 `storage`

**Zweck**
- Kapselt Persistenz fuer Betriebszustand, Events und Outbox.

**Zu speichernde Datenarten**
- aktueller Anlagenzustand
- Event-Historie
- Alarmhistorie
- Exportstatus
- optionale Rohartefakte wie JSONL oder PCAP

**Wichtige Regeln**
- saubere Trennung von aktuellem Zustand und historischer Ereignisspur
- einfache Sicherung und schneller Reset

### 6.11 `test-harness`

**Zweck**
- Bietet Testwerkzeuge, Fixtures und Referenzszenarien.

**Verantwortung**
- reproduzierbare Tests gegen Module und Gesamtsystem
- Regressionstests
- Realismus- und Anti-Fingerprint-Tests

## 7. Empfohlene Modulgrenzen

Diese Grenzen sollen bewusst hart gezogen werden:

- `protocol-modbus` kennt keine Exporter
- `hmi-web` kennt keine Exporter
- `plant-sim` kennt keine Versandkanaele
- `rule-engine` kennt keine konkreten Mail- oder Telegram-APIs
- `exporter-sdk` enthaelt keine Fachlogik der Anlage

Wenn diese Grenzen weich werden, steigt das Risiko fuer:
- unklare Verantwortungen
- schwer testbares Verhalten
- inkonsistente Fehlermeldungen
- verratende Seiteneffekte

## 8. Daten- und Ereignisfluss im Detail

Ein typischer Ablauf fuer eine Schreiboperation soll konzeptionell so aussehen:

1. Ein Client sendet einen Schreibbefehl ueber Modbus oder die HMI.
2. Das Protokollmodul prueft Syntax, Adressierung und Berechtigung im Rahmen
   der simulierten Anlage.
3. Der Befehl wird in eine fachliche Operation uebersetzt.
4. `plant-sim` prueft die Operation gegen den aktuellen Anlagenzustand.
5. Der Zustand wird geaendert oder kontrolliert abgelehnt.
6. `event-core` speichert Anfrage, Entscheidung und resultierenden Zustand.
7. `rule-engine` bewertet, ob daraus ein Alarm oder ein Hinweis entsteht.
8. `exporter-runner` verteilt relevante Events oder Alerts asynchron weiter.

Das ist wichtig, weil:
- der sichtbare Effekt fuer Angreifer konsistent bleiben muss
- die Ereignisspur forensisch verwertbar sein muss
- externe Benachrichtigungen den Simulationsfluss nicht stoeren duerfen

## 9. Logging- und Alerting-Architektur

Logging wird in drei Ebenen gedacht:

1. **Protokoll- und Zugriffsebene**
   - Verbindungen
   - Requests
   - Responses
   - Login-Versuche

2. **Fach- und Prozesszustand**
   - Messwerte
   - Setpoints
   - Zustandsaenderungen
   - Alarmwechsel

3. **Export- und Betriebszustand**
   - Versandversuche
   - Fehler der Exporter
   - Retry-Zustaende
   - interne Health-Informationen

### Empfohlener Grundaufbau

- Ein lokaler Eventstore als autoritative Quelle
- Eine Outbox fuer weiterzuleitende Events und Alerts
- Optionale Rohdatenablage fuer JSONL und PCAP

### Warum dieser Aufbau?

- robust gegen Zielausfaelle
- gute Forensik
- spaetere Nachlieferung moeglich
- sauber testbar
- keine Inline-Abhaengigkeit von Mail-, Webhook- oder Chat-Diensten

## 10. Exporter-Modell

Die Exporter sollen separat anbaubar sein.

Moegliche Exportziele:
- E-Mail
- Webhook
- Telegram
- syslog
- OpenSearch
- Loki
- Splunk

### Vorgesehener Ablauf

1. Das Kernsystem erzeugt Events oder Alerts.
2. Die Outbox markiert, was exportiert werden soll.
3. Der `exporter-runner` uebergibt gebuendelte Daten an aktive Exporter.
4. Jeder Exporter bestaetigt Erfolg oder meldet Fehler zurueck.
5. Fehler fuehren zu Retry, nicht zum Ausfall des Honeypots.

### Anforderungen an Exporter

- definierte Konfiguration
- dokumentierte Fehlerbehandlung
- Rate-Limit-Unterstuetzung
- Idempotenz oder Dedupe-Strategie
- Health-Check
- Testbarkeit ohne echte Zielsysteme

## 11. Teststrategie als Architekturbaustein

Tests sind hier kein Zusatz, sondern Teil des Entwurfs.

Die Teststrategie sollte mindestens diese Ebenen abdecken:

1. **Unit-Tests**
   - kleine fachliche Regeln
   - Zustandsuebergaenge
   - Konfigurationsvalidierung

2. **Contract-Tests**
   - Modbus-Verhalten
   - Event-Schema
   - Exporter-Vertraege

3. **Scenario-Tests**
   - Curtailment senkt Leistung
   - Breaker offen erzeugt Alarmfolge
   - Kommunikationsverlust fuehrt zu anderem Verhalten als Leistungsverlust

4. **UI-/HTTP-Tests**
   - konsistente Fehlermeldungen
   - keine Debug- oder Entwicklungsartefakte
   - stabile Navigations- und Login-Flows

5. **Logging-Completeness-Tests**
   - jede sichtbare Aktion erzeugt die erwarteten Events
   - `correlation_id` bleibt entlang eines Ablaufs erhalten

6. **Anti-Fingerprint-Tests**
   - keine Tracebacks
   - keine verratenden Platzhalter
   - keine unnatuerlich perfekten Antwortmuster
   - keine widerspruechlichen Fehlerantworten

Leitsatz fuer das Projekt:
- **Jede sichtbare Fehlersituation braucht einen Test.**

## 12. Sicherheitsgrenzen in der Architektur

Folgende Grenzen muessen in der Architektur sichtbar bleiben:

- keine echte Fernsteuerung externer Systeme
- keine Shell fuer Angreifer
- keine impliziten Abhaengigkeiten zu realer Infrastruktur
- ausgehender Traffic nur kontrolliert und optional
- keine echten Secrets in Defaults oder Testdaten
- schneller Reset der Umgebung

Diese Grenzen sind wichtig, damit die Anlage:
- keinen realen Schaden verursachen kann
- kein Pivot-System wird
- trotz Interaktivitaet kontrollierbar bleibt

## 13. Erweiterungspfad

Die Architektur soll spaeter folgende Erweiterungen erlauben, ohne V1 zu
zerlegen:

- weitere Protokolle neben Modbus/TCP
- read-only OPC-UA-Sicht
- zusaetzliche HMI-Seiten
- mehr Alarmklassen
- mehrere Exporter gleichzeitig
- strengere Rollen- oder Session-Modelle
- weitere Anlagentypen mit derselben Event- und Exporter-Basis

## 14. Offene Architekturfragen

Diese Punkte muessen spaeter in eigenen Dokumenten vertieft werden:

- exakter Vertrag des Event-Schemas
- genaue Form der Exporter-Schnittstelle
- Persistenzmodell fuer Zustand, Events und Outbox
- Fehler- und Timeout-Strategie der HMI
- Granularitaet der Alarmklassen
- Umfang der V1-Protokolltreue im Modbus-/SunSpec-Modell

## 15. Kurzfazit

Der modulare Monolith ist fuer dieses Projekt der sinnvollste Kurs:
- einfach genug fuer einen kontrollierten Start
- modular genug fuer spaetere Erweiterungen
- testbar genug fuer glaubhafte Fehlerbilder
- robust genug fuer sauberes Logging und entkoppelte Benachrichtigungen

Damit bekommt die Deckscrew ein Projekt, das nicht nur "irgendwie laeuft",
sondern fachlich sauber wachsen kann.
