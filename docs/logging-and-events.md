# Logging, Events und Benachrichtigungen

## 1. Zweck dieses Dokuments

Dieses Dokument beschreibt, wie der Honeypot Ereignisse erfasst, speichert,
korreliert, bewertet und an nachgelagerte Ziele weiterleitet.

Das Thema ist fuer dieses Projekt besonders wichtig, weil der Honeypot nicht
nur "laufen", sondern beobachtbar, forensisch nutzbar und glaubwuerdig sein
soll. Schlechte oder lueckenhafte Logs sind ein Sicherheitsproblem. Ebenso
koennen verratende Fehler oder haengende Benachrichtigungen Angreifern Hinweise
auf eine Attrappe geben.

## 2. Ziele des Logging-Systems

Das Logging-System soll gleichzeitig mehrere Aufgaben erfuellen:

- vollstaendige Beobachtbarkeit der relevanten Interaktionen
- forensisch nutzbare Ereignisspur
- Korrelation zwischen Netzwerk, Protokoll, HMI und Prozesszustand
- Grundlage fuer Benachrichtigungen und Export
- robuste Funktion auch bei Ausfall externer Ziele
- keine sichtbaren Stoerungen fuer Angreifer bei Export- oder Alerting-Fehlern

## 3. Leitprinzipien

1. **Events vor Textlogs**
   - Freitext-Logs allein reichen nicht.
   - Das Kernsystem arbeitet mit strukturierten Events.

2. **Ein lokaler Wahrheitskern**
   - Bevor irgendetwas weitergeleitet wird, wird das Ereignis lokal
     persistiert.

3. **Export ist nachgelagert**
   - E-Mail, Webhook, Telegram oder Suchsysteme sind Verbraucher, nicht
     Wahrheitsquelle.

4. **Jede sichtbare Aktion hat eine Ereignisspur**
   - Was ein Angreifer sieht oder ausloest, muss spaeter rekonstruiert werden
     koennen.

5. **Fehler im Logging duerfen nicht sichtbar enttarnen**
   - Export- oder Versandprobleme duerfen keine Stacktraces, Timeouts oder
     inkonsistenten Antworten an der Aussenkante erzeugen.

6. **Sprachtrennung bleibt erhalten**
   - Angreifer-HMI darf lokalisiert sein, aber Events, Logs und
     Betreiberdiagnose bleiben deutsch oder sprachneutral.

## 4. Empfohlener Logging-Weg fuer V1

Fuer V1 empfehle ich einen dreistufigen Aufbau:

### 4.1 Autoritativer lokaler Eventstore

Der Kern des Systems speichert jedes normalisierte Ereignis in einem lokalen
Eventstore, zum Beispiel in `SQLite` oder einem gleichwertigen lokalen
Persistenzmechanismus.

Warum das sinnvoll ist:
- einfach genug fuer V1
- transaktional genug fuer Ereignis- und Outbox-Modell
- lokal schnell und gut testbar
- keine Abhaengigkeit von externer Infrastruktur

### 4.2 JSONL-Archiv fuer einfache Analyse

Parallel oder nachgelagert kann ein taegliches `JSONL`-Archiv geschrieben
werden.

Warum das sinnvoll ist:
- leicht lesbar
- leicht in Analysewerkzeuge importierbar
- gut fuer manuelle Auswertung und Forschung

### 4.3 Optionale Rohdatenablage

Optional koennen Netzwerkrohdaten oder technische Mitschnitte zusaetzlich
gespeichert werden, zum Beispiel:
- `PCAP`
- Rohtranskripte von HTTP-Sessions
- Rohframes von Protokollzugriffen

Wichtige Vorgabe:
- Rohdaten nur kontrolliert aktivieren
- Speicherwachstum begrenzen
- nicht als einzige Quelle betrachten

## 5. Warum nicht nur auf ein Ziel loggen?

Ein reiner Versand an Mail, Telegram, Webhook oder Suchcluster ist fuer den
Honeypot nicht ausreichend.

Gruende:
- Zielsysteme koennen ausfallen
- Netzverbindungen koennen blockiert sein
- externe Abhaengigkeiten veraendern Latenz und Fehlerbilder
- Replay, Retry und Nachlieferung werden unnoetig schwer

Deshalb gilt:
- **lokal speichern zuerst**
- **weiterleiten danach**

## 6. Event-Taxonomie

Die Events sollen in klaren Klassen organisiert werden.

### 6.1 Transport- und Sitzungsereignisse

Beispiele:
- TCP-Verbindung aufgebaut
- TCP-Verbindung beendet
- HTTP-Session begonnen
- Session-Timeout

Nutzen:
- Verhaltensanalyse
- Korrelation zwischen Sessions und Folgeaktionen

### 6.2 Authentifizierungs- und Zugriffsereignisse

Beispiele:
- Login-Versuch
- Login erfolgreich
- Login fehlgeschlagen
- Session invalidiert

Nutzen:
- Erkennung von Credential-Stuffing oder Passwortprobing
- Grundlage fuer Benachrichtigungen

### 6.3 Protokollereignisse

Beispiele:
- Modbus-Lesezugriff
- Modbus-Schreibzugriff
- illegale Funktionsanfrage
- ungultige Registeradresse
- schreibender Zugriff auf read-only Bereich

Nutzen:
- Sicht auf Reconnaissance und Manipulationsversuche
- Bewertung von Standardkonformitaet und Missbrauch

### 6.4 HMI- und UI-Ereignisse

Beispiele:
- Seite aufgerufen
- Alarmansicht geoeffnet
- Trendansicht geoeffnet
- Bedienoperation versucht

Nutzen:
- Einschaetzung des Operator-/Recon-Verhaltens
- Korrelation zwischen UI und Protokollpfad

### 6.5 Prozess- und Zustandsereignisse

Beispiele:
- Leistung gefallen
- Curtailment-Wert geaendert
- Breaker-Zustand geaendert
- Kommunikationsstatus einer Teilanlage gewechselt
- Alarm aktiviert oder quittiert

Nutzen:
- fachlich nachvollziehbare Ereignisspur
- Rekonstruktion der Auswirkung eines Angriffs

### 6.6 System- und Exportereignisse

Beispiele:
- Exporter gestartet
- Exportbatch erfolgreich
- Exportbatch fehlgeschlagen
- Retry geplant
- lokaler Speicher an Schwellwert

Nutzen:
- Betriebssicht fuer die Deckscrew
- Diagnose ohne Einfluss auf Aussenverhalten

## 7. Kanonisches Event-Schema

Alle Module sollen auf ein gemeinsames Ereignisschema schreiben.

### 7.1 Pflichtfelder

- `timestamp`
  - Zeitpunkt des Ereignisses in normalisiertem Format
- `event_id`
  - eindeutige Kennung fuer dieses Event
- `correlation_id`
  - verbindet zusammengehoerige Ereignisse ueber mehrere Module
- `event_type`
  - fachlicher oder technischer Typ des Ereignisses
- `category`
  - grobe Klasse wie `transport`, `auth`, `protocol`, `process`, `alert`
- `severity`
  - Einordnung der Wichtigkeit
- `source_ip`
  - beobachtete Quell-IP, soweit vorhanden
- `actor_type`
  - z. B. `remote_client`, `hmi_user`, `internal_scheduler`, `system`
- `component`
  - erzeugendes Modul, z. B. `protocol-modbus` oder `hmi-web`
- `asset_id`
  - betroffenes fachliches Asset, falls vorhanden
- `action`
  - beobachtete oder ausgefuehrte Handlung
- `result`
  - Ergebnis wie `accepted`, `rejected`, `failed`, `timeout`

### 7.2 Stark empfohlene Zusatzfelder

- `session_id`
- `causation_id`
- `protocol`
- `service`
- `endpoint_or_register`
- `requested_value`
- `previous_value`
- `resulting_value`
- `resulting_state`
- `alarm_code`
- `error_code`
- `message`
- `tags`

### 7.3 Modellgedanke

Die Pflichtfelder halten das Schema stabil. Zusatzfelder erlauben
protokollspezifische oder fachliche Tiefe, ohne das Grundmodell zu zerbrechen.

### 7.4 Sprachregel fuer Events und Logs

Das Event-Schema selbst bleibt sprachneutral.

Das bedeutet:
- `event_type`, `category`, `action`, `result` und `alarm_code` bleiben stabile
  Schluessel
- Admin-Sicht, Betriebsdiagnose und Freitext-Logs bleiben deutsch
- die Lokalisierung angreiferzugewandter HMI-Texte passiert ausserhalb des
  Event-Kerns

Wichtige Regel:
- V1 kennt keine deployment-abhaengige Lokalisierung der Roh-Logs

## 8. Beispiel fuer ein Event

```json
{
  "timestamp": "2026-04-09T15:31:22Z",
  "event_id": "evt_01JSAMPLE123",
  "correlation_id": "corr_01JSAMPLE999",
  "causation_id": "evt_01JSAMPLE122",
  "event_type": "process.setpoint.curtailment_changed",
  "category": "process",
  "severity": "high",
  "source_ip": "203.0.113.24",
  "actor_type": "remote_client",
  "component": "protocol-modbus",
  "asset_id": "ppc-01",
  "session_id": "sess_01JSAMPLE777",
  "protocol": "modbus-tcp",
  "service": "holding-registers",
  "endpoint_or_register": "40125",
  "action": "write_single_register",
  "requested_value": 50,
  "previous_value": 100,
  "resulting_value": 50,
  "resulting_state": {
    "active_power_limit_pct": 50,
    "plant_power_mw": 3.1
  },
  "result": "accepted",
  "tags": [
    "control-path",
    "ppc",
    "curtailment"
  ]
}
```

## 9. Korrelation und Ereignisketten

Damit der Honeypot spaeter auswertbar bleibt, reichen einzelne Events nicht.
Wichtig ist die Verknuepfung.

### 9.1 Empfohlene Identitaeten

- `event_id`
  - einzelne Beobachtung
- `correlation_id`
  - gesamte Kette eines zusammenhaengenden Vorgangs
- `causation_id`
  - direkte fachliche Ursache
- `session_id`
  - Verbindung oder UI-Session

### 9.2 Typischer Ablauf

Ein Schreibzugriff kann zum Beispiel diese Kette erzeugen:

1. Verbindung aufgebaut
2. Modbus-Write empfangen
3. Schreibzugriff fachlich akzeptiert
4. Setpoint geaendert
5. Leistung sinkt
6. Alarm aktiviert
7. Alert in Outbox gestellt
8. Export an Webhook versucht

Alle diese Events teilen sich dieselbe `correlation_id`.

## 10. Severity- und Prioritaetsmodell

Ein einfaches, aber klares Modell ist fuer V1 ausreichend.

### 10.1 Empfohlene Severity-Werte

- `debug`
  - nur fuer interne Diagnose
- `info`
  - normale Beobachtungen ohne unmittelbaren Alarmwert
- `low`
  - auffaellig, aber noch nicht kritisch
- `medium`
  - sicherheits- oder betriebsrelevant
- `high`
  - deutlicher Missbrauch oder relevante Prozesswirkung
- `critical`
  - sehr hohe Relevanz oder mehrstufige Missbrauchsfolge

### 10.2 Beispielhafte Zuordnung

- `info`
  - normale Lesebefehle
- `low`
  - wiederholte Navigation durch HMI
- `medium`
  - fehlerhafte Login-Serien
- `high`
  - erfolgreiche Setpoint-Aenderung mit Prozesswirkung
- `critical`
  - Sequenz aus Auth-Erfolg, Steuerung und Alarmkaskade

## 11. Eventstore und Speicherbereiche

Der Persistenzteil sollte logisch in vier Bereiche getrennt sein:

### 11.1 `current_state`

Enthaelt den aktuellen Zustand der simulierten Anlage.

Beispiele:
- aktuelle Parkleistung
- aktuelle Setpoints
- Status der Assets
- aktive Alarme

### 11.2 `event_log`

Enthaelt die unveraenderliche Ereignisspur.

Wichtige Regel:
- Events werden nicht stillschweigend ueberschrieben oder "wegoptimiert".

### 11.3 `alert_log`

Enthaelt abgeleitete Alerts und Benachrichtigungsereignisse.

Warum getrennt?
- Ein Alert ist nicht dasselbe wie ein Roh-Event.
- Mehrere Events koennen zu einem Alert fuehren.

### 11.4 `outbox`

Enthaelt auszuliefernde Pakete fuer Exporter.

Wichtige Felder:
- Zieltyp
- Payload-Referenz oder Payload
- Status
- Retry-Zaehler
- naechster Sendezeitpunkt
- letzter Fehler

## 12. Outbox-Muster

Die Outbox ist der zentrale Puffer zwischen Kernsystem und Exportern.

### 12.1 Warum die Outbox wichtig ist

- entkoppelt Export vom Anfragepfad
- erlaubt Retry
- erlaubt Nachlieferung
- schuetzt gegen Zielausfaelle
- vermeidet sichtbare Seiteneffekte fuer Angreifer

### 12.2 Grundregel

Ein Event gilt fuer den Honeypot erst dann als korrekt verarbeitet, wenn es:

1. lokal normalisiert wurde
2. lokal persistiert wurde
3. falls noetig in die Outbox geschrieben wurde

Danach duerfen Exporter arbeiten, aber nie umgekehrt.

## 13. Alerting-Modell

Nicht jedes Event soll eine Benachrichtigung ausloesen.

Deshalb wird zwischen drei Ebenen unterschieden:

### 13.1 Event

Rohbeobachtung oder fachliches Ergebnis.

### 13.2 Alert

Bewertetes Ereignis oder Ereignisbundle, das fuer die Deckscrew relevant ist.

### 13.3 Notification

Konkrete Auslieferung eines Alerts an ein Ziel wie Mail, Webhook oder
Telegram.

Diese Trennung ist wichtig, weil:
- sonst zu viele Rohereignisse verschickt werden
- die Benachrichtigungslogik unkontrolliert im Kern landet
- spaetere Kanalwechsel unnoetig schwer werden

## 14. Benachrichtigungskanaele

Folgende Ziele sind fuer das Projekt plausibel:

### 14.1 Webhook

Staerken:
- technisch einfach
- gut fuer zentrale Automatisierung
- gut fuer eigene Analysepipelines

Risiken:
- Zielausfall oder langsame Antwortzeiten
- moegliche Leaks bei falscher Konfiguration

Empfehlung:
- fuer V1 der sinnvollste erste aktive Kanal

### 14.2 E-Mail

Staerken:
- gut fuer zusammenfassende Alerts und Reports
- vielen Nutzern vertraut

Risiken:
- traege fuer Echtzeit
- fehleranfaellig bei SMTP-Konfiguration

Empfehlung:
- gut fuer taegliche Reports oder wichtige Sammelalarme

### 14.3 Telegram

Staerken:
- schnelle Push-Benachrichtigung
- gut fuer Labor- oder Forschungsbetrieb

Risiken:
- externer Dienst
- zusaetzliche Secrets
- nicht ideal als alleiniger Primarkanal

Empfehlung:
- optionaler Kanal fuer Forschungsteam, nicht Kernabhaengigkeit

### 14.4 Weitere moegliche Ziele

- syslog
- Loki
- OpenSearch
- Splunk

Diese Ziele sind fuer Analyse oft wertvoller als rein menschliche Alerts.

## 15. Empfehlung fuer V1-Benachrichtigungen

Fuer V1 empfehle ich diesen Kurs:

- Primarer technischer Export: `Webhook`
- Primaerer Analysepfad: lokaler Eventstore plus `JSONL`
- Sekundaerer menschlicher Kanal: `E-Mail`
- Optionaler Forschungskanal: `Telegram`

Warum dieser Kurs sinnvoll ist:
- geringe Komplexitaet
- gute Entkopplung
- robuste Nachlieferung moeglich
- kein zu frueher Zwang zu externer Observability-Infrastruktur

## 16. Exporter-Schnittstelle

Das Kernsystem soll eine stabile Schnittstelle fuer anbaubare Exporter bieten.

### 16.1 Ziele der Schnittstelle

- klare Trennung zwischen Kern und Zielsystemen
- Exporter koennen separat entwickelt werden
- einfacher Austausch einzelner Kanaele
- kontrollierte Fehlerbehandlung

### 16.2 Minimale Faehigkeiten eines Exporters

- Konfiguration validieren
- eigenen Health-Zustand melden
- Event-Batches empfangen
- Alert-Batches empfangen
- Ergebnis kontrolliert zurueckgeben

### 16.3 Empfohlene logische Operationen

- `capabilities()`
- `validate_config(config)`
- `health()`
- `deliver_event_batch(batch)`
- `deliver_alert_batch(batch)`

Diese Namen sind noch konzeptionell. Wichtig ist der Vertrag, nicht die exakte
Programmierschnittstelle.

## 17. Exporter-Typen

Die Exporter lassen sich in zwei Familien teilen:

### 17.1 Event-Exporter

Aufgabe:
- liefern Roh- oder Normalform-Events an Analyseziele

Beispiele:
- OpenSearch
- Loki
- Datei-Archiv
- syslog

### 17.2 Alert-Exporter

Aufgabe:
- liefern bewertete Alerts an Menschen oder Workflows

Beispiele:
- E-Mail
- Webhook
- Telegram

Die Trennung ist wichtig, weil:
- Events oft hohes Volumen haben
- Alerts deutlich weniger, aber semantisch wertvoller sind

## 18. Fehlerbehandlung fuer Exporter

Exporter muessen als unsichere Umgebung betrachtet werden.

### 18.1 Anforderungen

- Fehler blockieren nie den Honeypot-Kern
- Fehler werden selbst wieder als Ereignisse protokolliert
- Retries laufen mit Backoff
- dauerhafte Fehler werden klar markiert
- Rate-Limits werden respektiert

### 18.2 Was nicht passieren darf

- ein langsamer Webhook verlangsamt Modbus-Antworten
- ein Mail-Fehler erzeugt sichtbare UI-Probleme
- ein Telegram-Timeout verraet interne Architekturdeetails
- Export-Fehler verschwinden unbemerkt

## 19. Konfigurationsprinzip fuer Logging und Export

Identitaetsnahe Werte sollen generisch bleiben. Dasselbe gilt fuer
Benachrichtigungskonfiguration: keine echten Secrets in Defaults.

Beispiele fuer spaetere Konfigurationswerte:

- `EVENT_STORE_BACKEND`
- `EVENT_STORE_PATH`
- `JSONL_ARCHIVE_ENABLED`
- `PCAP_CAPTURE_ENABLED`
- `OUTBOX_BATCH_SIZE`
- `OUTBOX_RETRY_BACKOFF_SECONDS`
- `ALERT_MIN_SEVERITY`
- `WEBHOOK_EXPORTER_ENABLED`
- `WEBHOOK_EXPORTER_URL`
- `SMTP_EXPORTER_ENABLED`
- `SMTP_FROM`
- `TELEGRAM_EXPORTER_ENABLED`

Wichtige Regeln:
- Secrets nur ueber Konfiguration
- keine echten Test-Secrets im Repo
- sichere Defaults mit deaktivierten Exportern
- sprachliche Umstellung der Angreifer-HMI aendert nicht die Log-Sprache
- Alert- und Betreibertexte bleiben in V1 deutsch

## 20. Teststrategie fuer Logging und Events

Das Logging-System braucht eigene Tests. Sonst drohen blinde Flecken oder
verratende Fehlerbilder.

### 20.1 Pflicht-Testklassen

- **Schema-Tests**
  - jedes erzeugte Event erfuellt den Vertrag
- **Korrelationstests**
  - zusammengehoerige Aktionen teilen dieselbe `correlation_id`
- **Completeness-Tests**
  - sichtbare Aktionen erzeugen alle erwarteten Folgeevents
- **Outbox-Tests**
  - Alerts landen korrekt in der Outbox
- **Retry-Tests**
  - fehlgeschlagene Exporte werden kontrolliert neu versucht
- **Exporter-Contract-Tests**
  - Plugins halten die vereinbarte Schnittstelle ein
- **Anti-Fingerprint-Tests**
  - Exporter-Fehler wirken sich nicht sichtbar auf Protokoll- oder UI-Antworten
    aus

### 20.2 Besonders wichtige Negativtests

- ungultige Registeranfrage erzeugt korrektes Fehler-Event
- Auth-Fehler erzeugt Alert nur ab definierter Schwelle
- Webhook-Ziel ist nicht erreichbar
- SMTP antwortet langsam
- Telegram liefert Rate-Limit
- Eventstore ist temporaer ausgelastet

## 21. Sicherheitsaspekte

Logging ist selbst Angriffsoberflaeche und muss daher bewusst abgesichert
werden.

### 21.1 Risiken

- versehentliche Speicherung von Secrets
- unkontrolliertes Wachstum von Rohdaten
- Export sensibler Informationen an falsche Ziele
- Log-Injection durch unbereinigte Felder
- sichtbare Stoerungen bei Export-Ausfall

### 21.2 Gegenmassnahmen

- klare Feldvalidierung
- strukturierte statt frei zusammengesetzter Logs
- konfigurierbare Aufbewahrung
- kontrollierte Aktivierung von Rohdaten
- strikte Entkopplung von Export und Anfragepfad

## 22. Offene Entscheidungen

Diese Punkte muessen spaeter noch konkretisiert werden:

- welches lokale Speicherformat V1 genau nutzt
- wie lang Rohdaten aufbewahrt werden
- ob `PCAP` standardmaessig deaktiviert bleibt
- welche Alert-Regeln in V1 zuerst aktiv sind
- ob Exporter im selben Prozess oder in getrennten Worker-Kontexten laufen
- wie streng Dedupe und Suppression anfangs sein sollen

## 23. V1-Empfehlung in einem Satz

V1 sollte auf **lokalen Eventstore + JSONL-Archiv + Outbox + entkoppelte
Exporter** setzen, mit `Webhook` als erstem technischen Kanal und `E-Mail` als
spaeterem menschenorientierten Zusatz.
