# Teststrategie V1: Funktion, Realismus und Anti-Fingerprint

## 1. Zweck dieses Dokuments

Dieses Dokument beschreibt die Teststrategie fuer den Solarpark-Honeypot. Es
legt fest:

- welche Testebenen es gibt
- welche Risiken damit abgedeckt werden sollen
- welche Testumgebungen benoetigt werden
- welche Mindestkriterien fuer V1 gelten
- welche sichtbaren Fehlerbilder zwingend getestet werden muessen

Die Teststrategie ist hier keine Nebensache. Sie ist Teil der
Glaubwuerdigkeit. Ein Honeypot, der sich durch krumme Fehlermeldungen,
inkonsistente Zustandswechsel oder lueckenhaftes Logging verraet, ist schlechter
als gar keiner.

## 2. Testziele

Die Teststrategie soll sicherstellen, dass das System:

1. fachlich konsistent arbeitet
2. ueber Modbus und HMI dieselbe Wahrheit zeigt
3. sichtbar plausible Prozesswirkungen erzeugt
4. vollstaendig und belastbar loggt
5. bei Fehlern kontrolliert und glaubhaft reagiert
6. sich nicht durch triviale Fingerprints verraten laesst

## 3. Leitsatz

Der wichtigste Leitsatz fuer dieses Projekt lautet:

- **Jede sichtbare Fehlersituation braucht einen Test.**

Ergaenzend gelten:

- **Jede schreibbare Operation braucht einen Wirkungstest.**
- **Jeder Exportpfad braucht einen Ausfalltest.**
- **Jede Datenquelle braucht einen Konsistenztest gegen das Fachmodell.**

## 4. Testprinzipien

### 4.1 Ein Fachmodell, viele Tests

Alle Testebenen pruefen letztlich dieselbe fachliche Grundlage:

- [domain-model.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/domain-model.md)
- [protocol-profile.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/protocol-profile.md)
- [register-matrix.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/register-matrix.md)
- [hmi-concept.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/hmi-concept.md)
- [logging-and-events.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/logging-and-events.md)

### 4.2 Kleine Tests zuerst, Szenarien danach

Wir pruefen zuerst:

- Fachregeln
- Datentypen
- Mapping
- Fehlercodes

und erst danach:

- ganze End-to-End-Ablaufe
- laengere Session-Verhalten
- Exporter-Ausfall

### 4.3 Reproduzierbar, aber nicht steril

Die Testumgebung muss reproduzierbar sein. Die simulierte Anlage darf aber fuer
bestimmte Integrations- und Realismus-Tests leichte Jitter oder dynamische
Prozessentwicklung zeigen.

Darum braucht das Projekt spaeter:

- deterministische Tests
- kontrolliert dynamische Tests

### 4.4 Keine echten Fremdsysteme in Standardtests

Standardtests duerfen nie abhaengig sein von:

- echtem SMTP
- echtem Telegram
- echtem Webhook-Ziel im Internet
- realen SCADA- oder OT-Systemen

Externe Ziele werden simuliert oder lokal emuliert.

## 5. Testpyramide fuer das Projekt

Die Testpyramide fuer V1 sollte so aussehen:

1. Unit-Tests
2. Contract-Tests
3. Modul-Integrations-Tests
4. Szenario-Tests
5. End-to-End-Tests
6. Anti-Fingerprint- und Soak-Tests

Je hoeher die Stufe, desto teurer und langsamer der Test. Je tiefer die Stufe,
desto haeufiger soll sie laufen.

## 6. Testumgebungen

Technische Festlegung fuer V1:

- `pytest` fuer Unit-, Contract-, Integrations- und Szenario-Tests
- `pytest-asyncio` fuer asynchrone Modul- und Integrationspfade
- `httpx` fuer HTTP-nahe Tests
- `Playwright` fuer HMI-End-to-End, Screenshots und UI-Fehlerpfade

### 6.1 `fast-local`

Zweck:
- schnelle Rueckmeldung fuer die Deckscrew

Enthaelt:
- deterministische Simulationszeit
- keine externen Exportziele
- minimales Logging

Geeignet fuer:
- Unit-Tests
- Contract-Tests
- Modul-Integrations-Tests

### 6.2 `integration-local`

Zweck:
- Zusammenspiel der Module pruefen

Enthaelt:
- Modbus
- HMI
- Eventstore
- Outbox
- lokale Exporter-Doubles

Geeignet fuer:
- Szenario-Tests
- HMI-/Modbus-Konsistenztests
- Logging-Completeness-Tests

### 6.3 `realism-lab`

Zweck:
- Glaubwuerdigkeit, Fehlerbilder und laengere Interaktion pruefen

Enthaelt:
- realistischere Zeitverlaeufe
- Polling
- Session-Verhalten
- simulierte Latenzen und Zielausfaelle

Geeignet fuer:
- Anti-Fingerprint-Tests
- Soak-Tests
- laengere Reconnaissance- und Bediensequenzen

## 7. Testdaten und Fixtures

### 7.1 Kanonische Testzustaende

Das Projekt sollte spaeter feste Startzustaende bereitstellen:

- `normal_operation`
- `curtailed_operation`
- `breaker_open`
- `comm_loss_single_block`
- `multi_block_unavailable`
- `tracker_stow`

### 7.2 Deterministische Startwerte

Jeder Testfall braucht:

- definierte Startzeit
- definierte Wetterwerte
- definierte Asset-Zustaende
- definierte Alarmlage

### 7.3 Keine echten Identitaetsdaten

Testdaten duerfen nicht enthalten:

- reale Firmennamen
- reale Ortsdaten
- echte Zugangsdaten
- echte Betreiberartefakte

## 8. Unit-Tests

Unit-Tests pruefen kleine, lokale Regeln ohne volles System.

### 8.1 Fachlogik

Pflichttests:

- `active_power_limit_pct` akzeptiert nur gueltigen Bereich
- `reactive_power_target` akzeptiert nur gueltigen Bereich
- Breaker-Zustaende wechseln nur ueber erlaubte Pfade
- Alarmzustandswechsel sind konsistent
- `acknowledged` ist nicht gleich `cleared`

### 8.2 Simulationsregeln

Pflichttests:

- Einstrahlung beeinflusst verfuegbare Leistung plausibel
- offene Breaker reduzieren Export
- Kommunikationsverlust markiert Wertequalitaet
- Blockausfall wirkt anders als Kommunikationsverlust

### 8.3 Konfiguration

Pflichttests:

- generische Defaults werden korrekt geladen
- invalide Konfiguration wird frueh abgewiesen
- deaktivierte Exporter erzeugen keine Laufzeitfehler

## 9. Contract-Tests

Contract-Tests pruefen feste Schnittstellenvertraege.

### 9.1 Modbus-Contract

Pflichttests:

- korrekter MBAP-Header
- `Protocol Identifier = 0`
- Transaction ID wird korrekt gespiegelt
- `FC03`, `FC06`, `FC16` verhalten sich wie dokumentiert
- `FC04` liefert in V1-Default `01 Illegal Function`

### 9.2 Registermatrix-Contract

Pflichttests:

- jede gelistete Adresse hat den dokumentierten Typ
- `reserved` Register lesen `0x0000`
- `ro` Register lehnen Schreiben mit `02 Illegal Data Address` ab
- ungueltige Werte liefern `03 Illegal Data Value`
- `rw-pulse` Register self-clearen

### 9.3 Event-Schema-Contract

Pflichttests:

- Pflichtfelder sind immer vorhanden
- `event_type`, `category` und `severity` sind gueltig
- `correlation_id` wird entlang zusammenhaengender Ketten beibehalten

### 9.4 Exporter-Contract

Pflichttests:

- Exporter validieren Konfiguration
- Exporter melden Health-Zustand
- Exporter koennen Batch-Ergebnisse eindeutig melden
- Exporter-Ausfall blockiert den Kern nicht

## 10. Modul-Integrations-Tests

Diese Tests pruefen das Zusammenspiel einzelner Module.

### 10.1 `plant-sim` + `protocol-modbus`

Beispiele:

- Schreiben eines Setpoints aendert spaeter die lesbaren Register
- Schreibablehnung bleibt auf Registerebene konsistent

### 10.2 `plant-sim` + `hmi-web`

Beispiele:

- HMI zeigt denselben Zustand wie das Fachmodell
- Kommunikationsverlust erscheint als `stale` oder `invalid`

### 10.3 `event-core` + `rule-engine`

Beispiele:

- relevante Ereignisse erzeugen passende Alerts
- irrelevante Events erzeugen keinen Alarmsturm

### 10.4 `event-core` + `exporter-runner`

Beispiele:

- Events landen korrekt in der Outbox
- Fehler fuehren zu Retry
- dauerhafte Fehler werden sichtbar markiert

## 11. Szenario-Tests

Szenario-Tests pruefen fachlich sinnvolle Ereignisketten.

### 11.1 Normale Erzeugung

Pruefen:

- Wetter gut
- alle Blocks online
- Breaker geschlossen
- Leistung und Export plausibel
- keine kritischen Alarme

### 11.2 Curtailment-Szenario

Pruefen:

- Setpoint wird akzeptiert
- Parkleistung sinkt zeitlich plausibel
- HMI, Modbus und Eventspur zeigen dieselbe Wirkung
- `PLANT_CURTAILED` wird aktiv

### 11.3 Breaker-Offen-Szenario

Pruefen:

- Bedienhandlung wird angenommen
- Exportpfad wird unverfuegbar
- Revenue Meter faellt ab
- `BREAKER_OPEN` wird aktiv

### 11.4 Kommunikationsverlust

Pruefen:

- Wertequalitaet wird `stale` oder `invalid`
- Blockstatus wird `degraded` oder `offline`
- Leistungseffekt ist nicht identisch zu echtem Anlagenverlust
- `COMM_LOSS_INVERTER_BLOCK` wird aktiv

### 11.5 Service-Login plus Bedienung

Pruefen:

- Login erfolgreich
- geschuetzte Aktion wird sichtbar
- Bedienung erzeugt Event, Wirkung und HMI-Aktualisierung

## 12. End-to-End-Tests

Diese Tests fahren den kompletten Pfad durch:

- Client -> Modbus oder HMI -> Fachmodell -> Eventsystem -> Outbox -> Exporter

### 12.1 Modbus-End-to-End

Pflichttests:

- erfolgreicher Read
- erfolgreicher Write mit Prozesswirkung
- ungueltige Adresse
- ungueltiger Wert

### 12.2 HMI-End-to-End

Pflichttests:

- Seiten rendern konsistent
- Login-Flow arbeitet stabil
- Bedienungen werden korrekt rueckgespiegelt
- Fehlerseiten bleiben ruhig und generisch
- erster Browser-Slice prueft `/service/login -> /service/panel -> breaker open -> /alarms`
  gegen den echten lokalen Runtime-Pfad
- zweiter Browser-Slice prueft `power_limit` auf `/service/panel` mit sichtbarer
  Shared-Truth-Wirkung in `/overview` und `/trends`
- dritter Browser-Slice prueft `breaker open -> breaker close` auf
  `/service/panel` mit sichtbarer Wirkung in `/meter` und der Alarmhistorie
- vierter Browser-Slice prueft `block_enable_request` und
  `block_power_limit_pct` auf `/service/panel` mit sichtbarer Wirkung in
  `/inverters`
- fuenfter Browser-Slice prueft `block_reset_request` nach simuliertem
  `COMM_LOSS_INVERTER_BLOCK` auf `/service/panel` mit sichtbarer Wirkung in
  `/inverters` und `/alarms`
- sechster Browser-Slice prueft fehlgeschlagenen Service-Login und den
  unauthentifizierten `GET /service/panel` mit ruhigem `401`
- siebter Browser-Slice prueft den Session-Ablauf nach `20` Minuten Idle-Zeit
  mit ruhigem `401` auf `/service/panel`
- achter Browser-Slice prueft deaktiviertes Service-Login mit ruhigem `403`
  auf `/service/login` und `/service/panel`
- neunter Browser-Slice prueft wiederholte fehlgeschlagene Service-Logins mit
  sichtbarem `REPEATED_LOGIN_FAILURE` auf `/alarms`
- zehnter Browser-Slice prueft weitere Fehlversuche nach aktivem
  `REPEATED_LOGIN_FAILURE` ohne duplizierten Alert auf `/alarms`
- elfter Browser-Slice prueft erfolgreichen Service-Login nach aktivem
  `REPEATED_LOGIN_FAILURE` mit sichtbarem `cleared` auf `/alarms`
- zwoelfter Browser-Slice prueft `GRID_PATH_UNAVAILABLE` als zweiten
  history-only Rule-Alert sichtbar auf `/alarms`
- dreizehnter Browser-Slice prueft einen weiteren `breaker_open_request` bei
  aktivem `GRID_PATH_UNAVAILABLE` ohne duplizierten Folge-Alert auf `/alarms`
- vierzehnter Browser-Slice prueft `LOW_SITE_OUTPUT_UNEXPECTED` nach
  mehrfachen Block-Ausfaellen sichtbar auf `/alarms`
- fuenfzehnter Browser-Slice prueft `LOW_SITE_OUTPUT_UNEXPECTED` nach
  Block-Erholung mit sichtbarem `cleared` auf `/alarms`
- sechzehnter Browser-Slice prueft `LOW_SITE_OUTPUT_UNEXPECTED` bei weiterem
  Block-Control waehrend aktiver Folge-Lage ohne duplizierten Alert auf
  `/alarms`
- siebzehnter Browser-Slice prueft `reactive_power_target` auf
  `/service/panel` mit sichtbarer Shared-Truth-Rueckspiegelung in
  `/overview`
- achtzehnter Browser-Slice prueft `plant_mode_request` auf
  `/service/panel` als gelatchten Bedienwunsch ohne heimlichen Wechsel des
  echten `operating_mode`
- neunzehnter Browser-Slice prueft `breaker open` auf `/service/panel` mit
  sichtbarer Rueckspiegelung im read-only `/single-line`-Schema

### 12.3 Alerting-End-to-End

Pflichttests:

- relevantes Ereignis erzeugt Alert
- Alert landet in Outbox
- lokaler Exporter-Double empfaengt Payload
- Exportfehler bleibt fuer den Client unsichtbar

## 13. Logging- und Event-Tests

Das Logging braucht eine eigene Testschicht.

### 13.1 Schema- und Feldtests

Pflichttests:

- jedes Event erfuellt den Vertrag
- Modbus-spezifische Felder sind vorhanden
- HTTP-spezifische Felder sind vorhanden

### 13.2 Completeness-Tests

Pflichttests:

- sichtbare HMI-Aktion erzeugt Eventspur
- Modbus-Schreibzugriff erzeugt Eventspur
- Prozesswirkung erzeugt Folgeevent
- Alerting erzeugt Alert- und Outbox-Eintrag

### 13.3 Korrelationstests

Pflichttests:

- Verbindungsaufbau, Bedienung, Zustandswechsel und Alert teilen passende
  `correlation_id`

### 13.4 Negativtests

Pflichttests:

- ungultige Registeranfrage erzeugt korrektes Fehler-Event
- Login-Fehler erzeugt korrektes Auth-Event
- Exporter-Ausfall erzeugt System-/Exporter-Event

## 14. HMI- und HTTP-Tests

Diese Tests sind ueber die End-to-End-Ebene hinaus auf sichtbare Webdetails
fokussiert.

Pflichttests:

- alle dokumentierten Seiten erreichbar
- `401`, `403`, `404` konsistent
- keine Debug-Header
- keine Framework-Signaturen
- stale/invalid-Werte sichtbar markiert
- Alarmlisten und Overview widersprechen sich nicht

## 15. Anti-Fingerprint-Tests

Diese Testklasse ist fuer das Projekt besonders kritisch.

### 15.1 Protokoll-Fingerprint

Pflichttests:

- wiederholte ungueltige Registeranfragen liefern dasselbe Fehlerbild
- Registerbreiten und Wortreihenfolge bleiben stabil
- unbekannte Unit-IDs verhalten sich konsistent

### 15.2 UI-Fingerprint

Pflichttests:

- keine Default-Fehlerseiten
- keine offensichtlichen Framework-Pfade
- keine Platzhaltertexte oder Entwicklerreste
- Seiten ohne Daten wirken kontrolliert, nicht kaputt

### 15.3 Timing-Fingerprint

Pflichttests:

- Antworten sind nicht unnatuerlich perfekt
- Schreibwirkungen duerfen leicht zeitversetzt erscheinen
- Export- oder Alerting-Fehler veraendern Client-Latenz nicht auffaellig

## 16. Resilienz- und Ausfalltests

Diese Tests pruefen Robustheit unter Stoerung.

Pflichttests:

- Eventstore temporaer langsam
- Outbox wachsend
- Webhook nicht erreichbar
- SMTP langsam
- Telegram liefert Rate-Limit
- einzelne Asset-Kommunikation faellt aus

Erwartung:

- Honeypot bleibt nutzbar
- Logging bleibt moeglichst vollstaendig
- Fehler werden intern sichtbar, aber aussen ruhig behandelt

## 17. Soak- und Polling-Tests

Da OT-Systeme oft wiederholt gepollt werden, braucht V1 auch laengere Tests.

Pflichttests:

- wiederholtes Polling ueber laengere Zeit
- wiederholte Login-Versuche
- wiederholtes Lesen `reserved` Register
- wiederholte Wechsel zwischen normal und curtailed

Diese Tests sollen finden:

- Speicherlecks
- Drift in Zustandswerten
- Event-Stau
- unplausible Zeitmuster

## 18. Sicherheitsrelevante Testregeln

Die Teststrategie muss selbst Sicherheitsgrenzen respektieren.

Nicht erlaubt in Standardtests:

- echte Internetziele
- reale Mailserver
- echte Telegram-Bots
- echte Betreiber- oder Standortdaten
- Tests gegen produktionsnahe OT-Infrastruktur

Pflicht:

- alle Exportziele lokal oder emuliert
- Secrets nur synthetisch
- Testdaten generisch halten

## 19. Test-Gates fuer V1

Ein V1-Build sollte nur dann als ausreichend gelten, wenn mindestens:

- alle Unit-Tests gruen sind
- alle Contract-Tests gruen sind
- alle Kern-Szenarien gruen sind
- alle HMI-Fehlersituationen einen Test haben
- Logging-Completeness fuer Kernpfade nachgewiesen ist
- Anti-Fingerprint-Basissuite gruen ist

Kernpfade fuer V1:

- normaler Modbus-Read
- gueltiger Modbus-Write
- ungueltiger Modbus-Write
- HMI-Overview
- Login-Fehler
- HMI-Bedienung einer erlaubten Aktion
- Exporter-Ausfall ohne sichtbare Aussenwirkung

## 20. Testartefakte und Reports

Die Tests sollten spaeter mehr liefern als nur `pass/fail`.

Sinnvolle Artefakte:

- strukturierte Testreports
- Event-Auszug pro Szenario
- Vergleich zwischen erwarteten und beobachteten Registerwerten
- HMI-Screenshots fuer End-to-End-Tests
- Fehlerklassifikation pro Testlauf

## 21. Offene Punkte

Spaeter noch zu konkretisieren:

- Verteilung der Tests nach Modulpfaden
- Umgang mit Snapshot-Tests fuer HMI
- Schwellwerte fuer Timing- und Soak-Tests
- Priorisierung fuer Nightly- gegen PR-Testlaeufe

## 22. Kurzfazit

Die V1-Teststrategie muss nicht nur Funktion pruefen, sondern vor allem
Konsistenz, Fehlerruhe und Glaubwuerdigkeit. Ein sauber getesteter Honeypot
taeuscht nicht durch mehr Features, sondern durch weniger Widersprueche. Genau
dafuer ist diese Testpyramide gedacht.
