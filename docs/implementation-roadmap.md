# Implementierungs-Roadmap V1: Von der Dokumentation zur baubaren Anlage

## 1. Zweck dieses Dokuments

Dieses Dokument uebersetzt die bisherigen Architektur- und Fachdokumente in
einen umsetzbaren Bauplan. Es beschreibt:

- in welcher Reihenfolge die Deckscrew die Module bauen sollte
- welche Abhaengigkeiten zwischen den Arbeitspaketen bestehen
- welche Ergebnisse pro Phase erwartet werden
- wann eine Phase als abgeschlossen gelten darf
- welche Sicherheits- und Testgates vor dem naechsten Schritt erreicht sein
  muessen

Diese Roadmap ist bewusst fuer einen kleinen, modularen Monolithen geschrieben.
Sie richtet sich an ein Projekt, das pragmatisch wachsen soll, ohne frueh in
Komplexitaet oder unsichere Betriebsnaehe zu geraten.

## 2. Zielbild der Umsetzung

Am Ende von V1 soll ein lokaler, kontrollierter Honeypot vorliegen, der:

- einen kleinen, glaubhaften Solarpark simuliert
- eine standardnahe `Modbus/TCP`-Sicht bietet
- eine kleine, konsistente Web-HMI bietet
- alle relevanten Interaktionen strukturiert loggt
- Alerts und Export ueber eine entkoppelte Outbox verarbeiten kann
- sich durch Tests gegen triviale Fingerprints absichert

## 3. Roadmap-Prinzipien

### 3.1 Vertikale Scheiben statt grosser Big-Bang-Phasen

Die Deckscrew sollte frueh funktionsfaehige Vertikalscheiben bauen:

- zuerst wenig Umfang
- dafuer komplett durchgestochen
- von Fachmodell bis Eventsystem

Das ist besser als:

- erst alles im Datenmodell
- dann alles im Protokoll
- dann alles in der HMI

Denn genau so entstehen spaeter Widersprueche.

### 3.2 Logging frueh, nicht spaet

Das Eventsystem gehoert nicht ans Ende. Sobald Interaktion entsteht, muss die
Ereignisspur mitlaufen.

### 3.3 Oeffentliche Exponierung erst ganz am Ende

Vor echter Exponierung muessen zuerst stehen:

- fachliche Konsistenz
- Logging
- Fehlerverhalten
- Anti-Fingerprint-Basisschutz
- Egress-Kontrolle

### 3.4 Jede Phase hat ein Exit-Kriterium

Eine Phase gilt erst als beendet, wenn:

- die benoetigten Tests laufen
- die definierten Pfade dokumentiert sind
- keine kritischen Sicherheitsluecken fuer den naechsten Schritt offen sind

## 4. Eingangsartefakte

Diese Dokumente bilden die Grundlage der Umsetzung:

- [v1-decisions.md](v1-decisions.md)
- [solarpark-honeypot-scope.md](solarpark-honeypot-scope.md)
- [architecture.md](architecture.md)
- [domain-model.md](domain-model.md)
- [logging-and-events.md](logging-and-events.md)
- [protocol-profile.md](protocol-profile.md)
- [register-matrix.md](register-matrix.md)
- [hmi-concept.md](hmi-concept.md)
- [testing-strategy.md](testing-strategy.md)

## 5. Empfohlene Projektstruktur

Die Struktur soll modular gedacht werden. Der technische Grundkurs fuer V1 ist
in `docs/v1-decisions.md` verbindlich festgezogen.

Empfohlene Zielstruktur:

```text
docs/
src/
  honeypot/
    config_core/
    asset_domain/
    plant_sim/
    event_core/
    storage/
    rule_engine/
    protocol_modbus/
    hmi_web/
    exporter_sdk/
    exporter_runner/
tests/
  unit/
  contract/
  integration/
  scenarios/
  e2e/
  realism/
tools/
fixtures/
```

Wichtige Regel:
- Die Ordner trennen Verantwortung.
- Die Laufzeit darf trotzdem ein modularer Monolith bleiben.

## 6. Vorbedingungen vor dem ersten Code

Diese Entscheidungen sollten vor Implementierungsstart bewusst getroffen werden.

### 6.1 Technischer Grundkurs

Fuer V1 festgelegt:

- Hauptsprache: `Python 3.12`
- Paket- und Startwerkzeug: `uv`
- Web-Stack: `FastAPI` plus serverseitige `Jinja2`-Templates
- Modbus-Stack: `pymodbus`
- lokales Persistenzformat: `SQLite` im `WAL`-Modus
- Teststack: `pytest`, `pytest-asyncio`, `httpx`, `Playwright`
- lokale Startmethode: `uv sync --dev` und `uv run python -m honeypot.main`

### 6.2 Festgezogene Fachschalter

Vor Coding fuer V1 festgezogen:

- `Tracker` standardmaessig deaktiviert
- `FC04` bleibt in der V1-Default-Konfiguration deaktiviert
- Exporter laufen in V1 im selben Prozess ueber entkoppelte
  Outbox-/Runner-Logik
- `ENABLE_SERVICE_LOGIN` ist in der V1-Default-Konfiguration aktiviert

### 6.3 Sicherheitsvorgabe

Vor Implementierung einer oeffentlichen Exponierung festlegen:

- Laborbetrieb zuerst
- kein echter Egress
- keine echten Secrets
- keine echten Betreiberdaten

## 7. Phasenuebersicht

Die empfohlene Reihenfolge fuer V1:

1. Phase A: Grundgeruest und Testharness
2. Phase B: Fachmodell und Simulationskern
3. Phase C: Event-Core, Storage und Outbox
4. Phase D: Read-only Modbus Vertical Slice
5. Phase E: Vollstaendige Registermatrix und Write-Pfade
6. Phase F: Read-only HMI Vertical Slice
7. Phase G: HMI-Servicepfade und Bedienhandlungen
8. Phase H: Rule Engine, Alerts und Exporter-SDK
9. Phase I: Hardening, Realismus und Release-Gates

## 8. Phase A: Grundgeruest und Testharness

### 8.1 Ziel

Ein minimales, sauberes Projektgeruest schaffen, in dem die Module spaeter
konsistent wachsen koennen.

### 8.2 Arbeitspakete

- Basisstruktur unter `src/`, `tests/`, `fixtures/`
- Konfigurationsladen mit generischen Defaults
- Basales Testharness fuer Unit- und Contract-Tests
- Fixture-System fuer Startzustaende
- Zeitabstraktion fuer deterministische Tests

### 8.3 Ergebnis

Noch kein glaubhafter Honeypot, aber:

- saubere Modulgrenzen
- startbare Testumgebung
- reproduzierbare Konfigurationsbasis

### 8.4 Exit-Kriterien

- Testframework laeuft
- Konfigurationsvalidierung vorhanden
- mindestens ein Fixture-Zustand ladbar
- Zeitquelle ist fuer Tests kontrollierbar

### 8.5 Aufwand

- `klein bis mittel`

## 9. Phase B: Fachmodell und Simulationskern

### 9.1 Ziel

Die Anlage intern modellieren, bevor externe Protokolle darauf zugreifen.

### 9.2 Arbeitspakete

- `asset_domain` fuer Site, PPC, Inverter-Bloecke, Wetter, Meter, Grid
- `plant_sim` fuer:
  - normale Erzeugung
  - Curtailment
  - Breaker offen
  - Kommunikationsverlust
- Alarmzustandslogik
- Zustandsqualitaet `good/estimated/stale/invalid`

### 9.3 Ergebnis

Ein interner Simulationskern, der ohne Modbus und HMI schon:

- Messwerte liefert
- Setpoints annimmt
- plausible Prozesswirkung erzeugt
- Alarmzustaende aendert

### 9.4 Exit-Kriterien

- Kern-Szenarien aus [domain-model.md](domain-model.md) als Tests vorhanden
- Parkleistung, Breaker und Kommunikationsverlust wirken unterschiedlich
- keine externen Protokolle notwendig, um Simulation zu pruefen

### 9.5 Aufwand

- `mittel`

## 10. Phase C: Event-Core, Storage und Outbox

### 10.1 Ziel

Den Beobachtungskern schaffen, bevor die Anlage nach aussen spricht.

### 10.2 Arbeitspakete

- Eventschema implementieren
- lokaler Eventstore
- `current_state`, `event_log`, `alert_log`, `outbox`
- JSONL-Archivpfad
- Basis fuer `correlation_id`
- minimale Rule-Engine-Schnittstelle

### 10.3 Ergebnis

Jede fachliche Aktion kann jetzt:

- in ein Event uebersetzt
- lokal persistiert
- fuer spaetere Alerts markiert

werden.

### 10.4 Exit-Kriterien

- Schema-Tests laufen
- Korrelationstests laufen
- Outbox-Eintrag kann erzeugt werden
- Schreibwirkung im Simulationskern erzeugt Eventspur

### 10.5 Sicherheitsrelevanter Hinweis

Diese Phase sollte **vor** HMI- oder Exporter-Komfortfunktionen abgeschlossen
sein. Sonst fehlen Euch spaeter die forensischen Leitplanken.

### 10.6 Aufwand

- `mittel`

## 11. Phase D: Read-only Modbus Vertical Slice

### 11.1 Ziel

Die erste glaubhafte OT-Sicht bereitstellen, aber noch ohne schreibende
Interaktion.

### 11.2 Arbeitspakete

- `protocol_modbus` mit TCP-Listener
- MBAP-Handling
- `FC03` fuer `Unit 1`
- Identitaetsblock
- wenige Kernregister:
  - Plant power
  - Breaker state
  - Alarm count
  - Communications health

### 11.3 Warum zuerst read-only

- weniger Fehlerflaeche
- schneller Abgleich gegen Registermatrix
- frueher Reconnaissance-Pfad fuer Tests

### 11.4 Exit-Kriterien

- `FC03` auf Kernregister funktioniert
- MBAP-Contract-Tests laufen
- unbekannte Bereiche liefern dokumentierte Fehler
- Eventsystem loggt Modbus-Lesezugriffe

### 11.5 Aufwand

- `mittel`

## 12. Phase E: Vollstaendige Registermatrix und Write-Pfade

### 12.1 Ziel

Aus dem Read-only-Slice eine interaktive, aber kontrollierte Modbus-Sicht
machen.

### 12.2 Arbeitspakete

- restliche Unit-IDs `11/12/13/21/31/41`
- optional `51`
- `FC06` und `FC16`
- `ro`, `rw-latched`, `rw-pulse`
- `reserved` Verhalten
- Exception-Codes gemaess Profil

### 12.3 Kritische Pfade

Zuerst implementieren:

- `active_power_limit_pct`
- `breaker_open_request`
- `breaker_close_request`
- `block_enable_request`
- `block_reset_request`

Danach:

- reactive power
- optionale Tracker-Pfade

### 12.4 Exit-Kriterien

- Registermatrix wird fuer alle aktiven Units eingehalten
- alle dokumentierten Schreibrechte sind testbar
- Prozesswirkung ist sichtbar
- Eventspur und Registerwirkung sind konsistent

### 12.5 Sicherheitsgate

Vor Freigabe dieser Phase muessen gelten:

- keine unkontrollierten write-all-Pfade
- keine stillen Schreibfehler
- keine widerspruechlichen Modbus-Exceptions

### 12.6 Aufwand

- `mittel bis gross`

## 13. Phase F: Read-only HMI Vertical Slice

### 13.1 Ziel

Die erste glaubhafte Web-HMI liefern, ohne gleich Service-Aktionen zu oeffnen.

### 13.2 Arbeitspakete

- Seitenlayout
- `overview`
- `single-line`
- `inverters`
- `weather`
- `meter`
- `alarms`
- `trends`

### 13.3 Schwerpunkt

Die HMI muss in dieser Phase schon:

- dieselbe Wahrheit wie Modbus zeigen
- keine Framework-Spuren tragen
- kontrolliert mit `stale/invalid` Daten umgehen

### 13.4 Exit-Kriterien

- alle dokumentierten Seiten liefern `200`
- `overview` und Registerwerte stimmen ueberein
- keine Default-Fehlerseiten sichtbar
- stale/invalid-Zustaende sind markiert

### 13.5 Aufwand

- `mittel`

## 14. Phase G: HMI-Servicepfade und Bedienhandlungen

### 14.1 Ziel

Die Web-HMI von beobachtend zu begrenzt interaktiv erweitern.

### 14.2 Arbeitspakete

- `/service/login`
- Session-Grundlogik
- `401/403/404` Verhalten
- schreibende Bedienfelder fuer erlaubte Aktionen

### 14.3 Zuerst erlauben

- aktive Leistungsbegrenzung
- Breaker open/close
- Block enable/reset

### 14.4 Spaeter oder optional

- reactive power target
- Tracker-Bedienung

### 14.5 Exit-Kriterien

- Login-Fehler sind ruhig und konsistent
- erlaubte Bedienungen wirken in Fachmodell, HMI und Modbus gleich
- Session-Auslauf erzeugt keine inkonsistenten Zwischenzustaende

### 14.6 Sicherheitsgate

Vor Abschluss dieser Phase:

- keine Datei-Uploads
- keine generischen Debug- oder Service-Pfade
- keine Bedienfelder ohne echte serverseitige Wirkung

### 14.7 Aufwand

- `mittel`

## 15. Phase H: Rule Engine, Alerts und Exporter-SDK

### 15.1 Ziel

Von blosser Beobachtung zu bewertbarer Sicherheits- und Betriebsreaktion
kommen.

### 15.2 Arbeitspakete

- Basis-Regeln fuer Alerts
- Outbox-Worker oder Runner
- `exporter_sdk`
- lokaler Test-Exporter
- erster echter technischer Kanal:
  - `webhook`

Optional spaeter:

- `smtp`
- `telegram`

### 15.3 Startmenge fuer Rules

Empfohlene erste Regeln:

- wiederholte Login-Fehler
- erfolgreiche Setpoint-Aenderung
- Breaker open
- Kommunikationsverlust eines Inverter-Blocks
- mehrstufige Sequenz aus Bedienung plus Alarmfolge

### 15.4 Exit-Kriterien

- Alerts werden korrekt abgeleitet
- Outbox fuellt sich korrekt
- Exportfehler blockieren den Honeypot nicht
- Retry mit Backoff funktioniert

### 15.5 Sicherheitsgate

Vor Aktivierung echter Exportziele:

- keine echten Secrets im Repo
- lokale oder emulierte Ziele im Test
- Ausfallpfade getestet

### 15.6 Aufwand

- `mittel`

## 16. Phase I: Hardening, Realismus und Release-Gates

### 16.1 Ziel

Die Anlage gegen triviale Enttarnung absichern und fuer kontrollierten
Forschungseinsatz vorbereiten.

### 16.2 Arbeitspakete

- Anti-Fingerprint-Suite
- Timing- und Polling-Tests
- Soak-Tests
- Header- und Fehlerseiten-Hardening
- Start-/Reset-Mechanismus
- Betriebsprofile fuer Laborbetrieb

### 16.3 Besonderer Fokus

- keine Framework-Signaturen
- konsistente Fehlercodes
- keine zweite Wahrheit zwischen HMI und Modbus
- keine sichtbaren Exporter-Ausfaelle
- kontrollierte Session-Zeit und Antwortmuster

### 16.4 Exit-Kriterien

- Anti-Fingerprint-Basissuite gruen
- V1-Test-Gates aus
  [testing-strategy.md](testing-strategy.md)
  erfuellt
- keine kritischen offenen Sicherheitsluecken fuer den Laborbetrieb

### 16.5 Aufwand

- `mittel bis gross`

## 17. Empfohlene erste Vertikalscheibe

Falls die Deckscrew moeglichst frueh einen sichtbaren Prototyp haben will,
empfehle ich diese erste End-to-End-Scheibe:

1. `site` + `power_plant_controller`
2. `plant_power`, `breaker_state`, `active_power_limit_pct`
3. `FC03` und `FC06`
4. `overview`-Seite
5. Eventstore + `correlation_id`
6. ein Curtailment-Szenario als Test

Warum diese Scheibe gut ist:

- klein
- sichtbar
- fachlich plausibel
- sofort testbar
- gute Basis fuer alle spaeteren Module

## 18. Empfohlene Reihenfolge fuer einen Solo-Builder

Wenn eine einzelne Person oder ein kleines Team baut, sollte die Reihenfolge
so aussehen:

1. Phase A
2. Phase B
3. Phase C
4. erste Vertikalscheibe
5. Phase E
6. Phase F
7. Phase G
8. Phase H
9. Phase I

Der Fehler waere:

- zuerst viel UI
- dann viel Protokoll
- Logging und Tests spaet

Das fuehrt fast sicher zu Reibung und Fingerprints.

## 19. Was der Kapitaen als Nicht-Programmierer gut pruefen kann

Diese Punkte koennen auch ohne tiefen Codeblick aktiv geprueft werden:

- zeigen HMI und Modbus denselben Zustand?
- fuehrt ein Curtailment sichtbar zu sinkender Leistung?
- fuehrt `breaker open` sichtbar zu Exportverlust?
- bleiben Fehlermeldungen ruhig und technisch glaubhaft?
- taucht jede Aktion spaeter in den Logs wieder auf?
- bleiben Firmen- und Ortsdetails generisch?

Das ist wichtig, weil Glaubwuerdigkeit nicht nur im Code steckt, sondern in der
gesamten Wirkung.

## 20. Sicherheitsgates vor Internet-Exponierung

Die Anlage sollte **nicht** exponiert werden, bevor diese Gates erfuellt sind:

- Modbus- und HMI-Fehlerpfade getestet
- Logging-Completeness fuer Kernpfade nachgewiesen
- Exporter-Ausfallpfade getestet
- Debug- und Entwicklungspfade deaktiviert
- keine echten Secrets oder Produktdaten
- Egress-Kontrolle aktiv
- schneller Reset moeglich

Ich empfehle ausdruecklich, diese Gates **vor** jeder echten Exponierung jetzt
als verbindlich zu behandeln. Spaeter nachzuziehen ist deutlich teurer und
risikoreicher.

## 21. Deliverables am Ende von V1

Am Ende von V1 sollten mindestens vorliegen:

- startbare modulare Anwendung
- dokumentierte `.env.example` oder aequivalente Konfiguration
- Modbus/TCP mit dokumentierter Registermatrix
- kleine HMI mit Login- und Service-Sicht
- lokaler Eventstore und JSONL-Archiv
- Rule Engine mit erster Alert-Menge
- Exporter-SDK plus mindestens ein lokaler Test-Exporter und ein Webhook-Exporter
- gruen laufende Kern- und Anti-Fingerprint-Tests

## 22. Offene Punkte fuer spaetere Planung

Diese Punkte sind bewusst noch nicht fest:

- Containerisierung oder Prozessmanager fuer V1
- Nightly- vs PR-Teststrategie
- Rolloutmodell fuer mehrere Honeypot-Instanzen

## 23. Kurzfazit

Die Roadmap setzt den richtigen Kurs fuer einen modularen, glaubhaften und
testbaren Honeypot: erst Fachlogik und Beobachtbarkeit, dann Protokoll und HMI,
dann Alerts und Hardening. Wer die Reihenfolge umdreht, baut schnell eine
falsche Kulisse. Wer sie einhaelt, bekommt eine Anlage, die klein wirkt, aber
technisch sauber aufgezogen ist.
