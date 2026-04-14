# Protokollprofil: Standardnahe Aussenwirkung fuer den Solarpark-Honeypot

## 1. Zweck dieses Dokuments

Dieses Dokument beschreibt die externe Protokolloberflaeche des Honeypots.
Es legt fest, welche Protokolle in V1 sichtbar sind, wie sie fachlich auf das
Domaenenmodell abgebildet werden und wie sich das System bei gueltigen,
ungueltigen oder grenzwertigen Anfragen verhalten soll.

Wichtige Ziele:
- schnelle Orientierung fuer Angreifer anhand gaengiger OT-Muster
- konsistente, standardnahe Antworten
- klare Trennung zwischen Fachlogik und Protokollabbildung
- testbares Fehler- und Zeitverhalten

## 2. Normative Ausrichtung

Die V1-Aussenwirkung soll sich an zwei etablierten Standardfamilien
orientieren:

1. `Modbus` als allgemein verbreitetes industrielles Anwendungsprotokoll
2. `SunSpec Modbus` als DER-/PV-nahe Modellfamilie fuer Inverter, Meter,
   Tracker und weitere Balance-of-System-Komponenten

Fuer dieses Projekt bedeutet das:
- Wir bauen **keine zertifizierte Vollimplementation** aller SunSpec-Modelle.
- Wir bauen eine **SunSpec-nahe, glaubhafte Teilmenge** fuer einen Solarpark.
- Die Teilmenge muss in Struktur, Namensgebung, Lesbarkeit und Fehlerverhalten
  wie eine plausible industrielle Implementierung wirken.

## 3. Quellenbasis fuer das Profil

Dieses Dokument stuetzt sich konzeptionell auf:

- die `Modbus Organization`, die Modbus als Layer-7-Protokoll mit
  standardisierten Befehlen, Datenadressierung und Datenformat beschreibt
- die `SunSpec Alliance`, die SunSpec Modbus als offenen Standard fuer
  Inverter, Speicher, Meter, Tracker und andere DER-Komponenten beschreibt
- die `SunSpec Specifications`, die Device- und DER-Information-Modelle,
  Modellreferenzen sowie Konformitaetstests fuer SunSpec Modbus auffuehren

Wichtige Schlussfolgerung fuer unser Projekt:
- `Modbus/TCP` ist der richtige OT-Anker fuer V1
- `SunSpec` gibt die fachliche Form fuer PV-/DER-nahe Daten vor
- `IEEE 2030.5`, `IEEE 1815` oder `OPC UA` bleiben Erweiterungspfade, aber
  nicht Teil des V1-Kerns

## 4. V1-Protokollumfang

### 4.1 In V1 enthalten

- `Modbus/TCP` als primaere OT-Schnittstelle
- `HTTP` als HMI-Zugang

### 4.2 Nicht Teil von V1

- `OPC UA`
- `IEEE 2030.5`
- `IEEE 1815 / DNP3`
- `IEC 61850`
- proprietaere OEM-Protokolle

### 4.3 Begruendung

V1 braucht eine glaubhafte, leicht erkennbare OT-Oberflaeche mit niedriger
Komplexitaet. Diese Rolle erfuellt `Modbus/TCP` am besten. Eine zusaetzliche
HMI ueber `HTTP` erhoeht den Reiz fuer Angreifer und schafft einen zweiten
Interaktionspfad.

Weitere Protokolle waeren fachlich moeglich, wuerden aber in V1:
- den Testaufwand stark erhoehen
- mehr verratende Randfehler produzieren
- die Pflege des Honeypots unnoetig erschweren

## 5. Grundsaetze des Protokollprofils

1. **Ein Fachmodell, mehrere Oberflaechen**
   - Modbus und HMI zeigen auf dasselbe Domaenenmodell.

2. **Standardnahe Antworten vor Vollstaendigkeit**
   - Lieber wenige Dinge glaubhaft als viele Dinge halbgar.

3. **Keine verratenden Framework-Spuren**
   - Keine Tracebacks, Default-Banner oder inkonsistenten Fehlerpfade.

4. **Fehler sind Teil des Profils**
   - Fehlerantworten muessen bewusst modelliert und getestet werden.

5. **Zeitverhalten ist Teil des Profils**
   - Nicht nur der Inhalt, auch die Antwortform muss plausibel sein.

6. **Sprache bleibt an der richtigen Grenze**
   - Nur sichtbare HMI-Texte duerfen pro Deployment lokalisiert werden;
     Modbus und Protokollsemantik bleiben sprachneutral.

## 6. Modbus/TCP-Profil fuer V1

### 6.1 Rolle im System

`Modbus/TCP` ist die primaere OT-Sicht des Honeypots. Sie dient dazu:
- Messwerte lesbar zu machen
- begrenzte Steuerhandlungen zuzulassen
- Reconnaissance und Manipulationsversuche standardnah beobachtbar zu machen

### 6.2 Transportannahmen

V1 verhaelt sich als `Modbus/TCP`-Server mit:
- einem stabilen TCP-Endpunkt
- korrektem MBAP-Header-Verhalten
- korrekt rueckgespiegelter Transaction ID
- `Protocol Identifier = 0`
- konsistenter Laengenangabe

Wichtige Regeln:
- Sessionlos auf Protokollebene, aber intern korrelierbar
- mehrere Verbindungen moeglich
- konkurrierende Schreibzugriffe muessen intern serialisiert oder klar
  geordnet werden, damit der Anlagenzustand konsistent bleibt

### 6.3 Port-Sicht

Der Standardport ist:
- `502/tcp`

Das Projekt soll spaeter konfigurierbar erlauben:
- alternativen Port fuer Laborbetrieb
- weiterhin dieselbe fachliche Protokollwirkung

Wichtige Sicherheitsvorgabe:
- Port-Aenderung fuer den Betrieb ist eine Deployment-Entscheidung, keine
  fachliche Aenderung des Profils

## 7. Logische Geraete- und Unit-ID-Sicht

Damit sich Angreifer schneller zurechtfinden, empfehle ich fuer V1 eine
gateway-aehnliche Darstellung mit mehreren logischen Geraeten hinter einem
TCP-Endpunkt.

### 7.1 Empfohlene Unit-ID-Belegung

- `1` -> `site` / `power_plant_controller`
- `11` -> `inverter_block_01`
- `12` -> `inverter_block_02`
- `13` -> `inverter_block_03`
- `21` -> `weather_station`
- `31` -> `revenue_meter`
- `41` -> `grid_interconnect`
- `51` -> `tracker_controller` falls aktiviert

### 7.2 Warum diese Form sinnvoll ist

- wirkt fuer Angreifer wie ein typisches aggregierendes OT-Gateway
- erlaubt klares fachliches Scannen ueber bekannte Modbus-Muster
- reduziert die Zahl der benoetigten IPs oder Dienste in V1
- haelt trotzdem mehrere Assets sichtbar

### 7.3 Verhalten bei unbekannten Unit-IDs

Empfohlener V1-Kurs:
- nur die definierten Unit-IDs liefern fachliche Daten
- unbekannte Unit-IDs fuehren zu kontrollierter Nicht-Unterstuetzung

Die exakte technische Behandlung soll spaeter in Tests festgezurrt werden.
Wichtig ist nur:
- konsistent
- keine internen Fehler
- kein zufaellig wechselndes Verhalten

## 8. Datenmodell-Sicht auf Modbus

### 8.1 SunSpec-nahe Struktur statt OEM-Eigenlogik

Die Registersicht soll wie ein DER-/PV-orientiertes Datenmodell wirken:
- Identitaet und Geraeteinformationen
- Betriebsstatus und Messwerte
- Setpoints und Steuerwerte
- Alarm- und Zustandsinformationen

### 8.2 Keine direkte OEM-Nachbildung

Nicht gewuenscht sind:
- reale OEM-Modellbezeichnungen
- echte OEM-Alarmnummern
- echte Produktlogos oder Geraeteserien
- 1:1 uebernommene proprietaere Registerkarten

Gewuenscht sind dagegen:
- SunSpec-nahe, generische Modellstruktur
- konsistente Feldnamen und Einheiten
- plausible Registergruppen je Asset-Typ

## 9. Registerkonventionen

### 9.1 Menschliche und interne Adresssicht

Die Dokumentation fuer Menschen darf die klassische Modbus-Sicht verwenden:
- `0xxxx` fuer Coils
- `1xxxx` fuer Discrete Inputs
- `3xxxx` fuer Input Registers
- `4xxxx` fuer Holding Registers

Intern soll die Implementierung trotzdem mit klaren, nullbasierten Offsets
arbeiten. Das ist wichtig, weil moderne Modbus-Systeme haeufig eine Differenz
zwischen menschlicher Mapping-Sicht und internem Offset besitzen.

### 9.2 V1-Entscheidung fuer Registertypen

V1 soll sich primaer auf Registerdaten stuetzen.

Empfohlener Kurs:
- `Holding Registers (4xxxx)` als primaere Lese- und Schreibflaeche
- `Input Registers (3xxxx)` nur optional fuer gezielte read-only Spiegelungen
- `Coils` und `Discrete Inputs` in V1 entweder gar nicht oder nur sehr sparsam

Warum:
- SunSpec-nahe DER-Modelle sind stark registerorientiert
- Register bieten genug Tiefe fuer Telemetrie und Setpoints
- zu viele Bit-Flaechen vergroessern Testaufwand und Inkonsistenzen

### 9.3 Registerbloecke pro logischem Geraet

Fuer jedes logische Geraet wird dieselbe grobe Struktur empfohlen:

- `40001-40049` -> Identitaet und Modellinformationen
- `40100-40199` -> Messwerte und Betriebsstatus
- `40200-40249` -> Setpoints und steuerbare Werte
- `40300-40349` -> Alarm- und Diagnosewerte

Diese Zahlen sind als **Profilkonvention fuer V1** zu verstehen, nicht als
fertige Endtabelle. Sie geben der Deckscrew aber einen sauberen Raster fuer die
spaetere konkrete Registermatrix.

## 10. Datentypen und Werteabbildung

### 10.1 Grunddatentyp

Der Basisdatentyp von Modbus bleibt:
- `16-bit register`

### 10.2 Mehrwortwerte

Wo fachlich sinnvoll, duerfen Werte ueber mehrere Register abgebildet werden,
zum Beispiel fuer:
- Leistung
- Energiezaehler
- Frequenz
- Spannungen mit hoeherer Aufloesung

Wichtige Regel:
- Wortreihenfolge und Skalierung muessen im Projekt **einheitlich** bleiben
- dieselbe fachliche Groesse darf nicht je nach Asset willkuerlich anders
  codiert werden

### 10.3 Skalierungsmodell

Fuer V1 empfehle ich eine SunSpec-nahe Denkweise:
- wo sinnvoll ganzzahlige Basiswerte
- dazu klar definierte Skalierung oder feste Aufloesung

Das reduziert:
- Floating-Point-Wirrwarr
- inkonsistente Rundungen
- leicht erkennbare Implementierungsfehler

### 10.4 Strings und Kennungen

Strings sollen:
- kurz
- ASCII-kompatibel
- fest und konsistent formatiert

sein.

Nicht gewuenscht:
- wechselnde Platzhaltertexte
- Framework-Reste
- Testdaten mit Entwicklercharakter
- sprachabhaengige Registerinhalte ohne klaren Grund

## 11. Fachliche Registerklassen je Asset

### 11.1 `site` / `power_plant_controller`

Typische Datenklassen:
- Parkstatus
- globale Leistungsbegrenzung
- Blindleistungsziel
- Betriebsmodus
- Anzahl aktiver Alarme

Typische schreibbare Punkte:
- `active_power_limit_pct`
- `reactive_power_target`
- `plant_mode_request`

### 11.2 `inverter_block`

Typische Datenklassen:
- Blockleistung
- AC-/DC-nahe Messwerte
- Verfuegbarkeit
- Kommunikationsstatus
- blockbezogene Alarme

Typische schreibbare Punkte:
- `block_enable_request`
- `block_power_limit_pct`
- `block_reset_request`

### 11.3 `weather_station`

Typische Datenklassen:
- Einstrahlung
- Modultemperatur
- Umgebungstemperatur
- Windgeschwindigkeit

Schreibbarkeit:
- in V1 read-only

### 11.4 `revenue_meter`

Typische Datenklassen:
- Exportleistung
- Exportenergie
- Netzspannung
- Netzfrequenz
- Leistungsfaktor

Schreibbarkeit:
- in V1 read-only

### 11.5 `grid_interconnect`

Typische Datenklassen:
- Breaker-Zustand
- Exportpfad-Verfuegbarkeit
- netzseitige Freigabe in einfacher Form

Typische schreibbare Punkte:
- `breaker_open_request`
- `breaker_close_request`

### 11.6 `tracker_controller`

Der `tracker_controller` bleibt in der V1-Default-Konfiguration deaktiviert
und ist nur fuer bewusst erweiterte Deployments vorgesehen.

Typische Datenklassen:
- Tracking-Status
- Stow-Status
- Kommunikationsstatus

Typische schreibbare Punkte:
- `tracking_enable_request`
- `stow_request`

## 12. Unterstuetzte Modbus-Funktionscodes in V1

### 12.1 Pflichtunterstuetzung

V1 sollte mindestens diese Funktionscodes unterstuetzen:

- `03` -> Read Holding Registers
- `06` -> Write Single Register
- `16` -> Write Multiple Registers

Diese drei Codes bilden den Kern fuer:
- Telemetrie
- Setpoint-Aenderungen
- glaubhafte Steuerpfade

### 12.2 Optionale Unterstuetzung ausserhalb der V1-Default-Konfiguration

Optional, aber nicht Teil der V1-Default-Konfiguration:

- `04` -> Read Input Registers

Falls `04` implementiert wird, dann nur:
- konsistent
- klar dokumentiert
- mit sauberem read-only Verhalten

### 12.3 Nicht vorgesehene Funktionscodes in V1

Nicht Teil von V1:
- `01`
- `02`
- `05`
- `15`
- Diagnose- und Spezialfunktionen

Sie koennen spaeter ergaenzt werden, aber nur wenn:
- ein echter fachlicher Mehrwert entsteht
- das Fehlerprofil weiterhin konsistent bleibt

## 13. Exception- und Fehlerverhalten auf Modbus-Ebene

Fehlerantworten muessen standardnah und ruhig bleiben.

### 13.1 Empfohlene Exceptions fuer V1

- `01 Illegal Function`
  - bei nicht unterstuetztem Funktionscode
- `02 Illegal Data Address`
  - bei unbekanntem oder ungueltigem Registerbereich
- `03 Illegal Data Value`
  - bei formal gueltiger Adresse, aber fachlich ungueltigem Wert
- `06 Slave Device Busy`
  - sparsam und nur fuer bewusst modellierte Uebergangssituationen

### 13.2 Was vermieden werden soll

- generische interne Fehler ohne Modbus-Sinn
- zufaellig wechselnde Exceptions
- harte Verbindungsabbrueche bei normalen Fehlanfragen
- Debug-Hinweise oder Framework-Texte ausserhalb des Protokolls

### 13.3 Fachliche Ablehnung

Wird ein Setpoint fachlich abgelehnt, dann soll:
- die Ablehnung konsistent ueber Modbus sichtbar sein
- die Eventspur dieselbe Entscheidung enthalten
- die HMI denselben Zustand spaeter plausibel widerspiegeln

## 14. Schreibrechte und Sichtbarkeit

Nicht jede sichtbare Variable soll schreibbar sein.

### 14.1 Read-only in V1

Empfohlen read-only:
- Wetterdaten
- Revenue-Meter-Werte
- berechnete Site-Aggregate
- diagnostische Metadaten

### 14.2 Schreibbar in V1

Empfohlen schreibbar:
- globale Leistungsbegrenzung
- Blindleistungsziel
- Betriebsmodus-Anfrage
- blockbezogene Aktivierungs- oder Reset-Anfragen
- Breaker-Bedienhandlung
- Tracker-Stow-Anfrage falls Tracker aktiv

### 14.3 Nur scheinbar direkt steuerbar

Einige Punkte duerfen zwar als Steuerpfad sichtbar sein, ihre Wirkung kann aber
fachlich begrenzt oder indirekt modelliert werden.

Das ist sinnvoll fuer:
- glaubhafte Interaktion
- kontrollierte Wirkung
- geringeres Risiko unplausibler Sofortreaktionen

## 15. Zeit- und Antwortverhalten auf Modbus-Ebene

Zeitverhalten ist Teil der Glaubwuerdigkeit.

### 15.1 Grundregeln

- Antworten sollen schnell, aber nicht unnatuerlich perfekt sein
- leichte Jitter sind erlaubt
- laengere Operationen duerfen kurzfristige Uebergangszustaende erzeugen
- dieselbe Anfrage darf nicht bei jedem Polling millisekundengenau identisch
  wirken, wenn sich im Prozess etwas aendert

### 15.2 Schreibvorgaenge

Ein Schreibzugriff darf:
- sofort bestaetigt werden
- seine Prozesswirkung aber erst kurz danach sichtbar machen

Beispiele:
- Curtailment-Wert aendert sich sofort
- Parkleistung faellt erst in der naechsten Simulationsrunde

### 15.3 Busy-Zustaende

`Slave Device Busy` soll kein Standardfehler fuer alles sein. Er darf nur
auftauchen, wenn:
- eine fachliche Uebergangssituation modelliert wird
- diese Situation spaeter wieder aufgeloest wird

## 16. HTTP-Profil fuer die HMI

Die HMI ist keine OEM-Kopie, aber eine glaubhafte Betriebsoberflaeche.

### 16.1 Zweck

Die HMI dient dazu:
- den Anlagenzustand sichtbar zu machen
- Alarme und Trends anzuzeigen
- begrenzte Bedienpfade anzubieten
- einen zweiten, fuer Angreifer attraktiven Interaktionskanal zu schaffen

### 16.2 Seiten fuer V1

Empfohlen:
- `/`
- `/overview`
- `/single-line`
- `/inverters`
- `/weather`
- `/meter`
- `/alarms`
- `/trends`
- `/service/login`

### 16.3 HTTP-Verhalten

Wichtige Regeln:
- konsistente Statuscodes
- keine Debug-Header
- keine Standard-Serverfehlerseiten
- klare Trennung zwischen nicht vorhanden, nicht erlaubt und nicht
  authentifiziert
- kein sichtbarer Sprachumschalter in der HMI

Empfohlene Semantik:
- `200` fuer normale Seiten
- `401` fuer nicht authentifizierte Service-Bereiche
- `403` fuer bewusst gesperrte Bereiche
- `404` fuer wirklich nicht vorhandene Routen

### 16.4 UI-Datenherkunft

Die HMI darf keine eigenen Sonderwahrheiten produzieren. Sie liest:
- dieselben Messwerte
- dieselben Alarmzustaende
- dieselben Setpoint-Staende

aus derselben Fachlogik wie Modbus.

### 16.5 Sprachregel fuer die HMI

Die HTTP-HMI darf pro Deployment in einer Angreifer-Sprache ausgeliefert
werden. Das gilt nur fuer sichtbare UI-Texte.

Wichtige Regeln:
- interne Codes, Register und Protokollfelder bleiben sprachneutral
- neue Locale-Pakete wie `uk` muessen spaeter addierbar sein
- gemischte Sprachfragmente auf einer Seite sind zu vermeiden
- Admin-Sicht und Logs bleiben ausserhalb dieses Profils deutsch

## 17. Beziehung zwischen HMI und Modbus

Die beiden Protokollpfade muessen fachlich zusammenpassen.

Wenn ein Setpoint ueber Modbus gesetzt wird, dann soll:
- die HMI ihn spaeter anzeigen
- das Eventsystem beide Beobachtungen korrelieren
- der Prozesszustand dieselbe Wirkung zeigen

Wenn ein Bedienvorgang ueber die HMI stattfindet, dann soll:
- die Modbus-Sicht den neuen Zustand plausibel wiederfinden lassen

Was nicht passieren darf:
- HMI zeigt Zustand A, Modbus zeigt dauerhaft Zustand B
- Alarmliste und Registersicht widersprechen sich
- nur ein Protokollpfad kennt Fehler oder Grenzwerte

## 18. Logging-Anforderungen pro Protokollzugriff

Jeder Protokollzugriff soll zusaetzlich zum allgemeinen Event-Schema folgende
Felder sauber tragen, soweit vorhanden:

### 18.1 Modbus-spezifisch

- `unit_id`
- `function_code`
- `register_start`
- `register_count`
- `exception_code`
- `value_encoding`

### 18.2 HTTP-spezifisch

- `http_method`
- `http_path`
- `http_status`
- `session_id`
- `auth_result`

### 18.3 Fachbezug

Soweit moeglich:
- `asset_id`
- `setpoint_name`
- `previous_value`
- `requested_value`
- `resulting_state`

## 19. Anti-Fingerprint-Regeln

Dieses Protokollprofil ist nur dann brauchbar, wenn es nicht durch banale
Inkonsistenzen auffliegt.

### 19.1 Vermeiden

- inkonsistente Registerbreiten
- wechselnde Wortreihenfolge
- zufaellige Leerrueckgaben
- unplausible Ausnahmeantworten
- HTTP-Fehlerseiten mit Framework-Signatur
- Entwicklungspfadnamen wie `/debug`, `/swagger`, `/docs` ohne klare Absicht

### 19.2 Erzwingen

- stabile Registerzuordnung
- konsistente Statuscodes
- konsistente Exception-Codes
- reproduzierbare, aber nicht mechanisch starre Prozessfolgen
- keine gemischtsprachigen HMI-Fehlerbilder innerhalb eines Deployments

## 20. Teststrategie fuer das Protokollprofil

Das Protokollprofil braucht eine eigene Testmatrix.

### 20.1 Contract-Tests fuer Modbus

- korrekter MBAP-Header
- korrekte Echo-Rueckgabe der Transaction ID
- korrekte Funktionscode-Antworten
- korrekte Exception-Codes bei Fehlerfaellen
- konsistente Registerbreiten und Wortreihenfolge

### 20.2 Fachtests fuer Registerwirkung

- Curtailment-Aenderung senkt Leistung
- Breaker-Open beeinflusst Exportpfad
- Kommunikationsverlust markiert Wertequalitaet
- read-only Punkte bleiben read-only

### 20.3 HTTP-/HMI-Tests

- Seiten liefern korrekte Statuscodes
- Login-Pfade liefern konsistente Antworten
- keine Tracebacks
- keine inkonsistenten Redirects

### 20.4 Anti-Fingerprint-Tests

- wiederholte ungueltige Registeranfragen bleiben konsistent
- gleiche Fehler fuehren zu gleichem Exception-Muster
- HMI und Modbus widersprechen sich nicht
- Export- oder Alerting-Fehler veraendern die Protokollantwort nicht sichtbar

## 21. Erweiterungspfad nach V1

Das Profil soll spaeter erweiterbar bleiben.

Moegliche V2-/V3-Pfade:
- read-only `OPC UA` fuer northbound Sicht
- zusaetzliche `Modbus`-Funktioncodes
- feinere SunSpec-Modellabdeckung
- optional `IEEE 2030.5` fuer andere DER-Kommunikationssichten

Wichtige Regel:
- Neue Protokolle duerfen nie ein zweites Fachmodell einfuehren.

## 22. Sicherheitsgrenzen

Auch im Protokollprofil gilt:
- keine echte Fernsteuerung externer Systeme
- keine Shell
- keine Debug-Schnittstellen
- keine realen OEM-Secrets
- keine unkontrollierten Dateidownloads oder Uploadpfade

Besonders wichtig:
- Protokollstandardnaehe darf nicht in gefaehrliche Betriebsnaehe kippen
- glaubhafte Interaktion ja, reale Steuerbarkeit nein

## 23. Offene Punkte fuer die naechste Runde

- exakte Registermatrix je Unit-ID
- genaue Wortreihenfolge fuer Mehrregisterwerte
- konkrete HMI-Login-Semantik

## 24. Kurzfazit

V1 sollte sich nach aussen als kleiner, aggregierter PV-/DER-Knoten mit
`Modbus/TCP` und schlanker `HTTP`-HMI zeigen. Die Modbus-Sicht muss
SunSpec-nah, registerorientiert und konsistent sein; die HMI muss denselben
fachlichen Zustand spiegeln. Genau diese Konsistenz entscheidet spaeter, ob
der Honeypot glaubhaft wirkt oder durch schlampige Protokollraender kentert.

## 25. Referenzen

- [Modbus Organization: An Introduction to Modbus](https://www.modbus.org/introduction-to-modbus)
- [SunSpec Alliance: SunSpec Modbus](https://sunspec.org/sunspec-modbus/)
- [SunSpec Alliance: Specifications](https://sunspec.org/specifications/)
