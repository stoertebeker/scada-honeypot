# HMI-Konzept V1: Bedien- und Beobachtungsoberflaeche fuer den Solarpark-Honeypot

## 1. Zweck dieses Dokuments

Dieses Dokument beschreibt die fachliche und funktionale Konzeption der
Web-HMI des Honeypots. Es legt fest:

- welche Seiten sichtbar sind
- welche Informationen pro Seite dargestellt werden
- welche Bedienpfade existieren
- wie Login- und Servicebereiche wirken
- wie Fehler, Leerzustaende und Stoerungen angezeigt werden
- welche HMI-Ereignisse spaeter geloggt und getestet werden muessen

Die HMI ist fuer V1 ein bewusst kleiner, aber glaubhafter zweiter
Interaktionspfad neben `Modbus/TCP`.

## 2. Ziele der HMI

Die HMI soll gleichzeitig mehrere Aufgaben erfuellen:

1. Sie soll einem Angreifer eine klar lesbare Betriebsoberflaeche bieten.
2. Sie soll dieselbe Fachlogik wie die Modbus-Sicht widerspiegeln.
3. Sie soll kontrollierte Bedienhandlungen erlauben, ohne reale Steuernaehe zu
   erzeugen.
4. Sie soll keine verratenden Web- oder Framework-Spuren tragen.
5. Sie soll robuste Logging- und Testpunkte liefern.
6. Sie soll in der angreiferzugewandten Sicht pro Deployment lokalisierbar
   bleiben.

## 3. HMI-Leitprinzipien

### 3.1 Generisch statt OEM-Kopie

Die HMI soll wie eine einfache industrielle Betriebsoberflaeche wirken, aber
nicht wie eine direkte Nachbildung eines echten Herstellers.

Das bedeutet:
- keine echten Logos
- keine echten Produktnamen
- keine realen OEM-Farb- oder Komponentenbibliotheken
- keine kopierten Alarmcodes oder Textbausteine realer Produkte

### 3.2 Eine Wahrheit fuer alle Pfade

Die HMI zeigt keine Sonderwelt. Sie liest dieselben:
- Messwerte
- Setpoints
- Alarmzustaende
- Asset-Namen

wie Modbus und das Eventsystem.

### 3.3 Uebersichtlich statt ueberladen

V1 soll sich auf wenige, klar verstaendliche Seiten beschraenken.

Zu viele Menues oder zu viele leere Unterseiten wuerden:
- unnoetig Scope erzeugen
- mehr Fehlerbilder produzieren
- den Honeypot leichter enttarnen

### 3.4 Fehlerverhalten ist Teil des Designs

Nicht nur erfolgreiche Seiten, sondern auch:
- nicht autorisierte Zugriffe
- gesperrte Bedienungen
- fehlende Daten
- Kommunikationsstoerungen

muessen bewusst gestaltet werden.

### 3.5 Sprache gehoert zur HMI, nicht zum Kern

Nur die angreiferzugewandte HMI ist lokalisierbar. Fachlogik, Modbus,
interne Event-Typen und Betreiberdiagnose bleiben sprachneutral oder deutsch.

Das bedeutet:
- sichtbare HMI-Texte kommen aus Locale-Paketen
- neue Sprachen wie `uk` muessen spaeter ohne Kernumbau ergaenzbar sein
- es gibt keinen sichtbaren Sprachumschalter in der HMI
- Admin-Sicht und Logs bleiben deutsch

Empfohlene Locale-Regel:
- Locale-Keys folgen `ll` oder `ll-RR`
- Beispiele: `en`, `uk`, `en-US`, `uk-UA`
- V1 bevorzugt Basissprachen wie `en` oder `uk`
- bei spaeteren Regionsvarianten faellt die HMI erst auf die Basissprache und
  dann auf `ATTACKER_UI_FALLBACK_LOCALE` zurueck

Empfohlene Ressourcenstruktur:
- Locale-Pakete liegen logisch unter `resources/locales/attacker-ui/`
- pro Locale genau eine Hauptdatei wie `en.json` oder `uk-UA.json`
- sichtbare Texte nutzen stabile Schluessel wie `nav.overview`,
  `page.alarms.title` oder `alarm.BREAKER_OPEN`
- Templates und Seiten tragen keine hartcodierten deutschen oder englischen
  Strings

## 4. Zielbild der HMI

Die HMI repraesentiert eine kleine Betriebsoberflaeche fuer einen einzelnen
Solarpark mit:

- zentraler Statusuebersicht
- einfacher Einliniensicht
- Blockuebersicht fuer Inverter
- Wetter- und Leistungsdarstellung
- Alarm- und Trendansichten
- kleinem Service-/Login-Bereich

Die HMI soll wie eine schlichte SCADA-/PPC-nahe Webansicht wirken:
- funktional
- leicht altmodisch
- sparsam modernisiert
- klar technisch

## 5. Informationsarchitektur

### 5.1 Hauptnavigation

Empfohlene Top-Level-Navigation:

- `Overview`
- `Single Line`
- `Inverters`
- `Weather`
- `Meter`
- `Alarms`
- `Trends`
- `Service`

### 5.2 Globale Layout-Bereiche

Jede Hauptseite sollte dieselbe Grundstruktur besitzen:

1. Kopfbereich
   - HMI-Titel
   - Site-Tag
   - Uhrzeit
   - Kommunikationsstatus
   - Login- oder Session-Hinweis

2. Hauptnavigation
   - feste Reihenfolge
   - klarer aktiver Zustand

3. Seiteninhalt
   - tabellarische und kartenartige Betriebsdaten

4. Alarm-/Statusleiste
   - sichtbare Anzahl aktiver Alarme
   - hoechste aktuelle Severity

5. Fussbereich
   - Version / Build-Tag generisch
   - keine Framework-Signaturen

## 6. Globale HMI-Elemente

### 6.1 Kopfbereich

Im Kopfbereich sollen sichtbar sein:

- `HMI_TITLE`
- `SITE_CODE`
- lokale Zeit nach `TIMEZONE`
- Kommunikationsindikator
- Alarmindikator

Nicht sichtbar:
- interne Hostnamen
- Container-IDs
- Framework-Versionen
- Debug-Schalter

### 6.2 Globale Statusindikatoren

Immer sichtbar:

- `Site operating mode`
- `Breaker state`
- `Plant power`
- `Alarm count`
- `Comms health`

Diese Werte muessen dieselbe Fachlogik widerspiegeln wie:
- `Unit 1` in Modbus
- Alarm- und Eventsystem

### 6.3 Farb- und Zustandssprache

Empfohlene Zustandsfarben:

- neutral / normal -> grau oder blau
- warning -> amber / gelb
- high severity -> rot
- stale / degraded -> orange oder grau gestreift

Wichtige Regel:
- Farbe allein reicht nie
- jeder Zustand braucht zusaetzlich Text oder Icon

## 7. Seitenkonzept im Detail

### 7.1 `/` und `/overview`

Zweck:
- schnellster Ueberblick ueber den Park

Anzuzeigende Inhalte:

- aktuelle Parkleistung
- aktuelle Leistungsbegrenzung
- Blindleistungsziel
- Breaker-Zustand
- Anzahl aktiver Alarme
- Kommunikationszustand
- Kurzstatus der drei Inverter-Bloecke
- Wetter-Kurzwerte

Empfohlene Darstellung:

- 4 bis 6 kompakte Statuskacheln
- kleine Tabelle fuer Blockstatus
- Liste der 3 wichtigsten aktiven Alarme

Bedienung:
- keine direkten Schreibaktionen auf dieser Seite
- nur Navigation zu Detailseiten

### 7.2 `/single-line`

Zweck:
- einfache technische Anlagenansicht
- interaktive, read-only Energiekarte im Stil eines vereinfachten
  SCADA-Single-Line-Diagramms

Anzuzeigende Inhalte:

- PV-Park als Sammelsymbol
- PPC
- drei Inverter-Bloecke
- getrennte DC-String-Zweige vor den Inverter-Bloecken
- AC-Sammelschiene erst nach der Inverter-Wandlung
- Revenue Meter
- Grid Interconnect / Breaker mit sichtbarer Open/Closed-Stellung

Zustaende:

- Breaker offen/geschlossen
- Block online/offline/degraded
- Kommunikationsverlust
- Leistungsfluss in einfacher Form
- Hover/Fokus auf Knoten hebt die zugehoerige Flusslinie hervor
- automatische Linienfaerbung markiert gespeiste, degradierte oder getrennte
  Pfade

Wichtige Regel:
- das Einlinienschema ist bewusst simpel
- keine echte Schutz- oder Netzdetailtreue
- ein Klick auf den Breaker ist ein sichtbarer Koederpfad: er schreibt keinen
  Prozesszustand, protokolliert `hmi.action.unauthenticated_control_attempt`
  und fuehrt zur Service-Anmeldung
- DC- und AC-Seite duerfen optisch nicht als dieselbe Leitung erscheinen
- PPC wird als Controller gezeigt, nicht als Energiepfad
- keine Schreibaktionen oder versteckten Steuerpfade in der Grafik

### 7.3 `/inverters`

Zweck:
- Vergleich der drei Blockaggregate

Anzuzeigende Inhalte je Block:

- Status
- Kommunikationszustand
- Leistung
- PV-/DC-Isolatorzustand
- AC-/DC-nahe Werte
- Temperatur
- lokale Alarmanzahl

Optionale Interaktion:

- nur fuer berechtigte Service-Sicht:
  - enable/disable request
  - power limit request
  - PV-/DC-Isolator oeffnen/schliessen
  - reset request

### 7.4 `/weather`

Zweck:
- Wetter und Verfuegbarkeitskontext sichtbar machen

Anzuzeigende Inhalte:

- Einstrahlung
- Modul- und Umgebungstemperatur
- Windgeschwindigkeit
- Wetterqualitaet / Datenqualitaet
- Zusammenhang zu aktueller Parkleistung

Wichtige Regel:
- die Werte muessen die Leistungsentwicklung plausibel stuetzen
- Wetter und Parkleistung duerfen nicht dauerhaft widerspruechlich erscheinen

### 7.5 `/meter`

Zweck:
- Einspeise- und Netzsicht

Anzuzeigende Inhalte:

- Exportleistung
- Tages- oder Gesamtenergie
- Netzspannung
- Netzfrequenz
- Leistungsfaktor
- Exportpfad verfuegbar / nicht verfuegbar

Optional fuer berechtigte Nutzer:

- Sicht auf Breaker-Bedienpfad ueber Link oder Panel

### 7.6 `/alarms`

Zweck:
- zentrale Alarmliste

Anzuzeigende Inhalte:

- Alarmcode
- Alarmname
- Severity
- Asset-Bezug
- Zustand
- First seen
- Last changed
- Ack state

Wichtige Regeln:

- Alarme muessen sortierbar oder filterbar sein
- `acknowledged` ist klar von `cleared` zu trennen
- Kommunikationsverlust ist klar von Prozessstoerung zu unterscheiden

### 7.7 `/trends`

Zweck:
- einfache historische Entwicklung

Anzuzeigende Standardtrends:

- Plant power
- Power limit
- Irradiance
- Export power
- Export energy
- Daily energy bars in MWh/day
- Block power je Inverter-Block

Wichtige Regel:
- die Trenddaten muessen nicht hochaufgeloest oder endlos sein
- die sichtbare Anlagenhistorie ist auf 30 Tage begrenzt
- ein glaubhafter Verlauf der Erzeugungswerte ist wichtiger als
  historische Wetterdetails
- Tagesenergie wird aus dem kumulativen Export-Energy-Zaehler abgeleitet und
  nach lokalem Kalendertag gruppiert
- auswaehlbare Zeitfenster fuer V1: `1h`, `6h`, `24h`, `7d`, `30d`
- die sichtbare Snapshot-Zeit muss aus dem gemeinsamen `observed_at` kommen
- die Trendkarten sollen aus persistierter Runtime-Historie statt aus einer
  reinen Fixture-Baseline gespeist werden

### 7.8 `/service/login`

Zweck:
- separater Einstieg fuer service-nahe Funktionen

Die Seite soll:
- glaubhaft aussehen
- Login-Versuche erlauben
- aber keine echten Admin-Funktionen freischalten, die ueber die definierten
  V1-Bedienpfade hinausgehen

In der V1-Default-Konfiguration ist `ENABLE_SERVICE_LOGIN=1`.

Sichtbare Elemente:

- Username
- Password
- Login-Schaltflaeche
- allgemeiner Service-Hinweis

Nicht sichtbar:
- Passwort-Reset-Fluesse
- echte Support-Links
- Framework-Standardformulare

## 8. Berechtigungsmodell fuer V1

V1 braucht kein komplexes Rollenmodell, aber eine glaubhafte Trennung.

### 8.1 Empfohlene Sichten

- `anonymous_view`
  - kann alle read-only Betriebsseiten ansehen
  - kann keine schreibenden Aktionen ausfuehren

- `service_view`
  - sieht zusaetzliche Bedienfelder
  - kann nur die dokumentierten V1-Setpoints ausloesen

### 8.2 Warum diese Trennung sinnvoll ist

- Angreifer sehen schnell relevante Informationen
- Service-Pfade erhoehen den Reiz
- die UI bleibt klein
- die Testmatrix bleibt beherrschbar

## 9. Login- und Session-Verhalten

### 9.1 Login-Semantik

Empfohlener V1-Kurs:

- `/service/login` liefert `200`
- unautorisierte Aufrufe auf geschuetzte Service-Aktionen liefern `401`
- wirklich gesperrte oder ausser Betrieb gesetzte Service-Seiten liefern `403`

### 9.2 Login-Ergebnis

Bei erfolgreichem Login:

- Session-Cookie oder aequivalenter Session-Zustand
- sichtbarer Wechsel in `service_view`
- keine weitreichenderen Funktionen als im V1-Scope dokumentiert
- kein sichtbarer Logout-Link in V1

Bei fehlgeschlagenem Login:

- ruhige, generische Fehlermeldung
- keine Hinweise auf gueltige Usernamen
- keine technischen Fehltexte
- in der fuer das Deployment gesetzten Angreifer-Sprache

### 9.3 Session-Lebensdauer

Sessions sollen:

- serverseitig ueber einen signierten Cookie-Handle verwaltet werden
- zeitlich begrenzt sein
- sauber auslaufen
- keine inkonsistenten Zwischenzustaende erzeugen
- `HttpOnly` und `SameSite=Lax` tragen
- bei browserseitigem HTTPS-Betrieb hinter TLS-Proxy zusaetzlich per
  `HMI_COOKIE_SECURE=1` und `SERVICE_COOKIE_SECURE=1` als `Secure` markiert
  werden

V1-Startwerte:
- `20` Minuten Idle-Timeout
- Prozessneustart invalidiert bestehende Sessions

Abgelaufene Session:

- bei Seitenaufruf oder Action -> kontrolliert auf `401` oder erneute
  Login-Anforderung

## 10. Bedienhandlungen in der HMI

Die HMI darf nur dieselben Fachhandlungen ausloesen wie die Modbus-Sicht.

### 10.1 Zulassige Bedienhandlungen

- `active_power_limit_pct`
- `reactive_power_target`
- `plant_mode_request`
- `block_enable_request`
- `block_power_limit_pct`
- `block_reset_request`
- `breaker_open_request`
- `breaker_close_request`
- optional `tracking_enable_request`
- optional `stow_request`

### 10.2 Bedienmuster

Empfohlene Form:

- kleine Eingabefelder oder Dropdowns
- klare Einheiten
- sichtbarer aktueller Ist-Wert
- sichtbarer zuletzt angeforderter Sollwert
- ruhige Rueckmeldung nach dem Schreiben

### 10.3 Keine verbotenen Bedienpfade

Nicht vorgesehen:

- Dateiupload
- Script-Ausfuehrung
- freie Kommandozeilenfelder
- generische SQL-/API-Testseiten
- echte Wartungs-Backdoors

## 11. HMI-Fehlerbilder

Fehlerbilder muessen bewusst vereinheitlicht werden.

### 11.1 Nicht authentifiziert

- HTTP `401`
- ruhiger Hinweis wie `Authentication required`
- Link oder Hinweis auf `/service/login`

### 11.2 Nicht erlaubt

- HTTP `403`
- ruhiger Hinweis wie `Access denied`
- kein Stacktrace
- kein Rollendetail

### 11.3 Nicht gefunden

- HTTP `404`
- einfache generische Seite
- keine Router- oder Framework-Signatur

### 11.4 Datenstale oder Kommunikationsverlust

Die Seite bleibt grundsaetzlich renderbar, aber:

- betroffene Werte werden markiert
- Qualitaet wird als `stale` oder `invalid` sichtbar
- passende Alarme erscheinen

### 11.5 Fachliche Ablehnung einer Bedienung

Wenn ein Sollwert fachlich abgelehnt wird:

- ruhige Fehlermeldung im UI
- gleiche Fachlogik wie Modbus
- keine widerspruechliche Anzeige zwischen Formular und Anlagenzustand
- keine gemischten Sprachfragmente auf derselben Seite

## 12. HMI-Artefakte fuer Glaubwuerdigkeit

Eine kleine Zahl interner Artefakte kann die Glaubwuerdigkeit erhoehen.

Geeignet fuer V1:

- kleine Alarmhistorie
- letzter Event-Hinweis
- einfacher Tagesreport-Link ohne echten Export
- generisches Wartungsfenster-Hinweisfeld

Nicht empfohlen fuer V1:

- ausufernde Dokumentenbibliothek
- echte Firmenadressen
- belastbare Standortdaten
- reale Handbuecher oder OEM-PDFs

## 13. Datenbindung zwischen HMI und Modbus

Die HMI soll zentrale Werte direkt aus denselben Fachobjekten lesen, aus denen
auch die Registermatrix gespeist wird.

Beispiele:

- `overview.plant_power` <-> `Unit 1 / 40104-40105`
- `overview.breaker_state` <-> `Unit 1 / 40109`
- `inverters.block_power` <-> `Unit 11-13 / 40104-40105`
- `inverters.pv_isolator` <-> gemeinsamer `PlantSnapshot.inverter_blocks[*].dc_disconnect_state`
- `weather.irradiance` <-> `Unit 21 / 40103`
- `meter.export_power` <-> `Unit 31 / 40103-40104`
- `single-line.breaker_state` <-> `Unit 41 / 40102`

Wichtige Regel:
- keine UI-only Schattenwerte
- keine gecachten Fantasiewerte ohne Bezug zur Fachlogik

## 14. Logging-Anforderungen fuer die HMI

Jeder HMI-Aufruf soll zusaetzlich zum allgemeinen Event-Schema mindestens
loggen:

- `component` mit Wert `hmi-web`
- `service` mit Wert `web-hmi`
- `endpoint_or_register` mit Wert des angefragten HTTP-Pfads
- `http_method`
- `http_path`
- `http_status`
- `session_id`

Bei Login-Versuchen zusaetzlich:

- `auth_result`
- `username_present`
- `failure_reason_class`

Bei Bedienhandlungen zusaetzlich:

- `asset_id`
- `setpoint_name`
- `requested_value`
- `previous_value`
- `resulting_value`
- `resulting_state`
- `correlation_id`

Wichtige Sprachregel:
- sichtbarer UI-Text darf lokalisiert sein
- Log-Inhalt und Betreiberdiagnose bleiben deutsch
- Events behalten sprachneutrale Codes wie `event_type`, `alarm_code` und
  `result`

## 15. Anti-Fingerprint-Regeln fuer die HMI

Die HMI darf nicht durch typische Web-Schlamperei verraten, dass sie ein
Honeypot ist.

### 15.1 Vermeiden

- Framework-Default-Fehlerseiten
- offen sichtbare `/swagger`, `/openapi`, `/debug`, `/metrics`
- inkonsistente Statuscodes
- Formulare ohne serverseitige Wirkung
- perfekte, unrealistisch latenzfreie Aktualisierung
- Seiten, die Daten zeigen, die Modbus nicht kennt
- halb uebersetzte oder gemischtsprachige Ansichten

### 15.2 Erzwingen

- konsistente Terminologie
- konsistente Asset-Namen
- konsistente Alarmbezeichnungen
- kontrollierte leichtere Zeitverzoegerung bei Bedienhandlungen
- gleiche Fachwahrheit wie Modbus
- alle sichtbaren Texte pro Deployment aus genau einem aktiven Locale-Paket

## 16. Testpflichten fuer die HMI

Pflichttests fuer V1:

- alle dokumentierten Seiten liefern die erwarteten Statuscodes
- Betriebsseiten sind ohne Login lesbar
- Service-Aktionen verlangen Authentifizierung
- Login-Fehler liefern ruhige, konsistente Antworten
- gueltige Bedienhandlungen erscheinen spaeter in UI und Modbus konsistent
- Kommunikationsverlust wird sichtbar markiert
- Alarmzustandswechsel erscheinen in Liste und Overview konsistent
- keine Debug-Header und keine Framework-Signaturen

Besonders wichtig:
- Jede sichtbare Fehlersituation braucht einen Test.

## 17. Konfigurierbare HMI-Werte

Spaeter ueber `.env` oder aequivalente Konfiguration sinnvoll:

- `HMI_TITLE`
- `SITE_CODE`
- `TIMEZONE`
- `ATTACKER_UI_LOCALE`
- `ATTACKER_UI_FALLBACK_LOCALE`
- `ENABLE_SERVICE_LOGIN`
- `HMI_COOKIE_SECURE`
- `SERVICE_COOKIE_SECURE`
- `ENABLE_TRACKER`
- `TREND_WINDOW_MINUTES`
- `ALARM_PAGE_SIZE`

Wichtige Regel:
- Defaults bleiben generisch und nicht OSINT-freundlich
- keine feste Begrenzung auf nur zwei Sprachen
- `ATTACKER_UI_FALLBACK_LOCALE` muss immer auf ein vorhandenes Locale-Paket
  zeigen
- `ATTACKER_UI_LOCALE` und `ATTACKER_UI_FALLBACK_LOCALE` referenzieren Dateinamen
  ohne `.json`

## 18. Punkte fuer spaetere Verfeinerung

- wie stark Trends geglaettet oder verrauscht werden
- ob eine kleine Event-Liste auf `/overview` zusaetzlich sichtbar sein soll
- ob exponierte Deployments spaeter eine restriktivere `anonymous_view`
  erhalten

## 19. Kurzfazit

Die HMI fuer V1 soll eine kleine, generische Betriebsoberflaeche fuer einen
einzelnen Solarpark sein: uebersichtlich, standardnah, technisch plausibel und
eng an das Fachmodell und die Modbus-Sicht gekoppelt. Wenn diese Kopplung
sauber bleibt, bekommt die Deckscrew einen interaktiven Webpfad, der Angreifer
an Bord lockt, ohne durch Web-Unfug den Honeypot zu verraeten.
