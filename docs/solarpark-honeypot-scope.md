# Scope-Definition: Interaktiver SCADA-Honeypot fuer einen fiktiven Solarpark

## 1. Zielbild

Dieses Projekt beschreibt einen interaktiven Honeypot fuer eine fiktive
SCADA-Umgebung im Bereich Energieerzeugung. Die Anlage soll glaubhaft genug
sein, um Reconnaissance, Interaktionsversuche und versuchte Prozessmanipulation
beobachten zu koennen, ohne eine reale Anlage, reale Herstelleridentitaeten oder
reale Standortdaten nachzubilden.

Der Honeypot ist fuer Analyse, Logging und kontrollierte Forschung gedacht. Er
ist nicht dazu gedacht, echte industrielle Steuerung nachzubilden oder echte
Anlagenlogik zu betreiben.

## 2. Gewaehlter Scope

Die simulierte Anlage ist ein einzelner, fiktiver Freiflaechen-Solarpark im
einstelligen MW-Bereich.

Festgelegter V1-Scope:
- Ein Standort
- Keine Ortsangabe
- Kein Firmenname
- Keine echte Vendor-Identitaet
- Keine echte OEM-UI oder echte Modellbezeichnungen
- Fokus auf betriebliche Stoerung und beobachtbare Prozesswirkung
- Alle identitaetsnahen Werte sollen spaeter ueber Konfiguration gesetzt werden

Empfohlene Leistungsordnung fuer V1:
- Zielbereich: 5 bis 8 MW
- Arbeitshypothese: ca. 6 bis 7 MW

Diese Groesse ist gross genug fuer glaubhafte SCADA-Interaktion, aber klein
genug, um keine auffaellige oder leicht zuzuordnende reale Anlage zu spiegeln.

## 3. Nicht-Ziele

Die folgenden Punkte sind explizit nicht Teil des Projekts:
- Nachbau einer realen PV-Anlage, eines realen Netzanschlusspunkts oder eines
  realen Betreibers
- Einsatz echter SPSen, echter Wechselrichter oder echter Schutztechnik
- Bereitstellung echter Fernwartungswege oder echter Herstellerzugriffe
- Modellierung physischer Schaeden oder Zerstoerung realer Hardware
- Nachbildung eines prominenten Multi-Site-Leitstands oder Flottenportals

## 4. Glaubwuerdigkeit fuer Angreifer

Die Attraktivitaet der Umgebung soll nicht aus realen Namen oder realen
Herstellermerkmalen kommen, sondern aus plausibler Prozesswirkung.

Ein Angreifer soll erkennen koennen, dass Eingriffe Konsequenzen haben, etwa:
- sichtbare Aenderung der Einspeiseleistung
- Curtailment oder Setpoint-Aenderungen
- Blindleistungs-Sollwertwechsel
- Online-/Offline-Status von Teilanlagen
- Breaker-Statuswechsel am Uebergabepunkt
- Alarmkaskaden und Stoerungsmeldungen
- Kommunikationsverlust einzelner Segmente

Die Wirkung soll betrieblich relevant wirken, ohne physische Zerstoerung,
unsichere Fernsteuerbarkeit oder echte Prozessgefaehrdung zu simulieren.

## 5. Anlagenmodell

Die V1-Anlage besteht aus einer bewusst kleinen, aber zusammenhaengenden
Topologie:

- 1 Power Plant Controller (PPC)
- 3 Wechselrichter-Bloecke
- 1 Wetterstation
- 1 Revenue Meter
- 1 Uebergabefeld / Grid Interconnect mit Breaker-Status
- Optional 1 Tracker-Controller
- 1 HMI / Betriebsoberflaeche
- 1 Historian- / Alarm-Ansicht

Jedes logische Asset bekommt:
- eine generische Kennung
- einen simulierten Verbindungsstatus
- einen Satz lesbarer Messwerte
- einen Satz steuerbarer oder scheinbar steuerbarer Variablen
- ein Alarmprofil

## 6. Interaktionsmodell

Der Honeypot soll fuer Beobachtung aktiv genug sein, um ueber einfaches Port-
Scanning hinauszugehen.

Vorgesehene Interaktionen:
- Lesen von Messwerten und Stati
- Schreiben plausibler Setpoints innerhalb sicherer Simulationsgrenzen
- Navigieren durch eine kleine HMI
- Betrachten von Alarmen, Trends und Betriebsstatus
- Optionale Login-Versuche an HMI- oder Service-Oberflaechen

Nicht vorgesehen:
- echte Shells auf Host-Ebene
- echte Dateisystemzugriffe
- echte Steuerpfade zu externer Infrastruktur
- unkontrollierte Ausbreitung zwischen Hosts

## 7. Prozesslogik fuer V1

Die Prozesslogik bleibt absichtlich einfach, muss aber sichtbare Rueckkopplung
erzeugen.

Empfohlene Kernzustandsvariablen:
- Einstrahlung
- Modultemperatur
- AC-Gesamtleistung
- Verfuegbarkeit pro Wechselrichter-Block
- Wirkleistungsbegrenzung
- Blindleistungs-Sollwert
- Breaker-Status
- Kommunikationsstatus
- Alarmstatus

Beispielhafte Prozessereignisse:
- Wetteraenderung beeinflusst Verfuegbarkeit und Leistung
- Setpoint-Aenderung reduziert sichtbare Einspeisung
- Breaker offen fuehrt zu Leistungsverlust und Alarmen
- Kommunikationsverlust blendet Teilanlagen aus
- Rueckkehr in Normalzustand nach Ablauf eines Simulationsfensters

## 8. HMI-Umfang

Die HMI soll klein, aber schluessig sein. Keine reale Markenoptik, sondern eine
generische Betriebsoberflaeche.

Empfohlene Seiten:
- Uebersicht / Parkstatus
- Einlinienschema in einfacher Form
- Wechselrichter-Uebersicht
- Wetter- und Leistungsansicht
- Alarm- und Ereignisliste
- Historische Trends
- Service- / Login-Dialog mit rein simuliertem Verhalten

## 9. Logging-Anforderungen

Logging ist ein Kernziel des Projekts. Jede relevante Aktion muss
korrelierbar, analysierbar und exportierbar sein.

Pflichtfelder pro Event:
- `timestamp`
- `event_id`
- `correlation_id`
- `event_type`
- `category`
- `severity`
- `source_ip`
- `actor_type`
- `component`
- `asset_id`
- `action`
- `result`

Hauefige Zusatzfelder fuer Protokoll- und HMI-Zugriffe:
- `protocol`
- `service`
- `endpoint_or_register`
- `requested_value`
- `previous_value`
- `resulting_value`
- `resulting_state`

Zu protokollieren sind mindestens:
- Verbindungsaufbau und Session-Daten
- HMI-Zugriffe
- Login-Versuche
- Lese- und Schreiboperationen auf Protokollebene
- Aenderungen am simulierten Prozesszustand
- Alarmwechsel
- Fehlerzustaende und Timeouts

Empfohlene Ausgabeformate:
- JSONL fuer strukturierte Analyse
- optionale PCAP-Mitschnitte fuer Netzwerkforensik

## 10. Konfigurationsprinzip

Viele Werte, die auf Identitaet oder Wiedererkennung einzahlen, sollen nicht
hart codiert werden, sondern ueber eine `.env` oder aequivalente Konfiguration
befuellbar sein.

Beispiele fuer spaeter konfigurierbare Werte:
- `SITE_NAME`
- `SITE_CODE`
- `OPERATOR_NAME`
- `HMI_TITLE`
- `TIMEZONE`
- `CAPACITY_MW`
- `INVERTER_BLOCK_COUNT`
- `ENABLE_TRACKER`
- `DEFAULT_POWER_LIMIT_PCT`
- `LOG_LEVEL`

Wichtige Vorgabe:
- Standardwerte bleiben generisch und bewusst nicht OSINT-freundlich.
- Reale Firmen-, Orts- oder Herstellerdaten werden nicht als Defaults
  hinterlegt.

## 11. Sicherheitsgrenzen

Der Honeypot darf nie zum realen Steuer- oder Pivot-System werden.

Verbindliche Grenzen:
- Betrieb nur in isolierter Umgebung
- kein Zugriff auf reale OT-, IT- oder Cloud-Systeme
- ausgehender Traffic standardmaessig sperren
- keine echten Zugangsdaten
- keine echte Herstellerkennzeichnung
- schneller Reset per Container oder Snapshot
- klare Trennung zwischen Simulationszustand und Host-System

## 12. Betriebsannahmen

Die Anlage ist absichtlich unterdokumentiert und fuehrt ein duennes OSINT-
Profil. Das heisst:
- keine oeffentliche Firmenhistorie
- keine belastbaren Ortsreferenzen
- keine echte Presse- oder Projektkommunikation
- nur minimale, generische Artefakte innerhalb der HMI oder Dateioberflaeche

Das Ziel ist Glaubwuerdigkeit bei Interaktion, nicht Aussenwirkung durch
einfache Web-Recherche.

## 13. V1-Erfolgskriterien

V1 ist erfolgreich, wenn:
- ein Angreifer mehrere glaubhafte Assets vorfindet
- Messwerte und Setpoints interaktiv wirken
- Aktionen sichtbare Prozessfolgen erzeugen
- alle relevanten Aktionen vollstaendig geloggt werden
- der Honeypot ohne reale Identitaetsmerkmale auskommt
- die Umgebung schnell und sauber ruecksetzbar ist

## 14. Punkte fuer spaetere Erweiterung

- zusaetzliche Protokolle neben `Modbus/TCP` und `HTTP`
- feinere Alarm- und Severity-Unterklassen ueber die V1-Startmenge hinaus
- weitere Log-Senken neben lokalem Eventstore und `JSONL`
- tracker-nahe Zusatzsichten fuer bewusst erweiterte Deployments
