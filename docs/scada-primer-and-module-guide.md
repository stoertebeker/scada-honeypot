# SCADA-Primer und Modulguide

## 1. Zweck dieses Dokuments

Dieses Dokument ist die Einsteigerkarte fuer Menschen, die den Honeypot
betreiben, testen oder angreiferseitig nachvollziehen wollen, aber noch nicht
tief in `SCADA`, `OT` oder Solarpark-Fachlogik stecken.

Es beantwortet drei Fragen:

1. Was bedeuten die wichtigsten Anlagenkomponenten?
2. Was machen die einzelnen Module im Repo?
3. Wo sieht ein Testangreifer welche Wirkung?

Wichtige Sicherheitsregel:
- Diese Erklaerungen machen die Anlage **bedienbar**, aber nicht automatisch
  sicher fuer Internetbetrieb.
- Fuer echte Exponierung bleiben `ALLOW_NONLOCAL_BIND`,
  `APPROVED_INGRESS_BINDINGS`, `APPROVED_EGRESS_TARGETS`,
  `APPROVED_EGRESS_RECIPIENTS` und der Sweep
  `--verify-exposed-research` harte Gates.

## 2. Was hier mit SCADA gemeint ist

`SCADA` steht vereinfacht fuer eine Leit- und Beobachtungsumgebung.
In diesem Repo ist das **keine echte Kraftwerkssteuerung**, sondern ein
kontrollierter Honeypot fuer einen fiktiven Solarpark.

Der Honeypot zeigt bewusst typische OT-Bausteine:

- `HMI`
  - Web-Oberflaeche fuer Uebersicht, Alarme, Trends und einige Serviceaktionen.
- `Modbus/TCP`
  - industrielles Protokoll fuer Lesen und gezielte Schreibaktionen.
- `PPC`
  - `Power Plant Controller`, also die uebergeordnete Leitstelle des Parks.
- `Inverter Block`
  - Gruppe von Wechselrichtern, die Gleichstrom aus PV-Feldern in
    netzfaehigen Wechselstrom umwandeln.
- `Weather Station`
  - liefert Einstrahlung, Temperatur und Wind. Daraus wird abgeleitet, ob die
    aktuelle Leistung plausibel ist.
- `Revenue Meter`
  - Zaehler am Netzanschlusspunkt. Zeigt, was wirklich exportiert wird.
- `Grid Interconnect`
  - Uebergabepunkt zum Netz. Hier sitzt der relevante `breaker`
    (Leistungsschalter).
- `Alarm`
  - sichtbarer Hinweis auf Stoerung, Bedienfolge oder Folgeereignis.

## 3. Die wichtigsten Anlagenkomponenten in Klartext

### 3.1 `site` / `power_plant_controller`

Das ist die zusammengefasste Leit- und Sicht auf den ganzen Solarpark.
Wenn du als Testangreifer nur **ein** logisches Geraet lesen willst, faengst du
hier an.

Hier liegen zum Beispiel:
- Parkleistung
- Betriebsmodus
- Leistungslimit
- Blindleistungsziel
- Alarmanzahl
- Kommunikationslage

### 3.2 `inverter_block_01..03`

Ein Inverter-Block ist eine gruppierte Sicht auf einen Teil des Parks. In echt
waere das meist ein Feld oder Cluster mehrerer Wechselrichter.

Hier siehst du:
- Blockleistung
- Verfuegbarkeit
- Kommunikationszustand
- lokale Alarmzahl
- Bedienwunsch `enable/disable`
- Leistungslimit pro Block
- Reset fuer simulierten Kommunikationsverlust

### 3.3 `weather_station`

Die Wetterstation liefert den Plausibilitaetskontext:
- wie viel Sonne anliegt
- ob Wind und Temperatur normal wirken
- wie gut oder schlecht die Datenqualitaet ist

Fuer einen Testangreifer ist das wichtig, weil Minderleistung nicht automatisch
eine Stoerung ist. Wenn wenig Einstrahlung da ist, ist auch wenig Leistung
plausibel.

### 3.4 `revenue_meter`

Der Revenue Meter ist die Sicht am Netzpunkt. Er beantwortet die Frage:

- Was geht wirklich ins Netz?

Wenn der `breaker` offen ist, faellt hier der Export weg. Deshalb ist die
Meter-Seite eine der wichtigsten Gegenproben nach Breaker-Aktionen.

### 3.5 `grid_interconnect`

Das ist die Netzkopplung. Der wichtigste Bedienpunkt ist hier der
`breaker`.

Wenn der Breaker:
- `closed` ist, kann der Park exportieren.
- `open` ist, ist der Exportpfad getrennt.

Im Honeypot fuehrt das sichtbar zu:
- Alarm `BREAKER_OPEN`
- Null-Export am Meter
- geaenderter Darstellung in `/single-line`, `/meter` und `/alarms`

## 4. Welche Module im Honeypot was tun

Die folgende Tabelle beschreibt die eigentlichen Repo-Module aus Sicht einer
Deckscrew, nicht nur aus Sicht des Python-Packagings.

| Modul | Aufgabe | Warum es fuer dich wichtig ist |
| --- | --- | --- |
| `config_core` | laedt `.env`, setzt Defaults, validiert Ports, Exporter, Locale und Exposure-Gates | hier entscheidet sich, ob die Runtime lokal bleibt oder bewusst exponiert |
| `asset_domain` | typisiertes Fachmodell fuer Site, PPC, Inverter, Wetter, Meter, Grid und Alarme | hier liegt die gemeinsame Wahrheit der Anlage |
| `plant_sim` | berechnet Prozesswirkung aus Setpoints und Stoerungen | hier entsteht sichtbare Wirkung wie Curtailment, Blockverlust oder Breaker-Reaktion |
| `protocol_modbus` | Modbus-Abbildung fuer `FC03`, `FC06`, `FC16`, Unit-IDs und Fehlercodes | hier arbeitet der klassische OT-Testangreifer |
| `hmi_web` | FastAPI-/Jinja2-HMI fuer Uebersicht, Detailseiten, Login und Service-Panel | hier arbeitet der Web-/Service-orientierte Testangreifer |
| `event_core` | erzeugt, korreliert und persistiert Events, Alerts und Outbox-Eintraege | hier wird jede relevante Aktion forensisch festgehalten |
| `rule_engine` | leitet Folge-Alerts aus Ereignissen und Zustandsketten ab | hier entstehen Alerts wie `GRID_PATH_UNAVAILABLE` oder `REPEATED_LOGIN_FAILURE` |
| `storage` | SQLite-Eventstore und JSONL-Archiv | hier landen Eventspur, Alarmhistorie und Export-Warteschlange |
| `monitoring` | schreibt den lokalen Runtime-Heartbeat nach `RUNTIME_STATUS_PATH` | wichtig fuer `pre-exposure` und `exposed-research`-Betrieb |
| `exporter_sdk` | Vertrag fuer Exporter-Faehigkeiten, Health und Batch-Delivery | trennt Kernlogik von Zielkanal-Implementierung |
| `exporter_runner` | Hintergrundrunner fuer Outbox, Webhook, SMTP und Telegram | hier sieht man, ob Alerts den Kern verlassen duerfen und konnten |
| `runtime_reset` | definierter Reset von Eventstore, JSONL, Runtime-Status und PCAP-Artefakten | wichtig fuer reproduzierbare Neustarts vor Tests |
| `runtime_egress` | prueft, ob aktive Exportziele explizit freigegeben sind | verhindert versehentliche Ausleitung |
| `runtime_ingress` | prueft, ob externe Bindings explizit freigegeben sind | verhindert versehentlich offene Ports |
| `runtime_exposure` | letztes Gate fuer `exposed-research`, Findings-Log und Exposure-Sweep | hier wird echter Internetkurs bewusst freigezogen oder blockiert |
| `time_core` | abstrahiert Zeit fuer deterministische Tests | sorgt dafuer, dass Alarm- und Retry-Pfade reproduzierbar bleiben |
| `main` | baut die Runtime zusammen, startet Dienste und bietet CLI-Pfade | hier laufen lokaler Start, Reset und Exposure-Sweep zusammen |

## 5. Wie HMI, Modbus und Fachmodell zusammenhaengen

Der Honeypot hat bewusst **keine** zweite Wahrheit.

Das bedeutet:
- Modbus schreibt nicht an einer anderen Stelle als die HMI.
- Das Service-Panel benutzt dieselben Fachpfade wie Modbus.
- Alarmseite, Trendseite und Meter-Sicht lesen dieselbe Snapshot- und
  Event-Wahrheit.

Wichtige Folgen:

1. Wenn du den Breaker in der HMI oeffnest, muss der Export am Meter
   verschwinden.
2. Wenn du per Modbus `active_power_limit_pct_x10` aenderst, muss sich das in
   `/overview` und `/trends` spiegeln.
3. Wenn du einen Block resettest, muessen `/inverters` und `/alarms`
   zusammenpassen.

## 6. Sicht eines Testangreifers: wo man sinnvoll beginnt

### 6.1 Webpfad

Fuer einen menschlichen Tester ist die HMI meist der schnellste Einstieg:

1. `/overview`
   - Parkzustand, Leistung, Limit, Alarmanzahl
2. `/single-line`
   - technische Einlinien-Sicht mit Breaker und Leistungsfluss
3. `/inverters`
   - Blockvergleich und Comm-Loss-Indikatoren
4. `/weather`
   - Plausibilitaetskontext fuer Leistung
5. `/meter`
   - Gegenprobe fuer Netzexport
6. `/alarms`
   - aktive und historisierte Alerts
7. `/trends`
   - kurze synthetische Verlaufsansicht
8. `/service/login` und `/service/panel`
   - wenn du aktiv steuern willst

### 6.2 Modbus-Pfad

Fuer einen OT-orientierten Tester ist das uebliche Muster:

1. bekannte Unit-IDs lesen
2. Identitaetsblock `40001-40049` pruefen
3. Statusblock `40100-40199` lesen
4. gezielte Write-Punkte in `40200-40249` bedienen
5. Wirkung auf Alarmen, Meter und HMI gegenpruefen

Wichtige aktive Units in V1:

| Unit-ID | Komponente | Zweck |
| --- | --- | --- |
| `1` | `site` / `ppc-01` | Parkgesamtzustand und PPC-Setpoints |
| `11-13` | `invb-01..03` | Inverter-Blocke lesen und bedienen |
| `21` | `wx-01` | Wetterstation, read-only |
| `31` | `meter-01` | Revenue Meter, read-only |
| `41` | `grid-01` | Grid Interconnect und Breaker-Aktionen |

## 7. Was die wichtigsten Bedienungen fachlich bedeuten

| Pfad | Was du tust | Was fachlich passiert | Wo du es sehen solltest |
| --- | --- | --- | --- |
| Unit `1`, `40200` oder HMI `power limit` | Wirkleistungsgrenze setzen | Park wird `curtailed`, Leistung sinkt, Alarm `PLANT_CURTAILED` wird moeglich | `/overview`, `/trends`, `/alarms` |
| Unit `1`, `40201` oder HMI `reactive power` | Blindleistungsziel setzen | PPC-Sollwert aendert sich, ohne dass der Park ausfaellt | `/overview`, Unit `1` |
| Unit `1`, `40202` oder HMI `plant mode` | Bedienwunsch fuer Modus setzen | `plant_mode_request` wird gelatcht, echter Betriebsmodus springt nicht heimlich um | Service-Panel, Modbus |
| Unit `41`, `40200/40201` oder HMI `breaker` | Breaker oeffnen oder schliessen | Exportpfad trennt oder verbindet den Park | `/single-line`, `/meter`, `/alarms` |
| Unit `11-13`, `40200` oder HMI Block Enable | Block deaktivieren oder aktivieren | Block faellt aus oder kommt wieder | `/single-line`, `/inverters`, `/overview`, `/alarms` |
| Unit `11-13`, `40201` oder HMI Block Limit | Blockleistung begrenzen | Minderleistung pro Block | `/inverters`, `/trends`, Folge-Alerts moeglich |
| Unit `11-13`, `40203` oder HMI PV Disconnect | PV-/DC-Isolator eines Blocks oeffnen oder schliessen | DC-Eingang des Blocks wird simuliert getrennt, Inverter bleibt kommunikativ sichtbar | `/single-line`, `/service/panel`, `/inverters`, `/overview`, `/trends`, Modbus |
| Unit `11-13`, `40202` oder HMI Block Reset | simulierten Block-Reset ausloesen | Comm-Loss kann in den Normalzustand zurueckgefuehrt werden | `/inverters`, `/alarms` |

## 8. Wichtige Folge-Alerts in V1

Nicht jeder sichtbare Alert kommt direkt von einem einzelnen Register. Ein Teil
entsteht erst durch die `rule_engine`.

Die wichtigsten Beispiele:

- `REPEATED_LOGIN_FAILURE`
  - nach wiederholten fehlgeschlagenen Service-Logins
- `GRID_PATH_UNAVAILABLE`
  - wenn der Exportpfad aus Sicht der Folgelogik nicht verfuegbar ist
- `LOW_SITE_OUTPUT_UNEXPECTED`
  - wenn die Parkleistung deutlich zu niedrig ist, ohne dass Breaker oder
    Curtailment das sauber erklaeren
- `MULTI_BLOCK_UNAVAILABLE`
  - wenn mehr als ein Inverter-Block zugleich ernsthaft ausfaellt

Diese Alerts koennen in `/alarms` sichtbar sein, obwohl es keinen einzelnen
direkten "Alarm-Register-Write" dazu gibt.

## 9. Was du als Nicht-SCADA-Mensch im Kopf behalten solltest

Wenn du nur die grobe Bedienlogik mitnehmen willst, reicht diese Kurzfassung:

1. `overview` sagt dir, ob der Park gesund wirkt.
2. `single-line` zeigt dir, ob der Strompfad zum Netz offen oder geschlossen
   ist und ob einzelne PV-/DC- oder Inverter-Schalter geoeffnet wirken.
3. `inverters` zeigt dir, ob einzelne Blocke ausfallen, begrenzt oder PV-seitig
   isoliert werden.
4. `weather` sagt dir, ob geringe Leistung plausibel oder verdaechtig ist.
5. `meter` zeigt dir, ob wirklich etwas ins Netz geht.
6. `alarms` zeigt die Folgen deiner Aktionen und der Folgelogik.
7. `trends` zeigt, ob die Reaktion nur ein Moment oder ein Verlauf ist.

## 10. Weiterfuehrende Karten

- [docs/test-attacker-guide.md](test-attacker-guide.md)
  - konkreter Bedienkurs fuer HMI, Service-Panel und Modbus
- [docs/register-matrix.md](register-matrix.md)
  - genaue Register und Zugriffstypen
- [docs/hmi-concept.md](hmi-concept.md)
  - fachliches Zielbild der Web-HMI
- [docs/architecture.md](architecture.md)
  - technische Gesamtstruktur des Projekts
