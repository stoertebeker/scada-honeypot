# Domänenmodell: Fiktiver Solarpark

## 1. Zweck dieses Dokuments

Dieses Dokument beschreibt das fachliche Modell der simulierten Anlage. Es
legt fest, welche logischen Assets es gibt, welche Zustaende und Messwerte sie
tragen, welche Setpoints oder Bedienhandlungen moeglich sind und welche Alarme
daraus entstehen koennen.

Wichtig:
- Dieses Dokument ist **fachlich**, nicht protokollspezifisch.
- Es beschreibt die Anlage so, wie sie intern verstanden wird.
- Modbus, HMI und spaetere Exporter sollen alle auf dasselbe Modell zeigen.

## 2. Modellziele

Das Domänenmodell soll vier Dinge leisten:

1. Eine glaubhafte, aber kontrollierte Solarpark-Anlage beschreiben
2. Interaktion fuer Angreifer interessant machen
3. Konsistente Grundlage fuer Logging, Alerts und Tests schaffen
4. Erweiterungen erlauben, ohne die Fachlogik neu zu schneiden

## 3. Anlagenumfang fuer V1

Die Anlage ist ein einzelner fiktiver Freiflaechen-Solarpark im Bereich von
ca. 6 bis 7 MW.

V1 umfasst diese logischen Assets:
- 1 `site`
- 1 `power_plant_controller`
- 3 `inverter_block`
- 1 `weather_station`
- 1 `revenue_meter`
- 1 `grid_interconnect`
- optional 1 `tracker_controller`
- 1 `hmi_context`

Der Honeypot bildet keinen echten Netzbetreiber, keine echte Schutztechnik und
keinen echten OEM nach. Die Fachlogik bleibt aber nah genug an typischen PV-
Betriebsmustern, damit sich ein Angreifer schnell zurechtfindet.

## 4. Asset-Hierarchie

Die fachlichen Beziehungen sehen in V1 so aus:

```text
site
├── power_plant_controller
├── weather_station
├── revenue_meter
├── grid_interconnect
├── inverter_block[1..3]
└── tracker_controller (optional)
```

### 4.1 `site`

Das `site`-Objekt repraesentiert den gesamten Solarpark.

Es dient als:
- fachliche Wurzel
- Aggregationspunkt fuer Leistung und Status
- Bezugspunkt fuer Alarme und HMI-Uebersichten

### 4.2 `power_plant_controller`

Der `power_plant_controller` ist die zentrale logische Steuerinstanz.

Er:
- sammelt Betriebswerte
- haelt globale Setpoints
- beeinflusst die Einspeisung des Parks
- verarbeitet Betriebsmodi und Begrenzungen

### 4.3 `inverter_block`

Ein `inverter_block` steht fuer einen zusammengefassten Teilbereich des Parks.

Ein Block repraesentiert bewusst **mehrere reale Wechselrichter**, aber nur als
ein fachliches Aggregat. Das haelt V1 uebersichtlich und glaubhaft.

Jeder Block hat:
- Verfuegbarkeit
- AC-Leistung
- DC-nahe Indikatoren
- Kommunikationsstatus
- eigene Alarme

### 4.4 `weather_station`

Die `weather_station` liefert Umgebungsdaten, die in die Simulation
einwirken.

Wichtige Messgroessen:
- Globalstrahlung
- Modultemperatur
- Umgebungstemperatur
- Windgeschwindigkeit

### 4.5 `revenue_meter`

Der `revenue_meter` repraesentiert die abrechnungsrelevante Leistung am
Abgabepunkt.

Er ist wichtig, weil:
- er eine zweite Sicht auf Leistung liefert
- HMI, Trend und Manipulationswirkung glaubwuerdiger werden
- Abweichungen zwischen interner Erzeugung und Netzabgabe modellierbar sind

### 4.6 `grid_interconnect`

Das `grid_interconnect`-Objekt repraesentiert den Netzuebergabepunkt.

Es modelliert:
- Breaker-Status
- Verfuegbarkeit des Abgabepfads
- netzseitige Betriebsfreigabe in einfacher Form

### 4.7 `tracker_controller`

Der `tracker_controller` ist optional. In der V1-Default-Konfiguration bleibt
er deaktiviert. Falls er fuer ein bewusst erweitertes Deployment enthalten ist,
bleibt seine Rolle bewusst klein.

Er modelliert:
- normalen Tracking-Betrieb
- Stow-Modus
- Kommunikationsverlust

### 4.8 `hmi_context`

`hmi_context` ist kein physisches Asset, sondern eine fachliche Hilfsentitaet.

Sie beschreibt:
- aktuell sichtbare Uebersichtswerte
- aktive Bedienkontexte
- Session-bezogene UI-Zustaende

Das ist hilfreich, um HMI-Verhalten fachlich zu beschreiben, ohne UI-Details in
die eigentliche Prozesslogik zu ziehen.

## 5. Kernzustände der Anlage

Der Solarpark hat einen globalen Anlagenzustand und mehrere Asset-Zustaende.

### 5.1 Globaler `site_state`

Der Parkzustand umfasst mindestens:
- `operating_mode`
- `availability_state`
- `plant_power_mw`
- `plant_power_limit_pct`
- `reactive_power_setpoint`
- `breaker_state`
- `communications_health`
- `active_alarm_count`

Empfohlene Auspraegungen:

- `operating_mode`
  - `normal`
  - `curtailed`
  - `maintenance`
  - `faulted`

- `availability_state`
  - `available`
  - `partially_available`
  - `unavailable`

- `breaker_state`
  - `closed`
  - `open`
  - `transitioning`

- `communications_health`
  - `healthy`
  - `degraded`
  - `lost`

### 5.2 Asset-spezifische Zustaende

Jedes Asset traegt mindestens:
- `status`
- `communication_state`
- `last_update_ts`
- `quality`

Empfohlene Auspraegungen fuer `status`:
- `online`
- `offline`
- `degraded`
- `faulted`

Empfohlene Auspraegungen fuer `quality`:
- `good`
- `estimated`
- `stale`
- `invalid`

## 6. Fachliche Messwerte

Messwerte sind lesbare Beobachtungen, nicht direkt steuernde Werte.

### 6.1 Site-Messwerte

- `plant_power_mw`
- `plant_energy_mwh_today`
- `plant_availability_pct`
- `active_alarm_count`
- `communications_health_score`

### 6.2 PPC-Messwerte

- `active_power_limit_pct`
- `reactive_power_target`
- `dispatch_mode`
- `control_authority`

### 6.3 Inverter-Block-Messwerte

- `block_power_kw`
- `block_dc_voltage_v`
- `block_dc_current_a`
- `block_ac_voltage_v`
- `block_ac_current_a`
- `internal_temperature_c`
- `availability_pct`

### 6.4 Wetterstations-Messwerte

- `irradiance_w_m2`
- `module_temperature_c`
- `ambient_temperature_c`
- `wind_speed_m_s`

### 6.5 Revenue-Meter-Messwerte

- `export_power_kw`
- `export_energy_mwh_total`
- `grid_voltage_v`
- `grid_frequency_hz`
- `power_factor`

### 6.6 Grid-Interconnect-Messwerte

- `breaker_state`
- `export_path_available`
- `grid_acceptance_state`

### 6.7 Tracker-Messwerte

- `tracking_mode`
- `stow_state`
- `position_state`

## 7. Setpoints und Bedienhandlungen

Setpoints sind bewusst begrenzte fachliche Eingriffe. Sie erzeugen sichtbare
Wirkung, aber keine echte Gefaehrdung.

### 7.1 Globale Setpoints

- `active_power_limit_pct`
- `reactive_power_target`
- `plant_mode_request`

### 7.2 Block-bezogene Setpoints

- `block_enable_request`
- `block_power_limit_pct`
- `block_reset_request`

### 7.3 Grid-bezogene Bedienhandlungen

- `breaker_open_request`
- `breaker_close_request`

### 7.4 Tracker-bezogene Bedienhandlungen

- `tracking_enable_request`
- `stow_request`

## 8. Sicherheitsgrenzen fuer Setpoints

Damit der Honeypot glaubhaft, aber kontrolliert bleibt, gelten fachliche
Grenzen:

- keine Befehle an reale Hardware
- keine direkte Shell oder Host-Steuerung
- keine externen Steuerpfade ausserhalb der Simulation
- Wertebereiche muessen plausibel, aber begrenzt sein
- Ablehnungen muessen konsistent und standardnah wirken

Das ist wichtig, weil unrealistische Grenzwerte oder chaotische Fehlerbilder den
Honeypot verraten koennen.

## 9. Abhängigkeiten zwischen Assets

Die Anlage lebt von fachlicher Rueckkopplung. Darum muessen die Beziehungen
klar sein.

### 9.1 Wetter beeinflusst Erzeugung

Wenn `irradiance_w_m2` steigt:
- steigt typischerweise die verfuegbare Leistung
- kann die Modultemperatur steigen
- kann sich die AC-Gesamtleistung erhoehen

### 9.2 PPC begrenzt Erzeugung

Wenn `active_power_limit_pct` sinkt:
- sinkt die sichtbare Parkleistung
- sinkt die Leistung der Inverter-Bloecke
- sinkt typischerweise auch der Export am Revenue Meter

### 9.3 Grid-Interconnect beeinflusst Export

Wenn der Breaker offen ist:
- faellt die Exportleistung stark ab oder auf null
- Alarme koennen aktiv werden
- die Anlage kann in `faulted` oder `unavailable` wechseln

### 9.4 Kommunikation beeinflusst Sichtbarkeit

Wenn ein Asset `communication_state = lost` hat:
- werden Werte als `stale` oder `invalid` markiert
- die HMI zeigt unvollstaendige oder veraltete Daten
- Alarme fuer Kommunikationsverlust koennen entstehen

## 10. Alarmmodell

Alarme sind fachliche Verdichtungen von Zustaenden oder Sequenzen.

### 10.1 Alarmkategorien

- `communication`
- `process`
- `control`
- `equipment`
- `site`

### 10.2 Severity-Vorschlag

- `low`
- `medium`
- `high`
- `critical`

### 10.3 Beispielhafte V1-Alarme

- `COMM_LOSS_INVERTER_BLOCK`
  - Kommunikationsverlust zu einem Block
- `PLANT_CURTAILED`
  - aktive Wirkleistungsbegrenzung unter Normalniveau
- `BREAKER_OPEN`
  - Netzuebergabepfad geoeffnet
- `LOW_SITE_OUTPUT_UNEXPECTED`
  - Leistung deutlich unter erwarteter Verfuegbarkeit
- `REACTIVE_POWER_DEVIATION`
  - Blindleistungsziel weicht deutlich ab
- `TRACKER_STOW_ACTIVE`
  - Tracker im Stow-Modus
- `MULTI_BLOCK_UNAVAILABLE`
  - mehrere Teilbereiche gleichzeitig nicht verfuegbar

### 10.4 Alarmzustände

Ein Alarm kann diese Zustaende durchlaufen:
- `inactive`
- `active_unacknowledged`
- `active_acknowledged`
- `cleared`

### 10.5 Wichtige Alarmregeln

- Nicht jeder Fehler erzeugt sofort `critical`
- Wiederkehrende Alarme muessen nachvollziehbar bleiben
- Quittierung ist nicht gleich Behebung
- Kommunikationsverlust muss anders wirken als Prozessverlust

## 11. Typische fachliche Szenarien

Diese Szenarien helfen spaeter bei Tests, HMI und Logging.

### 11.1 Normale Erzeugung

- Wetterstation meldet gute Einstrahlung
- alle drei Inverter-Bloecke sind `online`
- Breaker ist `closed`
- Parkleistung bewegt sich im erwartbaren Bereich
- keine kritischen Alarme aktiv

### 11.2 Curtailment-Szenario

- Angreifer oder Bediener setzt `active_power_limit_pct` herab
- PPC uebernimmt den neuen Wert
- Inverter-Bloecke reduzieren Leistung
- Revenue Meter zeigt sinkenden Export
- Alarm `PLANT_CURTAILED` wird aktiv

### 11.3 Breaker-Offen-Szenario

- Breaker wird auf `open` gesetzt
- Exportpfad ist nicht verfuegbar
- Revenue Meter faellt ab
- HMI zeigt Stoerung am Netzuebergabepunkt
- Alarm `BREAKER_OPEN` wird aktiv

### 11.4 Kommunikationsverlust

- ein Inverter-Block verliert Kommunikation
- Wertequalitaet wird `stale`
- Blockstatus wechselt auf `degraded` oder `offline`
- Gesamtpark bleibt moeglicherweise teilweise verfuegbar
- Alarm `COMM_LOSS_INVERTER_BLOCK` wird aktiv

## 12. Sicht fuer Angreifer und Bediener

Das Domänenmodell muss aus zwei Blickwinkeln funktionieren:

### 12.1 Sicht des Angreifers

Ein Angreifer soll:
- einen klaren Parkaufbau erkennen
- lesbare Betriebswerte finden
- schreibbare, aber begrenzte Einflussmoeglichkeiten sehen
- nachvollziehbare Prozessfolgen beobachten

### 12.2 Sicht der Deckscrew

Die Betreiberseite braucht:
- saubere Korrelation von Ursache und Wirkung
- klare Alarmgrenzen
- testbare Zustandsuebergaenge
- stabile Grundlage fuer Export und Benachrichtigung

## 13. Fachliche Namenskonventionen

Das Modell sollte generische, aber konsistente Kennungen verwenden.

Beispiele:
- `site-01`
- `ppc-01`
- `invb-01`
- `invb-02`
- `invb-03`
- `wx-01`
- `meter-01`
- `grid-01`
- `trk-01`

Warum das sinnvoll ist:
- leicht in HMI, Modbus und Logs wiederverwendbar
- nicht an reale Hersteller gebunden
- gut fuer Testdaten und Korrelation

## 14. Konfigurierbare Domänenwerte

Ein Teil des Domänenmodells soll spaeter konfigurierbar sein, ohne die
Fachstruktur zu aendern.

Geeignete Parameter:
- `CAPACITY_MW`
- `INVERTER_BLOCK_COUNT`
- `ENABLE_TRACKER`
- `DEFAULT_POWER_LIMIT_PCT`
- `ALARM_THRESHOLD_LOW_OUTPUT_PCT`
- `TIMEZONE`

Nicht konfigurierbar im Sinne des Domänenmodells:
- grundlegende Existenz des `site`
- Grundbeziehung zwischen PPC, Blocks und Grid-Interconnect
- Trennung zwischen Event, Alert und Notification

## 15. Abgrenzung zu Protokoll und UI

Dieses Dokument legt **nicht** fest:
- welche Registeradressen genutzt werden
- welche HTTP-Routen existieren
- welche Response-Codes ein Protokoll liefert
- wie ein Hersteller-Layout aussieht

Diese Dinge gehoeren spaeter in:
- ein Protokollprofil
- ein HMI-Konzept
- technische Schnittstellendokumente

## 16. Testrelevante Fachinvarianten

Diese fachlichen Regeln sollten spaeter explizit getestet werden:

- Parkleistung kann nicht ueber laengere Zeit deutlich ueber verfuegbarem
  Wetterpotenzial liegen
- geoeffneter Breaker reduziert Export sichtbar
- Kommunikationsverlust fuehrt nicht automatisch zu denselben Effekten wie
  echte Leistungsreduktion
- Quittierung eines Alarms setzt den Prozess nicht automatisch zurueck
- Setpoint-Aenderung muss in Anlage, HMI und Eventspur konsistent erscheinen

## 17. Sicherheitsrelevante Hinweise

Das Domänenmodell darf nicht unbemerkt in gefaehrliche Richtung wachsen.

Besonders kritisch waere:
- Nachbildung echter OEM-spezifischer Schutzlogik
- zu detaillierte Nachbildung realer Fernwirkpfade
- Vermischung von fachlicher Simulation und Host-Kontrolle
- unklare oder widerspruechliche Fehlerzustände

Die Fachseite muss glaubhaft sein, aber unter voller Kontrolle der Deckscrew
bleiben.

## 18. Offene Punkte

Diese Punkte sind fuer die naechste Dokumentationsrunde offen:

- wie fein die Inverter-Bloecke intern weiter unterteilt werden
- welche Alarmgrenzen fuer `LOW_SITE_OUTPUT_UNEXPECTED` gelten
- welche Betriebsmodi der PPC exakt anbietet
- welche Setpoints schreibbar und welche nur scheinbar schreibbar sind

## 19. Kurzfazit

Das Domänenmodell bildet einen kleinen, aber glaubhaften Solarpark mit klarer
Wurzelstruktur, sichtbarer Prozesswirkung und kontrollierten Bedienpfaden ab.
Es ist damit die fachliche Grundlage fuer Protokollprofil, HMI, Logging,
Benachrichtigung und spaetere Tests.
