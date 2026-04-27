# Registermatrix V1: Modbus/TCP fuer den Solarpark-Honeypot

## 1. Zweck dieses Dokuments

Dieses Dokument uebersetzt das Protokollprofil in eine konkrete V1-
Registermatrix. Es beschreibt, welche Holding Registers pro Unit-ID sichtbar
sind, welche Datentypen und Skalierungen verwendet werden und welche Punkte
read-only oder schreibbar sind.

Die Matrix ist absichtlich:
- konkret genug fuer Implementierung und Tests
- klein genug fuer V1
- generisch genug, um keine echte OEM-Implementierung nachzubauen

## 2. Geltungsbereich

Diese Matrix gilt fuer:
- `Modbus/TCP`
- `Holding Registers (4xxxx)`
- Funktionscodes `03`, `06`, `16`

Nicht Teil dieser Matrix:
- `Input Registers (3xxxx)`
- `Coils`
- `Discrete Inputs`

V1-Entscheidung:
- `04 Read Input Registers` wird in der Default-Konfiguration **nicht**
  angeboten.
- Ein Aufruf mit `04` fuehrt in V1 zu `01 Illegal Function`.

## 3. Allgemeine Abbildungsregeln

### 3.1 Menschliche Adresssicht

Dieses Dokument verwendet die klassische menschliche Modbus-Notation `4xxxx`.

Interne Implementierungsregel:
- `internal_offset = register_address - 40001`

Beispiel:
- `40100` entspricht intern Offset `99`

### 3.2 V1-Namensraum

Alle V1-Daten liegen in vier logischen Bereichen je Unit-ID:

- `40001-40049` -> Identitaet
- `40100-40199` -> Messwerte und Status
- `40200-40249` -> Setpoints und Bedienhandlungen
- `40300-40349` -> Alarme und Diagnose

### 3.3 Unlisted/Reserved-Verhalten

V1 nutzt einen scan-freundlichen, aber kontrollierten Kurs:

- nicht gelistete Register **innerhalb** eines aktiven Blockbereichs gelten als
  `reserved`
- `reserved` Register liefern bei `FC03` den Wert `0x0000`
- Schreibzugriffe auf `reserved` Register fuehren zu `02 Illegal Data Address`
- Zugriffe auf Bereiche **ausserhalb** der definierten V1-Bloecke fuehren zu
  `02 Illegal Data Address`

### 3.4 Read-only und Schreibregeln

- `ro` -> nur lesen, Schreibzugriff fuehrt zu `02 Illegal Data Address`
- `rw-latched` -> Wert bleibt gesetzt, bis er fachlich geaendert wird
- `rw-pulse` -> Schreiben von `1` loest Aktion aus; Wert faellt innerhalb
  einer Simulationsrunde wieder auf `0`

### 3.5 Mehrregisterwerte

Fuer `s32` und `u32` gilt:
- High Word zuerst
- Low Word danach
- konsistent fuer alle Units

Beispiel:
- `40104-40105`
  - `40104` = high word
  - `40105` = low word

### 3.6 Skalierung

V1 verwendet nur wenige, klar erkennbare Skalierungsregeln:

- Suffix `_x10` -> Rohwert / 10
- Suffix `_x100` -> Rohwert / 100
- Suffix `_x1000` -> Rohwert / 1000

Wo kein Suffix genannt ist, gilt:
- Wert ist bereits in der angegebenen Einheit gespeichert

## 4. Gemeinsame Datentypen

- `u16` -> unsigned 16-bit
- `s16` -> signed 16-bit
- `u32` -> unsigned 32-bit
- `s32` -> signed 32-bit
- `ascii[8]` -> 8 ASCII-Zeichen, verteilt auf 4 Register, 2 Zeichen je
  Register

## 5. Gemeinsame Enum-Codes

### 5.1 `device_class_code`

| Wert | Bedeutung |
| --- | --- |
| `1001` | site / power_plant_controller |
| `1101` | inverter_block |
| `1201` | weather_station |
| `1301` | revenue_meter |
| `1401` | grid_interconnect |
| `1501` | tracker_controller |

### 5.2 `asset_status`

| Wert | Bedeutung |
| --- | --- |
| `0` | online |
| `1` | offline |
| `2` | degraded |
| `3` | faulted |

### 5.3 `communication_state`

| Wert | Bedeutung |
| --- | --- |
| `0` | healthy |
| `1` | degraded |
| `2` | lost |

### 5.4 `data_quality`

| Wert | Bedeutung |
| --- | --- |
| `0` | good |
| `1` | estimated |
| `2` | stale |
| `3` | invalid |

### 5.5 `operating_mode`

| Wert | Bedeutung |
| --- | --- |
| `0` | normal |
| `1` | curtailed |
| `2` | maintenance |
| `3` | faulted |

### 5.6 `availability_state`

| Wert | Bedeutung |
| --- | --- |
| `0` | available |
| `1` | partially_available |
| `2` | unavailable |

### 5.7 `breaker_state`

| Wert | Bedeutung |
| --- | --- |
| `0` | closed |
| `1` | open |
| `2` | transitioning |

### 5.8 `dc_disconnect_state`

| Wert | Bedeutung |
| --- | --- |
| `0` | closed |
| `1` | open |
| `2` | transitioning |

### 5.9 `alarm_state`

| Wert | Bedeutung |
| --- | --- |
| `0` | inactive |
| `1` | active_unacknowledged |
| `2` | active_acknowledged |
| `3` | cleared |

### 5.10 `severity_code`

| Wert | Bedeutung |
| --- | --- |
| `0` | none |
| `1` | low |
| `2` | medium |
| `3` | high |
| `4` | critical |

### 5.11 `control_authority`

| Wert | Bedeutung |
| --- | --- |
| `0` | local_auto |
| `1` | remote_scada |
| `2` | schedule |

### 5.12 `grid_acceptance_state`

| Wert | Bedeutung |
| --- | --- |
| `0` | accepted |
| `1` | limited |
| `2` | unavailable |

### 5.13 `tracking_mode`

| Wert | Bedeutung |
| --- | --- |
| `0` | tracking |
| `1` | fixed |
| `2` | stow |

### 5.14 `boolean_flag`

| Wert | Bedeutung |
| --- | --- |
| `0` | false |
| `1` | true |

### 5.15 `command_request`

| Wert | Bedeutung |
| --- | --- |
| `0` | idle |
| `1` | execute |

## 6. Unit-ID-Uebersicht

| Unit-ID | Asset | Device Class | Asset Tag |
| --- | --- | --- | --- |
| `1` | site / power_plant_controller | `1001` | `ppc-01` |
| `11` | inverter_block_01 | `1101` | `invb-01` |
| `12` | inverter_block_02 | `1101` | `invb-02` |
| `13` | inverter_block_03 | `1101` | `invb-03` |
| `21` | weather_station | `1201` | `wx-01` |
| `31` | revenue_meter | `1301` | `meter-01` |
| `41` | grid_interconnect | `1401` | `grid-01` |
| `51` | tracker_controller, optional | `1501` | `trk-01` |

## 7. Gemeinsamer Identitaetsblock

Dieser Block gilt fuer **jede** aktive Unit-ID.

| Register | Name | Typ | Zugriff | Inhalt / Regel |
| --- | --- | --- | --- | --- |
| `40001` | `profile_version` | `u16` | `ro` | V1-Profilversion, Startwert `100` |
| `40002` | `device_class_code` | `u16` | `ro` | gemaess Tabelle `device_class_code` |
| `40003` | `unit_id_echo` | `u16` | `ro` | spiegelt die aktive Unit-ID |
| `40004` | `asset_instance` | `u16` | `ro` | `1`, `2`, `3` oder `0` fuer aggregierte Geraete |
| `40005-40008` | `asset_tag_ascii` | `ascii[8]` | `ro` | kurzer Asset-Tag wie `ppc-01` |

Regel fuer `40009-40049`:
- `reserved`
- lesbar als `0x0000`
- nicht schreibbar

## 8. Unit 1: `site / power_plant_controller`

### 8.1 Messwerte und Status

| Register | Name | Typ | Zugriff | Einheit / Enum | Domaenenbezug |
| --- | --- | --- | --- | --- | --- |
| `40100` | `operating_mode` | `u16` | `ro` | `operating_mode` | `site_state.operating_mode` |
| `40101` | `availability_state` | `u16` | `ro` | `availability_state` | `site_state.availability_state` |
| `40102` | `communications_health` | `u16` | `ro` | `communication_state` | `site_state.communications_health` |
| `40103` | `control_authority` | `u16` | `ro` | `control_authority` | `ppc.control_authority` |
| `40104-40105` | `plant_power_kw` | `s32` | `ro` | `kW` | abgeleitet aus `plant_power_mw` |
| `40106-40107` | `plant_energy_kwh_today` | `u32` | `ro` | `kWh` | `plant_energy_mwh_today * 1000` |
| `40108` | `plant_availability_pct_x10` | `u16` | `ro` | `% x10` | `plant_availability_pct` |
| `40109` | `breaker_state` | `u16` | `ro` | `breaker_state` | `site_state.breaker_state` |
| `40110` | `reactive_power_target_pct_x10` | `s16` | `ro` | `% x10` | `reactive_power_setpoint` |
| `40111` | `active_alarm_count` | `u16` | `ro` | count | `site_state.active_alarm_count` |

### 8.2 Setpoints und Bedienhandlungen

| Register | Name | Typ | Zugriff | Wertebereich | Domaenenbezug / Regel |
| --- | --- | --- | --- | --- | --- |
| `40200` | `active_power_limit_pct_x10` | `u16` | `rw-latched` | `0..1000` | `active_power_limit_pct` |
| `40201` | `reactive_power_target_pct_x10` | `s16` | `rw-latched` | `-1000..1000` | `reactive_power_target` |
| `40202` | `plant_mode_request` | `u16` | `rw-latched` | `0..2` | `0=normal`, `1=curtailed`, `2=maintenance` |

Regeln:
- Wert `3` auf `40202` ist in V1 nicht schreibbar und fuehrt zu
  `03 Illegal Data Value`
- Bereich `40203-40249` ist `reserved`

### 8.3 Alarme und Diagnose

| Register | Name | Typ | Zugriff | Einheit / Enum | Domaenenbezug |
| --- | --- | --- | --- | --- | --- |
| `40300` | `primary_alarm_code` | `u16` | `ro` | code | fuehrender aktiver Alarm |
| `40301` | `primary_alarm_severity` | `u16` | `ro` | `severity_code` | Severity des fuehrenden Alarms |
| `40302` | `alarm_plant_curtailed_state` | `u16` | `ro` | `alarm_state` | `PLANT_CURTAILED` |
| `40303` | `alarm_breaker_open_state` | `u16` | `ro` | `alarm_state` | `BREAKER_OPEN` |
| `40304` | `alarm_low_site_output_state` | `u16` | `ro` | `alarm_state` | `LOW_SITE_OUTPUT_UNEXPECTED` |
| `40305` | `alarm_multi_block_unavailable_state` | `u16` | `ro` | `alarm_state` | `MULTI_BLOCK_UNAVAILABLE` |

## 9. Unit 11-13: `inverter_block_*`

Die drei Inverter-Units nutzen dieselbe Matrix. Unterschiede liegen nur in:
- `unit_id_echo`
- `asset_instance`
- `asset_tag_ascii`
- den dynamischen Zustandswerten

### 9.1 Messwerte und Status

| Register | Name | Typ | Zugriff | Einheit / Enum | Domaenenbezug |
| --- | --- | --- | --- | --- | --- |
| `40100` | `block_status` | `u16` | `ro` | `asset_status` | `status` |
| `40101` | `communication_state` | `u16` | `ro` | `communication_state` | `communication_state` |
| `40102` | `data_quality` | `u16` | `ro` | `data_quality` | `quality` |
| `40103` | `availability_pct_x10` | `u16` | `ro` | `% x10` | `availability_pct` |
| `40104-40105` | `block_power_kw` | `s32` | `ro` | `kW` | `block_power_kw` |
| `40106` | `block_dc_voltage_v_x10` | `u16` | `ro` | `V x10` | `block_dc_voltage_v` |
| `40107` | `block_dc_current_a_x10` | `u16` | `ro` | `A x10` | `block_dc_current_a` |
| `40108` | `block_ac_voltage_v_x10` | `u16` | `ro` | `V x10` | `block_ac_voltage_v` |
| `40109` | `block_ac_current_a_x10` | `u16` | `ro` | `A x10` | `block_ac_current_a` |
| `40110` | `internal_temperature_c_x10` | `s16` | `ro` | `C x10` | `internal_temperature_c` |
| `40111` | `local_alarm_count` | `u16` | `ro` | count | lokale Alarmanzahl |
| `40112` | `dc_disconnect_state` | `u16` | `ro` | `dc_disconnect_state` | `dc_disconnect_state` |

### 9.2 Setpoints und Bedienhandlungen

| Register | Name | Typ | Zugriff | Wertebereich | Domaenenbezug / Regel |
| --- | --- | --- | --- | --- | --- |
| `40200` | `block_enable_request` | `u16` | `rw-latched` | `0..1` | `0=disable`, `1=enable` |
| `40201` | `block_power_limit_pct_x10` | `u16` | `rw-latched` | `0..1000` | `block_power_limit_pct` |
| `40202` | `block_reset_request` | `u16` | `rw-pulse` | `0..1` | `1` loest simulierten Reset aus |
| `40203` | `dc_disconnect_request` | `u16` | `rw-latched` | `0..1` | `0=closed`, `1=open` |

Regeln:
- Schreiben anderer Werte als `0` oder `1` auf `40200`, `40202` oder `40203`
  fuehrt zu `03 Illegal Data Value`
- Bereich `40204-40249` ist `reserved`

### 9.3 Alarme und Diagnose

| Register | Name | Typ | Zugriff | Einheit / Enum | Domaenenbezug |
| --- | --- | --- | --- | --- | --- |
| `40300` | `primary_alarm_code` | `u16` | `ro` | code | fuehrender lokaler Alarm |
| `40301` | `primary_alarm_severity` | `u16` | `ro` | `severity_code` | Severity des fuehrenden Alarms |
| `40302` | `alarm_comm_loss_state` | `u16` | `ro` | `alarm_state` | Kommunikationsverlust |
| `40303` | `alarm_block_fault_state` | `u16` | `ro` | `alarm_state` | Blockfehler |
| `40304` | `alarm_block_unavailable_state` | `u16` | `ro` | `alarm_state` | Block nicht verfuegbar |
| `40305` | `alarm_overtemp_state` | `u16` | `ro` | `alarm_state` | interne Uebertemperatur |

## 10. Unit 21: `weather_station`

### 10.1 Messwerte und Status

| Register | Name | Typ | Zugriff | Einheit / Enum | Domaenenbezug |
| --- | --- | --- | --- | --- | --- |
| `40100` | `station_status` | `u16` | `ro` | `asset_status` | `status` |
| `40101` | `communication_state` | `u16` | `ro` | `communication_state` | `communication_state` |
| `40102` | `data_quality` | `u16` | `ro` | `data_quality` | `quality` |
| `40103` | `irradiance_w_m2` | `u16` | `ro` | `W/m2` | `irradiance_w_m2` |
| `40104` | `module_temperature_c_x10` | `s16` | `ro` | `C x10` | `module_temperature_c` |
| `40105` | `ambient_temperature_c_x10` | `s16` | `ro` | `C x10` | `ambient_temperature_c` |
| `40106` | `wind_speed_m_s_x10` | `u16` | `ro` | `m/s x10` | `wind_speed_m_s` |
| `40107` | `weather_confidence_pct_x10` | `u16` | `ro` | `% x10` | simulierte Datenqualitaet |

### 10.2 Setpoints und Bedienhandlungen

V1-Regel:
- `40200-40249` sind fuer Unit `21` **nicht implementiert**
- Lesen oder Schreiben in diesem Bereich fuehrt zu `02 Illegal Data Address`

### 10.3 Alarme und Diagnose

| Register | Name | Typ | Zugriff | Einheit / Enum | Domaenenbezug |
| --- | --- | --- | --- | --- | --- |
| `40300` | `primary_alarm_code` | `u16` | `ro` | code | fuehrender lokaler Alarm |
| `40301` | `primary_alarm_severity` | `u16` | `ro` | `severity_code` | Severity des fuehrenden Alarms |
| `40302` | `alarm_comm_loss_state` | `u16` | `ro` | `alarm_state` | Kommunikationsverlust Wetterstation |

## 11. Unit 31: `revenue_meter`

### 11.1 Messwerte und Status

| Register | Name | Typ | Zugriff | Einheit / Enum | Domaenenbezug |
| --- | --- | --- | --- | --- | --- |
| `40100` | `meter_status` | `u16` | `ro` | `asset_status` | `status` |
| `40101` | `communication_state` | `u16` | `ro` | `communication_state` | `communication_state` |
| `40102` | `data_quality` | `u16` | `ro` | `data_quality` | `quality` |
| `40103-40104` | `export_power_kw` | `s32` | `ro` | `kW` | `export_power_kw` |
| `40105-40106` | `export_energy_kwh_total` | `u32` | `ro` | `kWh` | `export_energy_mwh_total * 1000` |
| `40107` | `grid_voltage_v_x10` | `u16` | `ro` | `V x10` | `grid_voltage_v` |
| `40108` | `grid_frequency_hz_x100` | `u16` | `ro` | `Hz x100` | `grid_frequency_hz` |
| `40109` | `power_factor_x1000` | `s16` | `ro` | `pf x1000` | `power_factor` |
| `40110` | `export_path_available` | `u16` | `ro` | `boolean_flag` | abgeleitet aus Grid-Interconnect |

### 11.2 Setpoints und Bedienhandlungen

V1-Regel:
- `40200-40249` sind fuer Unit `31` **nicht implementiert**
- Lesen oder Schreiben in diesem Bereich fuehrt zu `02 Illegal Data Address`

### 11.3 Alarme und Diagnose

| Register | Name | Typ | Zugriff | Einheit / Enum | Domainenbezug |
| --- | --- | --- | --- | --- | --- |
| `40300` | `primary_alarm_code` | `u16` | `ro` | code | fuehrender lokaler Alarm |
| `40301` | `primary_alarm_severity` | `u16` | `ro` | `severity_code` | Severity des fuehrenden Alarms |
| `40302` | `alarm_breaker_open_state` | `u16` | `ro` | `alarm_state` | abgeleitet aus `BREAKER_OPEN` |
| `40303` | `alarm_comm_loss_state` | `u16` | `ro` | `alarm_state` | Kommunikationsverlust Meter |

## 12. Unit 41: `grid_interconnect`

### 12.1 Messwerte und Status

| Register | Name | Typ | Zugriff | Einheit / Enum | Domainenbezug |
| --- | --- | --- | --- | --- | --- |
| `40100` | `grid_status` | `u16` | `ro` | `asset_status` | `status` |
| `40101` | `communication_state` | `u16` | `ro` | `communication_state` | `communication_state` |
| `40102` | `breaker_state` | `u16` | `ro` | `breaker_state` | `breaker_state` |
| `40103` | `export_path_available` | `u16` | `ro` | `boolean_flag` | `export_path_available` |
| `40104` | `grid_acceptance_state` | `u16` | `ro` | `grid_acceptance_state` | `grid_acceptance_state` |

### 12.2 Setpoints und Bedienhandlungen

| Register | Name | Typ | Zugriff | Wertebereich | Domaenenbezug / Regel |
| --- | --- | --- | --- | --- | --- |
| `40200` | `breaker_open_request` | `u16` | `rw-pulse` | `0..1` | `1` fordert Oeffnen an |
| `40201` | `breaker_close_request` | `u16` | `rw-pulse` | `0..1` | `1` fordert Schliessen an |

Regeln:
- Wenn `40200` und `40201` in derselben `FC16`-Anfrage beide `1` erhalten,
  folgt `03 Illegal Data Value`
- Bereich `40202-40249` ist `reserved`

### 12.3 Alarme und Diagnose

| Register | Name | Typ | Zugriff | Einheit / Enum | Domaenenbezug |
| --- | --- | --- | --- | --- | --- |
| `40300` | `primary_alarm_code` | `u16` | `ro` | code | fuehrender lokaler Alarm |
| `40301` | `primary_alarm_severity` | `u16` | `ro` | `severity_code` | Severity des fuehrenden Alarms |
| `40302` | `alarm_breaker_open_state` | `u16` | `ro` | `alarm_state` | `BREAKER_OPEN` |
| `40303` | `alarm_export_path_unavailable_state` | `u16` | `ro` | `alarm_state` | Pfad nicht verfuegbar |

## 13. Unit 51: `tracker_controller` optional und in V1 standardmaessig aus

Diese Unit ist in der V1-Default-Konfiguration deaktiviert und nur aktiv,
wenn der Tracker bewusst zugeschaltet wurde.

Wenn der Tracker deaktiviert ist:
- Zugriffe auf Unit `51` fuehren bei `FC03`, `FC06` und `FC16` zu
  `02 Illegal Data Address`

### 13.1 Messwerte und Status

| Register | Name | Typ | Zugriff | Einheit / Enum | Domaenenbezug |
| --- | --- | --- | --- | --- | --- |
| `40100` | `tracker_status` | `u16` | `ro` | `asset_status` | `status` |
| `40101` | `communication_state` | `u16` | `ro` | `communication_state` | `communication_state` |
| `40102` | `tracking_mode` | `u16` | `ro` | `tracking_mode` | `tracking_mode` |
| `40103` | `stow_state` | `u16` | `ro` | `boolean_flag` | `stow_state` |
| `40104` | `position_state` | `u16` | `ro` | enum, projektspezifisch | `position_state` |

### 13.2 Setpoints und Bedienhandlungen

| Register | Name | Typ | Zugriff | Wertebereich | Domaenenbezug / Regel |
| --- | --- | --- | --- | --- | --- |
| `40200` | `tracking_enable_request` | `u16` | `rw-latched` | `0..1` | `0=disabled`, `1=enabled` |
| `40201` | `stow_request` | `u16` | `rw-pulse` | `0..1` | `1` fordert `stow` an |

### 13.3 Alarme und Diagnose

| Register | Name | Typ | Zugriff | Einheit / Enum | Domaenenbezug |
| --- | --- | --- | --- | --- | --- |
| `40300` | `primary_alarm_code` | `u16` | `ro` | code | fuehrender lokaler Alarm |
| `40301` | `primary_alarm_severity` | `u16` | `ro` | `severity_code` | Severity des fuehrenden Alarms |
| `40302` | `alarm_tracker_stow_state` | `u16` | `ro` | `alarm_state` | `TRACKER_STOW_ACTIVE` |
| `40303` | `alarm_comm_loss_state` | `u16` | `ro` | `alarm_state` | Kommunikationsverlust Tracker |

## 14. Alarmcode-Vorschlag fuer V1

Diese Codes sind bewusst generisch und stabil.

| Code | Alarm |
| --- | --- |
| `0` | none |
| `100` | COMM_LOSS_INVERTER_BLOCK |
| `110` | PLANT_CURTAILED |
| `120` | BREAKER_OPEN |
| `130` | LOW_SITE_OUTPUT_UNEXPECTED |
| `140` | REACTIVE_POWER_DEVIATION |
| `150` | TRACKER_STOW_ACTIVE |
| `160` | MULTI_BLOCK_UNAVAILABLE |
| `170` | BLOCK_OVERTEMP |
| `180` | GRID_PATH_UNAVAILABLE |

## 15. Fehlerverhalten fuer Schreibzugriffe

V1 legt folgende stabile Regeln fest:

- nicht unterstuetzter Funktionscode -> `01 Illegal Function`
- Bereich ausserhalb der Matrix -> `02 Illegal Data Address`
- Schreibzugriff auf `ro` oder `reserved` -> `02 Illegal Data Address`
- formal gueltige Adresse, aber ungueltiger Wert -> `03 Illegal Data Value`
- bewusst modellierte Uebergangssituation -> `06 Slave Device Busy`

Beispiele:
- Schreiben von `1500` auf `40200 active_power_limit_pct_x10` -> `03`
- Schreiben auf `40103 active_alarm_count` -> `02`
- Zugriff auf `40400` -> `02`
- `FC04` auf V1-Defaultsystem -> `01`

## 16. Logging-Anforderungen pro Registerzugriff

Jeder Registerzugriff soll mindestens diese Felder im Eventsystem tragen:

- `unit_id`
- `function_code`
- `register_start`
- `register_count`
- `value_encoding`
- `asset_id`
- `requested_value`
- `previous_value`
- `result`
- `exception_code`

Bei Mehrregisterzugriffen zusaetzlich:
- zusammenhaengende `correlation_id`
- normalisierte Fachbezeichnungen aller betroffenen Felder

## 17. Testpflichten fuer diese Matrix

Diese Registermatrix ist erst brauchbar, wenn sie direkt getestet wird.

Pflichttests:
- jede gelistete Adresse liefert Typ und Zugriff wie dokumentiert
- `reserved` Register liefern bei `FC03` konsistent `0x0000`
- `rw-pulse` Register self-clearen konsistent
- `rw-latched` Register bleiben ueber Polling hinweg stabil
- Mehrregisterwerte halten Wortreihenfolge ein
- HMI und Modbus spiegeln dieselben Werte fuer dieselbe Fachgroesse
- Schreibzugriffe erzeugen sichtbare Prozesswirkung und Eventspur

Besonders wichtig:
- Ein Angreifer darf durch kaputte Offsets, wechselnde Typen oder
  widerspruechliche Schreibrechte keinen Fingerabdruck fuer den Honeypot
  bekommen.

## 18. Offene Punkte nach dieser Matrix

Mit diesem Dokument sind folgende Punkte **vorlaeufig** entschieden:
- V1 nutzt nur `4xxxx`
- `FC04` ist in der Default-Konfiguration aus
- Wortreihenfolge fuer `u32` und `s32` ist festgelegt
- Schreibrechte sind fuer V1 eng begrenzt

Fuer spaeter offen:
- ob V2 zusaetzliche `3xxxx`-Spiegelungen bekommt
- ob bestimmte Alarmcodes feiner aufgeteilt werden
- ob Block 11-13 intern weitere Untergeraete simulieren sollen

## 19. Kurzfazit

Diese Registermatrix macht aus dem bisherigen Protokollprofil eine konkret
implementierbare und testbare V1-Abbildung. Sie ist klein genug fuer eine
kontrollierte erste Version, aber standardnah genug, damit Angreifer sich
schnell zurechtfinden und die Deckscrew saubere Contract-Tests fahren kann.
