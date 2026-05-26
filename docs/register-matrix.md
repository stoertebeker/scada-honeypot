# Register Matrix

## Scope

This file summarizes the current Modbus register intent. The executable truth is
the register map in `protocol_modbus`.

## Identity Block, All Active Units

All active units expose a fictional identity block at holding-register offsets
`0..48` (`40001..40049`). It is designed to look like ordinary industrial
metadata without copying a real OEM profile.

| Offset | Meaning |
| --- | --- |
| `0` | profile schema version, currently `124` |
| `1` | fictional device-class code |
| `2` | Modbus unit ID |
| `3` | per-class instance number |
| `4..7` | eight-character ASCII asset tag |
| `8` | fictional family code |
| `9` | fictional model code |
| `10` | hardware revision encoded as `major * 100 + minor` |
| `11..13` | firmware major, minor, and patch |
| `14` | firmware build number |
| `15..16` | deterministic fictional serial segment |
| `17` | capability bitmap for the exposed V1 slice |
| `18..48` | reserved, currently `0` |

Current identity values:

| Unit | Role | Device Class | Tag | Family | Model | HW | FW | Serial | Capabilities |
| --- | --- | ---: | --- | ---: | ---: | ---: | --- | --- | ---: |
| `1` | plant controller | `4103` | `PPC-A01` | `7100` | `7112` | `213` | `3.7.4+1182` | `51026-1001` | `0x0007` |
| `11` | inverter block 1 | `4211` | `INV-B01` | `7200` | `7206` | `209` | `2.9.6+904` | `51026-2111` | `0x000f` |
| `12` | inverter block 2 | `4211` | `INV-B02` | `7200` | `7206` | `209` | `2.9.6+904` | `51026-2112` | `0x000f` |
| `13` | inverter block 3 | `4211` | `INV-B03` | `7200` | `7206` | `209` | `2.9.6+904` | `51026-2113` | `0x000f` |
| `21` | weather station | `4307` | `MET-A01` | `7300` | `7314` | `104` | `1.8.2+441` | `51026-3021` | `0x0001` |
| `31` | revenue meter | `4419` | `MTR-R01` | `7400` | `7421` | `315` | `4.2.1+226` | `51026-4031` | `0x0001` |
| `41` | grid interconnect | `4523` | `GRD-T01` | `7500` | `7508` | `226` | `3.4.8+1009` | `51026-5041` | `0x0005` |

No-OEM rule: identity values must stay fictional and internally consistent. Do
not copy real manufacturer names, order-code formats, serial-number schemes,
firmware strings, module IDs, MAC/OUI values, or exact device register maps.

## Plant Controller, Unit 1

- active-power limit
- reactive-power target
- plant-mode request
- current output
- alarm summary

Writable service setpoints use the same process path as the HMI service panel.

## Inverter Blocks, Units 11 To 13

Each block exposes:

- block status
- communication state
- block power
- block enable request
- block power limit
- reset pulse
- PV/DC disconnect state

## Weather, Unit 21

Weather registers expose derived weather values only. Exact configured
coordinates are not exposed.

## Revenue Meter, Unit 31

Meter values expose export power and export energy state derived from the shared
plant model.

## Grid Interconnect, Unit 41

Grid registers expose breaker state and export-path availability. Breaker
open/close requests affect HMI, meter, alarms, and events.

## Rule

If a register represents a value that is also shown in the HMI, both views must
agree after the same state transition.
