# SCADA Primer And Module Guide

## SCADA In One Paragraph

SCADA means Supervisory Control And Data Acquisition. In this project, the HMI
is the browser-based operator-style frontend, Modbus is the industrial protocol
surface, and the Ops backend is the protected operator backend for maintaining
the honeypot.

## How To Approach The Honeypot

For a test attacker, start with:

- HMI `/overview`
- HMI `/robots.txt`
- HMI `/service/login`
- Modbus Unit `1`
- Modbus Units `11` to `13`

## Important Components

| Module | Role |
| --- | --- |
| `config_core` | loads and validates runtime config |
| `asset_domain` | typed plant state |
| `plant_sim` | process effects and alarms |
| `runtime_evolution` | clock-driven trends and weather |
| `protocol_modbus` | Modbus/TCP endpoint |
| `hmi_web` | attacker-facing HMI frontend |
| `ops_web` | protected operator backend |
| `storage` | SQLite/WAL persistence |
| `event_core` | events, alerts, outbox records |
| `exporter_runner` | Webhook, SMTP, Telegram delivery |

## Shared Truth

The HMI and Modbus do not maintain separate state. If you open the breaker in
the HMI, Modbus and meter views must reflect the same grid path. If you write a
setpoint over Modbus, the HMI must show the same effect.

## Safe Test Actions

- change active-power limit
- change reactive-power target
- latch a plant-mode request
- open or close the breaker
- disable or enable an inverter block
- change block power limit
- open or close a PV/DC disconnect
- request a block reset

All actions stay inside the simulated plant.
