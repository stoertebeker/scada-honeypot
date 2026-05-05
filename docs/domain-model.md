# Domain Model

## Purpose

The domain model is the shared truth for the solar-plant honeypot. HMI, Modbus,
Ops, alerts, trends, and exporters must read from or write through this model.

## Core Objects

- site: name, code, capacity, current output, active alarms
- power plant controller: active-power limit, reactive-power target, mode request
- inverter blocks: status, communication state, power, limits, DC disconnect
- grid interconnect: breaker state and export-path availability
- revenue meter: export power and export energy
- weather: irradiance, cloud cover, temperature, wind, provider metadata

## Process Effects

The simulator makes operator actions visible:

- active-power limits reduce output
- breaker open isolates export
- inverter communication loss reduces availability
- block power limits reduce block contribution
- PV/DC disconnect separates a block from DC input
- reset can recover simulated block communication loss

## Time and Weather

The runtime evolves over time. The model uses the configured timezone and can use
deterministic weather or Open-Meteo weather providers. Exact configured
coordinates are never shown in the attacker-facing HMI.

## Alarm Intent

Alarms are part of the lure and the forensic trail. Examples:

- repeated service-login failures
- breaker open
- grid path unavailable
- unexpected low site output
- inverter communication loss
- multiple blocks unavailable

## Consistency Rule

If a value is visible in more than one place, it must agree:

- HMI overview and Modbus registers
- inverter page and block Unit IDs
- meter page and grid state
- alert page and event store
- Ops event view and persisted records
