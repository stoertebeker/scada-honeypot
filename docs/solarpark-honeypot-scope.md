# Solar Plant Honeypot Scope

## In Scope

- fictional solar plant identity
- HMI frontend
- Modbus/TCP endpoint
- service-login lure
- bounded service controls
- Ops backend
- event and alert logging
- plant trends
- weather-driven realism
- controlled exporters

## Out Of Scope

- real OEM branding
- real plant control
- real OT connectivity
- real user credentials
- shell access lures
- exploit payload hosting
- malware execution

## Plant Model

The fictional plant contains:

- one site
- one power plant controller
- several inverter blocks
- one grid interconnect
- one revenue meter
- weather context

## Attacker Paths

Expected test behavior:

- browse the HMI
- attempt service login
- use the service panel after successful lure login
- read and write Modbus registers
- trigger alarms through simulated actions

Every meaningful action should leave a useful forensic trace.
