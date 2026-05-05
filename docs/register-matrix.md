# Register Matrix

## Scope

This file summarizes the current Modbus register intent. The executable truth is
the register map in `protocol_modbus`.

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
