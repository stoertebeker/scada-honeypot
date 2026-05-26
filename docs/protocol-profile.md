# Protocol Profile

## External Surfaces

- Modbus/TCP for register-oriented OT interaction
- HTTP HMI frontend for browser-based attacker interaction
- protected HTTP Ops backend on host loopback

## Modbus/TCP

Default public host port: `1502`

Supported core functions:

- `FC03` Read Holding Registers
- `FC06` Write Single Register
- `FC16` Write Multiple Registers

`FC04` remains disabled by default.

### Response Timing

Modbus responses are immediate by default. Optional response timing can be
enabled with `MODBUS_RESPONSE_DELAY_MIN_MS` and
`MODBUS_RESPONSE_DELAY_MAX_MS`.

- Default `0/0` disables the delay.
- Values are validated in the range `0..2000` milliseconds.
- `MODBUS_RESPONSE_DELAY_MIN_MS` must not exceed
  `MODBUS_RESPONSE_DELAY_MAX_MS`.
- When enabled, the server applies a deterministic bounded delay per response
  before sending the Modbus ADU. It does not create background peer traffic.

## Unit Intent

- Unit `1`: plant controller values and setpoints
- Units `11` to `13`: inverter block views and block controls
- Unit `21`: weather and irradiance view
- Unit `31`: revenue meter view
- Unit `41`: grid interconnect and breaker controls

## HTTP HMI

The HMI is not an OEM clone. It is a generic but plausible operator screen for a
fictional solar plant. It must reflect the same state as Modbus.

Important routes:

- `/overview`
- `/single-line`
- `/inverters`
- `/weather`
- `/meter`
- `/alarms`
- `/trends`
- `/service/login`
- `/service/panel`
- `/service/logout`

## Consistency Requirements

- Modbus writes produce the same visible effects as HMI service actions.
- HMI service actions produce event records and process effects.
- Error paths are quiet and generic.
- No OpenAPI, debug, stack-trace, or framework fingerprinting routes are exposed.
