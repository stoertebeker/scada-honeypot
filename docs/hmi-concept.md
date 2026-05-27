# HMI Concept

## Definition

HMI means Human-Machine Interface. In this project it is the attacker-facing
honeypot frontend. It is separate from the protected Ops backend.

## Pages

- `/overview`: plant summary
- `/single-line`: simplified electrical path
- `/inverters`: block state and power
- `/weather`: current weather context
- `/meter`: export and energy view
- `/alarms`: active alarms and recent historical alarm context
- `/trends`: plant-history charts
- `/service/login`: lure login
- `/service/panel`: bounded service controls after login
- `/robots.txt`: quiet service-login lure

The `/trends` page may show a short planned-maintenance context when the stored
history contains a seeded maintenance sample. This is derived from the shared
plant history and does not add a new HMI route or a live scheduler.

## Service Panel

The service panel supports bounded actions only:

- active-power limit
- reactive-power target
- plant-mode request
- breaker open/close request
- inverter block enable/disable
- inverter block power limit
- PV/DC disconnect
- block reset pulse
- service logout

Logout is a visible button in the service panel and is implemented as a
CSRF-protected `POST /service/logout`.

## Design Rules

- no OEM branding
- no real plant names
- no exact weather coordinates in the HMI
- no technical stack traces
- no debug routes or OpenAPI pages exposed to attackers
- no separate HMI state

## Localization

Only attacker-facing HMI text is localizable. Events, logs, register names, and
operator documentation stay stable and English.

## Security Notes

Service-login credentials are lure credentials. Configure them in the Ops
backend under `/settings`, not as real operator secrets.

When HTTPS is provided by a reverse proxy, set:

```env
HMI_COOKIE_SECURE=1
SERVICE_COOKIE_SECURE=1
```
