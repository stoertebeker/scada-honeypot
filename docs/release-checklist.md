# Release-Checkliste V1: Lokaler Labor-Release

## Zweck

Diese Checkliste gilt fuer den **ersten lokalen V1-Release** des
Solarpark-Honeypots.

Sie ist **keine** Freigabe fuer `pre-exposure` oder fuer eine echte
Internet-Exponierung. Dafuer gelten zusaetzlich
[security-operations.md](/Users/schrammn/Documents/VSCodium/scada-honeypot/docs/security-operations.md)
und die dort beschriebenen Sicherheitsgates.

## Scope des ersten V1-Releases

Der erste Release gilt als ausreichend, wenn:

- der lokale Runtime-Pfad startbar ist
- Modbus, HMI und Service-Panel auf derselben Wahrheit laufen
- Logging, Alert-Store und Outbox sauber schreiben
- Webhook, SMTP und Telegram kontrolliert liefern oder ruhig in Retry fallen
- die Kern- und Release-Gates gruen sind

Nicht Teil dieses Releases:

- `pre-exposure`
- Internet-Exponierung
- weitere Protokolle ausser `Modbus/TCP` und HTTP-HMI
- weitere HMI-Seiten oder Modbus-Units ausserhalb des dokumentierten V1-Slices

## Pflichtchecks vor Go

1. Testgesamtlauf:
   `uv run pytest -q`

2. Lokaler Runtime-Start:
   `uv run python -m honeypot.main`

3. Sichtprobe nach Runtime-Start:
   - HMI auf `http://127.0.0.1:8080/overview` erreichbar
   - Modbus auf `127.0.0.1:1502` erreichbar
   - keine Framework-Fehlerseite sichtbar

4. Sicherheitsgrenzen:
   - `MODBUS_BIND_HOST=127.0.0.1`
   - `HMI_BIND_HOST=127.0.0.1`
   - keine echte Fernsteuerung externer Systeme
   - keine realen Identitaetsmerkmale im Deployment

5. Recovery-/Stabilitaetsgates:
   - Exporter-Ausfall bleibt intern in der Outbox
   - HMI und Modbus bleiben unter Retry-/Recovery-Lagen stabil
   - Folge-Alerts fluten `alert_log` und Outbox nicht

6. Reset-Pfad bekannt:
   - `uv run python -m honeypot.main --reset-runtime`
   - entfernt lokale Runtime-Artefakte fuer einen frischen Neustart

## Go/No-Go

`GO` nur wenn:

- alle Tests gruen sind
- der lokale Runtime-Start funktioniert
- die HMI ruhig wirkt
- Modbus korrekt antwortet
- Exporter-Fehler keine sichtbaren Client-Leaks erzeugen

`NO-GO` wenn mindestens eines davon auftritt:

- rote Tests
- HMI-/Modbus-Widerspruch
- Framework-/Traceback-Leckage
- Exporter-Fehlertext in HMI oder Modbus
- Bindung auf unerwuenschte Interfaces

## Klarer Kurs nach diesem Release

Nach diesem lokalen V1-Release sind zwei Richtungen sauber getrennt:

1. Produktpflege im Labor:
   - weitere Rule-/Exporter-Feinschnitte
   - weitere HMI-/Modbus-Slices

2. Sicherheitskurs Richtung `pre-exposure`:
   - Monitoring aktivieren und den lokalen Heartbeat unter
     `RUNTIME_STATUS_PATH` pruefen
   - Reset-Prozess ueber `uv run python -m honeypot.main --reset-runtime`
     validieren
   - Egress-Kontrolle
   - letzte bewusste Sicherheitsfreigabe
