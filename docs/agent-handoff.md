# Agent-Handoff

Dieses Projekt bleibt bis auf weiteres in Dokumentations- und Planungsnaehe,
aber die fachliche Richtung ist klar genug fuer eine erste Umsetzung.

- Ziel: interaktiver SCADA-Honeypot fuer einen fiktiven Solarpark im
  einstelligen MW-Bereich
- V1-Architektur: modularer Monolith
- Primaere Aussenwirkung: `Modbus/TCP` plus schlanke Web-HMI
- Fachmodell, Registerprofil, Logging, Teststrategie und Security-Gates sind
  in `docs/` dokumentiert
- Angreifer-HMI ist pro Deployment lokalisierbar; Admin-Sicht und Logs bleiben
  deutsch
- Locale-Regel: `ll` oder `ll-RR`, Fallback `ll-RR -> ll -> ATTACKER_UI_FALLBACK_LOCALE`
- Locale-Ablage: `resources/locales/attacker-ui/<locale>.json`
- Default-Annahmen fuer V1: `Tracker` aus, `FC04` aus, kein sichtbarer
  Logout-Link
- Exporter laufen in V1 im selben Prozess, aber nur ueber entkoppelte
  Outbox-/Runner-Logik
- Keine OEM-Kopie, keine echten Orts-/Firmendaten, keine Shell, keine realen
  Fernsteuerpfade
- Logging ist Kernfunktion; jede sichtbare Fehlersituation braucht spaeter
  einen Test
- Vor Implementierung zuerst diese Karten lesen:
  `docs/solarpark-honeypot-scope.md`, `docs/architecture.md`,
  `docs/domain-model.md`, `docs/protocol-profile.md`,
  `docs/register-matrix.md`, `docs/hmi-concept.md`,
  `docs/logging-and-events.md`, `docs/testing-strategy.md`,
  `docs/security-operations.md`, `docs/implementation-roadmap.md`
