"""Minimale lokale Rule-Engine fuer eventgetriebene Alert-Ableitung."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol

from honeypot.event_core.models import AlertSeverity, AlertState, EventRecord

ALERT_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SETPOINT_ALERT_CODE = "SETPOINT_CHANGE_ACCEPTED"


@dataclass(frozen=True, slots=True)
class DerivedAlert:
    """Minimale Alert-Ableitung aus einem Event fuer spaetere Persistenz."""

    alarm_code: str
    severity: AlertSeverity
    state: AlertState = "active_unacknowledged"
    message: str | None = None


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Leichter Auswertungskontext ohne direkte Store-Abhaengigkeit."""

    current_state: Mapping[str, Any] = field(default_factory=dict)


class EventRule(Protocol):
    """Kleiner Vertrag fuer deterministische Event-zu-Alert-Regeln."""

    rule_id: str

    def evaluate(self, event: EventRecord, *, context: RuleContext) -> tuple[DerivedAlert, ...]:
        """Leitet 0..n Alerts aus einem Event ab."""


@dataclass(frozen=True, slots=True)
class SuccessfulSetpointChangeRule:
    """Leitet erfolgreiche Setpoint-Aenderungen mit Prozesswirkung in Alerts ueber."""

    rule_id: str = "successful_setpoint_change"

    def evaluate(self, event: EventRecord, *, context: RuleContext) -> tuple[DerivedAlert, ...]:
        del context
        if event.category != "process" or event.result != "accepted":
            return ()
        if not event.event_type.startswith("process.setpoint."):
            return ()
        if event.action == "set_plant_mode_request":
            return ()
        if event.alarm_code is not None:
            return ()
        if "control-path" not in event.tags:
            return ()

        return (
            DerivedAlert(
                alarm_code=SETPOINT_ALERT_CODE,
                severity="high",
                message=f"Erfolgreiche Setpoint-Aenderung: {event.action} auf {event.asset_id}",
            ),
        )


@dataclass(slots=True)
class RuleEngine:
    """Registry und deterministische Auswertung fuer lokale Event-Regeln."""

    min_severity: AlertSeverity = "low"
    _rules: dict[str, EventRule] = field(default_factory=dict, init=False, repr=False)

    @classmethod
    def default_v1(cls, *, min_severity: AlertSeverity = "medium") -> "RuleEngine":
        engine = cls(min_severity=min_severity)
        engine.register(SuccessfulSetpointChangeRule())
        return engine

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(self._rules)

    def register(self, rule: EventRule) -> None:
        if rule.rule_id in self._rules:
            raise ValueError(f"Rule-ID bereits registriert: {rule.rule_id}")
        self._rules[rule.rule_id] = rule

    def evaluate(
        self,
        event: EventRecord,
        *,
        context: RuleContext | None = None,
    ) -> tuple[DerivedAlert, ...]:
        resolved_context = RuleContext() if context is None else context
        collected: list[DerivedAlert] = []
        seen: set[tuple[str, AlertSeverity, AlertState, str | None]] = set()

        for rule in self._rules.values():
            for derived_alert in rule.evaluate(event, context=resolved_context):
                if ALERT_SEVERITY_ORDER[derived_alert.severity] < ALERT_SEVERITY_ORDER[self.min_severity]:
                    continue
                dedupe_key = (
                    derived_alert.alarm_code,
                    derived_alert.severity,
                    derived_alert.state,
                    derived_alert.message,
                )
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                collected.append(derived_alert)

        return tuple(collected)
