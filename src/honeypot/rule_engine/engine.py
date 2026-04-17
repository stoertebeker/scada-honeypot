"""Minimale lokale Rule-Engine fuer eventgetriebene Alert-Ableitung."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol

from honeypot.event_core.models import AlertRecord, AlertSeverity, AlertState, EventRecord

ALERT_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SETPOINT_ALERT_CODE = "SETPOINT_CHANGE_ACCEPTED"
REPEATED_LOGIN_FAILURE_ALERT_CODE = "REPEATED_LOGIN_FAILURE"
COMM_LOSS_ALERT_CODE = "COMM_LOSS_INVERTER_BLOCK"
MULTI_BLOCK_UNAVAILABLE_ALERT_CODE = "MULTI_BLOCK_UNAVAILABLE"
GRID_PATH_UNAVAILABLE_ALERT_CODE = "GRID_PATH_UNAVAILABLE"
SITE_AGGREGATE_ASSET_ID = "site"
LOGIN_FAILURE_THRESHOLD = 3
MULTI_BLOCK_UNAVAILABLE_THRESHOLD = 2


@dataclass(frozen=True, slots=True)
class DerivedAlert:
    """Minimale Alert-Ableitung aus einem Event fuer spaetere Persistenz."""

    alarm_code: str
    severity: AlertSeverity
    state: AlertState = "active_unacknowledged"
    message: str | None = None
    asset_id: str | None = None


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Leichter Auswertungskontext ohne direkte Store-Abhaengigkeit."""

    current_state: Mapping[str, Any] = field(default_factory=dict)
    alert_history: tuple[AlertRecord, ...] = ()


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


@dataclass(frozen=True, slots=True)
class BreakerOpenRule:
    """Leitet einen Alert aus sichtbaren Breaker-Open-Prozessereignissen ab."""

    rule_id: str = "breaker_open"

    def evaluate(self, event: EventRecord, *, context: RuleContext) -> tuple[DerivedAlert, ...]:
        del context
        if event.result != "accepted":
            return ()
        if event.event_type != "process.breaker.state_changed":
            return ()
        if event.action != "breaker_open_request":
            return ()
        if event.resulting_value != "open":
            return ()

        return (
            DerivedAlert(
                alarm_code="BREAKER_OPEN",
                severity="high",
                message=f"Breaker open isoliert Exportpfad auf {event.asset_id}",
            ),
        )


@dataclass(frozen=True, slots=True)
class InverterCommLossRule:
    """Leitet einen Alert aus Kommunikationsverlust eines Inverter-Blocks ab."""

    rule_id: str = "inverter_comm_loss"

    def evaluate(self, event: EventRecord, *, context: RuleContext) -> tuple[DerivedAlert, ...]:
        del context
        if event.result != "accepted":
            return ()
        if event.event_type != "system.communication.inverter_block_lost":
            return ()
        if event.action != "simulate_comm_loss":
            return ()
        if event.resulting_value != "lost":
            return ()

        return (
            DerivedAlert(
                alarm_code=COMM_LOSS_ALERT_CODE,
                severity="medium",
                message=f"Kommunikationsverlust fuer Inverter-Block {event.asset_id}",
            ),
        )


@dataclass(frozen=True, slots=True)
class MultiBlockUnavailableRule:
    """Eskaliert auf Site-Ebene, wenn mehrere Block-Kommunikationsverluste gleichzeitig aktiv sind."""

    threshold: int = MULTI_BLOCK_UNAVAILABLE_THRESHOLD
    aggregate_asset_id: str = SITE_AGGREGATE_ASSET_ID
    rule_id: str = "multi_block_unavailable"

    def evaluate(self, event: EventRecord, *, context: RuleContext) -> tuple[DerivedAlert, ...]:
        if event.result != "accepted":
            return ()
        if event.event_type != "system.communication.inverter_block_lost":
            return ()
        if event.action != "simulate_comm_loss":
            return ()
        if event.resulting_value != "lost":
            return ()

        active_block_assets = {
            alert.asset_id
            for alert in context.alert_history
            if alert.alarm_code == COMM_LOSS_ALERT_CODE and alert.state != "cleared"
        }
        if event.asset_id in active_block_assets:
            return ()

        total_affected_blocks = active_block_assets | {event.asset_id}
        if len(total_affected_blocks) < self.threshold:
            return ()

        return (
            DerivedAlert(
                alarm_code=MULTI_BLOCK_UNAVAILABLE_ALERT_CODE,
                severity="critical",
                message="Mehrere Inverter-Bloecke gleichzeitig nicht verfuegbar",
                asset_id=self.aggregate_asset_id,
            ),
        )


@dataclass(frozen=True, slots=True)
class GridPathUnavailableRule:
    """Eskaliert sichtbare Breaker-Open/Close-Ereignisse auf den Exportpfadzustand."""

    rule_id: str = "grid_path_unavailable"

    def evaluate(self, event: EventRecord, *, context: RuleContext) -> tuple[DerivedAlert, ...]:
        if event.result != "accepted":
            return ()
        if event.event_type != "process.breaker.state_changed":
            return ()

        grid_state = context.current_state.get("grid_interconnect", {})
        if not isinstance(grid_state, Mapping):
            return ()

        message = f"Exportpfad nicht verfuegbar auf {event.asset_id}"
        if event.action == "breaker_open_request" and event.resulting_value == "open":
            if grid_state.get("export_path_available") is not False:
                return ()
            return (
                DerivedAlert(
                    alarm_code=GRID_PATH_UNAVAILABLE_ALERT_CODE,
                    severity="critical",
                    message=message,
                    asset_id=event.asset_id,
                ),
            )

        if event.action == "breaker_close_request" and event.resulting_value == "closed":
            if grid_state.get("export_path_available") is not True:
                return ()
            latest_alert = self._latest_matching_alert(event=event, context=context, message=message)
            if latest_alert is None or latest_alert.state == "cleared":
                return ()
            return (
                DerivedAlert(
                    alarm_code=GRID_PATH_UNAVAILABLE_ALERT_CODE,
                    severity="critical",
                    state="cleared",
                    message=message,
                    asset_id=event.asset_id,
                ),
            )

        return ()

    def _latest_matching_alert(
        self,
        *,
        event: EventRecord,
        context: RuleContext,
        message: str,
    ) -> AlertRecord | None:
        latest_matching_alert: AlertRecord | None = None
        for alert in context.alert_history:
            if (
                alert.alarm_code == GRID_PATH_UNAVAILABLE_ALERT_CODE
                and alert.component == event.component
                and alert.asset_id == event.asset_id
                and alert.message == message
            ):
                latest_matching_alert = alert
        return latest_matching_alert


@dataclass(slots=True)
class RepeatedServiceLoginFailureRule:
    """Leitet ab der Schwellzahl wiederholter Login-Fehler einen Auth-Alert ab."""

    threshold: int = LOGIN_FAILURE_THRESHOLD
    rule_id: str = "repeated_service_login_failure"
    _failure_counts: dict[tuple[str, str], int] = field(default_factory=dict, init=False, repr=False)

    def evaluate(self, event: EventRecord, *, context: RuleContext) -> tuple[DerivedAlert, ...]:
        del context
        if event.event_type != "hmi.auth.service_login_attempt":
            return ()

        requested_value = event.requested_value if isinstance(event.requested_value, Mapping) else {}
        username = str(requested_value.get("username", "unknown")).strip() or "unknown"
        source_ip = event.source_ip
        key = (source_ip, username)

        if event.result == "success":
            self._failure_counts.pop(key, None)
            return ()
        if event.result != "failure":
            return ()

        failure_count = self._failure_counts.get(key, 0) + 1
        self._failure_counts[key] = failure_count
        if failure_count != self.threshold:
            return ()

        return (
            DerivedAlert(
                alarm_code=REPEATED_LOGIN_FAILURE_ALERT_CODE,
                severity="medium",
                message=f"Wiederholte Login-Fehlschlaege fuer {username} von {source_ip}",
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
        engine.register(RepeatedServiceLoginFailureRule())
        engine.register(SuccessfulSetpointChangeRule())
        engine.register(BreakerOpenRule())
        engine.register(GridPathUnavailableRule())
        engine.register(InverterCommLossRule())
        engine.register(MultiBlockUnavailableRule())
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
        seen: set[tuple[str, AlertSeverity, AlertState, str | None, str]] = set()

        for rule in self._rules.values():
            for derived_alert in rule.evaluate(event, context=resolved_context):
                if ALERT_SEVERITY_ORDER[derived_alert.severity] < ALERT_SEVERITY_ORDER[self.min_severity]:
                    continue
                if self._is_suppressed(
                    event=event,
                    derived_alert=derived_alert,
                    context=resolved_context,
                ):
                    continue
                dedupe_key = (
                    derived_alert.alarm_code,
                    derived_alert.severity,
                    derived_alert.state,
                    derived_alert.message,
                    self._resolved_asset_id(event=event, derived_alert=derived_alert),
                )
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                collected.append(derived_alert)

        return tuple(collected)

    def _is_suppressed(
        self,
        *,
        event: EventRecord,
        derived_alert: DerivedAlert,
        context: RuleContext,
    ) -> bool:
        latest_matching_alert: AlertRecord | None = None
        for alert in context.alert_history:
            if (
                alert.alarm_code == derived_alert.alarm_code
                and alert.severity == derived_alert.severity
                and alert.component == event.component
                and alert.asset_id == self._resolved_asset_id(event=event, derived_alert=derived_alert)
                and alert.message == derived_alert.message
            ):
                latest_matching_alert = alert

        if latest_matching_alert is None:
            return False
        if derived_alert.state == "cleared":
            return latest_matching_alert.state == "cleared"
        return latest_matching_alert.state != "cleared"

    def _resolved_asset_id(self, *, event: EventRecord, derived_alert: DerivedAlert) -> str:
        return event.asset_id if derived_alert.asset_id is None else derived_alert.asset_id
