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
LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE = "LOW_SITE_OUTPUT_UNEXPECTED"
SITE_AGGREGATE_ASSET_ID = "site"
LOGIN_FAILURE_THRESHOLD = 3
MULTI_BLOCK_UNAVAILABLE_THRESHOLD = 2
DEFAULT_CAPACITY_MW = 6.5
DEFAULT_LOW_OUTPUT_THRESHOLD_PCT = 35


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
        latest_alert = self._latest_matching_alert(event=event, context=context)
        active_block_assets_from_state = self._active_block_assets_from_state(context.current_state)

        if self._is_matching_comm_loss_event(event):
            total_affected_blocks = active_block_assets_from_state
            if total_affected_blocks is None:
                active_block_assets = self._active_block_assets_from_alert_history(context)
                if event.asset_id in active_block_assets:
                    return ()
                total_affected_blocks = active_block_assets | {event.asset_id}

            if len(total_affected_blocks) < self.threshold:
                return ()

            return (
                DerivedAlert(
                    alarm_code=MULTI_BLOCK_UNAVAILABLE_ALERT_CODE,
                    severity="critical",
                    message=self._message,
                    asset_id=self.aggregate_asset_id,
                ),
            )

        if active_block_assets_from_state is None:
            return ()
        if len(active_block_assets_from_state) >= self.threshold:
            return ()
        if latest_alert is None or latest_alert.state == "cleared":
            return ()

        return (
            DerivedAlert(
                alarm_code=MULTI_BLOCK_UNAVAILABLE_ALERT_CODE,
                severity="critical",
                state="cleared",
                message=self._message,
                asset_id=self.aggregate_asset_id,
            ),
        )

    @property
    def _message(self) -> str:
        return "Mehrere Inverter-Bloecke gleichzeitig nicht verfuegbar"

    def _is_matching_comm_loss_event(self, event: EventRecord) -> bool:
        return (
            event.result == "accepted"
            and event.event_type == "system.communication.inverter_block_lost"
            and event.action == "simulate_comm_loss"
            and event.resulting_value == "lost"
        )

    def _active_block_assets_from_alert_history(self, context: RuleContext) -> set[str]:
        return {
            alert.asset_id
            for alert in context.alert_history
            if alert.alarm_code == COMM_LOSS_ALERT_CODE and alert.state != "cleared"
        }

    def _active_block_assets_from_state(self, current_state: Mapping[str, Any]) -> set[str] | None:
        inverter_blocks = current_state.get("inverter_blocks")
        if not isinstance(inverter_blocks, list):
            return None

        active_assets: set[str] = set()
        for block in inverter_blocks:
            if not isinstance(block, Mapping):
                continue
            if block.get("communication_state") != "lost":
                continue
            asset_id = block.get("asset_id")
            if isinstance(asset_id, str) and asset_id:
                active_assets.add(asset_id)
        return active_assets

    def _latest_matching_alert(
        self,
        *,
        event: EventRecord,
        context: RuleContext,
    ) -> AlertRecord | None:
        latest_matching_alert: AlertRecord | None = None
        for alert in context.alert_history:
            if (
                alert.alarm_code == MULTI_BLOCK_UNAVAILABLE_ALERT_CODE
                and alert.component == event.component
                and alert.asset_id == self.aggregate_asset_id
                and alert.message == self._message
            ):
                latest_matching_alert = alert
        return latest_matching_alert


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


@dataclass(frozen=True, slots=True)
class LowSiteOutputUnexpectedRule:
    """Leitet einen Folge-Alert ab, wenn die Parkleistung deutlich unter der Erwartung liegt."""

    capacity_mw: float = DEFAULT_CAPACITY_MW
    threshold_pct: int = DEFAULT_LOW_OUTPUT_THRESHOLD_PCT
    aggregate_asset_id: str = SITE_AGGREGATE_ASSET_ID
    rule_id: str = "low_site_output_unexpected"

    def evaluate(self, event: EventRecord, *, context: RuleContext) -> tuple[DerivedAlert, ...]:
        if event.category not in {"process", "system"}:
            return ()

        site_state = context.current_state.get("site", {})
        weather_state = context.current_state.get("weather_station", {})
        grid_state = context.current_state.get("grid_interconnect", {})
        alarms_state = context.current_state.get("alarms", ())
        if not isinstance(site_state, Mapping) or not isinstance(weather_state, Mapping):
            return ()

        actual_power_mw = self._as_float(site_state.get("plant_power_mw"))
        irradiance_w_m2 = self._as_float(weather_state.get("irradiance_w_m2"))
        if actual_power_mw is None or irradiance_w_m2 is None:
            return ()

        latest_alert = self._latest_matching_alert(event=event, context=context)
        condition_active = self._is_low_output_condition_active(
            actual_power_mw=actual_power_mw,
            irradiance_w_m2=irradiance_w_m2,
            site_state=site_state,
            grid_state=grid_state,
            alarms_state=alarms_state,
        )
        if condition_active:
            return (
                DerivedAlert(
                    alarm_code=LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE,
                    severity="high",
                    message=self._message,
                    asset_id=self.aggregate_asset_id,
                ),
            )

        if latest_alert is None or latest_alert.state == "cleared":
            return ()
        return (
            DerivedAlert(
                alarm_code=LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE,
                severity="high",
                state="cleared",
                message=self._message,
                asset_id=self.aggregate_asset_id,
            ),
        )

    @property
    def _message(self) -> str:
        return "Parkleistung deutlich unter erwarteter Verfuegbarkeit"

    def _is_low_output_condition_active(
        self,
        *,
        actual_power_mw: float,
        irradiance_w_m2: float,
        site_state: Mapping[str, Any],
        grid_state: Mapping[str, Any],
        alarms_state: Any,
    ) -> bool:
        expected_power_mw = self.capacity_mw * (min(max(irradiance_w_m2, 0.0), 1000.0) / 1000.0)
        if expected_power_mw <= 0:
            return False
        if self._has_explanatory_state(site_state=site_state, grid_state=grid_state, alarms_state=alarms_state):
            return False

        shortfall_pct = ((expected_power_mw - actual_power_mw) / expected_power_mw) * 100
        return shortfall_pct >= self.threshold_pct

    def _has_explanatory_state(
        self,
        *,
        site_state: Mapping[str, Any],
        grid_state: Mapping[str, Any],
        alarms_state: Any,
    ) -> bool:
        if site_state.get("breaker_state") != "closed":
            return True
        if isinstance(grid_state, Mapping) and grid_state.get("export_path_available") is False:
            return True
        if self._has_active_alarm(alarms_state, "PLANT_CURTAILED"):
            return True
        plant_power_limit_pct = self._as_float(site_state.get("plant_power_limit_pct"))
        return plant_power_limit_pct is not None and plant_power_limit_pct < 100

    def _latest_matching_alert(
        self,
        *,
        event: EventRecord,
        context: RuleContext,
    ) -> AlertRecord | None:
        latest_matching_alert: AlertRecord | None = None
        for alert in context.alert_history:
            if (
                alert.alarm_code == LOW_SITE_OUTPUT_UNEXPECTED_ALERT_CODE
                and alert.component == event.component
                and alert.asset_id == self.aggregate_asset_id
                and alert.message == self._message
            ):
                latest_matching_alert = alert
        return latest_matching_alert

    def _has_active_alarm(self, alarms_state: Any, code: str) -> bool:
        if not isinstance(alarms_state, (list, tuple)):
            return False
        for alarm in alarms_state:
            if not isinstance(alarm, Mapping):
                continue
            if alarm.get("code") != code:
                continue
            if alarm.get("state") in {"active_unacknowledged", "active_acknowledged"}:
                return True
        return False

    def _as_float(self, value: Any) -> float | None:
        if isinstance(value, bool) or value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None


@dataclass(slots=True)
class RepeatedServiceLoginFailureRule:
    """Leitet ab der Schwellzahl wiederholter Login-Fehler einen Auth-Alert ab."""

    threshold: int = LOGIN_FAILURE_THRESHOLD
    rule_id: str = "repeated_service_login_failure"
    _failure_counts: dict[tuple[str, str], int] = field(default_factory=dict, init=False, repr=False)

    def evaluate(self, event: EventRecord, *, context: RuleContext) -> tuple[DerivedAlert, ...]:
        if event.event_type != "hmi.auth.service_login_attempt":
            return ()

        requested_value = event.requested_value if isinstance(event.requested_value, Mapping) else {}
        username = str(requested_value.get("username", "unknown")).strip() or "unknown"
        source_ip = event.source_ip
        key = (source_ip, username)
        message = f"Wiederholte Login-Fehlschlaege fuer {username} von {source_ip}"

        if event.result == "success":
            self._failure_counts.pop(key, None)
            latest_matching_alert = self._latest_matching_alert(event=event, context=context, message=message)
            if latest_matching_alert is None or latest_matching_alert.state == "cleared":
                return ()
            return (
                DerivedAlert(
                    alarm_code=REPEATED_LOGIN_FAILURE_ALERT_CODE,
                    severity="medium",
                    state="cleared",
                    message=message,
                ),
            )
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
                message=message,
            ),
        )

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
                alert.alarm_code == REPEATED_LOGIN_FAILURE_ALERT_CODE
                and alert.component == event.component
                and alert.asset_id == event.asset_id
                and alert.message == message
            ):
                latest_matching_alert = alert
        return latest_matching_alert


@dataclass(slots=True)
class RuleEngine:
    """Registry und deterministische Auswertung fuer lokale Event-Regeln."""

    min_severity: AlertSeverity = "low"
    _rules: dict[str, EventRule] = field(default_factory=dict, init=False, repr=False)

    @classmethod
    def default_v1(
        cls,
        *,
        min_severity: AlertSeverity = "medium",
        capacity_mw: float = DEFAULT_CAPACITY_MW,
        low_output_threshold_pct: int = DEFAULT_LOW_OUTPUT_THRESHOLD_PCT,
    ) -> "RuleEngine":
        engine = cls(min_severity=min_severity)
        engine.register(RepeatedServiceLoginFailureRule())
        engine.register(SuccessfulSetpointChangeRule())
        engine.register(BreakerOpenRule())
        engine.register(GridPathUnavailableRule())
        engine.register(
            LowSiteOutputUnexpectedRule(
                capacity_mw=capacity_mw,
                threshold_pct=low_output_threshold_pct,
            )
        )
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
