"""Read-only Registerabbildung fuer den ersten Modbus-V1-Slice."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Any

from honeypot.asset_domain import PlantAlarm, PlantSnapshot
from honeypot.event_core import EventRecorder
from honeypot.plant_sim import PlantSimulationError, PlantSimulator, SimulationEventContext

PROFILE_VERSION = 100
READ_HOLDING_REGISTERS = 3
READ_INPUT_REGISTERS = 4
WRITE_SINGLE_REGISTER = 6
WRITE_MULTIPLE_REGISTERS = 16
ILLEGAL_FUNCTION = 1
ILLEGAL_DATA_ADDRESS = 2
ILLEGAL_DATA_VALUE = 3

IDENTITY_BLOCK = range(0, 49)
UNIT_1_STATUS_BLOCK = range(99, 111)
UNIT_1_SETPOINT_BLOCK = range(199, 249)
UNIT_1_ALARM_BLOCK = range(299, 305)
UNIT_1_ACTIVE_POWER_LIMIT_OFFSET = 199
UNIT_1_REACTIVE_POWER_TARGET_OFFSET = 200
UNIT_1_PLANT_MODE_REQUEST_OFFSET = 201
UNIT_11_13_STATUS_BLOCK = range(99, 111)
UNIT_11_13_ALARM_BLOCK = range(299, 305)
UNIT_21_STATUS_BLOCK = range(99, 107)
UNIT_21_ALARM_BLOCK = range(299, 302)
UNIT_31_STATUS_BLOCK = range(99, 110)
UNIT_31_ALARM_BLOCK = range(299, 303)
UNIT_41_STATUS_BLOCK = range(99, 104)
UNIT_41_SETPOINT_BLOCK = range(199, 249)
UNIT_41_ALARM_BLOCK = range(299, 303)
UNIT_41_BREAKER_OPEN_REQUEST_OFFSET = 199
UNIT_41_BREAKER_CLOSE_REQUEST_OFFSET = 200

DEVICE_CLASS_CODE = {
    1: 1001,
    11: 1101,
    12: 1101,
    13: 1101,
    21: 1201,
    31: 1301,
    41: 1401,
}
ASSET_INSTANCE = {
    1: 0,
    11: 1,
    12: 2,
    13: 3,
    21: 0,
    31: 0,
    41: 0,
}
ASSET_TAG = {
    1: "ppc-01",
    11: "invb-01",
    12: "invb-02",
    13: "invb-03",
    21: "wx-01",
    31: "meter-01",
    41: "grid-01",
}
ASSET_ID = {
    1: "ppc-01",
    11: "invb-01",
    12: "invb-02",
    13: "invb-03",
    21: "wx-01",
    31: "meter-01",
    41: "grid-01",
}

ASSET_STATUS = {"online": 0, "offline": 1, "degraded": 2, "faulted": 3}
OPERATING_MODE = {"normal": 0, "curtailed": 1, "maintenance": 2, "faulted": 3}
AVAILABILITY_STATE = {"available": 0, "partially_available": 1, "unavailable": 2}
COMMUNICATION_STATE = {"healthy": 0, "degraded": 1, "lost": 2}
DATA_QUALITY = {"good": 0, "estimated": 1, "stale": 2, "invalid": 3}
BREAKER_STATE = {"closed": 0, "open": 1, "transitioning": 2}
GRID_ACCEPTANCE_STATE = {"accepted": 0, "limited": 1, "unavailable": 2}
ALARM_STATE = {
    "inactive": 0,
    "active_unacknowledged": 1,
    "active_acknowledged": 2,
    "cleared": 3,
}
SEVERITY_CODE = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CONTROL_AUTHORITY = {"local_auto": 0, "remote_scada": 1, "schedule": 2}

ALARM_CODE = {
    "COMM_LOSS_INVERTER_BLOCK": 100,
    "PLANT_CURTAILED": 110,
    "BREAKER_OPEN": 120,
    "LOW_SITE_OUTPUT_UNEXPECTED": 130,
    "REACTIVE_POWER_DEVIATION": 140,
    "TRACKER_STOW_ACTIVE": 150,
    "MULTI_BLOCK_UNAVAILABLE": 160,
    "BLOCK_OVERTEMP": 170,
    "GRID_PATH_UNAVAILABLE": 180,
}
PRIMARY_ALARM_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class ModbusRegisterError(ValueError):
    """Signalisiert dokumentierte Modbus-Fehlerfaelle."""

    def __init__(self, exception_code: int, message: str):
        super().__init__(message)
        self.exception_code = exception_code


@dataclass(frozen=True, slots=True)
class RegisterReadResult:
    """Rueckgabe eines Read-Zugriffs inklusive Asset-Metadaten."""

    values: tuple[int, ...]
    asset_id: str


@dataclass(frozen=True, slots=True)
class RegisterWriteResult:
    """Rueckgabe eines Write-Zugriffs inklusive sichtbarer Zustandswirkung."""

    register_address: int
    requested_value: int
    previous_value: int
    resulting_value: int
    asset_id: str
    resulting_state: dict[str, object]


@dataclass(frozen=True, slots=True)
class RegisterMultiWriteResult:
    """Rueckgabe eines FC16-Zugriffs inklusive sichtbarer Zustandswirkung."""

    start_register_address: int
    quantity: int
    requested_values: tuple[int, ...]
    previous_values: tuple[int, ...]
    resulting_values: tuple[int, ...]
    asset_id: str
    resulting_state: dict[str, object]


class ReadOnlyRegisterMap:
    """Registersicht fuer die aktiven V1-Modbus-Slices."""

    def __init__(self, snapshot: PlantSnapshot, *, event_recorder: EventRecorder | None = None):
        self._lock = Lock()
        self._snapshot = snapshot
        self._event_recorder = event_recorder
        self._simulator = PlantSimulator.from_snapshot(snapshot, event_recorder=event_recorder)
        self._plant_mode_request_override: int | None = None

    @property
    def snapshot(self) -> PlantSnapshot:
        with self._lock:
            return self._snapshot

    def set_active_power_limit_pct(
        self,
        *,
        active_power_limit_pct: float,
        event_context: SimulationEventContext | None = None,
    ) -> RegisterWriteResult:
        """Setzt das PPC-Wirkleistungslimit ueber denselben Fachpfad wie FC06."""

        try:
            return self.write_single_register(
                unit_id=1,
                start_offset=UNIT_1_ACTIVE_POWER_LIMIT_OFFSET,
                value=int(round(active_power_limit_pct * 10)),
                event_context=event_context,
            )
        except ModbusRegisterError as exc:
            raise ValueError(str(exc)) from exc

    def set_reactive_power_target_pct(
        self,
        *,
        reactive_power_target_pct: float,
        event_context: SimulationEventContext | None = None,
    ) -> RegisterWriteResult:
        """Setzt das PPC-Blindleistungsziel ueber denselben Fachpfad wie FC16."""

        try:
            result = self.write_multiple_registers(
                unit_id=1,
                start_offset=UNIT_1_REACTIVE_POWER_TARGET_OFFSET,
                values=(encode_i16(int(round(reactive_power_target_pct * 10))),),
                event_context=event_context,
            )
        except ModbusRegisterError as exc:
            raise ValueError(str(exc)) from exc

        return RegisterWriteResult(
            register_address=result.start_register_address,
            requested_value=result.requested_values[0],
            previous_value=result.previous_values[0],
            resulting_value=result.resulting_values[0],
            asset_id=result.asset_id,
            resulting_state=result.resulting_state,
        )

    def get_plant_mode_request(self) -> int:
        """Liefert den aktuell sichtbaren gelatchten Plant-Mode-Request fuer Unit 1."""

        with self._lock:
            return self._current_setpoint_value(
                1,
                UNIT_1_PLANT_MODE_REQUEST_OFFSET,
                snapshot=self._snapshot,
                plant_mode_request_override=self._plant_mode_request_override,
            )

    def set_plant_mode_request(
        self,
        *,
        plant_mode_request: int,
        event_context: SimulationEventContext | None = None,
    ) -> RegisterWriteResult:
        """Setzt den PPC-Plant-Mode-Request ueber denselben Fachpfad wie FC16."""

        try:
            result = self.write_multiple_registers(
                unit_id=1,
                start_offset=UNIT_1_PLANT_MODE_REQUEST_OFFSET,
                values=(plant_mode_request,),
                event_context=event_context,
            )
        except ModbusRegisterError as exc:
            raise ValueError(str(exc)) from exc

        return RegisterWriteResult(
            register_address=result.start_register_address,
            requested_value=result.requested_values[0],
            previous_value=result.previous_values[0],
            resulting_value=result.resulting_values[0],
            asset_id=result.asset_id,
            resulting_state=result.resulting_state,
        )

    def request_breaker_open(
        self,
        *,
        event_context: SimulationEventContext | None = None,
    ) -> RegisterWriteResult:
        """Fordert das Oeffnen des Netzuebergabebreakers ueber denselben Fachpfad wie FC06 an."""

        try:
            return self.write_single_register(
                unit_id=41,
                start_offset=UNIT_41_BREAKER_OPEN_REQUEST_OFFSET,
                value=1,
                event_context=event_context,
            )
        except ModbusRegisterError as exc:
            raise ValueError(str(exc)) from exc

    def request_breaker_close(
        self,
        *,
        event_context: SimulationEventContext | None = None,
    ) -> RegisterWriteResult:
        """Fordert das Schliessen des Netzuebergabebreakers ueber denselben Fachpfad wie FC06 an."""

        try:
            return self.write_single_register(
                unit_id=41,
                start_offset=UNIT_41_BREAKER_CLOSE_REQUEST_OFFSET,
                value=1,
                event_context=event_context,
            )
        except ModbusRegisterError as exc:
            raise ValueError(str(exc)) from exc

    def read_holding_registers(
        self,
        *,
        unit_id: int,
        start_offset: int,
        quantity: int,
    ) -> RegisterReadResult:
        if quantity <= 0 or quantity > 125:
            raise ModbusRegisterError(ILLEGAL_DATA_VALUE, "quantity fuer FC03 muss im Bereich 1..125 liegen")
        if start_offset < 0 or start_offset > 0xFFFF:
            raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, "ungueltiger Startoffset")

        if unit_id not in ASSET_ID:
            raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, f"unit_id {unit_id} ist in V1 noch nicht aktiv")

        end_offset = start_offset + quantity - 1
        for offset in range(start_offset, end_offset + 1):
            if not _is_supported_offset(unit_id, offset):
                raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, f"offset {offset} liegt ausserhalb der V1-Matrix")

        with self._lock:
            unit_registers = _build_registers_for_unit(
                unit_id,
                self._snapshot,
                plant_mode_request_override=self._plant_mode_request_override,
            )
        return RegisterReadResult(
            values=tuple(unit_registers.get(offset, 0) for offset in range(start_offset, end_offset + 1)),
            asset_id=ASSET_ID[unit_id],
        )

    def write_single_register(
        self,
        *,
        unit_id: int,
        start_offset: int,
        value: int,
        event_context: SimulationEventContext | None = None,
    ) -> RegisterWriteResult:
        result = self._apply_write_sequence(
            unit_id=unit_id,
            start_offset=start_offset,
            values=(value,),
            event_context=event_context,
            allow_fc06=True,
        )

        return RegisterWriteResult(
            register_address=result.start_register_address,
            requested_value=result.requested_values[0],
            previous_value=result.previous_values[0],
            resulting_value=result.resulting_values[0],
            asset_id=result.asset_id,
            resulting_state=result.resulting_state,
        )

    def write_multiple_registers(
        self,
        *,
        unit_id: int,
        start_offset: int,
        values: tuple[int, ...],
        event_context: SimulationEventContext | None = None,
    ) -> RegisterMultiWriteResult:
        return self._apply_write_sequence(
            unit_id=unit_id,
            start_offset=start_offset,
            values=values,
            event_context=event_context,
            allow_fc06=False,
        )

    def _apply_write_sequence(
        self,
        *,
        unit_id: int,
        start_offset: int,
        values: tuple[int, ...],
        event_context: SimulationEventContext | None,
        allow_fc06: bool,
    ) -> RegisterMultiWriteResult:
        offsets = self._validate_write_sequence(
            unit_id=unit_id,
            start_offset=start_offset,
            values=values,
            allow_fc06=allow_fc06,
        )

        with self._lock:
            previous_values = tuple(
                self._current_setpoint_value(
                    unit_id,
                    offset,
                    snapshot=self._snapshot,
                    plant_mode_request_override=self._plant_mode_request_override,
                )
                for offset in offsets
            )
            working_snapshot = self._snapshot
            working_mode_request_override = self._plant_mode_request_override

            for offset, value in zip(offsets, values):
                if unit_id == 1:
                    if offset == UNIT_1_ACTIVE_POWER_LIMIT_OFFSET:
                        try:
                            working_snapshot = self._simulator.apply_curtailment(
                                working_snapshot,
                                active_power_limit_pct=round(value / 10, 1),
                                event_context=event_context,
                            )
                        except PlantSimulationError as exc:
                            raise ModbusRegisterError(ILLEGAL_DATA_VALUE, str(exc)) from exc
                        continue

                    if offset == UNIT_1_REACTIVE_POWER_TARGET_OFFSET:
                        try:
                            working_snapshot = self._simulator.apply_reactive_power_target(
                                working_snapshot,
                                reactive_power_target=decode_i16(value) / 1000,
                                event_context=event_context,
                            )
                        except PlantSimulationError as exc:
                            raise ModbusRegisterError(ILLEGAL_DATA_VALUE, str(exc)) from exc
                        continue

                    if offset == UNIT_1_PLANT_MODE_REQUEST_OFFSET:
                        previous_mode_request = self._current_setpoint_value(
                            unit_id,
                            offset,
                            snapshot=working_snapshot,
                            plant_mode_request_override=working_mode_request_override,
                        )
                        working_mode_request_override = value
                        self._record_plant_mode_request_change(
                            snapshot=working_snapshot,
                            previous_mode_request=previous_mode_request,
                            requested_mode_request=value,
                            event_context=event_context,
                        )
                        continue

                if unit_id == 41 and value == 1:
                    try:
                        if offset == UNIT_41_BREAKER_OPEN_REQUEST_OFFSET:
                            working_snapshot = self._simulator.open_breaker(
                                working_snapshot,
                                event_context=event_context,
                            )
                        elif offset == UNIT_41_BREAKER_CLOSE_REQUEST_OFFSET:
                            working_snapshot = self._simulator.close_breaker(
                                working_snapshot,
                                event_context=event_context,
                            )
                    except PlantSimulationError as exc:
                        raise ModbusRegisterError(ILLEGAL_DATA_VALUE, str(exc)) from exc

            self._snapshot = working_snapshot
            self._plant_mode_request_override = working_mode_request_override
            resulting_state = self._write_result_state(unit_id)
            resulting_values = tuple(
                self._current_setpoint_value(
                    unit_id,
                    offset,
                    snapshot=self._snapshot,
                    plant_mode_request_override=self._plant_mode_request_override,
                )
                for offset in offsets
            )

        return RegisterMultiWriteResult(
            start_register_address=human_register_address(start_offset),
            quantity=len(values),
            requested_values=tuple(values),
            previous_values=previous_values,
            resulting_values=resulting_values,
            asset_id=ASSET_ID[unit_id],
            resulting_state=resulting_state,
        )

    def _validate_write_sequence(
        self,
        *,
        unit_id: int,
        start_offset: int,
        values: tuple[int, ...],
        allow_fc06: bool,
    ) -> tuple[int, ...]:
        if start_offset < 0 or start_offset > 0xFFFF:
            raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, "ungueltiger Startoffset")
        if unit_id not in ASSET_ID:
            raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, f"unit_id {unit_id} ist in V1 noch nicht aktiv")
        if not values:
            raise ModbusRegisterError(ILLEGAL_DATA_VALUE, "es muss mindestens ein Registerwert geschrieben werden")
        if len(values) > 123:
            raise ModbusRegisterError(ILLEGAL_DATA_VALUE, "quantity fuer FC16 muss im Bereich 1..123 liegen")

        offsets = tuple(range(start_offset, start_offset + len(values)))
        if unit_id == 1:
            return _validate_unit_1_write_sequence(offsets=offsets, values=values, allow_fc06=allow_fc06)
        if unit_id in (11, 12, 13):
            raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, "inverter_block ist im aktuellen Slice read-only")
        if unit_id == 21:
            raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, "weather_station ist in V1 read-only")
        if unit_id == 31:
            raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, "revenue_meter ist in V1 read-only")
        if unit_id == 41:
            return _validate_unit_41_write_sequence(offsets=offsets, values=values, allow_fc06=allow_fc06)
        raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, f"unit_id {unit_id} ist in V1 noch nicht aktiv")

    def _current_setpoint_value(
        self,
        unit_id: int,
        offset: int,
        *,
        snapshot: PlantSnapshot,
        plant_mode_request_override: int | None,
    ) -> int:
        if unit_id == 1:
            if offset == UNIT_1_ACTIVE_POWER_LIMIT_OFFSET:
                return _encode_active_power_limit_pct_x10(snapshot)
            if offset == UNIT_1_REACTIVE_POWER_TARGET_OFFSET:
                return encode_i16(round(snapshot.power_plant_controller.reactive_power_target * 1000))
            if offset == UNIT_1_PLANT_MODE_REQUEST_OFFSET:
                return _plant_mode_request(snapshot, plant_mode_request_override=plant_mode_request_override)
            raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, f"offset {offset} ist kein PPC-Setpoint")

        if unit_id == 41 and offset in (
            UNIT_41_BREAKER_OPEN_REQUEST_OFFSET,
            UNIT_41_BREAKER_CLOSE_REQUEST_OFFSET,
        ):
            return 0
        raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, f"offset {offset} ist im aktuellen Slice kein Setpoint")

    def _write_result_state(self, unit_id: int) -> dict[str, object]:
        if unit_id == 1:
            return {
                "active_power_limit_pct": self._snapshot.power_plant_controller.active_power_limit_pct,
                "reactive_power_target": self._snapshot.power_plant_controller.reactive_power_target,
                "plant_mode_request": _plant_mode_request(
                    self._snapshot,
                    plant_mode_request_override=self._plant_mode_request_override,
                ),
                "operating_mode": self._snapshot.site.operating_mode,
                "plant_power_mw": self._snapshot.site.plant_power_mw,
                "active_alarm_codes": list(self._snapshot.active_alarm_codes),
            }

        return {
            "breaker_state": self._snapshot.grid_interconnect.breaker_state,
            "export_path_available": self._snapshot.grid_interconnect.export_path_available,
            "grid_acceptance_state": self._snapshot.grid_interconnect.grid_acceptance_state,
            "plant_power_mw": self._snapshot.site.plant_power_mw,
            "active_alarm_codes": list(self._snapshot.active_alarm_codes),
        }

    def _record_plant_mode_request_change(
        self,
        *,
        snapshot: PlantSnapshot,
        previous_mode_request: int,
        requested_mode_request: int,
        event_context: SimulationEventContext | None,
    ) -> None:
        if self._event_recorder is None:
            return

        context = SimulationEventContext() if event_context is None else event_context
        event = self._event_recorder.build_event(
            event_type="process.setpoint.plant_mode_request_changed",
            category="process",
            severity="medium",
            source_ip=context.source_ip,
            actor_type=context.actor_type,
            component="plant-sim",
            asset_id=ASSET_ID[1],
            action="set_plant_mode_request",
            result="accepted",
            correlation_id=context.correlation_id,
            session_id=context.session_id,
            causation_id=context.causation_id,
            protocol=context.protocol,
            service=context.service,
            requested_value=requested_mode_request,
            previous_value=previous_mode_request,
            resulting_value=requested_mode_request,
            resulting_state={
                "plant_mode_request": requested_mode_request,
                "operating_mode": snapshot.site.operating_mode,
                "active_power_limit_pct": snapshot.power_plant_controller.active_power_limit_pct,
            },
            tags=("control-path", "ppc", "plant-mode"),
        )
        self._event_recorder.record(event)


def human_register_address(offset: int) -> int:
    return 40001 + offset


def _is_supported_offset(unit_id: int, offset: int) -> bool:
    if unit_id == 1:
        return (
            offset in IDENTITY_BLOCK
            or offset in UNIT_1_STATUS_BLOCK
            or offset in UNIT_1_SETPOINT_BLOCK
            or offset in UNIT_1_ALARM_BLOCK
        )
    if unit_id in (11, 12, 13):
        return (
            offset in IDENTITY_BLOCK
            or offset in UNIT_11_13_STATUS_BLOCK
            or offset in UNIT_11_13_ALARM_BLOCK
        )
    if unit_id == 21:
        return (
            offset in IDENTITY_BLOCK
            or offset in UNIT_21_STATUS_BLOCK
            or offset in UNIT_21_ALARM_BLOCK
        )
    if unit_id == 31:
        return (
            offset in IDENTITY_BLOCK
            or offset in UNIT_31_STATUS_BLOCK
            or offset in UNIT_31_ALARM_BLOCK
        )
    if unit_id == 41:
        return (
            offset in IDENTITY_BLOCK
            or offset in UNIT_41_STATUS_BLOCK
            or offset in UNIT_41_SETPOINT_BLOCK
            or offset in UNIT_41_ALARM_BLOCK
        )
    return False


def _build_registers_for_unit(
    unit_id: int,
    snapshot: PlantSnapshot,
    *,
    plant_mode_request_override: int | None = None,
) -> dict[int, int]:
    if unit_id == 1:
        return _build_unit_1_registers(snapshot, plant_mode_request_override=plant_mode_request_override)
    if unit_id in (11, 12, 13):
        return _build_unit_11_13_registers(snapshot, unit_id=unit_id)
    if unit_id == 21:
        return _build_unit_21_registers(snapshot)
    if unit_id == 31:
        return _build_unit_31_registers(snapshot)
    if unit_id == 41:
        return _build_unit_41_registers(snapshot)
    raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, f"unit_id {unit_id} ist in V1 noch nicht aktiv")


def _build_identity_registers(unit_id: int) -> dict[int, int]:
    registers: dict[int, int] = {
        0: PROFILE_VERSION,
        1: DEVICE_CLASS_CODE[unit_id],
        2: unit_id,
        3: ASSET_INSTANCE[unit_id],
    }
    registers.update(_ascii_registers(4, ASSET_TAG[unit_id], register_count=4))
    return registers


def _build_unit_1_registers(
    snapshot: PlantSnapshot,
    *,
    plant_mode_request_override: int | None = None,
) -> dict[int, int]:
    registers = _build_identity_registers(1)
    registers.update(
        {
            99: OPERATING_MODE[snapshot.site.operating_mode],
            100: AVAILABILITY_STATE[snapshot.site.availability_state],
            101: COMMUNICATION_STATE[snapshot.site.communications_health],
            102: CONTROL_AUTHORITY[snapshot.power_plant_controller.control_authority],
            107: _derive_plant_availability_pct_x10(snapshot),
            108: BREAKER_STATE[snapshot.site.breaker_state],
            109: encode_i16(round(snapshot.power_plant_controller.reactive_power_target * 1000)),
            110: snapshot.site.active_alarm_count,
            199: _encode_active_power_limit_pct_x10(snapshot),
            200: encode_i16(round(snapshot.power_plant_controller.reactive_power_target * 1000)),
            201: _plant_mode_request(snapshot, plant_mode_request_override=plant_mode_request_override),
            299: _primary_alarm_code(snapshot),
            300: _primary_alarm_severity(snapshot),
            301: _alarm_state_for_code(snapshot.alarms, "PLANT_CURTAILED"),
            302: _alarm_state_for_code(snapshot.alarms, "BREAKER_OPEN"),
            303: _alarm_state_for_code(snapshot.alarms, "LOW_SITE_OUTPUT_UNEXPECTED"),
            304: _alarm_state_for_code(snapshot.alarms, "MULTI_BLOCK_UNAVAILABLE"),
        }
    )
    registers.update(_u32_registers(103, round(snapshot.site.plant_power_mw * 1000)))
    registers.update(_u32_registers(105, 0))
    return registers


def _build_unit_41_registers(snapshot: PlantSnapshot) -> dict[int, int]:
    grid_primary_alarm = _primary_alarm_for_codes(snapshot, "GRID_PATH_UNAVAILABLE", "BREAKER_OPEN")
    registers = _build_identity_registers(41)
    registers.update(
        {
            99: ASSET_STATUS[snapshot.grid_interconnect.status],
            100: COMMUNICATION_STATE[snapshot.grid_interconnect.communication_state],
            101: BREAKER_STATE[snapshot.grid_interconnect.breaker_state],
            102: int(snapshot.grid_interconnect.export_path_available),
            103: GRID_ACCEPTANCE_STATE[snapshot.grid_interconnect.grid_acceptance_state],
            199: 0,
            200: 0,
            299: 0 if grid_primary_alarm is None else ALARM_CODE.get(grid_primary_alarm.code, 0),
            300: 0 if grid_primary_alarm is None else SEVERITY_CODE[grid_primary_alarm.severity],
            301: _alarm_state_for_code(snapshot.alarms, "BREAKER_OPEN"),
            302: _grid_export_path_alarm_state(snapshot),
        }
    )
    return registers


def _build_unit_11_13_registers(snapshot: PlantSnapshot, *, unit_id: int) -> dict[int, int]:
    block = _inverter_block_for_unit(snapshot, unit_id)
    comm_loss_state = _inverter_comm_loss_alarm_state(block)
    block_fault_state = _inverter_block_fault_alarm_state(block)
    block_unavailable_state = _inverter_block_unavailable_alarm_state(block)
    overtemp_state = ALARM_STATE["inactive"]
    primary_alarm_code, primary_alarm_severity = _inverter_primary_alarm(
        comm_loss_state=comm_loss_state,
        overtemp_state=overtemp_state,
    )

    registers = _build_identity_registers(unit_id)
    registers.update(
        {
            99: ASSET_STATUS[block.status],
            100: COMMUNICATION_STATE[block.communication_state],
            101: DATA_QUALITY[block.quality],
            102: block.availability_pct * 10,
            105: round((block.block_dc_voltage_v or 0) * 10),
            106: round((block.block_dc_current_a or 0) * 10),
            107: round((block.block_ac_voltage_v or 0) * 10),
            108: round((block.block_ac_current_a or 0) * 10),
            109: encode_i16(round((block.internal_temperature_c or 0) * 10)),
            110: _active_alarm_count(
                comm_loss_state,
                block_fault_state,
                block_unavailable_state,
                overtemp_state,
            ),
            299: primary_alarm_code,
            300: primary_alarm_severity,
            301: comm_loss_state,
            302: block_fault_state,
            303: block_unavailable_state,
            304: overtemp_state,
        }
    )
    registers.update(_i32_registers(103, round(block.block_power_kw)))
    return registers


def _build_unit_21_registers(snapshot: PlantSnapshot) -> dict[int, int]:
    weather_primary_alarm = _primary_alarm_for_codes(snapshot)
    registers = _build_identity_registers(21)
    registers.update(
        {
            99: ASSET_STATUS[snapshot.weather_station.status],
            100: COMMUNICATION_STATE[snapshot.weather_station.communication_state],
            101: DATA_QUALITY[snapshot.weather_station.quality],
            102: snapshot.weather_station.irradiance_w_m2,
            103: encode_i16(round(snapshot.weather_station.module_temperature_c * 10)),
            104: encode_i16(round(snapshot.weather_station.ambient_temperature_c * 10)),
            105: round(snapshot.weather_station.wind_speed_m_s * 10),
            106: _weather_confidence_pct_x10(snapshot),
            299: 0 if weather_primary_alarm is None else ALARM_CODE.get(weather_primary_alarm.code, 0),
            300: 0 if weather_primary_alarm is None else SEVERITY_CODE[weather_primary_alarm.severity],
            301: _weather_comm_loss_alarm_state(snapshot),
        }
    )
    return registers


def _build_unit_31_registers(snapshot: PlantSnapshot) -> dict[int, int]:
    meter_primary_alarm = _primary_alarm_for_codes(snapshot, "BREAKER_OPEN")
    registers = _build_identity_registers(31)
    registers.update(
        {
            99: ASSET_STATUS[snapshot.revenue_meter.status],
            100: COMMUNICATION_STATE[snapshot.revenue_meter.communication_state],
            101: DATA_QUALITY[snapshot.revenue_meter.quality],
            106: round((snapshot.revenue_meter.grid_voltage_v or 0) * 10),
            107: round((snapshot.revenue_meter.grid_frequency_hz or 0) * 100),
            108: encode_i16(round(snapshot.revenue_meter.power_factor * 1000)),
            109: int(snapshot.grid_interconnect.export_path_available),
            299: 0 if meter_primary_alarm is None else ALARM_CODE.get(meter_primary_alarm.code, 0),
            300: 0 if meter_primary_alarm is None else SEVERITY_CODE[meter_primary_alarm.severity],
            301: _alarm_state_for_code(snapshot.alarms, "BREAKER_OPEN"),
            302: _meter_comm_loss_alarm_state(snapshot),
        }
    )
    registers.update(_i32_registers(102, round(snapshot.revenue_meter.export_power_kw)))
    registers.update(_u32_registers(104, round((snapshot.revenue_meter.export_energy_mwh_total or 0) * 1000)))
    return registers


def _derive_plant_availability_pct_x10(snapshot: PlantSnapshot) -> int:
    if snapshot.site.availability_state == "available":
        return 1000
    if snapshot.site.availability_state == "partially_available":
        return 500
    return 0


def _encode_active_power_limit_pct_x10(snapshot: PlantSnapshot) -> int:
    return round(snapshot.power_plant_controller.active_power_limit_pct * 10)


def _plant_mode_request(snapshot: PlantSnapshot, plant_mode_request_override: int | None = None) -> int:
    if plant_mode_request_override is not None:
        return plant_mode_request_override
    if snapshot.site.operating_mode == "maintenance":
        return 2
    if snapshot.site.operating_mode == "curtailed" or snapshot.site.plant_power_limit_pct < 100:
        return 1
    return 0


def _primary_alarm_code(snapshot: PlantSnapshot) -> int:
    alarm = _primary_alarm(snapshot)
    if alarm is None:
        return 0
    return ALARM_CODE.get(alarm.code, 0)


def _primary_alarm_severity(snapshot: PlantSnapshot) -> int:
    alarm = _primary_alarm(snapshot)
    if alarm is None:
        return 0
    return SEVERITY_CODE[alarm.severity]


def _primary_alarm(snapshot: PlantSnapshot) -> PlantAlarm | None:
    active_alarms = tuple(alarm for alarm in snapshot.alarms if alarm.is_active)
    if not active_alarms:
        return None
    return sorted(
        active_alarms,
        key=lambda alarm: (-PRIMARY_ALARM_ORDER[alarm.severity], alarm.code),
    )[0]


def _primary_alarm_for_codes(snapshot: PlantSnapshot, *codes: str) -> PlantAlarm | None:
    active_alarms = tuple(alarm for alarm in snapshot.alarms if alarm.is_active and alarm.code in codes)
    if not active_alarms:
        return None
    return sorted(
        active_alarms,
        key=lambda alarm: (-PRIMARY_ALARM_ORDER[alarm.severity], alarm.code),
    )[0]


def _alarm_state_for_code(alarms: tuple[PlantAlarm, ...], code: str) -> int:
    for alarm in alarms:
        if alarm.code == code:
            return ALARM_STATE[alarm.state]
    return ALARM_STATE["inactive"]


def _grid_export_path_alarm_state(snapshot: PlantSnapshot) -> int:
    grid_path_alarm_state = _alarm_state_for_code(snapshot.alarms, "GRID_PATH_UNAVAILABLE")
    if grid_path_alarm_state != ALARM_STATE["inactive"]:
        return grid_path_alarm_state
    if snapshot.grid_interconnect.export_path_available:
        return ALARM_STATE["inactive"]
    breaker_alarm_state = _alarm_state_for_code(snapshot.alarms, "BREAKER_OPEN")
    if breaker_alarm_state != ALARM_STATE["inactive"]:
        return breaker_alarm_state
    return ALARM_STATE["active_unacknowledged"]


def _inverter_block_for_unit(snapshot: PlantSnapshot, unit_id: int):
    index = unit_id - 11
    if index < 0 or index >= len(snapshot.inverter_blocks):
        raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, f"unit_id {unit_id} ist im aktuellen Snapshot nicht verfuegbar")
    return snapshot.inverter_blocks[index]


def _inverter_comm_loss_alarm_state(block) -> int:
    if block.communication_state == "lost":
        return ALARM_STATE["active_unacknowledged"]
    return ALARM_STATE["inactive"]


def _inverter_block_fault_alarm_state(block) -> int:
    if block.status == "faulted":
        return ALARM_STATE["active_unacknowledged"]
    return ALARM_STATE["inactive"]


def _inverter_block_unavailable_alarm_state(block) -> int:
    if block.status == "offline" or block.availability_pct == 0:
        return ALARM_STATE["active_unacknowledged"]
    return ALARM_STATE["inactive"]


def _inverter_primary_alarm(*, comm_loss_state: int, overtemp_state: int) -> tuple[int, int]:
    if comm_loss_state != ALARM_STATE["inactive"]:
        return ALARM_CODE["COMM_LOSS_INVERTER_BLOCK"], SEVERITY_CODE["medium"]
    if overtemp_state != ALARM_STATE["inactive"]:
        return ALARM_CODE["BLOCK_OVERTEMP"], SEVERITY_CODE["high"]
    return 0, 0


def _active_alarm_count(*alarm_states: int) -> int:
    return sum(1 for state in alarm_states if state != ALARM_STATE["inactive"])


def _weather_comm_loss_alarm_state(snapshot: PlantSnapshot) -> int:
    if snapshot.weather_station.communication_state == "lost":
        return ALARM_STATE["active_unacknowledged"]
    return ALARM_STATE["inactive"]


def _weather_confidence_pct_x10(snapshot: PlantSnapshot) -> int:
    if snapshot.weather_station.quality == "good":
        return 1000
    if snapshot.weather_station.quality == "estimated":
        return 750
    if snapshot.weather_station.quality == "stale":
        return 500
    return 0


def _meter_comm_loss_alarm_state(snapshot: PlantSnapshot) -> int:
    if snapshot.revenue_meter.communication_state == "lost":
        return ALARM_STATE["active_unacknowledged"]
    return ALARM_STATE["inactive"]


def _validate_unit_1_write_sequence(
    *,
    offsets: tuple[int, ...],
    values: tuple[int, ...],
    allow_fc06: bool,
) -> tuple[int, ...]:
    if allow_fc06 and offsets != (UNIT_1_ACTIVE_POWER_LIMIT_OFFSET,):
        raise ModbusRegisterError(
            ILLEGAL_DATA_ADDRESS,
            f"offset {offsets[0]} ist im ersten Write-Slice nicht schreibbar",
        )
    if not allow_fc06 and offsets[-1] > UNIT_1_PLANT_MODE_REQUEST_OFFSET:
        raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, "FC16 ist im aktuellen Slice nur fuer 40200-40202 aktiv")

    for offset, value in zip(offsets, values):
        if offset not in (
            UNIT_1_ACTIVE_POWER_LIMIT_OFFSET,
            UNIT_1_REACTIVE_POWER_TARGET_OFFSET,
            UNIT_1_PLANT_MODE_REQUEST_OFFSET,
        ):
            raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, f"offset {offset} ist im aktuellen Slice nicht schreibbar")
        if value < 0 or value > 0xFFFF:
            raise ModbusRegisterError(ILLEGAL_DATA_VALUE, "Registerwerte muessen als u16 uebertragen werden")
        if offset == UNIT_1_ACTIVE_POWER_LIMIT_OFFSET and value > 1000:
            raise ModbusRegisterError(
                ILLEGAL_DATA_VALUE,
                "active_power_limit_pct_x10 muss im Bereich 0..1000 liegen",
            )
        if offset == UNIT_1_REACTIVE_POWER_TARGET_OFFSET and not -1000 <= decode_i16(value) <= 1000:
            raise ModbusRegisterError(
                ILLEGAL_DATA_VALUE,
                "reactive_power_target_pct_x10 muss im Bereich -1000..1000 liegen",
            )
        if offset == UNIT_1_PLANT_MODE_REQUEST_OFFSET and value not in (0, 1, 2):
            raise ModbusRegisterError(
                ILLEGAL_DATA_VALUE,
                "plant_mode_request muss einer der Werte 0, 1 oder 2 sein",
            )
    return offsets


def _validate_unit_41_write_sequence(
    *,
    offsets: tuple[int, ...],
    values: tuple[int, ...],
    allow_fc06: bool,
) -> tuple[int, ...]:
    allowed_offsets = (UNIT_41_BREAKER_OPEN_REQUEST_OFFSET, UNIT_41_BREAKER_CLOSE_REQUEST_OFFSET)
    if allow_fc06 and len(offsets) != 1:
        raise ModbusRegisterError(ILLEGAL_DATA_VALUE, "FC06 erlaubt genau ein Register")
    if not allow_fc06 and offsets[-1] > UNIT_41_BREAKER_CLOSE_REQUEST_OFFSET:
        raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, "FC16 ist im aktuellen Grid-Slice nur fuer 40200-40201 aktiv")

    for offset, value in zip(offsets, values):
        if offset not in allowed_offsets:
            raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, f"offset {offset} ist im aktuellen Slice nicht schreibbar")
        if value not in (0, 1):
            raise ModbusRegisterError(
                ILLEGAL_DATA_VALUE,
                "breaker_open_request und breaker_close_request muessen 0 oder 1 sein",
            )

    if (
        UNIT_41_BREAKER_OPEN_REQUEST_OFFSET in offsets
        and UNIT_41_BREAKER_CLOSE_REQUEST_OFFSET in offsets
        and values[offsets.index(UNIT_41_BREAKER_OPEN_REQUEST_OFFSET)] == 1
        and values[offsets.index(UNIT_41_BREAKER_CLOSE_REQUEST_OFFSET)] == 1
    ):
        raise ModbusRegisterError(
            ILLEGAL_DATA_VALUE,
            "breaker_open_request und breaker_close_request duerfen nicht gleichzeitig 1 sein",
        )
    return offsets


def _ascii_registers(start_offset: int, value: str, *, register_count: int) -> dict[int, int]:
    encoded = value.encode("ascii", errors="ignore")[: register_count * 2]
    encoded = encoded.ljust(register_count * 2, b" ")
    return {
        start_offset + index: int.from_bytes(encoded[index * 2 : index * 2 + 2], byteorder="big", signed=False)
        for index in range(register_count)
    }


def _u32_registers(start_offset: int, value: int) -> dict[int, int]:
    encoded = value & 0xFFFFFFFF
    return {
        start_offset: (encoded >> 16) & 0xFFFF,
        start_offset + 1: encoded & 0xFFFF,
    }


def _i32_registers(start_offset: int, value: int) -> dict[int, int]:
    encoded = value & 0xFFFFFFFF
    return {
        start_offset: (encoded >> 16) & 0xFFFF,
        start_offset + 1: encoded & 0xFFFF,
    }


def encode_i16(value: int) -> int:
    return value & 0xFFFF


def decode_i16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value
