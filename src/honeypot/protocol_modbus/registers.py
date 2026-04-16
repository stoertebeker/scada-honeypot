"""Read-only Registerabbildung fuer den ersten Modbus-V1-Slice."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock

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

DEVICE_CLASS_CODE = {
    1: 1001,
}
ASSET_INSTANCE = {
    1: 0,
}
ASSET_TAG = {
    1: "ppc-01",
}
ASSET_ID = {
    1: "ppc-01",
}

OPERATING_MODE = {"normal": 0, "curtailed": 1, "maintenance": 2, "faulted": 3}
AVAILABILITY_STATE = {"available": 0, "partially_available": 1, "unavailable": 2}
COMMUNICATION_STATE = {"healthy": 0, "degraded": 1, "lost": 2}
BREAKER_STATE = {"closed": 0, "open": 1, "transitioning": 2}
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


class ReadOnlyRegisterMap:
    """Registersicht fuer die erste Unit-1-Modbus-Scheibe mit erstem Write-Pfad."""

    def __init__(self, snapshot: PlantSnapshot, *, event_recorder: EventRecorder | None = None):
        self._lock = Lock()
        self._snapshot = snapshot
        self._simulator = PlantSimulator.from_snapshot(snapshot, event_recorder=event_recorder)

    @property
    def snapshot(self) -> PlantSnapshot:
        with self._lock:
            return self._snapshot

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

        if unit_id != 1:
            raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, f"unit_id {unit_id} ist in V1 noch nicht aktiv")

        end_offset = start_offset + quantity - 1
        for offset in range(start_offset, end_offset + 1):
            if not _is_supported_unit_1_offset(offset):
                raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, f"offset {offset} liegt ausserhalb der V1-Matrix")

        with self._lock:
            unit_registers = _build_unit_1_registers(self._snapshot)
        return RegisterReadResult(
            values=tuple(unit_registers.get(offset, 0) for offset in range(start_offset, end_offset + 1)),
            asset_id=ASSET_ID[1],
        )

    def write_single_register(
        self,
        *,
        unit_id: int,
        start_offset: int,
        value: int,
        event_context: SimulationEventContext | None = None,
    ) -> RegisterWriteResult:
        if start_offset < 0 or start_offset > 0xFFFF:
            raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, "ungueltiger Startoffset")
        if value < 0 or value > 0xFFFF:
            raise ModbusRegisterError(ILLEGAL_DATA_VALUE, "registerwert fuer FC06 muss ein u16 sein")
        if unit_id != 1:
            raise ModbusRegisterError(ILLEGAL_DATA_ADDRESS, f"unit_id {unit_id} ist in V1 noch nicht aktiv")
        if start_offset != UNIT_1_ACTIVE_POWER_LIMIT_OFFSET:
            raise ModbusRegisterError(
                ILLEGAL_DATA_ADDRESS,
                f"offset {start_offset} ist im ersten Write-Slice nicht schreibbar",
            )
        if value > 1000:
            raise ModbusRegisterError(ILLEGAL_DATA_VALUE, "active_power_limit_pct_x10 muss im Bereich 0..1000 liegen")

        active_power_limit_pct = round(value / 10, 1)
        with self._lock:
            previous_value = _encode_active_power_limit_pct_x10(self._snapshot)
            try:
                resulting_snapshot = self._simulator.apply_curtailment(
                    self._snapshot,
                    active_power_limit_pct=active_power_limit_pct,
                    event_context=event_context,
                )
            except PlantSimulationError as exc:
                raise ModbusRegisterError(ILLEGAL_DATA_VALUE, str(exc)) from exc
            self._snapshot = resulting_snapshot

        return RegisterWriteResult(
            register_address=human_register_address(start_offset),
            requested_value=value,
            previous_value=previous_value,
            resulting_value=_encode_active_power_limit_pct_x10(resulting_snapshot),
            asset_id=ASSET_ID[1],
            resulting_state={
                "active_power_limit_pct": resulting_snapshot.power_plant_controller.active_power_limit_pct,
                "plant_power_mw": resulting_snapshot.site.plant_power_mw,
                "active_alarm_codes": list(resulting_snapshot.active_alarm_codes),
            },
        )


def human_register_address(offset: int) -> int:
    return 40001 + offset


def _is_supported_unit_1_offset(offset: int) -> bool:
    return (
        offset in IDENTITY_BLOCK
        or offset in UNIT_1_STATUS_BLOCK
        or offset in UNIT_1_SETPOINT_BLOCK
        or offset in UNIT_1_ALARM_BLOCK
    )


def _build_unit_1_registers(snapshot: PlantSnapshot) -> dict[int, int]:
    registers: dict[int, int] = {
        0: PROFILE_VERSION,
        1: DEVICE_CLASS_CODE[1],
        2: 1,
        3: ASSET_INSTANCE[1],
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
        201: _plant_mode_request(snapshot),
        299: _primary_alarm_code(snapshot),
        300: _primary_alarm_severity(snapshot),
        301: _alarm_state_for_code(snapshot.alarms, "PLANT_CURTAILED"),
        302: _alarm_state_for_code(snapshot.alarms, "BREAKER_OPEN"),
        303: _alarm_state_for_code(snapshot.alarms, "LOW_SITE_OUTPUT_UNEXPECTED"),
        304: _alarm_state_for_code(snapshot.alarms, "MULTI_BLOCK_UNAVAILABLE"),
    }
    registers.update(_ascii_registers(4, ASSET_TAG[1], register_count=4))
    registers.update(_u32_registers(103, round(snapshot.site.plant_power_mw * 1000)))
    registers.update(_u32_registers(105, 0))
    return registers


def _derive_plant_availability_pct_x10(snapshot: PlantSnapshot) -> int:
    if snapshot.site.availability_state == "available":
        return 1000
    if snapshot.site.availability_state == "partially_available":
        return 500
    return 0


def _encode_active_power_limit_pct_x10(snapshot: PlantSnapshot) -> int:
    return round(snapshot.power_plant_controller.active_power_limit_pct * 10)


def _plant_mode_request(snapshot: PlantSnapshot) -> int:
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


def _alarm_state_for_code(alarms: tuple[PlantAlarm, ...], code: str) -> int:
    for alarm in alarms:
        if alarm.code == code:
            return ALARM_STATE[alarm.state]
    return ALARM_STATE["inactive"]


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


def encode_i16(value: int) -> int:
    return value & 0xFFFF
