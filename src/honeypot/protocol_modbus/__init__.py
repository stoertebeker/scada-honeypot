"""Modbus/TCP-Abbildung auf das Fachmodell."""

from honeypot.protocol_modbus.registers import (
    ILLEGAL_DATA_ADDRESS,
    ILLEGAL_FUNCTION,
    ILLEGAL_DATA_VALUE,
    READ_HOLDING_REGISTERS,
    READ_INPUT_REGISTERS,
    WRITE_MULTIPLE_REGISTERS,
    WRITE_SINGLE_REGISTER,
    ModbusRegisterError,
    ReadOnlyRegisterMap,
    RegisterReadResult,
    RegisterWriteResult,
)
from honeypot.protocol_modbus.server import ReadOnlyModbusTcpService

__all__ = [
    "ILLEGAL_DATA_ADDRESS",
    "ILLEGAL_FUNCTION",
    "ILLEGAL_DATA_VALUE",
    "ModbusRegisterError",
    "READ_HOLDING_REGISTERS",
    "READ_INPUT_REGISTERS",
    "WRITE_MULTIPLE_REGISTERS",
    "WRITE_SINGLE_REGISTER",
    "ReadOnlyModbusTcpService",
    "ReadOnlyRegisterMap",
    "RegisterReadResult",
    "RegisterWriteResult",
]
