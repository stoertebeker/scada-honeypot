"""Kleiner Modbus/TCP-Server fuer den ersten V1-Slice."""

from __future__ import annotations

from dataclasses import dataclass, field
from socket import SHUT_RDWR
from socketserver import BaseRequestHandler, ThreadingTCPServer
from struct import pack, unpack
from threading import Thread
from typing import Any
from uuid import uuid4

from honeypot.event_core import EventRecorder
from honeypot.plant_sim import SimulationEventContext
from honeypot.protocol_modbus.registers import (
    ILLEGAL_DATA_ADDRESS,
    ILLEGAL_FUNCTION,
    ILLEGAL_DATA_VALUE,
    ModbusRegisterError,
    READ_HOLDING_REGISTERS,
    READ_INPUT_REGISTERS,
    ReadOnlyRegisterMap,
    WRITE_MULTIPLE_REGISTERS,
    WRITE_SINGLE_REGISTER,
    human_register_address,
)

DEFAULT_PROTOCOL = "modbus-tcp"
DEFAULT_SERVICE = "holding-registers"
DEFAULT_COMPONENT = "protocol-modbus"


class _ModbusThreadingServer(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], handler_cls: type[BaseRequestHandler]):
        super().__init__(address, handler_cls)


@dataclass(slots=True)
class ReadOnlyModbusTcpService:
    """Verwaltet einen kleinen Modbus/TCP-Server fuer den aktuellen V1-Slice."""

    register_map: ReadOnlyRegisterMap
    bind_host: str
    port: int
    event_recorder: EventRecorder | None = None
    _server: _ModbusThreadingServer | None = field(default=None, init=False, repr=False)
    _thread: Thread | None = field(default=None, init=False, repr=False)

    def start_in_thread(self) -> "ReadOnlyModbusTcpService":
        """Startet den Server in einem Hintergrund-Thread."""

        if self._server is not None:
            raise RuntimeError("Modbus-Server laeuft bereits")

        handler_cls = _build_handler(self.register_map, self.event_recorder)
        server = _ModbusThreadingServer((self.bind_host, self.port), handler_cls)
        thread = Thread(target=server.serve_forever, name="modbus-readonly-server", daemon=True)
        thread.start()
        self._server = server
        self._thread = thread
        return self

    def stop(self) -> None:
        """Beendet den Server sauber."""

        if self._server is None:
            return

        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            return (self.bind_host, self.port)
        host, port = self._server.server_address
        return str(host), int(port)


def _build_handler(
    register_map: ReadOnlyRegisterMap,
    event_recorder: EventRecorder | None,
) -> type[BaseRequestHandler]:
    class ModbusTcpHandler(BaseRequestHandler):
        def handle(self) -> None:
            while True:
                header = _recv_exact(self.request, 7)
                if header is None:
                    return

                transaction_id, protocol_id, length, unit_id = unpack(">HHHB", header)
                if length < 2:
                    return

                pdu = _recv_exact(self.request, length - 1)
                if pdu is None:
                    return

                function_code = pdu[0]
                source_ip = str(self.client_address[0])

                if protocol_id != 0:
                    _log_request(
                        event_recorder,
                        source_ip=source_ip,
                        unit_id=unit_id,
                        function_code=function_code,
                        register_start=None,
                        register_count=None,
                        asset_id=f"unit-{unit_id}",
                        result="rejected",
                        error_code="modbus_protocol_identifier_invalid",
                        message=f"ungueltiger Protocol Identifier: {protocol_id}",
                    )
                    return

                if function_code == READ_HOLDING_REGISTERS:
                    response = _handle_fc03_request(
                        register_map,
                        event_recorder,
                        transaction_id=transaction_id,
                        unit_id=unit_id,
                        pdu=pdu,
                        source_ip=source_ip,
                    )
                elif function_code == WRITE_SINGLE_REGISTER:
                    response = _handle_fc06_request(
                        register_map,
                        event_recorder,
                        transaction_id=transaction_id,
                        unit_id=unit_id,
                        pdu=pdu,
                        source_ip=source_ip,
                    )
                elif function_code == WRITE_MULTIPLE_REGISTERS:
                    response = _handle_fc16_request(
                        register_map,
                        event_recorder,
                        transaction_id=transaction_id,
                        unit_id=unit_id,
                        pdu=pdu,
                        source_ip=source_ip,
                    )
                else:
                    response = _exception_response(
                        transaction_id=transaction_id,
                        unit_id=unit_id,
                        function_code=function_code,
                        exception_code=ILLEGAL_FUNCTION,
                    )
                    _log_request(
                        event_recorder,
                        source_ip=source_ip,
                        unit_id=unit_id,
                        function_code=function_code,
                        register_start=None,
                        register_count=None,
                        asset_id=_asset_id_for_unit(unit_id),
                        result="rejected",
                        error_code="modbus_exception_01",
                        message=f"Funktionscode {function_code} ist im ersten Slice nicht aktiv",
                    )

                self.request.sendall(response)

        def finish(self) -> None:
            try:
                self.request.shutdown(SHUT_RDWR)
            except OSError:
                pass

    return ModbusTcpHandler


def _handle_fc03_request(
    register_map: ReadOnlyRegisterMap,
    event_recorder: EventRecorder | None,
    *,
    transaction_id: int,
    unit_id: int,
    pdu: bytes,
    source_ip: str,
) -> bytes:
    if len(pdu) != 5:
        response = _exception_response(
            transaction_id=transaction_id,
            unit_id=unit_id,
            function_code=READ_HOLDING_REGISTERS,
            exception_code=ILLEGAL_DATA_VALUE,
        )
        _log_request(
            event_recorder,
            source_ip=source_ip,
            unit_id=unit_id,
            function_code=READ_HOLDING_REGISTERS,
            register_start=None,
            register_count=None,
            asset_id=_asset_id_for_unit(unit_id),
            result="rejected",
            error_code="modbus_exception_03",
            message="ungueltige FC03-PDU-Laenge",
        )
        return response

    start_offset, quantity = unpack(">HH", pdu[1:])
    try:
        result = register_map.read_holding_registers(
            unit_id=unit_id,
            start_offset=start_offset,
            quantity=quantity,
        )
    except ModbusRegisterError as exc:
        response = _exception_response(
            transaction_id=transaction_id,
            unit_id=unit_id,
            function_code=READ_HOLDING_REGISTERS,
            exception_code=exc.exception_code,
        )
        _log_request(
            event_recorder,
            source_ip=source_ip,
            unit_id=unit_id,
            function_code=READ_HOLDING_REGISTERS,
            register_start=human_register_address(start_offset),
            register_count=quantity,
            asset_id=_asset_id_for_unit(unit_id),
            result="rejected",
            error_code=f"modbus_exception_{exc.exception_code:02d}",
            message=str(exc),
        )
        return response

    response_pdu = pack(">BB", READ_HOLDING_REGISTERS, len(result.values) * 2)
    response_pdu += b"".join(pack(">H", value) for value in result.values)
    response = _build_adu(
        transaction_id=transaction_id,
        unit_id=unit_id,
        pdu=response_pdu,
    )
    _log_request(
        event_recorder,
        source_ip=source_ip,
        unit_id=unit_id,
        function_code=READ_HOLDING_REGISTERS,
        register_start=human_register_address(start_offset),
        register_count=quantity,
        asset_id=result.asset_id,
        result="accepted",
        resulting_value=list(result.values),
        message="FC03 read accepted",
    )
    return response


def _handle_fc06_request(
    register_map: ReadOnlyRegisterMap,
    event_recorder: EventRecorder | None,
    *,
    transaction_id: int,
    unit_id: int,
    pdu: bytes,
    source_ip: str,
) -> bytes:
    if len(pdu) != 5:
        response = _exception_response(
            transaction_id=transaction_id,
            unit_id=unit_id,
            function_code=WRITE_SINGLE_REGISTER,
            exception_code=ILLEGAL_DATA_VALUE,
        )
        _log_request(
            event_recorder,
            source_ip=source_ip,
            unit_id=unit_id,
            function_code=WRITE_SINGLE_REGISTER,
            register_start=None,
            register_count=None,
            asset_id=_asset_id_for_unit(unit_id),
            result="rejected",
            error_code="modbus_exception_03",
            message="ungueltige FC06-PDU-Laenge",
        )
        return response

    start_offset, value = unpack(">HH", pdu[1:])
    correlation_id = f"corr_{uuid4().hex}"
    try:
        result = register_map.write_single_register(
            unit_id=unit_id,
            start_offset=start_offset,
            value=value,
            event_context=SimulationEventContext(
                source_ip=source_ip,
                actor_type="remote_client",
                correlation_id=correlation_id,
                protocol=DEFAULT_PROTOCOL,
                service=DEFAULT_SERVICE,
            ),
        )
    except ModbusRegisterError as exc:
        response = _exception_response(
            transaction_id=transaction_id,
            unit_id=unit_id,
            function_code=WRITE_SINGLE_REGISTER,
            exception_code=exc.exception_code,
        )
        _log_request(
            event_recorder,
            source_ip=source_ip,
            unit_id=unit_id,
            function_code=WRITE_SINGLE_REGISTER,
            register_start=human_register_address(start_offset),
            register_count=1,
            asset_id=_asset_id_for_unit(unit_id),
            result="rejected",
            requested_register_value=value,
            error_code=f"modbus_exception_{exc.exception_code:02d}",
            message=str(exc),
            correlation_id=correlation_id,
        )
        return response

    response = _build_adu(
        transaction_id=transaction_id,
        unit_id=unit_id,
        pdu=pack(">BHH", WRITE_SINGLE_REGISTER, start_offset, result.requested_value),
    )
    _log_request(
        event_recorder,
        source_ip=source_ip,
        unit_id=unit_id,
        function_code=WRITE_SINGLE_REGISTER,
        register_start=result.register_address,
        register_count=1,
        asset_id=result.asset_id,
        result="accepted",
        requested_register_value=result.requested_value,
        previous_value=result.previous_value,
        resulting_value=result.resulting_value,
        resulting_state=result.resulting_state,
        message="FC06 write accepted",
        correlation_id=correlation_id,
    )
    return response


def _handle_fc16_request(
    register_map: ReadOnlyRegisterMap,
    event_recorder: EventRecorder | None,
    *,
    transaction_id: int,
    unit_id: int,
    pdu: bytes,
    source_ip: str,
) -> bytes:
    if len(pdu) < 6:
        response = _exception_response(
            transaction_id=transaction_id,
            unit_id=unit_id,
            function_code=WRITE_MULTIPLE_REGISTERS,
            exception_code=ILLEGAL_DATA_VALUE,
        )
        _log_request(
            event_recorder,
            source_ip=source_ip,
            unit_id=unit_id,
            function_code=WRITE_MULTIPLE_REGISTERS,
            register_start=None,
            register_count=None,
            asset_id=_asset_id_for_unit(unit_id),
            result="rejected",
            error_code="modbus_exception_03",
            message="ungueltige FC16-PDU-Laenge",
        )
        return response

    start_offset, quantity, byte_count = unpack(">HHB", pdu[1:6])
    expected_byte_count = quantity * 2
    if quantity <= 0 or quantity > 123 or byte_count != expected_byte_count or len(pdu) != 6 + expected_byte_count:
        response = _exception_response(
            transaction_id=transaction_id,
            unit_id=unit_id,
            function_code=WRITE_MULTIPLE_REGISTERS,
            exception_code=ILLEGAL_DATA_VALUE,
        )
        _log_request(
            event_recorder,
            source_ip=source_ip,
            unit_id=unit_id,
            function_code=WRITE_MULTIPLE_REGISTERS,
            register_start=human_register_address(start_offset),
            register_count=quantity,
            asset_id=_asset_id_for_unit(unit_id),
            result="rejected",
            error_code="modbus_exception_03",
            message="ungueltiger FC16-Header oder Byte Count",
        )
        return response

    values = unpack(f">{quantity}H", pdu[6:])
    correlation_id = f"corr_{uuid4().hex}"
    try:
        result = register_map.write_multiple_registers(
            unit_id=unit_id,
            start_offset=start_offset,
            values=tuple(values),
            event_context=SimulationEventContext(
                source_ip=source_ip,
                actor_type="remote_client",
                correlation_id=correlation_id,
                protocol=DEFAULT_PROTOCOL,
                service=DEFAULT_SERVICE,
            ),
        )
    except ModbusRegisterError as exc:
        response = _exception_response(
            transaction_id=transaction_id,
            unit_id=unit_id,
            function_code=WRITE_MULTIPLE_REGISTERS,
            exception_code=exc.exception_code,
        )
        _log_request(
            event_recorder,
            source_ip=source_ip,
            unit_id=unit_id,
            function_code=WRITE_MULTIPLE_REGISTERS,
            register_start=human_register_address(start_offset),
            register_count=quantity,
            asset_id=_asset_id_for_unit(unit_id),
            result="rejected",
            requested_register_value=list(values),
            error_code=f"modbus_exception_{exc.exception_code:02d}",
            message=str(exc),
            correlation_id=correlation_id,
        )
        return response

    response = _build_adu(
        transaction_id=transaction_id,
        unit_id=unit_id,
        pdu=pack(">BHH", WRITE_MULTIPLE_REGISTERS, start_offset, result.quantity),
    )
    _log_request(
        event_recorder,
        source_ip=source_ip,
        unit_id=unit_id,
        function_code=WRITE_MULTIPLE_REGISTERS,
        register_start=result.start_register_address,
        register_count=result.quantity,
        asset_id=result.asset_id,
        result="accepted",
        requested_register_value=list(result.requested_values),
        previous_value=list(result.previous_values),
        resulting_value=list(result.resulting_values),
        resulting_state=result.resulting_state,
        message="FC16 write accepted",
        correlation_id=correlation_id,
    )
    return response


def _build_adu(*, transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
    return pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id) + pdu


def _exception_response(*, transaction_id: int, unit_id: int, function_code: int, exception_code: int) -> bytes:
    return _build_adu(
        transaction_id=transaction_id,
        unit_id=unit_id,
        pdu=pack(">BB", function_code | 0x80, exception_code),
    )


def _recv_exact(sock: Any, length: int) -> bytes | None:
    buffer = bytearray()
    while len(buffer) < length:
        chunk = sock.recv(length - len(buffer))
        if not chunk:
            return None
        buffer.extend(chunk)
    return bytes(buffer)


def _asset_id_for_unit(unit_id: int) -> str:
    if unit_id == 1:
        return "ppc-01"
    if unit_id == 41:
        return "grid-01"
    return f"unit-{unit_id}"


def _log_request(
    recorder: EventRecorder | None,
    *,
    source_ip: str,
    unit_id: int,
    function_code: int,
    register_start: int | None,
    register_count: int | None,
    asset_id: str,
    result: str,
    error_code: str | None = None,
    message: str | None = None,
    requested_register_value: Any | None = None,
    previous_value: int | None = None,
    resulting_value: Any | None = None,
    resulting_state: dict[str, object] | None = None,
    correlation_id: str | None = None,
) -> None:
    if recorder is None:
        return

    if function_code == READ_HOLDING_REGISTERS:
        event_type = "protocol.modbus.holding_registers_read"
        action = "read_holding_registers"
    elif function_code == WRITE_SINGLE_REGISTER and result == "accepted":
        event_type = "protocol.modbus.single_register_write"
        action = "write_single_register"
    elif function_code == WRITE_MULTIPLE_REGISTERS and result == "accepted":
        event_type = "protocol.modbus.multiple_register_write"
        action = "write_multiple_registers"
    else:
        event_type = "protocol.modbus.request_rejected"
        action = f"fc{function_code:02d}"

    requested_value = {
        "unit_id": unit_id,
        "function_code": function_code,
        "register_start": register_start,
        "register_count": register_count,
        "value_encoding": "u16",
    }
    if isinstance(requested_register_value, (list, tuple)):
        requested_value["register_values"] = list(requested_register_value)
    elif requested_register_value is not None:
        requested_value["register_value"] = requested_register_value

    event = recorder.build_event(
        event_type=event_type,
        category="protocol",
        severity="info" if result == "accepted" else "low",
        source_ip=source_ip,
        actor_type="remote_client",
        component=DEFAULT_COMPONENT,
        asset_id=asset_id,
        action=action,
        result=result,
        correlation_id=correlation_id,
        protocol=DEFAULT_PROTOCOL,
        service=DEFAULT_SERVICE,
        endpoint_or_register=(
            None
            if register_start is None or register_count is None
            else f"unit/{unit_id}/{register_start}-{register_start + register_count - 1}"
        ),
        requested_value=requested_value,
        previous_value=previous_value,
        resulting_value=resulting_value,
        resulting_state=resulting_state,
        error_code=error_code,
        message=message,
        tags=("protocol", "modbus", f"fc{function_code:02d}"),
    )
    recorder.record(event)
