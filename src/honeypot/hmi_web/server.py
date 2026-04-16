"""Kleiner lokaler HTTP-Dienst fuer den ersten HMI-Slice."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from threading import Thread
from time import monotonic, sleep

from fastapi import FastAPI
from uvicorn import Config, Server


class _ThreadedUvicornServer(Server):
    """Verhindert Signal-Handler-Installation ausserhalb des Haupt-Threads."""

    def install_signal_handlers(self) -> None:  # pragma: no cover - bewusst leer fuer Thread-Betrieb
        return


@dataclass(slots=True)
class LocalHmiHttpService:
    """Verwaltet den lokalen HTTP-Dienst fuer die read-only HMI."""

    app: FastAPI
    bind_host: str
    port: int
    log_level: str = "warning"
    _server: _ThreadedUvicornServer | None = field(default=None, init=False, repr=False)
    _thread: Thread | None = field(default=None, init=False, repr=False)
    _socket: socket.socket | None = field(default=None, init=False, repr=False)

    def start_in_thread(self) -> "LocalHmiHttpService":
        """Startet die HMI als echten lokalen HTTP-Dienst."""

        if self._server is not None:
            raise RuntimeError("HMI-HTTP-Dienst laeuft bereits")

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            listener.bind((self.bind_host, self.port))
            listener.listen(128)
            listener.setblocking(True)

            config = Config(
                app=self.app,
                host=self.bind_host,
                port=self.port,
                log_level=self.log_level,
                access_log=False,
                server_header=False,
                date_header=False,
            )
            server = _ThreadedUvicornServer(config)
            thread = Thread(
                target=server.run,
                kwargs={"sockets": [listener]},
                name="hmi-http-server",
                daemon=True,
            )
            thread.start()

            deadline = monotonic() + 5.0
            while monotonic() < deadline:
                if server.started:
                    self._socket = listener
                    self._server = server
                    self._thread = thread
                    return self
                if not thread.is_alive():
                    raise RuntimeError("HMI-HTTP-Dienst ist waehrend des Starts unerwartet beendet worden")
                sleep(0.01)
        except Exception:
            listener.close()
            raise

        server.should_exit = True
        thread.join(timeout=1.0)
        listener.close()
        raise RuntimeError("HMI-HTTP-Dienst konnte nicht innerhalb des Start-Zeitfensters gebootet werden")

    def stop(self) -> None:
        """Beendet den lokalen HMI-Dienst sauber."""

        if self._server is None:
            return

        self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        if self._socket is not None:
            self._socket.close()

        self._server = None
        self._thread = None
        self._socket = None

    @property
    def address(self) -> tuple[str, int]:
        if self._socket is None:
            return (self.bind_host, self.port)
        host, port = self._socket.getsockname()
        return str(host), int(port)
