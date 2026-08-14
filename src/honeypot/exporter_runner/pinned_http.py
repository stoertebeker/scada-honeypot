"""HTTPS transport that connects only to policy-vetted destination addresses."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import ssl
from typing import Any

import httpcore
import httpx


class PinnedNetworkBackend(httpcore.NetworkBackend):
    """Replace DNS at the socket boundary while preserving the original TLS SNI."""

    def __init__(
        self,
        *,
        pinned_hosts: Mapping[str, tuple[str, ...]],
        backend: Any | None = None,
    ) -> None:
        self._pinned_hosts = {
            host.lower(): tuple(addresses) for host, addresses in pinned_hosts.items()
        }
        self._backend = httpcore.SyncBackend() if backend is None else backend

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[tuple[Any, ...]] | None = None,
    ) -> httpcore.NetworkStream:
        addresses = self._pinned_hosts.get(host.lower())
        if not addresses:
            raise RuntimeError(f"HTTP-Zielhost ist nicht freigegeben: {host}")

        last_error: Exception | None = None
        for address in addresses:
            try:
                return self._backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[tuple[Any, ...]] | None = None,
    ) -> httpcore.NetworkStream:
        del path, timeout, socket_options
        raise RuntimeError("Unix-Sockets sind fuer Exporter nicht freigegeben")


class _ResponseStream(httpx.SyncByteStream):
    def __init__(self, stream: Iterable[bytes]) -> None:
        self._stream = stream

    def __iter__(self):
        yield from self._stream

    def close(self) -> None:
        close = getattr(self._stream, "close", None)
        if close is not None:
            close()


class PinnedHttpTransport(httpx.BaseTransport):
    """HTTPX transport backed by a DNS-free, address-pinned connection pool."""

    def __init__(
        self,
        *,
        host: str,
        addresses: tuple[str, ...],
        backend: Any | None = None,
    ) -> None:
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl.create_default_context(),
            max_connections=10,
            max_keepalive_connections=5,
            http1=True,
            http2=False,
            retries=0,
            network_backend=PinnedNetworkBackend(
                pinned_hosts={host: addresses},
                backend=backend,
            ),
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        assert isinstance(request.stream, httpx.SyncByteStream)
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        try:
            response = self._pool.handle_request(core_request)
        except (
            httpcore.NetworkError,
            httpcore.TimeoutException,
            httpcore.ProtocolError,
        ) as exc:
            raise httpx.TransportError(str(exc), request=request) from exc
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_ResponseStream(response.stream),
            extensions=response.extensions,
            request=request,
        )

    def close(self) -> None:
        self._pool.close()
