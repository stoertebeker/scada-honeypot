from __future__ import annotations

from starlette.requests import Request

from honeypot.config_core import RuntimeConfig
from honeypot.http_source import request_source_ip


def make_request(*, client_host: str, x_forwarded_for: str | None = None) -> Request:
    headers = []
    if x_forwarded_for is not None:
        headers.append((b"x-forwarded-for", x_forwarded_for.encode("ascii")))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/overview",
            "headers": headers,
            "client": (client_host, 45678),
            "server": ("testserver", 80),
            "scheme": "http",
            "query_string": b"",
        }
    )


def test_request_source_ip_ignores_forwarded_header_by_default() -> None:
    config = RuntimeConfig(_env_file=None)
    request = make_request(client_host="10.14.0.53", x_forwarded_for="193.16.163.243")

    assert request_source_ip(request, config) == "10.14.0.53"


def test_request_source_ip_accepts_forwarded_header_from_trusted_proxy() -> None:
    config = RuntimeConfig(
        _env_file=None,
        forwarded_header_enabled=True,
        trusted_proxy_cidrs=("10.14.0.0/24",),
    )
    request = make_request(client_host="10.14.0.53", x_forwarded_for="193.16.163.243")

    assert request_source_ip(request, config) == "193.16.163.243"


def test_request_source_ip_ignores_spoofed_forwarded_header_from_untrusted_peer() -> None:
    config = RuntimeConfig(
        _env_file=None,
        forwarded_header_enabled=True,
        trusted_proxy_cidrs=("10.14.0.0/24",),
    )
    request = make_request(client_host="203.0.113.44", x_forwarded_for="193.16.163.243")

    assert request_source_ip(request, config) == "203.0.113.44"


def test_request_source_ip_walks_forwarded_chain_from_trusted_proxy_edge() -> None:
    config = RuntimeConfig(
        _env_file=None,
        forwarded_header_enabled=True,
        trusted_proxy_cidrs=("10.14.0.0/24", "127.0.0.1/32"),
    )
    request = make_request(
        client_host="127.0.0.1",
        x_forwarded_for="198.51.100.10, 10.14.0.53",
    )

    assert request_source_ip(request, config) == "198.51.100.10"


def test_request_source_ip_falls_back_when_forwarded_header_is_invalid() -> None:
    config = RuntimeConfig(
        _env_file=None,
        forwarded_header_enabled=True,
        trusted_proxy_cidrs=("10.14.0.0/24",),
    )
    request = make_request(client_host="10.14.0.53", x_forwarded_for="not-an-ip")

    assert request_source_ip(request, config) == "10.14.0.53"


def test_request_source_ip_falls_back_when_forwarded_chain_contains_invalid_entry() -> None:
    config = RuntimeConfig(
        _env_file=None,
        forwarded_header_enabled=True,
        trusted_proxy_cidrs=("10.14.0.0/24",),
    )
    request = make_request(client_host="10.14.0.53", x_forwarded_for="not-an-ip, 193.16.163.243")

    assert request_source_ip(request, config) == "10.14.0.53"
