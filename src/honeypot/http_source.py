"""HTTP source-IP resolution with trusted-proxy guards."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Protocol

from starlette.requests import Request

from honeypot.config_core import RuntimeConfig

IpAddress = IPv4Address | IPv6Address
IpNetwork = IPv4Network | IPv6Network


class _RequestLike(Protocol):
    client: object
    headers: object


def request_source_ip(request: Request, config: RuntimeConfig) -> str:
    """Return the effective client IP, accepting XFF only from trusted proxies."""

    direct_ip = direct_request_source_ip(request)
    if not config.forwarded_header_enabled:
        return direct_ip

    trusted_networks = parse_trusted_proxy_networks(config.trusted_proxy_cidrs)
    direct_address = _parse_ip(direct_ip)
    if direct_address is None or not _is_in_networks(direct_address, trusted_networks):
        return direct_ip

    forwarded_for = request.headers.get("x-forwarded-for", "")
    raw_chain = tuple(part.strip() for part in forwarded_for.split(",") if part.strip())
    if not raw_chain:
        return direct_ip
    parsed_chain: list[IpAddress] = []
    for raw_part in raw_chain:
        parsed_address = _parse_ip(raw_part)
        if parsed_address is None:
            return direct_ip
        parsed_chain.append(parsed_address)
    forwarded_chain = tuple(parsed_chain)

    for candidate in reversed(forwarded_chain):
        if not _is_in_networks(candidate, trusted_networks):
            return str(candidate)
    return str(forwarded_chain[0])


def direct_request_source_ip(request: _RequestLike) -> str:
    client = getattr(request, "client", None)
    host = getattr(client, "host", None)
    return str(host) if host else "127.0.0.1"


def parse_trusted_proxy_networks(raw_cidrs: tuple[str, ...]) -> tuple[IpNetwork, ...]:
    networks: list[IpNetwork] = []
    for raw_cidr in raw_cidrs:
        networks.append(ip_network(raw_cidr, strict=False))
    return tuple(networks)


def _parse_ip(raw_value: str) -> IpAddress | None:
    value = raw_value.strip().strip('"').strip("'")
    if not value:
        return None
    if value.startswith("[") and "]" in value:
        value = value[1 : value.index("]")]
    try:
        parsed = ip_address(value)
    except ValueError:
        return None
    ipv4_mapped = getattr(parsed, "ipv4_mapped", None)
    return ipv4_mapped if ipv4_mapped is not None else parsed


def _is_in_networks(address: IpAddress, networks: tuple[IpNetwork, ...]) -> bool:
    return any(address.version == network.version and address in network for network in networks)
