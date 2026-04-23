"""Lokale Ingress-Gates fuer bewusst freigegebene Runtime-Bindings."""

from __future__ import annotations

from dataclasses import dataclass

from honeypot.config_core import RuntimeConfig


@dataclass(frozen=True, slots=True)
class IngressBinding:
    """Beschreibt ein bewusst zu genehmigendes Runtime-Binding."""

    service: str
    host: str
    port: int

    @property
    def spec(self) -> str:
        return f"{self.service}:{self.host}:{self.port}"


def enforce_runtime_ingress_policy(
    *,
    config: RuntimeConfig,
    modbus_port: int,
    hmi_port: int,
) -> tuple[str, ...]:
    """Prueft, ob externe Runtime-Bindings explizit freigegeben wurden."""

    planned_bindings = planned_ingress_bindings(
        modbus_bind_host=config.modbus_bind_host,
        modbus_port=modbus_port,
        hmi_bind_host=config.hmi_bind_host,
        hmi_port=hmi_port,
    )
    if not planned_bindings:
        return ()

    approved_bindings = set(config.approved_ingress_bindings)
    missing_bindings = tuple(binding.spec for binding in planned_bindings if binding.spec not in approved_bindings)
    if missing_bindings:
        missing_list = ", ".join(missing_bindings)
        raise RuntimeError(
            "Ingress-Freigabe fehlt fuer externe Bindings: "
            f"{missing_list}. APPROVED_INGRESS_BINDINGS muss diese Bindings explizit enthalten."
        )
    return tuple(binding.spec for binding in planned_bindings)


def planned_ingress_bindings(
    *,
    modbus_bind_host: str,
    modbus_port: int,
    hmi_bind_host: str,
    hmi_port: int,
) -> tuple[IngressBinding, ...]:
    """Leitet normalisierte Runtime-Bindings fuer nicht-lokale Dienste ab."""

    bindings: list[IngressBinding] = []
    for binding in (
        IngressBinding(service="modbus", host=modbus_bind_host.lower(), port=modbus_port),
        IngressBinding(service="hmi", host=hmi_bind_host.lower(), port=hmi_port),
    ):
        if _is_nonlocal_bind(binding.host) and binding.spec not in {existing.spec for existing in bindings}:
            bindings.append(binding)
    return tuple(bindings)


def _is_nonlocal_bind(host: str) -> bool:
    return host != "127.0.0.1"
