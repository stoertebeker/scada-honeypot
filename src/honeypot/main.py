"""Minimaler Einstiegspunkt fuer Phase A."""

from dataclasses import dataclass

from honeypot.config_core import load_runtime_config

MODULES: tuple[str, ...] = (
    "config_core",
    "asset_domain",
    "plant_sim",
    "event_core",
    "storage",
    "rule_engine",
    "protocol_modbus",
    "hmi_web",
    "exporter_sdk",
    "exporter_runner",
)


@dataclass(frozen=True, slots=True)
class RuntimeManifest:
    """Beschreibt das minimale Geruest der Anwendung."""

    components: tuple[str, ...]


def bootstrap_runtime() -> RuntimeManifest:
    """Liefert das dokumentierte Modulgeruest fuer Phase A."""

    return RuntimeManifest(components=MODULES)


def main() -> int:
    """Minimal startbarer Prozesseinstieg fuer das Repo-Bootstrapping."""

    config = load_runtime_config()
    manifest = bootstrap_runtime()
    print(f"honeypot scaffold ready for {config.site_code}: {', '.join(manifest.components)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
