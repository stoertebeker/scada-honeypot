"""Lokaler Prozesseinstieg fuer den ersten gemeinsamen Runtime-Pfad."""

from dataclasses import dataclass
from time import sleep

from fastapi import FastAPI

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.config_core import RuntimeConfig, load_runtime_config
from honeypot.event_core import EventRecorder
from honeypot.hmi_web import create_hmi_app
from honeypot.protocol_modbus import ReadOnlyModbusTcpService, ReadOnlyRegisterMap
from honeypot.rule_engine import RuleEngine
from honeypot.storage import JsonlEventArchive, SQLiteEventStore
from honeypot.time_core import SystemClock

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


@dataclass(slots=True)
class LocalRuntime:
    """Gebootstrappte lokale Runtime fuer den aktuellen V1-Slice."""

    config: RuntimeConfig
    manifest: RuntimeManifest
    snapshot: PlantSnapshot
    event_store: SQLiteEventStore
    event_recorder: EventRecorder
    hmi_app: FastAPI
    modbus_service: ReadOnlyModbusTcpService

    def start(self) -> "LocalRuntime":
        try:
            self.modbus_service.start_in_thread()
        except PermissionError as exc:
            raise RuntimeError(
                "Modbus-Listener konnte nicht gebunden werden; fuer design-local einen unprivilegierten "
                "MODBUS_PORT wie 1502 verwenden"
            ) from exc
        return self

    def stop(self) -> None:
        self.modbus_service.stop()


def bootstrap_runtime() -> RuntimeManifest:
    """Liefert das dokumentierte Modulgeruest fuer Phase A."""

    return RuntimeManifest(components=MODULES)


def build_local_runtime(
    *,
    env_file: str | None = ".env",
    modbus_port: int | None = None,
) -> LocalRuntime:
    """Verdrahtet den aktuellen lokalen Runtime-Slice mit Fixture, Store und Modbus."""

    config = load_runtime_config(env_file=env_file)
    if config.modbus_bind_host != "127.0.0.1":
        raise RuntimeError("MODBUS_BIND_HOST muss im aktuellen V1-Laborbetrieb auf 127.0.0.1 bleiben")

    manifest = bootstrap_runtime()
    snapshot = PlantSnapshot.from_fixture(load_plant_fixture("normal_operation"))
    event_store = SQLiteEventStore(config.event_store_path)
    event_recorder = EventRecorder(
        store=event_store,
        clock=SystemClock(),
        archive=(JsonlEventArchive(config.jsonl_archive_path) if config.jsonl_archive_enabled else None),
        rule_engine=RuleEngine.default_v1(min_severity=config.alert_min_severity),
    )
    register_map = ReadOnlyRegisterMap(snapshot, event_recorder=event_recorder)
    hmi_app = create_hmi_app(
        snapshot_provider=lambda: register_map.snapshot,
        config=config,
        event_recorder=event_recorder,
    )
    modbus_service = ReadOnlyModbusTcpService(
        register_map=register_map,
        bind_host=config.modbus_bind_host,
        port=config.modbus_port if modbus_port is None else modbus_port,
        event_recorder=event_recorder,
    )
    return LocalRuntime(
        config=config,
        manifest=manifest,
        snapshot=snapshot,
        event_store=event_store,
        event_recorder=event_recorder,
        hmi_app=hmi_app,
        modbus_service=modbus_service,
    )


def _runtime_banner(runtime: LocalRuntime) -> str:
    host, port = runtime.modbus_service.address
    return (
        f"honeypot runtime ready for {runtime.config.site_code}: "
        f"modbus://{host}:{port} fixture={runtime.snapshot.fixture_name} "
        f"components={', '.join(runtime.manifest.components)}"
    )


def _run_until_stopped(runtime: LocalRuntime) -> None:
    try:
        while True:
            sleep(3600)
    except KeyboardInterrupt:
        return
    finally:
        runtime.stop()


def main(*, env_file: str | None = ".env") -> int:
    """Startet den aktuellen lokalen Runtime-Slice fuer Modbus auf localhost."""

    runtime = build_local_runtime(env_file=env_file).start()
    print(_runtime_banner(runtime))
    _run_until_stopped(runtime)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
