"""Lokaler Prozesseinstieg fuer den ersten gemeinsamen Runtime-Pfad."""

from dataclasses import dataclass
from time import sleep

from fastapi import FastAPI

from honeypot.asset_domain import PlantSnapshot, load_plant_fixture
from honeypot.config_core import RuntimeConfig, load_runtime_config
from honeypot.event_core import EventRecorder
from honeypot.exporter_runner import (
    BackgroundOutboxRunnerService,
    OutboxRunner,
    SmtpExporter,
    TelegramExporter,
    WebhookExporter,
)
from honeypot.exporter_sdk import HoneypotExporter
from honeypot.hmi_web import LocalHmiHttpService, create_hmi_app
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
    hmi_service: LocalHmiHttpService
    modbus_service: ReadOnlyModbusTcpService
    outbox_runner: OutboxRunner | None = None
    outbox_runner_service: BackgroundOutboxRunnerService | None = None

    def start(self) -> "LocalRuntime":
        try:
            self.modbus_service.start_in_thread()
        except PermissionError as exc:
            raise RuntimeError(
                "Modbus-Listener konnte nicht gebunden werden; fuer design-local einen unprivilegierten "
                "MODBUS_PORT wie 1502 verwenden"
            ) from exc
        try:
            self.hmi_service.start_in_thread()
        except PermissionError as exc:
            self.modbus_service.stop()
            raise RuntimeError(
                "HMI-HTTP-Dienst konnte nicht gebunden werden; fuer design-local einen unprivilegierten "
                "HMI_PORT wie 8080 verwenden"
            ) from exc
        except Exception:
            self.modbus_service.stop()
            raise
        try:
            if self.outbox_runner_service is not None:
                self.outbox_runner_service.start_in_thread()
        except Exception:
            self.hmi_service.stop()
            self.modbus_service.stop()
            raise
        return self

    def stop(self) -> None:
        try:
            if self.outbox_runner_service is not None:
                self.outbox_runner_service.stop()
        finally:
            try:
                self.hmi_service.stop()
            finally:
                self.modbus_service.stop()


def bootstrap_runtime() -> RuntimeManifest:
    """Liefert das dokumentierte Modulgeruest fuer Phase A."""

    return RuntimeManifest(components=MODULES)


def build_local_runtime(
    *,
    env_file: str | None = ".env",
    modbus_port: int | None = None,
    hmi_port: int | None = None,
) -> LocalRuntime:
    """Verdrahtet den aktuellen lokalen Runtime-Slice mit Fixture, Store, Modbus und HMI."""

    config = load_runtime_config(env_file=env_file)
    if config.modbus_bind_host != "127.0.0.1":
        raise RuntimeError("MODBUS_BIND_HOST muss im aktuellen V1-Laborbetrieb auf 127.0.0.1 bleiben")
    if config.hmi_bind_host != "127.0.0.1":
        raise RuntimeError("HMI_BIND_HOST muss im aktuellen V1-Laborbetrieb auf 127.0.0.1 bleiben")

    manifest = bootstrap_runtime()
    snapshot = PlantSnapshot.from_fixture(load_plant_fixture("normal_operation"))
    event_store = SQLiteEventStore(config.event_store_path)
    event_recorder = EventRecorder(
        store=event_store,
        clock=SystemClock(),
        archive=(JsonlEventArchive(config.jsonl_archive_path) if config.jsonl_archive_enabled else None),
        rule_engine=RuleEngine.default_v1(
            min_severity=config.alert_min_severity,
            capacity_mw=config.capacity_mw,
            low_output_threshold_pct=config.alarm_threshold_low_output_pct,
        ),
    )
    register_map = ReadOnlyRegisterMap(snapshot, event_recorder=event_recorder)
    hmi_app = create_hmi_app(
        snapshot_provider=lambda: register_map.snapshot,
        config=config,
        event_recorder=event_recorder,
        service_controls=register_map,
    )
    modbus_service = ReadOnlyModbusTcpService(
        register_map=register_map,
        bind_host=config.modbus_bind_host,
        port=config.modbus_port if modbus_port is None else modbus_port,
        event_recorder=event_recorder,
    )
    hmi_service = LocalHmiHttpService(
        app=hmi_app,
        bind_host=config.hmi_bind_host,
        port=config.hmi_port if hmi_port is None else hmi_port,
        log_level=config.log_level,
    )
    exporters = _build_exporters(config)
    outbox_runner = None
    outbox_runner_service = None
    if exporters:
        outbox_runner = OutboxRunner(
            store=event_store,
            exporters=exporters,
            batch_size=config.outbox_batch_size,
            retry_backoff_seconds=config.outbox_retry_backoff_seconds,
            clock=event_recorder.clock,
        )
        outbox_runner_service = BackgroundOutboxRunnerService(runner=outbox_runner)
    return LocalRuntime(
        config=config,
        manifest=manifest,
        snapshot=snapshot,
        event_store=event_store,
        event_recorder=event_recorder,
        hmi_app=hmi_app,
        hmi_service=hmi_service,
        modbus_service=modbus_service,
        outbox_runner=outbox_runner,
        outbox_runner_service=outbox_runner_service,
    )


def _build_exporters(config: RuntimeConfig) -> dict[str, HoneypotExporter]:
    exporters: dict[str, HoneypotExporter] = {}
    if config.webhook_exporter_enabled and config.webhook_exporter_url is not None:
        exporters["webhook"] = WebhookExporter(
            url=str(config.webhook_exporter_url),
            retry_after_seconds=config.outbox_retry_backoff_seconds,
        )
    if config.smtp_exporter_enabled and config.smtp_host is not None and config.smtp_from is not None and config.smtp_to is not None:
        exporters["smtp"] = SmtpExporter(
            host=config.smtp_host,
            port=config.smtp_port,
            mail_from=config.smtp_from,
            rcpt_to=config.smtp_to,
            retry_after_seconds=config.outbox_retry_backoff_seconds,
        )
    if config.telegram_exporter_enabled and config.telegram_bot_token is not None and config.telegram_chat_id is not None:
        exporters["telegram"] = TelegramExporter(
            bot_token=config.telegram_bot_token,
            chat_id=config.telegram_chat_id,
            retry_after_seconds=config.outbox_retry_backoff_seconds,
        )
    return exporters


def _runtime_banner(runtime: LocalRuntime) -> str:
    modbus_host, modbus_port = runtime.modbus_service.address
    hmi_host, hmi_port = runtime.hmi_service.address
    return (
        f"honeypot runtime ready for {runtime.config.site_code}: "
        f"modbus://{modbus_host}:{modbus_port} "
        f"http://{hmi_host}:{hmi_port}/overview "
        f"fixture={runtime.snapshot.fixture_name} "
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
    """Startet den aktuellen lokalen Runtime-Slice fuer Modbus und HMI auf localhost."""

    runtime = build_local_runtime(env_file=env_file).start()
    print(_runtime_banner(runtime))
    _run_until_stopped(runtime)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
