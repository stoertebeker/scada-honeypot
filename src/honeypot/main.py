"""Lokaler Prozesseinstieg fuer den ersten gemeinsamen Runtime-Pfad."""

import argparse
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
import socket
from struct import pack, unpack
from time import sleep

import httpx
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
from honeypot.history_core import apply_history_sample_to_snapshot
from honeypot.runtime_egress import enforce_runtime_egress_policy
from honeypot.runtime_exposure import append_exposed_research_finding, enforce_exposed_research_policy
from honeypot.runtime_ingress import enforce_runtime_ingress_policy
from honeypot.hmi_web import LocalHmiHttpService, create_hmi_app
from honeypot.monitoring import BackgroundRuntimeStatusService, RuntimeStatusWriter
from honeypot.ops_web import create_ops_app
from honeypot.plant_sim import PlantSimulator
from honeypot.protocol_modbus import READ_HOLDING_REGISTERS, ReadOnlyModbusTcpService, ReadOnlyRegisterMap
from honeypot.runtime_reset import reset_local_runtime_artifacts
from honeypot.runtime_evolution import (
    PLANT_HISTORY_RETENTION_DAYS,
    BackgroundPlantEvolutionService,
    TrendHistoryBuffer,
    seed_plant_history_if_empty,
    trend_history_capacity,
)
from honeypot.rule_engine import RuleEngine
from honeypot.storage import JsonlEventArchive, SQLiteEventStore
from honeypot.time_core import Clock, SystemClock
from honeypot.weather_core import (
    DeterministicDiurnalWeatherProvider,
    OpenMeteoForecastProvider,
    OpenMeteoSatelliteRadiationProvider,
    WeatherObservationProvider,
)

MODULES: tuple[str, ...] = (
    "config_core",
    "asset_domain",
    "plant_sim",
    "event_core",
    "storage",
    "rule_engine",
    "protocol_modbus",
    "hmi_web",
    "ops_web",
    "runtime_evolution",
    "weather_core",
    "monitoring",
    "exporter_sdk",
    "exporter_runner",
)
EVOLUTION_INTERVAL_SECONDS = 5.0


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
    trend_history: TrendHistoryBuffer
    evolution_service: BackgroundPlantEvolutionService
    ops_app: FastAPI | None = None
    ops_service: LocalHmiHttpService | None = None
    exporters: dict[str, HoneypotExporter] = field(default_factory=dict)
    outbox_runner: OutboxRunner | None = None
    outbox_runner_service: BackgroundOutboxRunnerService | None = None
    runtime_status_service: BackgroundRuntimeStatusService | None = None

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
            if self.ops_service is not None:
                self.ops_service.start_in_thread()
        except PermissionError as exc:
            self.hmi_service.stop()
            self.modbus_service.stop()
            raise RuntimeError(
                "Ops-HTTP-Dienst konnte nicht gebunden werden; OPS_PORT oder OPS_BIND_HOST pruefen"
            ) from exc
        except Exception:
            self.hmi_service.stop()
            self.modbus_service.stop()
            raise
        try:
            self.evolution_service.start_in_thread()
        except Exception:
            if self.ops_service is not None:
                self.ops_service.stop()
            self.hmi_service.stop()
            self.modbus_service.stop()
            raise
        try:
            if self.outbox_runner_service is not None:
                self.outbox_runner_service.start_in_thread()
        except Exception:
            if self.ops_service is not None:
                self.ops_service.stop()
            self.evolution_service.stop()
            self.hmi_service.stop()
            self.modbus_service.stop()
            raise
        try:
            if self.runtime_status_service is not None:
                self.runtime_status_service.start_in_thread()
        except Exception:
            if self.outbox_runner_service is not None:
                self.outbox_runner_service.stop()
            if self.ops_service is not None:
                self.ops_service.stop()
            self.evolution_service.stop()
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
                self.evolution_service.stop()
            finally:
                try:
                    if self.ops_service is not None:
                        self.ops_service.stop()
                finally:
                    try:
                        self.hmi_service.stop()
                    finally:
                        try:
                            self.modbus_service.stop()
                        finally:
                            if self.runtime_status_service is not None:
                                self.runtime_status_service.stop()


def bootstrap_runtime() -> RuntimeManifest:
    """Liefert das dokumentierte Modulgeruest fuer Phase A."""

    return RuntimeManifest(components=MODULES)


def build_local_runtime(
    *,
    env_file: str | None = ".env",
    modbus_port: int | None = None,
    hmi_port: int | None = None,
    ops_port: int | None = None,
    clock: Clock | None = None,
) -> LocalRuntime:
    """Verdrahtet den lokalen Runtime-Slice mit Fixture, Store, Modbus, HMI und Ops."""

    config = load_runtime_config(env_file=env_file)
    _enforce_runtime_bind_policy(config)
    effective_hmi_port = config.hmi_port if hmi_port is None else hmi_port
    effective_modbus_port = config.modbus_port if modbus_port is None else modbus_port
    effective_ops_port = _effective_ops_port(config=config, hmi_port=hmi_port, ops_port=ops_port)
    enforce_runtime_ingress_policy(
        config=config,
        modbus_port=effective_modbus_port,
        hmi_port=effective_hmi_port,
        ops_port=effective_ops_port,
    )

    manifest = bootstrap_runtime()
    snapshot = PlantSnapshot.from_fixture(load_plant_fixture("normal_operation"))
    runtime_clock = SystemClock() if clock is None else clock
    weather_provider = _build_weather_provider(config)
    event_store = SQLiteEventStore(config.event_store_path)
    event_recorder = EventRecorder(
        store=event_store,
        clock=runtime_clock,
        archive=(JsonlEventArchive(config.jsonl_archive_path) if config.jsonl_archive_enabled else None),
        rule_engine=RuleEngine.default_v1(
            min_severity=config.alert_min_severity,
            capacity_mw=config.capacity_mw,
            low_output_threshold_pct=config.alarm_threshold_low_output_pct,
        ),
    )
    seed_simulator = PlantSimulator.from_snapshot(snapshot)
    simulator = PlantSimulator.from_snapshot(snapshot, event_recorder=event_recorder)
    seed_plant_history_if_empty(
        history_store=event_store,
        snapshot=snapshot,
        simulator=seed_simulator,
        clock=runtime_clock,
        timezone=config.timezone,
        weather_latitude=config.weather_latitude,
        weather_longitude=config.weather_longitude,
        weather_elevation_m=config.weather_elevation_m,
    )
    latest_history = event_store.fetch_plant_history(limit=1)
    if latest_history and weather_provider is not None:
        snapshot = apply_history_sample_to_snapshot(snapshot, latest_history[-1])
    register_map = ReadOnlyRegisterMap(snapshot, event_recorder=event_recorder, simulator=simulator)
    trend_history = TrendHistoryBuffer(
        max_samples=trend_history_capacity(
            window_minutes=config.trend_window_minutes,
            interval_seconds=EVOLUTION_INTERVAL_SECONDS,
        )
    )
    evolution_service = BackgroundPlantEvolutionService(
        register_map=register_map,
        history=trend_history,
        clock=runtime_clock,
        simulator=simulator,
        weather_provider=weather_provider,
        timezone=config.timezone,
        weather_latitude=config.weather_latitude,
        weather_longitude=config.weather_longitude,
        weather_elevation_m=config.weather_elevation_m,
        interval_seconds=EVOLUTION_INTERVAL_SECONDS,
        history_store=event_store,
    )
    hmi_app = create_hmi_app(
        snapshot_provider=lambda: register_map.snapshot,
        trend_history_provider=lambda: _merged_trend_history(
            event_store=event_store,
            trend_history=trend_history,
            clock=runtime_clock,
        ),
        config=config,
        event_recorder=event_recorder,
        service_controls=register_map,
    )
    modbus_service = ReadOnlyModbusTcpService(
        register_map=register_map,
        bind_host=config.modbus_bind_host,
        port=effective_modbus_port,
        event_recorder=event_recorder,
    )
    hmi_service = LocalHmiHttpService(
        app=hmi_app,
        bind_host=config.hmi_bind_host,
        port=effective_hmi_port,
        log_level=config.log_level,
    )
    ops_app = (
        create_ops_app(event_store=event_store, config=config, event_recorder=event_recorder)
        if config.ops_enabled
        else None
    )
    ops_service = (
        LocalHmiHttpService(
            app=ops_app,
            bind_host=config.ops_bind_host,
            port=effective_ops_port,
            log_level=config.log_level,
        )
        if ops_app is not None
        else None
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
    runtime_status_service = None
    if config.runtime_status_enabled:
        runtime_status_service = BackgroundRuntimeStatusService(
            writer=RuntimeStatusWriter(
                site_code=config.site_code,
                fixture_name=snapshot.fixture_name,
                path=config.runtime_status_path,
                event_store=event_store,
                modbus_service=modbus_service,
                hmi_service=hmi_service,
                ops_service=ops_service,
                exporters=exporters,
                outbox_runner_service=outbox_runner_service,
                clock=event_recorder.clock,
            ),
            interval_seconds=config.runtime_status_interval_seconds,
        )
    return LocalRuntime(
        config=config,
        manifest=manifest,
        snapshot=snapshot,
        event_store=event_store,
        event_recorder=event_recorder,
        hmi_app=hmi_app,
        hmi_service=hmi_service,
        ops_app=ops_app,
        ops_service=ops_service,
        modbus_service=modbus_service,
        trend_history=trend_history,
        evolution_service=evolution_service,
        exporters=exporters,
        outbox_runner=outbox_runner,
        outbox_runner_service=outbox_runner_service,
        runtime_status_service=runtime_status_service,
    )


def _enforce_runtime_bind_policy(config: RuntimeConfig) -> None:
    if config.allow_nonlocal_bind:
        return
    if config.modbus_bind_host != "127.0.0.1":
        raise RuntimeError(
            "MODBUS_BIND_HOST ausserhalb von 127.0.0.1 erfordert ALLOW_NONLOCAL_BIND=1"
        )
    if config.hmi_bind_host != "127.0.0.1":
        raise RuntimeError(
            "HMI_BIND_HOST ausserhalb von 127.0.0.1 erfordert ALLOW_NONLOCAL_BIND=1"
        )
    if config.ops_enabled and config.ops_bind_host != "127.0.0.1":
        raise RuntimeError(
            "OPS_BIND_HOST ausserhalb von 127.0.0.1 erfordert ALLOW_NONLOCAL_BIND=1"
        )


def _effective_ops_port(*, config: RuntimeConfig, hmi_port: int | None, ops_port: int | None) -> int:
    if ops_port is not None:
        return ops_port
    if hmi_port == 0:
        return 0
    return config.ops_port


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


def _build_weather_provider(config: RuntimeConfig) -> WeatherObservationProvider | None:
    if config.weather_provider == "disabled":
        return None
    if config.weather_provider == "deterministic":
        return DeterministicDiurnalWeatherProvider()
    if config.weather_provider == "open_meteo_forecast":
        return OpenMeteoForecastProvider(
            timeout_seconds=float(config.weather_request_timeout_seconds),
            cache_ttl_seconds=config.weather_cache_ttl_seconds,
        )
    return OpenMeteoSatelliteRadiationProvider(
        timeout_seconds=float(config.weather_request_timeout_seconds),
        cache_ttl_seconds=config.weather_cache_ttl_seconds,
    )


def _merged_trend_history(
    *,
    event_store: SQLiteEventStore,
    trend_history: TrendHistoryBuffer,
    clock: Clock,
) -> tuple:
    cutoff = clock.now() - timedelta(days=PLANT_HISTORY_RETENTION_DAYS)
    samples_by_time = {
        sample.observed_at: sample
        for sample in event_store.fetch_plant_history(since=cutoff)
    }
    for sample in trend_history.snapshot():
        if sample.observed_at >= cutoff:
            existing_sample = samples_by_time.get(sample.observed_at)
            if existing_sample is not None and sample.export_energy_mwh_total is None:
                continue
            samples_by_time[sample.observed_at] = sample
    return tuple(samples_by_time[key] for key in sorted(samples_by_time))


def _runtime_banner(runtime: LocalRuntime) -> str:
    modbus_host, modbus_port = runtime.modbus_service.address
    hmi_host, hmi_port = runtime.hmi_service.address
    ops_fragment = ""
    if runtime.ops_service is not None:
        ops_host, ops_port = runtime.ops_service.address
        ops_fragment = f" ops=http://{ops_host}:{ops_port}/"
    return (
        f"honeypot runtime ready for {runtime.config.site_code}: "
        f"modbus://{modbus_host}:{modbus_port} "
        f"http://{hmi_host}:{hmi_port}/overview"
        f"{ops_fragment} "
        f"fixture={runtime.snapshot.fixture_name} "
        f"components={', '.join(runtime.manifest.components)}"
    )


def verify_exposed_research_runtime(*, env_file: str | None = ".env") -> int:
    """Fuehrt einen lokalen Start-/Read-/Alert-/Stop-Sweep fuer exposed-research aus."""

    runtime = build_local_runtime(env_file=env_file)
    modbus_address: tuple[str, int] | None = None
    hmi_address: tuple[str, int] | None = None
    runtime_started = False
    try:
        enforce_runtime_egress_policy(config=runtime.config, exporters=runtime.exporters)
        enforce_exposed_research_policy(config=runtime.config, exporters=runtime.exporters)
        runtime.start()
        runtime_started = True
        modbus_address = _loopback_runtime_address(runtime.modbus_service.address)
        hmi_address = _loopback_runtime_address(runtime.hmi_service.address)
        modbus_response = _send_modbus_request(
            modbus_address,
            transaction_id=0x5EAD,
            unit_id=1,
            function_code=READ_HOLDING_REGISTERS,
            body=pack(">HH", 0, 8),
        )
        overview_response = httpx.get(
            f"http://{hmi_address[0]}:{hmi_address[1]}/overview",
            timeout=5.0,
            trust_env=False,
        )
        runtime.modbus_service.register_map.request_breaker_open()
        runtime.modbus_service.register_map.request_breaker_close()
    except Exception as exc:
        append_exposed_research_finding(
            config=runtime.config,
            status="failed",
            summary=str(exc),
            details=("sweep_status=failed",),
        )
        raise
    finally:
        if runtime_started:
            runtime.stop()

    _, protocol_id, unit_id, pdu = _parse_modbus_response(modbus_response)
    byte_count = pdu[1]
    registers = unpack(f">{byte_count // 2}H", pdu[2:])
    alerts = runtime.event_store.fetch_alerts()
    breaker_alerts = [alert for alert in alerts if alert.alarm_code == "BREAKER_OPEN"]
    if protocol_id != 0 or unit_id != 1 or registers[:2] != (100, 1001):
        raise RuntimeError("exposed-research-Sweep: Modbus-Antwort stimmt nicht mit dem erwarteten Profil ueberein")
    if overview_response.status_code != 200 or "Plant Overview" not in overview_response.text:
        raise RuntimeError("exposed-research-Sweep: HMI-/overview antwortet nicht mit dem erwarteten Profil")
    if len(breaker_alerts) < 2 or breaker_alerts[-1].state != "cleared":
        raise RuntimeError("exposed-research-Sweep: Alert-Pfad fuer BREAKER_OPEN wurde nicht sauber aktiv/cleared verifiziert")
    append_exposed_research_finding(
        config=runtime.config,
        status="passed",
        summary="runtime start, modbus read, hmi overview and breaker alert lifecycle verified",
        details=(
            f"modbus_address={modbus_address[0]}:{modbus_address[1]}",
            f"hmi_address={hmi_address[0]}:{hmi_address[1]}",
            "sweep_status=passed",
        ),
    )
    print(
        "exposed-research sweep ok: "
        f"modbus={modbus_address[0]}:{modbus_address[1]} "
        f"hmi={hmi_address[0]}:{hmi_address[1]} "
        f"site={runtime.config.site_code}"
    )
    return 0


def verify_exposed_research_target_host(*, env_file: str | None = ".env") -> int:
    """Fuehrt den Exposure-Sweep aus und gibt die relevanten Artefaktpfade fuer den Zielhost aus."""

    config = load_runtime_config(env_file=env_file)
    result = verify_exposed_research_runtime(env_file=env_file)
    print(
        "exposed-research target-host artifacts: "
        f"env_file={env_file or '.env'} "
        f"findings={config.findings_log_path} "
        f"runtime_status={config.runtime_status_path if config.runtime_status_enabled else 'disabled'} "
        f"event_store={config.event_store_path} "
        f"jsonl_archive={config.jsonl_archive_path if config.jsonl_archive_enabled else 'disabled'}"
    )
    return result


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

    runtime = build_local_runtime(env_file=env_file)
    enforce_runtime_egress_policy(config=runtime.config, exporters=runtime.exporters)
    enforce_exposed_research_policy(config=runtime.config, exporters=runtime.exporters)
    runtime.start()
    print(_runtime_banner(runtime))
    _run_until_stopped(runtime)
    return 0


def cli(argv: list[str] | None = None) -> int:
    """Bietet Start- und Reset-Pfad fuer den lokalen Runtime-Betrieb."""

    parser = argparse.ArgumentParser(prog="python -m honeypot.main")
    parser.add_argument("--env-file", default=".env", help="Pfad zur Runtime-.env-Datei")
    parser.add_argument(
        "--reset-runtime",
        action="store_true",
        help="entfernt lokale Runtime-Artefakte fuer einen frischen Neustart",
    )
    parser.add_argument(
        "--verify-exposed-research",
        action="store_true",
        help="fuehrt den lokalen Start-/Read-/Alert-/Stop-Sweep fuer exposed-research aus",
    )
    parser.add_argument(
        "--verify-exposed-research-target-host",
        action="store_true",
        help="fuehrt den exposed-research-Sweep aus und gibt die Zielhost-Artefakte danach kompakt aus",
    )
    args = parser.parse_args(argv)
    env_file = None if args.env_file == "" else str(Path(args.env_file))
    if args.reset_runtime:
        report = reset_local_runtime_artifacts(env_file=env_file)
        print(
            f"honeypot runtime artifacts reset for {report.site_code}: "
            f"removed={len(report.removed_paths)} missing={len(report.missing_paths)}"
        )
        return 0
    if args.verify_exposed_research_target_host:
        return verify_exposed_research_target_host(env_file=env_file)
    if args.verify_exposed_research:
        return verify_exposed_research_runtime(env_file=env_file)
    return main(env_file=env_file)


def _loopback_runtime_address(address: tuple[str, int]) -> tuple[str, int]:
    host, port = address
    if host == "0.0.0.0":
        return "127.0.0.1", port
    return host, port


def _send_modbus_request(
    address: tuple[str, int],
    *,
    transaction_id: int,
    unit_id: int,
    function_code: int,
    body: bytes,
) -> bytes:
    payload = bytes([function_code]) + body
    request = pack(">HHHB", transaction_id, 0, len(payload) + 1, unit_id) + payload
    with socket.create_connection(address, timeout=5.0) as connection:
        connection.sendall(request)
        return connection.recv(1024)


def _parse_modbus_response(response: bytes) -> tuple[int, int, int, bytes]:
    transaction_id, protocol_id, length, unit_id = unpack(">HHHB", response[:7])
    return transaction_id, protocol_id, unit_id, response[7 : 6 + length]


if __name__ == "__main__":
    raise SystemExit(cli())
