from pathlib import Path

from honeypot.config_core import load_runtime_config


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_example_env_files_load_with_inline_comments() -> None:
    base_config = load_runtime_config(env_file=str(REPO_ROOT / ".env.example"))
    assert base_config.honeypot_local_debug is False
    assert base_config.watch_officer_name is None
    assert base_config.duty_engineer_name is None
    assert base_config.hmi_port == 8080

    exposed_config = load_runtime_config(
        env_file=str(REPO_ROOT / "deploy" / "lab-vm-observer-01.env.example")
    )
    assert exposed_config.honeypot_local_debug is False
    assert exposed_config.watch_officer_name == "blue-watch"
    assert exposed_config.duty_engineer_name == "ops-duty"


def test_compose_uses_single_production_runtime() -> None:
    compose_yaml = (REPO_ROOT / "compose.yaml").read_text(encoding="utf-8")
    gateway_config = (REPO_ROOT / "deploy" / "haproxy-modbus.cfg").read_text(encoding="utf-8")
    entrypoint = (REPO_ROOT / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
    healthcheck = (REPO_ROOT / "docker" / "healthcheck.sh").read_text(encoding="utf-8")

    assert "honeypot-exposed:" not in compose_yaml
    assert "honeypot-sweep:" not in compose_yaml
    assert "profiles:" not in compose_yaml
    assert "HONEYPOT_ENV_FILE" not in compose_yaml
    assert 'HONEYPOT_FORCE_CONTAINER_BINDS: "1"' in compose_yaml
    assert 'path: .env' in compose_yaml
    assert 'required: false' in compose_yaml
    assert 'HMI_PORT: "8080"' in compose_yaml
    assert 'MODBUS_PORT: "1502"' in compose_yaml
    assert 'OPS_PORT: "9090"' in compose_yaml
    assert "HMI_PUBLISHED_PORT: ${HMI_PUBLISHED_PORT:-8080}" in compose_yaml
    assert '"0.0.0.0:${HMI_PUBLISHED_PORT:-8080}:8080"' in compose_yaml
    honeypot_section, gateway_section = compose_yaml.split("  modbus-gateway:", maxsplit=1)
    assert '"0.0.0.0:${MODBUS_PUBLISHED_PORT:-1502}:1502"' not in honeypot_section
    assert '"0.0.0.0:${MODBUS_PUBLISHED_PORT:-1502}:1502"' in gateway_section
    assert 'MODBUS_PROXY_PROTOCOL_ENABLED: "1"' in honeypot_section
    assert 'MODBUS_MAX_CONNECTIONS_PER_SOURCE: "64"' in honeypot_section
    assert "cap_drop:" in gateway_section
    assert "- ALL" in gateway_section
    assert "stick-table type ip size 100k expire 30s store conn_cur,conn_rate(10s)" in gateway_config
    assert "tcp-request connection reject if { sc_conn_cur(0) gt 8 }" in gateway_config
    assert "tcp-request connection reject if { sc_conn_rate(0) gt 20 }" in gateway_config
    assert "server honeypot honeypot:1502 check send-proxy" in gateway_config
    assert '"127.0.0.1:${OPS_PUBLISHED_PORT:-9090}:9090"' in compose_yaml
    assert "HMI_PUBLISHED_HOST" not in compose_yaml
    assert "MODBUS_PUBLISHED_HOST" not in compose_yaml
    assert "OPS_PUBLISHED_HOST" not in compose_yaml
    assert "EVENT_STORE_PATH: /app/data/events.sqlite3" in compose_yaml
    assert "JSONL_ARCHIVE_PATH: /app/logs/events.jsonl" in compose_yaml
    assert "PCAP_CAPTURE_PATH: /app/pcap/session.pcapng" in compose_yaml
    assert "GEOIP_DBIP_AUTO_UPDATE: ${GEOIP_DBIP_AUTO_UPDATE:-0}" in compose_yaml
    assert "GEOIP_DBIP_COUNTRY_SHA256" in compose_yaml
    assert "GEOIP_DBIP_ASN_SHA256" in compose_yaml
    assert "GEOIP_DBIP_MAX_COMPRESSED_BYTES" in compose_yaml
    assert "GEOIP_DBIP_MAX_DECOMPRESSED_BYTES" in compose_yaml
    assert "GEOIP_DBIP_MAX_EXPANSION_RATIO" in compose_yaml
    assert "GEOIP_DBIP_TOTAL_DEADLINE_SECONDS" in compose_yaml
    assert "GEOIP_DBIP_MAX_DIRECTORY_BYTES" in compose_yaml
    assert "./data/geoip:/app/data/geoip:rw" in compose_yaml
    assert "python -m honeypot.geoip_update" in entrypoint
    assert "gosu honeypot" in entrypoint
    assert "set -- python -m honeypot.geoip_update" not in entrypoint
    assert "--country-sha256" in entrypoint
    assert "--asn-sha256" in entrypoint
    assert "--max-compressed-bytes" in entrypoint
    assert "--max-decompressed-bytes" in entrypoint
    assert "--max-expansion-ratio" in entrypoint
    assert "--total-deadline-seconds" in entrypoint
    assert "--max-directory-bytes" in entrypoint
    assert "--approved-egress-targets" in entrypoint
    assert "--approved-egress-cidrs" in entrypoint
    assert "--prohibited-ot-cidrs" in entrypoint
    assert "! -name geoip" in entrypoint
    assert "export HMI_BIND_HOST=0.0.0.0" in entrypoint
    assert "export MODBUS_BIND_HOST=0.0.0.0" in entrypoint
    assert "export OPS_BIND_HOST=0.0.0.0" in entrypoint
    assert "EXPOSED_RESEARCH_ENABLED" not in entrypoint
    assert "PUBLIC_INGRESS_MAPPINGS" in entrypoint
    assert "HONEYPOT_RUNTIME_MODE" not in entrypoint
    assert "/healthz" in healthcheck
    assert "/overview" not in healthcheck


def test_example_env_keeps_only_host_ports_configurable_without_exposing_ops() -> None:
    env_text = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    active_keys = {
        line.split("=", 1)[0]
        for line in env_text.splitlines()
        if line and not line.lstrip().startswith("#") and "=" in line
    }
    reserved_reference_keys = {
        "OPERATOR_NAME",
        "INVERTER_BLOCK_COUNT",
        "ENABLE_TRACKER",
        "DEFAULT_POWER_LIMIT_PCT",
        "WEATHER_REFRESH_SECONDS",
        "EVENT_STORE_BACKEND",
        "PCAP_CAPTURE_ENABLED",
        "PCAP_CAPTURE_PATH",
        "ALARM_PAGE_SIZE",
    }

    assert "HONEYPOT_IMAGE=stoertebeker2k/scada-honeypot:latest" in env_text
    assert "MODBUS_GATEWAY_IMAGE=haproxy:3.2.21-alpine" in env_text
    assert "HMI_PUBLISHED_PORT=8080" in env_text
    assert "MODBUS_PUBLISHED_PORT=1502" in env_text
    assert "OPS_PUBLISHED_PORT=9090" in env_text
    assert "HMI_PORT" not in active_keys
    assert "MODBUS_PORT" not in active_keys
    assert "OPS_PORT" not in active_keys
    assert "HMI_BIND_HOST" not in active_keys
    assert "MODBUS_BIND_HOST" not in active_keys
    assert "OPS_BIND_HOST" not in active_keys
    assert "EXPOSED_RESEARCH_ENABLED" not in active_keys
    assert "HONEYPOT_LOCAL_DEBUG" not in active_keys
    assert "HMI_PUBLISHED_HOST" not in active_keys
    assert "MODBUS_PUBLISHED_HOST" not in active_keys
    assert "OPS_PUBLISHED_HOST" not in active_keys
    assert "GEOIP_DBIP_AUTO_UPDATE=0" in env_text
    assert active_keys.isdisjoint(reserved_reference_keys)
    for key in reserved_reference_keys:
        assert f"# {key}=" in env_text
