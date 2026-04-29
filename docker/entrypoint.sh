#!/bin/sh
set -eu

mkdir -p /app/data /app/logs /app/pcap /app/tmp

if [ "${GEOIP_DBIP_AUTO_UPDATE:-1}" = "1" ]; then
    mkdir -p /app/data/geoip
    geoip_timeout="${GEOIP_DBIP_TIMEOUT_SECONDS:-60}"
    if [ -n "${GEOIP_DBIP_RELEASE:-}" ]; then
        python -m honeypot.geoip_update \
            --provider dbip-lite \
            --target-dir /app/data/geoip \
            --release "${GEOIP_DBIP_RELEASE}" \
            --timeout-seconds "${geoip_timeout}" \
            --optional
    else
        python -m honeypot.geoip_update \
            --provider dbip-lite \
            --target-dir /app/data/geoip \
            --timeout-seconds "${geoip_timeout}" \
            --optional
    fi
    chmod 755 /app/data/geoip || true
    find /app/data/geoip -type f -exec chmod 644 {} +
fi

if [ "${HONEYPOT_FORCE_CONTAINER_BINDS:-0}" = "1" ]; then
    modbus_port="${MODBUS_PORT:-1502}"
    hmi_port="${HMI_PORT:-8080}"
    ops_port="${OPS_PORT:-9090}"
    modbus_public_port="${MODBUS_PUBLISHED_PORT:-$modbus_port}"
    hmi_public_port="${HMI_PUBLISHED_PORT:-$hmi_port}"

    export ALLOW_NONLOCAL_BIND=1
    export HMI_BIND_HOST=0.0.0.0
    export MODBUS_BIND_HOST=0.0.0.0
    export OPS_BIND_HOST=0.0.0.0
    export EXPOSED_RESEARCH_ENABLED=1
    export APPROVED_INGRESS_BINDINGS="modbus:0.0.0.0:${modbus_port},hmi:0.0.0.0:${hmi_port},ops:0.0.0.0:${ops_port}"
    export PUBLIC_INGRESS_MAPPINGS="${PUBLIC_INGRESS_MAPPINGS:-modbus:${modbus_public_port}:${modbus_port},hmi:${hmi_public_port}:${hmi_port}}"
    export WATCH_OFFICER_NAME="${WATCH_OFFICER_NAME:-compose-prod-watch}"
    export DUTY_ENGINEER_NAME="${DUTY_ENGINEER_NAME:-compose-prod-duty}"
fi

if [ "$(id -u)" = "0" ]; then
    chown honeypot:honeypot /app/data /app/logs /app/pcap /app/tmp
    find /app/data -mindepth 1 -maxdepth 1 ! -name geoip -exec chown -R honeypot:honeypot {} +
    chown -R honeypot:honeypot /app/logs /app/pcap /app/tmp
    exec gosu honeypot "$@"
fi

exec "$@"
