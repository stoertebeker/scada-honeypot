#!/bin/sh
set -eu

mkdir -p /app/data /app/logs /app/pcap /app/tmp

if [ "${GEOIP_DBIP_AUTO_UPDATE:-0}" = "1" ]; then
    mkdir -p /app/data/geoip
    if [ "$(id -u)" = "0" ]; then
        chown honeypot:honeypot /app/data/geoip
    fi
    run_geoip_update() {
        "$@" python -m honeypot.geoip_update \
            --provider dbip-lite \
            --target-dir /app/data/geoip \
            --release "${GEOIP_DBIP_RELEASE:-}" \
            --country-sha256 "${GEOIP_DBIP_COUNTRY_SHA256:-}" \
            --asn-sha256 "${GEOIP_DBIP_ASN_SHA256:-}" \
            --timeout-seconds "${GEOIP_DBIP_TIMEOUT_SECONDS:-60}" \
            --max-compressed-bytes "${GEOIP_DBIP_MAX_COMPRESSED_BYTES:-33554432}" \
            --max-decompressed-bytes "${GEOIP_DBIP_MAX_DECOMPRESSED_BYTES:-134217728}" \
            --max-expansion-ratio "${GEOIP_DBIP_MAX_EXPANSION_RATIO:-64}" \
            --total-deadline-seconds "${GEOIP_DBIP_TOTAL_DEADLINE_SECONDS:-120}" \
            --max-directory-bytes "${GEOIP_DBIP_MAX_DIRECTORY_BYTES:-268435456}" \
            --optional
    }
    if [ "$(id -u)" = "0" ]; then
        run_geoip_update gosu honeypot
    else
        run_geoip_update
    fi
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
