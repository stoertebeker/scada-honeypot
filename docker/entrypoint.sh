#!/bin/sh
set -eu

mkdir -p /app/data /app/logs /app/pcap /app/tmp

if [ "${HONEYPOT_FORCE_CONTAINER_BINDS:-0}" = "1" ]; then
    export ALLOW_NONLOCAL_BIND=1
    export HMI_BIND_HOST=0.0.0.0
    export MODBUS_BIND_HOST=0.0.0.0
    export APPROVED_INGRESS_BINDINGS="modbus:0.0.0.0:${MODBUS_PORT:-1502},hmi:0.0.0.0:${HMI_PORT:-8080}"
fi

case "${HONEYPOT_RUNTIME_MODE:-normal}" in
    normal)
        export EXPOSED_RESEARCH_ENABLED=0
        ;;
    exposed)
        export EXPOSED_RESEARCH_ENABLED=1
        ;;
    *)
        echo "ungueltiger HONEYPOT_RUNTIME_MODE: ${HONEYPOT_RUNTIME_MODE}" >&2
        exit 64
        ;;
esac

if [ "$(id -u)" = "0" ]; then
    chown -R honeypot:honeypot /app/data /app/logs /app/pcap /app/tmp
    exec gosu honeypot "$@"
fi

exec "$@"
