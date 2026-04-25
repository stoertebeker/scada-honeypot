#!/bin/sh
set -eu

mkdir -p /app/data /app/logs /app/pcap /app/tmp

if [ "$(id -u)" = "0" ]; then
    chown -R honeypot:honeypot /app/data /app/logs /app/pcap /app/tmp
    exec gosu honeypot "$@"
fi

exec "$@"
