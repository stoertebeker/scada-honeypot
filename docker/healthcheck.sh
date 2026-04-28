#!/bin/sh
set -eu

curl --fail --silent --show-error "http://127.0.0.1:${HMI_PORT:-8080}/healthz" >/dev/null

python -c 'import os, socket; s = socket.create_connection(("127.0.0.1", int(os.environ.get("MODBUS_PORT", "1502"))), timeout=2); s.close()'
