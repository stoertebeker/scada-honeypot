#!/bin/sh
set -eu

curl --fail --silent --show-error "http://127.0.0.1:${HMI_PORT:-8080}/healthz" >/dev/null

python -c 'import os, socket; s = socket.create_connection(("127.0.0.1", int(os.environ.get("MODBUS_PORT", "1502"))), timeout=2); src = s.getsockname(); dst = s.getpeername(); header = f"PROXY TCP4 {src[0]} {dst[0]} {src[1]} {dst[1]}\r\n".encode("ascii"); s.sendall(header) if os.environ.get("MODBUS_PROXY_PROTOCOL_ENABLED", "0") == "1" else None; s.close()'
