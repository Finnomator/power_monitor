#!/bin/bash
cd "$(dirname "$0")" || exit
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT=2938

echo "Activating environment"
source "$SCRIPT_DIR/venv/bin/activate"

echo "Starting service on port $PORT"
fastapi run grafana_neoom_connect_bridge.py --port "$PORT"
