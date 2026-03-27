#!/usr/bin/env bash
# Network Sentinel launcher — requires root for raw packet capture

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PY="/home/evren-bartlett/Documents/.venv/bin/python"

if [[ -x "$VENV_PY" ]]; then
    PYTHON_BIN="$VENV_PY"
else
    PYTHON_BIN="python3"
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Network Sentinel needs root for packet capture."
    if sudo -n true 2>/dev/null; then
        echo "Relaunching with sudo..."
        exec sudo -n "$PYTHON_BIN" "$SCRIPT_DIR/sentinel.py" "$@"
    fi
    echo "Sudo password prompt disabled for this launcher."
    echo "Run manually: sudo $PYTHON_BIN $SCRIPT_DIR/sentinel.py"
    exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/sentinel.py" "$@"
