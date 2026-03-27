#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="$SCRIPT_DIR/.venv"
VENV_PY="$VENV_DIR/bin/python"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "Error: python3 is required but was not found."
    exit 1
fi

if [[ ! -d "$VENV_DIR" ]]; then
    echo "[1/5] Creating virtual environment..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
else
    echo "[1/5] Virtual environment already exists."
fi

echo "[2/5] Installing Python dependencies..."
"$VENV_PY" -m pip install --upgrade pip
"$VENV_PY" -m pip install -r "$SCRIPT_DIR/requirements.txt"

echo "[3/5] Installing command shortcut..."
mkdir -p "$HOME/.local/bin"
TMP_LAUNCHER="$(mktemp)"
cat > "$TMP_LAUNCHER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "$SCRIPT_DIR/launch.sh" "\$@"
EOF
install -m 755 "$TMP_LAUNCHER" "$HOME/.local/bin/network-sentinel"
rm -f "$TMP_LAUNCHER"

echo "[4/5] Installing desktop entry..."
mkdir -p "$HOME/.local/share/applications"
cat > "$HOME/.local/share/applications/NetworkSentinel.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Network Sentinel
Comment=Live Network Intrusion Monitor — detects threats and explains what to do
Exec=$HOME/.local/bin/network-sentinel
Icon=/usr/share/icons/HighContrast/48x48/apps/config-firewall.png
Terminal=true
Categories=Network;Security;Monitor;
Keywords=network;monitor;intrusion;security;sentinel;
StartupNotify=true
EOF

echo "[5/5] Finished."

echo
echo "Install complete."
echo "Run with: network-sentinel"
echo "If command is not found, open a new terminal or run:"
echo "  export PATH=\"$HOME/.local/bin:\$PATH\""
