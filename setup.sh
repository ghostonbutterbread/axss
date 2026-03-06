#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/venv"
BIN_DIR="$HOME/.local/bin"
LAUNCHER="$ROOT_DIR/ai-xss-generator"
DEMO_SCRIPT="$ROOT_DIR/demo_top5.sh"

if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip
python -m pip install -r "$ROOT_DIR/requirements.txt"

mkdir -p "$BIN_DIR"

chmod +x "$ROOT_DIR/setup.sh" "$DEMO_SCRIPT" "$LAUNCHER" "$ROOT_DIR/ai-xss-generator.py"
if ! ln -sf "$LAUNCHER" "$BIN_DIR/ai-xss-generator"; then
  echo "Warning: could not link $BIN_DIR/ai-xss-generator in this environment." >&2
fi

echo "Run ./setup.sh then ai-xss-generator --help anywhere"
