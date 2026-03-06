#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUBLIC_TARGET="https://xss-game.appspot.com/level1/frame"
RUNNER=("$ROOT_DIR/venv/bin/python" "$ROOT_DIR/ai-xss-generator.py")

if "${RUNNER[@]}" -u "$PUBLIC_TARGET" -o list -t 5; then
  exit 0
fi

echo
echo "Public target fetch failed; falling back to local sample_target.html" >&2
"${RUNNER[@]}" -h "$ROOT_DIR/sample_target.html" -o list -t 5
