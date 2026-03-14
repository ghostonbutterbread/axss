#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUBLIC_TARGET="https://xss-game.appspot.com/level1/frame"
RUNNER=("$ROOT_DIR/venv/bin/python" "$ROOT_DIR/axss.py")

if [ ! -x "${RUNNER[0]}" ]; then
  echo "Missing virtualenv runner at ${RUNNER[0]}. Run ./setup.sh first." >&2
  exit 1
fi

if "${RUNNER[@]}" -v -u "$PUBLIC_TARGET" --generate -o list -t 5; then
  exit 0
fi

echo
echo "Public target fetch failed; falling back to local sample_target.html" >&2
"${RUNNER[@]}" -v -i "$ROOT_DIR/sample_target.html" --generate -o list -t 5
