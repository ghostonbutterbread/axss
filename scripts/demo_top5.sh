#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLIC_TARGET="https://xss-game.appspot.com/level1/frame"

if python3 "$ROOT_DIR/ai-xss-generator.py" --url "$PUBLIC_TARGET" --output list --top 5; then
  exit 0
fi

echo
echo "Public target fetch failed; falling back to local sample_target.html" >&2
python3 "$ROOT_DIR/ai-xss-generator.py" --html "$ROOT_DIR/sample_target.html" --output list --top 5
