#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/venv"
BIN_DIR="$HOME/.local/bin"
CONFIG_DIR="$HOME/.axss"
CONFIG_PATH="$CONFIG_DIR/config.json"
LAUNCHER="$ROOT_DIR/axss"
DEMO_SCRIPT="$ROOT_DIR/demo_top5.sh"
ENTRYPOINT="$ROOT_DIR/axss.py"
OLLAMA_LOG="$CONFIG_DIR/ollama-serve.log"

LOW_MEM_MODEL="qwen3.5:4b"
DEFAULT_MEM_MODEL="qwen3.5:9b"
HIGH_MEM_MODEL="qwen3.5:27b"
GPU_MODEL="qwen3.5:35b"
SELECTED_MODEL=""

# CLI tool detection results (set by detect_cli_tools)
DETECTED_CLI_BACKEND="api"
DETECTED_CLI_TOOL="claude"

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# Resolve the system Python 3 executable (python3 > python > error).
# Sets PYTHON to the full path of the first working Python 3.10+ found.
find_python() {
  local candidate
  for candidate in python3 python python3.13 python3.12 python3.11 python3.10; do
    if have_cmd "$candidate"; then
      local ver
      ver="$("$candidate" -c 'import sys; print(sys.version_info >= (3,10))' 2>/dev/null)"
      if [ "$ver" = "True" ]; then
        PYTHON="$(command -v "$candidate")"
        echo "Using Python: $PYTHON ($("$candidate" --version 2>&1))"
        return 0
      fi
    fi
  done
  echo "Error: Python 3.10 or newer is required but was not found on PATH." >&2
  echo "Install it with your package manager (e.g. apt install python3, brew install python)." >&2
  exit 1
}

PYTHON=""

ram_gb() {
  if have_cmd free; then
    free -g | awk '/^Mem:/ {print $2}'
    return 0
  fi
  if have_cmd sysctl; then
    local bytes
    bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
    awk -v bytes="$bytes" 'BEGIN { printf "%d\n", bytes / 1024 / 1024 / 1024 }'
    return 0
  fi
  echo 0
}

ram_summary() {
  if have_cmd free; then
    free -h | awk '/^Mem:/ {print $2 " total / " $7 " available"}'
    return 0
  fi
  if have_cmd sysctl; then
    local bytes
    bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
    awk -v bytes="$bytes" 'BEGIN { printf "%.1fG total\n", bytes / 1024 / 1024 / 1024 }'
    return 0
  fi
  echo "unknown"
}

gpu_memory_gb() {
  if have_cmd nvidia-smi; then
    local max_gb max_mib
    max_gb="$(
      nvidia-smi --query-gpu=memory.total --format=csv,noheader 2>/dev/null \
        | cut -d: -f1 \
        | grep 'GB' || true \
    )"
    max_gb="$(printf '%s\n' "$max_gb" \
        | awk '
            {
              value = $1 + 0
              if (value > max) {
                max = value
              }
            }
            END {
              if (max > 0) {
                printf "%d\n", max
              }
            }
          '
    )"
    if [ -n "${max_gb:-}" ]; then
      echo "$max_gb"
      return 0
    fi

    max_mib="$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | sort -nr | head -n1)"
    if [ -n "${max_mib:-}" ]; then
      awk -v mib="$max_mib" 'BEGIN { printf "%d\n", (mib + 1023) / 1024 }'
      return 0
    fi
  fi
  echo 0
}

gpu_summary() {
  if have_cmd nvidia-smi; then
    local memory_output
    memory_output="$(nvidia-smi 2>/dev/null | grep Memory || true)"
    if [ -n "$memory_output" ]; then
      echo "$memory_output"
      return 0
    fi
    echo "CPU"
    return 0
  fi
  echo "CPU"
}

select_model_profile() {
  local detected_ram_gb detected_gpu_gb
  detected_ram_gb="$(ram_gb)"
  detected_gpu_gb="$(gpu_memory_gb)"

  if [ "${detected_gpu_gb:-0}" -ge 24 ]; then
    SELECTED_PROFILE="gpu-24g+"
    SELECTED_MODEL="$GPU_MODEL"
  elif [ "${detected_ram_gb:-0}" -ge 32 ]; then
    SELECTED_PROFILE="ram-32g+"
    SELECTED_MODEL="$HIGH_MEM_MODEL"
  elif [ "${detected_ram_gb:-0}" -ge 8 ]; then
    SELECTED_PROFILE="ram-8g+"
    SELECTED_MODEL="$DEFAULT_MEM_MODEL"
  else
    SELECTED_PROFILE="low-mem"
    SELECTED_MODEL="$LOW_MEM_MODEL"
  fi
}

detect_cli_tools() {
  # Probe for claude and codex on PATH.  Set DETECTED_CLI_BACKEND and
  # DETECTED_CLI_TOOL so init_axss_dir() can write them to config.json.
  if have_cmd claude; then
    DETECTED_CLI_BACKEND="cli"
    DETECTED_CLI_TOOL="claude"
    echo "Found claude CLI at $(command -v claude) — will configure backend=cli, tool=claude"
  elif have_cmd codex; then
    DETECTED_CLI_BACKEND="cli"
    DETECTED_CLI_TOOL="codex"
    echo "Found codex CLI at $(command -v codex) — will configure backend=cli, tool=codex"
  else
    DETECTED_CLI_BACKEND="api"
    DETECTED_CLI_TOOL="claude"
    echo "No claude/codex CLI found — will configure backend=api (OpenRouter/OpenAI key required)"
  fi
}

install_ollama_if_needed() {
  if have_cmd ollama; then
    return 0
  fi
  if ! have_cmd curl; then
    echo "Warning: curl is required to install Ollama automatically." >&2
    return 1
  fi
  if curl -fsSL https://ollama.com/install.sh | sh; then
    echo "Ollama installed via official script"
    return 0
  fi
  return 1
}

ensure_ollama_ready() {
  if ! have_cmd ollama; then
    return 1
  fi
  mkdir -p "$CONFIG_DIR"
  if ollama list >/dev/null 2>&1; then
    return 0
  fi
  nohup ollama serve >"$OLLAMA_LOG" 2>&1 &
  sleep 3
  if ! ollama list >/dev/null 2>&1; then
    echo "Warning: Ollama daemon is not responding yet; model pull may fail." >&2
  fi
}

pull_selected_model() {
  if ! have_cmd ollama; then
    return 1
  fi
  if ollama list 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$SELECTED_MODEL"; then
    echo "Model $SELECTED_MODEL already present — skipping pull."
    return 0
  fi
  if ollama pull "$SELECTED_MODEL"; then
    return 0
  fi
  echo "Warning: unable to pull selected model $SELECTED_MODEL; keeping it as default_model in config" >&2
  return 1
}

init_axss_dir() {
  # 1. Main config dir — private to owner
  mkdir -p "$CONFIG_DIR"
  chmod 700 "$CONFIG_DIR"

  # 2. config.json — create with defaults on first run; on subsequent runs only
  #    update default_model + detected CLI backend so user edits to other fields
  #    (use_cloud, cloud_model, cli_model, etc.) are preserved.
  "$PYTHON" - "$CONFIG_PATH" "$SELECTED_MODEL" "$DETECTED_CLI_BACKEND" "$DETECTED_CLI_TOOL" <<'PYEOF'
import json, sys
path, model, backend, cli_tool = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
try:
    with open(path) as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        cfg = {}
except Exception:
    cfg = {}
# Always update hardware-detected model recommendation.
cfg["default_model"] = model
# Seed auto-detected CLI backend/tool only on first run; preserve user edits after that.
cfg.setdefault("ai_backend", backend)
cfg.setdefault("cli_tool", cli_tool)
# Write defaults for keys the user hasn't set yet.
cfg.setdefault("use_cloud", True)
cfg.setdefault("cloud_model", "anthropic/claude-3-5-sonnet")
cfg.setdefault("cli_model", None)
try:
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
except Exception as e:
    print(f"Error: could not write config {path}: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF

  # 4. keys — created once with strict permissions so the user can add API keys
  if [ ! -f "$CONFIG_DIR/keys" ]; then
    cat >"$CONFIG_DIR/keys" <<'KEYS'
# axss API keys — do NOT commit this file
# Lines: KEY = VALUE  (# = comment, whitespace around = is ignored)
#
# Cloud LLM escalation (optional — axss works fine with local Ollama only)
openrouter_api_key =
openai_api_key     =
#
# xssy.uk JWT — copy from localStorage key userData.token after logging in
# Used by axss_learn.py --xssy-token to get private lab instances
xssy_jwt           =
KEYS
    chmod 600 "$CONFIG_DIR/keys"
    echo "Created $CONFIG_DIR/keys (chmod 600) — add API keys there."
  else
    # Ensure perms are correct even if file already existed
    chmod 600 "$CONFIG_DIR/keys"
  fi

  # 5. ollama serve log placeholder (created lazily, just ensure dir is ready)
  : >"$OLLAMA_LOG" 2>/dev/null || true
}

find_python
echo "Detected RAM: $(ram_summary)"
echo "Detected GPU: $(gpu_summary)"
select_model_profile
echo "Selected model profile: $SELECTED_PROFILE ($SELECTED_MODEL)"

detect_cli_tools
install_ollama_if_needed || echo "Warning: continuing without automatic Ollama install." >&2
if have_cmd ollama; then
  ensure_ollama_ready || true
  pull_selected_model || true
else
  echo "Warning: Ollama is unavailable; axss will fall back to heuristics or OPENAI_API_KEY." >&2
fi
init_axss_dir

if [ ! -d "$VENV_DIR" ]; then
  "$PYTHON" -m venv "$VENV_DIR"
fi
# Reference the venv python by full path — avoids any 'python' vs 'python3'
# ambiguity regardless of OS, shell, or whether the venv is activated.
VENV_PYTHON="$VENV_DIR/bin/python"
if [ ! -f "$VENV_PYTHON" ]; then
  # Some systems name the venv binary python3
  VENV_PYTHON="$VENV_DIR/bin/python3"
fi

# Only reinstall packages (and playwright browser) when requirements.txt has changed
# or packages are broken.  The stamp file stores the last successful hash.
REQS_HASH_FILE="$CONFIG_DIR/.reqs_hash"
REQS_CURRENT_HASH="$(sha256sum "$ROOT_DIR/requirements.txt" 2>/dev/null | cut -d' ' -f1)"
if [ -f "$REQS_HASH_FILE" ] && [ "$(cat "$REQS_HASH_FILE" 2>/dev/null)" = "$REQS_CURRENT_HASH" ] \
    && "$VENV_PYTHON" -m pip check >/dev/null 2>&1; then
  echo "Python packages up-to-date (requirements.txt unchanged) — skipping install."
else
  "$VENV_PYTHON" -m pip install --upgrade pip
  "$VENV_PYTHON" -m pip install -r "$ROOT_DIR/requirements.txt"
  # Install Playwright browser binaries required by Scrapling's stealth fetcher.
  # Playwright version is pinned in requirements.txt so this only runs when packages change.
  _playwright_ok=1
  if ! "$VENV_PYTHON" -m playwright install chromium --with-deps; then
    echo "Warning: playwright install chromium failed — active scanner (--active) will not work." >&2
    _playwright_ok=0
  fi
  # Write the stamp only when both pip and playwright succeeded so a partial failure
  # forces a retry next run.
  if [ "$_playwright_ok" -eq 1 ]; then
    echo "$REQS_CURRENT_HASH" > "$REQS_HASH_FILE"
  fi
fi

mkdir -p "$BIN_DIR"

chmod +x "$ROOT_DIR/setup.sh" "$DEMO_SCRIPT" "$ROOT_DIR/scripts/demo_top5.sh" "$LAUNCHER" "$ENTRYPOINT"
if ! ln -sf "$LAUNCHER" "$BIN_DIR/axss"; then
  echo "Warning: could not link $BIN_DIR/axss in this environment." >&2
fi

echo "Configured $CONFIG_PATH with default_model=$SELECTED_MODEL"
echo "Run ./setup.sh then axss --help anywhere"
