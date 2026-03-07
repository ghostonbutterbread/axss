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

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

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

  # 2. Findings store directory
  mkdir -p "$CONFIG_DIR/findings"

  # 3. config.json — create with defaults on first run; on subsequent runs only
  #    update default_model so user edits to use_cloud / cloud_model are preserved.
  if [ -f "$CONFIG_PATH" ]; then
    python3 - "$CONFIG_PATH" "$SELECTED_MODEL" <<'PYEOF'
import json, sys
path, model = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        cfg = {}
except Exception:
    cfg = {}
cfg["default_model"] = model
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PYEOF
  else
    printf '{\n  "default_model": "%s",\n  "use_cloud": true,\n  "cloud_model": "anthropic/claude-3-5-sonnet"\n}\n' \
      "$SELECTED_MODEL" >"$CONFIG_PATH"
  fi

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

echo "Detected RAM: $(ram_summary)"
echo "Detected GPU: $(gpu_summary)"
select_model_profile
echo "Selected model profile: $SELECTED_PROFILE ($SELECTED_MODEL)"

install_ollama_if_needed || echo "Warning: continuing without automatic Ollama install." >&2
if have_cmd ollama; then
  ensure_ollama_ready || true
  pull_selected_model || true
else
  echo "Warning: Ollama is unavailable; axss will fall back to heuristics or OPENAI_API_KEY." >&2
fi
init_axss_dir

if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip
python -m pip install -r "$ROOT_DIR/requirements.txt"
# Install Playwright browser binaries required by Scrapling's stealth fetcher
python -m playwright install chromium --with-deps 2>/dev/null || true

mkdir -p "$BIN_DIR"

chmod +x "$ROOT_DIR/setup.sh" "$DEMO_SCRIPT" "$ROOT_DIR/scripts/demo_top5.sh" "$LAUNCHER" "$ENTRYPOINT"
if ! ln -sf "$LAUNCHER" "$BIN_DIR/axss"; then
  echo "Warning: could not link $BIN_DIR/axss in this environment." >&2
fi

echo "Configured $CONFIG_PATH with default_model=$SELECTED_MODEL"
echo "Run ./setup.sh then axss --help anywhere"
