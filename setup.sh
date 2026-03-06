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

LOW_MEM_MODELS=(
  "qwen2.5-coder:7b-instruct-q5_K_M"
  "qwen2.5-coder:7b-instruct-q5_K_M.gguf"
  "qwen2.5-coder:7b"
)
MID_MEM_MODELS=("qwen2.5-coder:14b")
HIGH_MEM_MODELS=("qwen2.5-coder:32b")
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
    local max_mib
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
    SELECTED_MODEL_CANDIDATES=("${HIGH_MEM_MODELS[@]}")
  elif [ "${detected_ram_gb:-0}" -ge 16 ]; then
    SELECTED_PROFILE="ram-16g+"
    SELECTED_MODEL_CANDIDATES=("${MID_MEM_MODELS[@]}")
  else
    SELECTED_PROFILE="low-mem"
    SELECTED_MODEL_CANDIDATES=("${LOW_MEM_MODELS[@]}")
  fi
}

install_ollama_if_needed() {
  if have_cmd ollama; then
    return 0
  fi
  if ! have_cmd brew; then
    echo "Warning: Homebrew is required to install Ollama automatically." >&2
    return 1
  fi
  HOMEBREW_NO_AUTO_UPDATE=1 brew install ollama
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
    SELECTED_MODEL="${SELECTED_MODEL_CANDIDATES[0]}"
    return 1
  fi
  local candidate
  for candidate in "${SELECTED_MODEL_CANDIDATES[@]}"; do
    if ollama pull "$candidate"; then
      SELECTED_MODEL="$candidate"
      return 0
    fi
  done
  SELECTED_MODEL="${SELECTED_MODEL_CANDIDATES[0]}"
  echo "Warning: unable to pull any preferred model variant, keeping default_model=$SELECTED_MODEL" >&2
  return 1
}

write_config() {
  mkdir -p "$CONFIG_DIR"
  printf '{\n  "default_model": "%s"\n}\n' "$SELECTED_MODEL" >"$CONFIG_PATH"
}

echo "Detected RAM: $(ram_summary)"
echo "Detected GPU: $(gpu_summary)"
select_model_profile
echo "Selected model profile: $SELECTED_PROFILE (${SELECTED_MODEL_CANDIDATES[0]})"

install_ollama_if_needed || echo "Warning: continuing without automatic Ollama install." >&2
if have_cmd ollama; then
  ensure_ollama_ready || true
  pull_selected_model || true
else
  SELECTED_MODEL="${SELECTED_MODEL_CANDIDATES[0]}"
  echo "Warning: Ollama is unavailable; axss will fall back to heuristics or OPENAI_API_KEY." >&2
fi
write_config

if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip
python -m pip install -r "$ROOT_DIR/requirements.txt"

mkdir -p "$BIN_DIR"

chmod +x "$ROOT_DIR/setup.sh" "$DEMO_SCRIPT" "$ROOT_DIR/scripts/demo_top5.sh" "$LAUNCHER" "$ENTRYPOINT"
if ! ln -sf "$LAUNCHER" "$BIN_DIR/axss"; then
  echo "Warning: could not link $BIN_DIR/axss in this environment." >&2
fi

echo "Configured $CONFIG_PATH with default_model=$SELECTED_MODEL"
echo "Run ./setup.sh then axss --help anywhere"
