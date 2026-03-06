# axss

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![CLI](https://img.shields.io/badge/interface-CLI-111111)
![Ollama](https://img.shields.io/badge/Ollama-auto--install-111111?logo=ollama)
![Model](https://img.shields.io/badge/default-Qwen3.5_9B-0F766E)

`axss` is a context-aware XSS recon CLI that parses target HTML, detects likely DOM sinks and framework fingerprints, then generates ranked payloads with Ollama-first AI assistance and heuristic fallback.

## Features

- `-u, --url TARGET` fetches live HTML and parses forms, inputs, inline handlers, inline scripts, DOM sinks, variables, objects, and framework fingerprints.
- `-h, --html FILE_OR_SNIPPET` parses either a local file or an inline snippet.
- `-l, --list-models` shows local Ollama models in a table.
- `-s, --search-models QUERY` searches for Ollama models by keyword.
- `-m, --model MODEL` overrides the default Ollama model from `~/.axss/config.json`.
- `-o, --output {list,json,heat}` controls terminal output.
- `-t, --top N` limits the ranked payload count.
- `setup.sh` auto-installs Ollama with Homebrew when needed, sizes the default Qwen3.5 model to your RAM/GPU, pulls it, creates `~/.axss/config.json`, builds the venv, and symlinks `~/.local/bin/axss`.

## Setup

```bash
./setup.sh
axss --help
```

`setup.sh` does all of the following:

- installs `ollama` via `brew install ollama` if it is missing
- detects memory with `free -h` when available and GPU memory with `nvidia-smi`
- picks a default Qwen3.5 tier:
  - less than 8 GB RAM: `qwen3.5:4b`
  - 8 GB to under 32 GB RAM: `qwen3.5:9b`
  - 32 GB+ RAM: `qwen3.5:27b`
  - 24 GB+ NVIDIA GPU: `qwen3.5:35b`
- starts `ollama serve` if needed and pulls the selected model
- creates `~/.axss/config.json` with `default_model`
- creates or refreshes `venv`, installs `requirements.txt`, marks scripts executable, and symlinks `~/.local/bin/axss`

If `~/.local/bin` is not already on your `PATH`, add this to your shell profile:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

The generated config looks like:

```bash
cat ~/.axss/config.json
```

```json
{
  "default_model": "qwen3.5:9b"
}
```

## Run

```bash
axss -l
axss -s qwen3.5
axss -h sample_target.html -o list -t 10
axss -h '<div onclick="{{user}}"></div><script>eval(location.hash.slice(1))</script>' -o heat
axss -u https://example.com -o json --json-out result.json
axss -u https://example.com -m qwen3.5:4b -t 5 -o list
./demo_top5.sh
```

## Demo

Run `./demo_top5.sh` for a quick top-5 payload demo against the public target, with a fallback to `sample_target.html` if the fetch fails.

## Model Notes

- Local first: the CLI uses `~/.axss/config.json` for `default_model`, then falls back to `qwen3.5:9b`.
- The supported Qwen3.5 sizes are `qwen3.5:4b`, `qwen3.5:9b`, `qwen3.5:27b`, and `qwen3.5:35b`.
- Performance guidance: `4b` is the lightest and fastest, `9b` is the balanced default, `27b` improves payload quality when you have 32 GB+ RAM, and `35b` is intended for systems with 24 GB+ NVIDIA VRAM.
- `axss -l` runs `ollama list` and formats the result as a table.
- `axss -s qwen3.5` prefers `ollama search qwen3.5` and falls back to Ollama's web search if the installed CLI does not support `search`.
- OpenAI fallback: set `OPENAI_API_KEY` to enable `gpt-4o-mini` fallback.
- Without optional packages such as `beautifulsoup4` or `esprima`, the CLI still runs with stdlib parsing and heuristic generation.

## Output Modes

- `list`: ranked table with payload, tags, and rationale.
- `heat`: compact risk heat view.
- `json`: full structured output.
