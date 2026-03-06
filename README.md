# AI XSS Payload Generator

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![CLI](https://img.shields.io/badge/interface-CLI-111111)
![AI](https://img.shields.io/badge/AI-Ollama--first-5A5A5A)

Context-aware XSS recon CLI that parses target HTML, detects likely DOM sinks and framework fingerprints, then generates ranked payloads with Ollama-first AI assistance and heuristic fallback.

## Features

- `-u, --url TARGET` fetches live HTML and parses forms, inputs, inline handlers, inline scripts, DOM sinks, variables, objects, and framework fingerprints.
- `-h, --html FILE_OR_SNIPPET` parses either a local file or an inline snippet.
- `-m, --model MODEL` selects the Ollama model. Default: `qwen2.5-coder:7b-instruct-q5_K_M`.
- `-o, --output {list,json,heat}` controls terminal output.
- `-t, --top N` limits the ranked payload count.
- Ollama-first model flow with OpenAI `gpt-4o-mini` fallback when `OPENAI_API_KEY` is set, then local heuristics if no AI backend is available.

## Setup

```bash
./setup.sh
ai-xss-generator --help
```

`setup.sh` creates or refreshes `venv`, upgrades `pip`, installs `requirements.txt`, makes the local launcher executable, and symlinks `~/.local/bin/ai-xss-generator` to the repo launcher.

If `~/.local/bin` is not already on your `PATH`, add this to your shell profile:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Run

```bash
ai-xss-generator -h sample_target.html -o list -t 10
ai-xss-generator -h '<div onclick="{{user}}"></div><script>eval(location.hash.slice(1))</script>' -o heat
ai-xss-generator -u https://example.com -o json --json-out result.json
./demo_top5.sh
```

## Demo

Run `./demo_top5.sh` for a quick top-5 payload demo against the public target, with a fallback to `sample_target.html` if the fetch fails.

GIF demo: not included in this repo yet. Add `docs/demo.gif` later if you want a recorded terminal run embedded here.

## Model Notes

- Local first: if `ollama` is installed, the CLI checks for `qwen2.5-coder:7b-instruct-q5_K_M` and runs `ollama pull` when missing.
- OpenAI fallback: set `OPENAI_API_KEY` to enable `gpt-4o-mini` fallback.
- Without optional packages such as `beautifulsoup4` or `esprima`, the CLI still runs with stdlib parsing and heuristic generation.

## Output Modes

- `list`: ranked table with payload, tags, and rationale.
- `heat`: compact risk heat view.
- `json`: full structured output.
