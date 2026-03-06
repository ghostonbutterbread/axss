# AI XSS Payload Generator

Context-aware XSS recon CLI that parses target HTML, detects likely DOM sinks/frameworks, then generates ranked payloads with Ollama-first AI assistance and heuristic fallback.

## Features

- `--url TARGET` fetches live HTML and parses forms, inputs, inline handlers, inline scripts, DOM sinks, variables, objects, and framework fingerprints.
- `--html FILE_OR_SNIPPET` parses either a local file or an inline snippet.
- Ollama-first model flow using `qwen2.5-coder:7b-instruct-q5_K_M`; falls back to OpenAI `gpt-4o-mini` if `OPENAI_API_KEY` is set; otherwise falls back to local heuristics.
- Ranked output with risk scoring, explanations, test vectors, terminal table view, JSON export, and ASCII heat view.
- Modular plugin hooks for additional parsers and payload mutators.

## Usage

```bash
python3 ai-xss-generator.py --html sample_target.html --output list --top 10
python3 ai-xss-generator.py --html '<div onclick="{{user}}"></div><script>eval(location.hash.slice(1))</script>' --output heat
python3 ai-xss-generator.py --url https://xss-game.appspot.com/level1/frame --output json --json-out result.json
bash scripts/demo_top5.sh
```

## Model Notes

- Local first: if `ollama` is installed, the CLI checks for `qwen2.5-coder:7b-instruct-q5_K_M` and runs `ollama pull` when missing.
- OpenAI fallback: set `OPENAI_API_KEY` to enable `gpt-4o-mini` fallback.
- Environment in this repo currently lacks `beautifulsoup4`, `esprima`, `openai`, and `ollama`. The CLI still runs with stdlib parsing and heuristic generation when those are absent.

## Output Modes

- `list`: ranked table with payload, tags, and rationale.
- `heat`: compact risk heat view.
- `json`: full structured output.
