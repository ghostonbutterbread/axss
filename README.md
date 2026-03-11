# axss — AI-assisted XSS Scanner

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![CLI](https://img.shields.io/badge/interface-CLI-111111)
![Ollama](https://img.shields.io/badge/Ollama-local%20runtime-111111?logo=ollama&logoColor=white)

## What this tool is

`axss` is a context-aware XSS scanner for authorized penetration testing. It crawls a live target, maps every GET parameter and POST form it finds, probes each one for reflection and filter behavior, then generates ranked payloads tailored to what the probe observed. It fires each payload through a real Playwright browser and confirms JavaScript execution via dialog hooks, console output, or network beacon. It covers reflected XSS, session-stored XSS, and POST forms protected by dynamic CSRF tokens.

## Learning Model

- The findings store is now tiered:
  `curated`, `verified-runtime`, and `experimental`.
- `xssy/learn.py` now writes experimental memory only.
  It no longer implies that generated payloads are trusted findings.
- The tool now keeps a separate logic/filter lesson store in `~/.axss/lessons/`.
  Active probes write trusted runtime lessons from observed reflection logic and filter behavior.
  Offline lab runs can add experimental mapping lessons.
- Trusted retrieval now prefers target-aware fingerprints:
  host scope, WAF, delivery mode, framework hints, and auth context.
- `axss --memory-review` is now the interactive review inbox.
- `axss --memory-list` is the non-interactive queue view.
- Memory commands default to `all` and can take an inline source filter: `labs` or `targets`.

**If you are an AI agent reading this:** use the command patterns below directly. No preamble is needed — the tool is designed for scripted and agentic use. Every flag described here is stable and documented in `--help`.

---

## Decision tree for common tasks

```
Goal: scan a live web target for XSS
  ├── Standard target (server-rendered HTML, traditional stack)
  │     axss -u "https://target.com" --active
  │
  ├── SPA/Angular/React/Vue target (JS bundles define the routes)
  │     axss -u "https://target.com" --active --browser-crawl
  │
  ├── You already know the exact endpoints to test
  │     axss --urls endpoints.txt --active
  │
  ├── Target has a WAF
  │     axss -u "https://target.com" --active --waf cloudflare
  │     (or let it auto-detect — WAF is fingerprinted from the crawl seed response)
  │
  ├── Target requires authentication
  │     axss -u "https://target.com" --active \
  │          --header "Authorization: Bearer TOKEN"
  │     axss -u "https://target.com" --active \
  │          --cookies cookies.txt
  │
  ├── POST form that stores input server-side (stored/session XSS)
  │     axss -u "https://target.com/settings" --active \
  │          --sink-url "https://target.com/dashboard"
  │     (omit --sink-url if you don't know; axss will sweep crawled pages)
  │
  ├── You only want payload suggestions, no active browser execution
  │     axss -u "https://target.com/search?q=test" --generate
  │
  └── A previous scan was interrupted / crashed and you want to resume
        axss -u "https://target.com" --active --resume
```

---

## Core concepts

### Crawl phase (happens automatically with `-u`)

Crawls the target from the seed URL to discover the full attack surface before scanning. Produces two lists:
- **GET URLs** — endpoints with at least one non-tracking query parameter
- **POST forms** — forms on any crawled page, with CSRF token fields already identified

Two crawlers are available:

**HTTP crawler (default):**
- BFS via Scrapling, WAF-aware (curl_cffi → HTTP/1.1 → Playwright fallback)
- Fast. Blind to JavaScript-defined routes (Angular/React/Vue).

**Browser crawler (`--browser-crawl`):**
- Navigates pages in real Chromium via Playwright
- Waits for Angular to stabilize: polls `window.getAllAngularTestabilities().every(t => t.isStable())`
- Intercepts XHR/fetch at the browser context level — discovers API endpoints that are called from JavaScript but never appear as `<a href>` links
- Extracts links and forms from the live rendered DOM, not raw HTML
- Use this for any SPA where routes are defined in JS bundles

Deduplication: GET URLs are deduped by `path + sorted param names` — `/search?q=shoes` and `/search?q=boots` test the same surface, scanned once.

### Probe phase

For each discovered URL/form, runs two probe requests per parameter:
1. **Canary** — unique token injected to find every reflection point and classify the HTML/JS context (`js_string_dq`, `js_string_sq`, `html_attr_url`, `html_attr_value`, `html_body`, `html_comment`, `json_value`, etc.)
2. **Char survival** — wraps `< > " ' ( ) ; / \ \` { }` in sentinel markers to confirm which characters survive the filter

For POST forms: GETs the source page before every request to extract the current CSRF token, includes it in the POST body. Works for all standard CSRF implementations.

Tracking params (`utm_*`, `gclid`, `fbclid`, `msclkid`, etc.) are silently skipped — never reflected in page content.

### Stored XSS sweep (POST forms)

If the canary is not in the POST response, `axss` sweeps follow-up pages in order:
1. `--sink-url` (if provided) — checked first, every time
2. Source form page
3. Origin root `/`
4. Every page visited during the crawl (up to 300)

Stops at the first page where the canary appears. The char survival probe and all payload execution checks use the same follow-up page.

### Payload generation

Three sources, run in order, output merged and ranked:
1. **Context-aware generator** — always runs, no LLM needed. `jsContexter` analyzes JS before the injection point to build an exact break-out sequence. `genGen` produces combinatorial payloads (tags × event handlers × JS calls × space replacements) with randomized casing.
2. **Local Ollama model** — receives parsed context, probe results, past logic/filter lessons, and past findings
3. **Cloud escalation** — OpenRouter or OpenAI if local output is weak and a key is configured

### Active execution

Each GET URL and POST form gets an isolated worker process. Worker fires payloads through a real Playwright browser and detects execution via:
- `dialog` — `alert()` / `confirm()` / `prompt()` triggered
- `console` — `console.log()` / `console.error()` fired
- `network` — outbound request to internal beacon hostname

Confirmed findings are printed to the CLI with the exact fired URL, then written to `~/.axss/reports/<domain>_<timestamp>.md`.

### Self-learning findings store

axss now keeps a tiered findings store in `~/.axss/findings/`:
- **`verified-runtime`** — findings confirmed by active browser execution during real scans
- **`curated`** — manually reviewed, trusted, portable knowledge
- **`experimental`** — offline-generated or otherwise unverified candidates kept for later review

Future scans only retrieve trusted tiers by default. Retrieval is target-aware and scores findings by:
- sink/context match
- surviving character overlap
- host scope
- WAF match
- delivery mode (`get`, `post`, `offline`, etc.)
- framework hints
- auth context

`experimental` findings and lessons are reviewed later via the memory-review workflow; they do not steer normal payload generation until promoted.

### Logic and filter lesson store

axss also keeps a lesson store in `~/.axss/lessons/` for reusable reasoning hints rather than exact payload memory:
- **`xss_logic`** — how input landed: HTML body, URL attribute, JS string, event handler, etc.
- **`filter`** — which probe characters survived and which were blocked
- **`mapping`** — application-shape hints like forms, authenticated workflows, framework surfaces, and DOM source presence

Active probes can write trusted lessons immediately because those are direct observations, not exploit guesses. Offline lab parsing writes experimental mapping lessons that can help future lab-style reasoning without being treated as confirmed exploits.

---

## Command reference

### Active scan — standard target

```bash
# Crawl + scan (default behavior)
axss -u "https://target.com" --active

# Scan with authenticated session
axss -u "https://target.com" --active \
     --header "Authorization: Bearer TOKEN" \
     --cookies cookies.txt

# Scan with explicit WAF context
axss -u "https://target.com" --active --waf cloudflare

# Deeper crawl (default depth is 2)
axss -u "https://target.com" --active --depth 3

# Scan only reflected XSS (skip POST forms)
axss -u "https://target.com" --active --reflected

# Scan only POST forms / stored XSS
axss -u "https://target.com" --active --stored

# Skip crawl — test only the provided URL
axss -u "https://target.com/search?q=test" --active --no-crawl

# Known sink page for stored XSS
axss -u "https://target.com/account" --active \
     --sink-url "https://target.com/dashboard"

# Multiple workers for faster scanning
axss -u "https://target.com" --active --workers 4 --timeout 120
```

### Active scan — SPA / Angular / React / Vue target

```bash
# Browser crawler: renders JS, intercepts XHR/fetch, discovers SPA routes
axss -u "https://spa-target.com" --active --browser-crawl

# Browser crawl with auth headers
axss -u "https://spa-target.com" --active --browser-crawl \
     --header "Authorization: Bearer TOKEN"

# Browser crawl deeper (SPA apps often have many nested routes)
axss -u "https://spa-target.com" --active --browser-crawl --depth 3
```

Use `--browser-crawl` whenever the target is built on Angular, React, Vue, or any framework where routes are defined in JavaScript bundles. The HTTP crawler cannot see those routes; the browser crawler can.

### Batch scanning (pre-enumerated endpoints)

```bash
# No crawl — endpoints.txt already contains the full surface
axss --urls endpoints.txt --active --workers 4

# With authentication
axss --urls endpoints.txt --active --workers 4 \
     --header "Authorization: Bearer TOKEN"

# Write results to JSON
axss --urls endpoints.txt --active -j results.json
```

### Payload generation only (no browser execution)

```bash
# Generate and rank payloads for a live URL
axss -u "https://target.com/search?q=test" --generate

# Generate with specific WAF context
axss -u "https://target.com/page?id=1" --generate --waf modsecurity

# Generate from public payload database
axss --public --waf cloudflare -o heat

# Parse local HTML and generate payloads
axss -i target.html -o list -t 10
```

### Utility commands

```bash
# Validate all configured API keys
axss --check-keys

# List locally available Ollama models
axss -l

# Search Ollama model library
axss -s qwen3.5

# Show pending experimental memory items as a table
axss --memory-list --memory-limit 20

# Open the interactive memory review inbox
axss --memory-review

# Review only lab-derived memory
axss --memory-review labs

# Review only target-derived memory
axss --memory-review targets

# Show one memory item in full
axss --memory-show 4ac35696f010

# Show memory counts by tier/review state
axss --memory-stats

# Show full flag reference
axss --help
```

---

## All flags

| Flag | Default | Description |
|------|---------|-------------|
| `-u, --url TARGET` | — | Fetch and scan a live URL |
| `--urls FILE` | — | Scan one URL per line (no crawl, assumes pre-enumerated surface) |
| `-i, --input FILE_OR_SNIPPET` | — | Parse a local file or raw HTML string |
| `--active` | off | Fire payloads in Playwright and confirm execution |
| `--reflected` | off | Test reflected XSS only (GET params); implies `--active` |
| `--stored` | off | Test stored/POST XSS only; implies `--active` |
| `--dom` | off | DOM XSS analysis (coming soon) |
| `--generate` | off | Generate AI-ranked payloads without browser execution |
| `--no-crawl` | off | Skip crawling — test only the provided URL |
| `--browser-crawl` | off | Use Playwright browser for crawling (required for SPAs) |
| `--depth N` | 2 | BFS crawl depth |
| `--sink-url URL` | — | Check this page after each injection for stored XSS reflection |
| `--workers N` | 1 | Parallel active-scan worker processes |
| `--timeout N` | 300 | Per-URL worker timeout in seconds |
| `--waf NAME` | auto | Set WAF context (auto-detected if omitted) |
| `--header 'Name: Value'` | — | Add a request header (repeatable) |
| `--cookies FILE` | — | Load session cookies from Netscape cookies.txt |
| `-m, --model MODEL` | config | Override local Ollama model |
| `--backend api\|cli` | config | Cloud escalation backend: `api` = OpenRouter/OpenAI keys, `cli` = CLI subprocess |
| `--cli-tool claude\|codex` | config | CLI tool to use when `--backend cli` (requires tool on PATH and logged in) |
| `--cli-model MODEL` | — | Model to pass to the CLI tool (e.g. `claude-opus-4-6`); omit for tool default |
| `--resume` | off | Resume the most recent interrupted/paused session for this target |
| `--no-resume` | off | Explicit fresh start (same as default; useful in scripts) |
| `--no-cloud` | off | Never escalate to cloud LLM |
| `--public` | off | Fetch community XSS payloads and inject as reference |
| `-o, --output` | `list` | Output format: `list`, `heat`, `json`, `interactive` |
| `-t, --top N` | 20 | Max payloads to display |
| `-j, --json-out PATH` | — | Write full JSON result to path |
| `-r, --rate N` | 25 | Max requests/sec (0 = uncapped) |
| `--threshold N` | 60 | Min risk score for output (always shows ≥ 5) |
| `--no-probe` | off | Skip active parameter probing |
| `--no-live` | off | Suppress streaming probe output |
| `-v, --verbose` | off | Show detailed sub-step output |
| `--merge-batch` | off | Combine all batch URLs into one payload set |
| `--check-keys` | — | Validate all configured API keys |
| `--memory-review [SOURCE]` | `all` | Open the interactive pending memory review inbox for `all`, `labs`, or `targets` |
| `--memory-list [SOURCE]` | `all` | Show the pending memory review queue for `all`, `labs`, or `targets` |
| `--memory-show ID` | — | Show one memory item from the store by stable ID |
| `--memory-promote ID` | — | Promote one memory item into a trusted tier |
| `--memory-reject ID` | — | Reject one pending memory item |
| `--memory-stats [SOURCE]` | `all` | Show memory counts for `all`, `labs`, or `targets` |
| `--memory-limit N` | `10` | Limit rows shown by memory review/list commands |
| `--memory-tier TIER` | `curated` | Target tier for `--memory-promote` |
| `--memory-scope SCOPE` | `global` | Target scope for `--memory-promote` |
| `--memory-reviewer NAME` | `manual-review` | Reviewer label stored with memory decisions |
| `--memory-note TEXT` | `""` | Optional note stored with memory promote/reject actions |
| `-l, --list-models` | — | List local Ollama models |
| `-s, --search-models QUERY` | — | Search Ollama model library |
| `-V, --version` | — | Show version |

---

## Setup

### Fast path

```bash
./setup.sh
axss --help
```

`setup.sh` installs Ollama (if missing), detects RAM/VRAM, pulls the appropriate Qwen3.5 tier, writes `~/.axss/config.json`, builds the venv, and symlinks `axss` to `~/.local/bin/axss`.

### Manual setup

```bash
# 1. Install Ollama and pull a model
curl -fsSL https://ollama.com/install.sh | sh
ollama serve
ollama pull qwen3.5:9b        # balanced default
ollama pull qwen3.5:4b        # low memory (< 8 GB RAM)
ollama pull qwen3.5:27b       # high quality (32 GB+ RAM)

# 2. Configure
mkdir -p ~/.axss
cat > ~/.axss/config.json <<'EOF'
{
  "default_model": "qwen3.5:9b",
  "use_cloud": true,
  "cloud_model": "anthropic/claude-3-5-sonnet"
}
EOF

# 3. Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium --with-deps
```

### Model sizing

| Tier | Model | Hardware |
|------|-------|----------|
| Low | `qwen3.5:4b` | < 8 GB RAM |
| Standard | `qwen3.5:9b` | 8–32 GB RAM |
| High | `qwen3.5:27b` | 32 GB+ RAM |
| GPU | `qwen3.5:35b` | 24 GB+ VRAM |

### Cloud escalation (optional)

Two backends are supported — configure one or both, axss picks the best available:

**API backend (default):** per-token billing via OpenRouter or OpenAI.

```
# ~/.axss/keys
openrouter_api_key = sk-or-v1-...
openai_api_key     = sk-...
```

Or via environment: `OPENROUTER_API_KEY`, `OPENAI_API_KEY`. Verify with `axss --check-keys`.

**CLI backend:** subscription-based auth via `claude` or `codex` CLI — no API key, no per-token cost. Requires the CLI tool to be installed and logged in.

```bash
# Use Claude CLI (subscription auth, no API key needed)
axss -u "https://target.com" --active --backend cli --cli-tool claude

# Use specific model
axss -u "https://target.com" --active --backend cli --cli-tool claude --cli-model claude-opus-4-6

# Use Codex CLI
axss -u "https://target.com" --active --backend cli --cli-tool codex
```

`setup.sh` auto-detects `claude`/`codex` on PATH and writes the result to `~/.axss/config.json`. Use `--backend api|cli` flag to override at runtime.

Cloud escalation only fires when local model output fails a quality check. Use `--no-cloud` to disable entirely.

### Model escalation chain

```
Context-aware generator (always runs, no LLM)
    │
    ▼
Local Ollama (qwen3.5:9b default, findings-enriched prompt)
    │ if output weak (< 3 payloads or all generic)
    ▼
Cloud escalation (one of:)
  ├── CLI backend (--backend cli)
  │     claude -p PROMPT [--model MODEL]
  │     codex exec PROMPT --skip-git-repo-check
  └── API backend (--backend api, default)
        OpenRouter → anthropic/claude-3-5-sonnet (preferred)
        OpenAI → gpt-4o-mini (fallback)
```

---

## Configuration files

### `~/.axss/config.json`

```json
{
  "default_model": "qwen3.5:9b",
  "use_cloud": true,
  "cloud_model": "anthropic/claude-3-5-sonnet",
  "ai_backend": "cli",
  "cli_tool": "claude",
  "cli_model": null
}
```

`ai_backend` and `cli_tool` are auto-configured by `setup.sh` based on what CLI tools are found on PATH. Set `ai_backend` to `"api"` to use OpenRouter/OpenAI keys instead.

### `~/.axss/keys`

```
openrouter_api_key = sk-or-v1-...
openai_api_key     = sk-...
```

### cookies.txt (Netscape format)

```
# Netscape HTTP Cookie File
.example.com	TRUE	/	FALSE	0	session_id	abc123
.example.com	TRUE	/	TRUE	0	csrf_token	xyz789
```

Most browser cookie export extensions produce this format.

---

## Supported WAFs

`cloudflare`, `akamai`, `imperva`, `aws`, `f5`, `modsecurity`, `fastly`, `sucuri`, `barracuda`, `wordfence`, `azure`

WAF is auto-detected from the seed response headers during crawl. Use `--waf NAME` to override or pre-configure.

---

## Resumable sessions

Every active scan automatically creates a session file in `~/.axss/sessions/` and checkpoints progress after every completed work item (atomic write — crash-safe). By default, axss always starts fresh; pass `--resume` to reload a prior session.

**Pause behavior:**
- First `Ctrl+C` — graceful pause: no new workers are started, in-flight workers are allowed to finish, then the scan stops. Session is marked `paused`.
- Second `Ctrl+C` — force kill: all workers are terminated immediately. Session stays `in_progress` so the next run can resume.

**Flags:**
```bash
# Default — always starts fresh, session file created for future resume
axss -u "https://target.com" --active

# Resume the most recent interrupted/paused session for this target
axss -u "https://target.com" --active --resume

# Explicit fresh start (same as default, useful to make intent clear in scripts)
axss -u "https://target.com" --active --no-resume
```

Sessions are identified by a hash of the sorted URL/form list and scan type flags. Auth headers, rate, and worker count are not part of the identity — you can adjust them on resume. Session files accumulate in `~/.axss/sessions/` and can be cleaned up with `rm ~/.axss/sessions/*.json`.

---

## Output

- **`list`** — ranked table with payload, inject vector, tags, risk score (default)
- **`heat`** — compact risk heat view for quick triage
- **`json`** — full structured output for automation
- **`interactive`** — scrollable TUI

Reports for active scans are written to `~/.axss/reports/<domain>_<timestamp>.md`.

---

## Findings store (`~/.axss/findings/`)

Each finding can capture:
- `sink_type`, `context_type`, `surviving_chars`, `bypass_family`
- `payload`, `test_vector`, `model`, `verified`
- `memory_tier`, `target_scope`, `waf_name`, `delivery_mode`
- `frameworks`, `auth_required`
- `evidence_type`, `evidence_detail`, `provenance`
- review metadata (`review_status`, `reviewed_by`, `review_note`)

Storage layout:
- `~/.axss/findings/<context_type>.jsonl`
- one partition per context type
- each partition trimmed independently (`MAX_PER_PARTITION = 2000`)

Retrieval:
- default prompt retrieval uses trusted tiers only: `curated` + `verified-runtime`
- host-scoped findings apply only back to the same host
- global findings transfer across targets
- ranking prefers exact sink/context matches, then char overlap, then target landscape matches (WAF, delivery mode, frameworks, auth)

Review workflow:
```bash
# Table view
axss --memory-list --memory-limit 20

# Interactive inbox
axss --memory-review

# Direct actions
axss --memory-show 4ac35696f010
axss --memory-promote 4ac35696f010 --memory-tier curated --memory-scope global
axss --memory-reject 94e8012d9997 --memory-note "too target-specific"
```

Active scans write verified browser-confirmed findings directly into trusted runtime memory and can also write trusted logic/filter lessons from observed probe behavior. Offline lab learning and cloud-generated unconfirmed payloads land in `experimental` until reviewed or later confirmed.

---

## Known limitations

- **DOM XSS (fragment/hash):** Client-side sinks driven by `location.hash` without a server round-trip are not yet covered.
- **Blind XSS:** No callback server. `--sink-url` covers self-visible stored XSS; payloads rendered only in admin panels or other users' sessions require out-of-band confirmation (planned).
- **Stored XSS scope:** The post-injection sweep covers all pages visited during the crawl. Payloads stored and rendered outside the crawl boundary require `--sink-url`.
- **SPA crawl coverage:** `--browser-crawl` discovers routes visible after initial load and user-triggered navigation. Deep lazy-loaded routes may require higher `--depth`.
