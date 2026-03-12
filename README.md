# axss — AI-assisted XSS Scanner

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![CLI](https://img.shields.io/badge/interface-CLI-111111)
![Ollama](https://img.shields.io/badge/Ollama-local%20runtime-111111?logo=ollama&logoColor=white)

## What this tool is

`axss` is a context-aware XSS scanner for authorized penetration testing. It crawls a live target, maps every GET parameter and POST form it finds, probes each one for reflection and filter behavior, then generates ranked payloads tailored to what the probe observed. It fires each payload through a real Playwright browser and confirms JavaScript execution via dialog hooks, console output, or network beacon. It covers reflected XSS, session-stored XSS, and POST forms protected by dynamic CSRF tokens.

## Learning Model

- The knowledge store is a single curated tier in SQLite at `~/.axss/knowledge.db`.
- All findings are globally scoped — no per-host partitioning.
- `xssy/learn.py` generates candidate payloads against xssy.uk labs, then pipes the
  results through `xssy/curate.py` — the LLM curation pipeline — which asks the
  configured AI backend to extract a structured finding (bypass family, context type,
  filter behaviour, explanation) and saves it to the store.
- `xssy/curate.py` (`curate_lab_finding()`) is the general curation pipeline and works
  on any confirmed XSS target — not just xssy.uk. It takes payloads, a lab name,
  objective string, and URL as plain parameters.
- Active probe observations (surviving chars, reflection context) are kept as ephemeral
  session lessons passed directly into the generation prompt — nothing is written to disk.
- Confirmed XSS findings go to the scan report, not the knowledge base.

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

### Knowledge base

axss keeps a curated findings store in SQLite at `~/.axss/knowledge.db`. Every entry is a
generalizable XSS bypass pattern with context type, bypass family, surviving chars, explanation,
and confidence. Retrieval scores candidates by:

- sink/context type match
- surviving character overlap
- WAF match
- delivery mode (`get`, `post`)
- framework hints
- auth context

Populated two ways:
- **Seed scripts** (`python xssy/seed_expert.py` etc.) — hand-curated lab knowledge
- **Lab learning** (`python xssy/learn.py`) — LLM extracts structured findings from xssy.uk labs

### Session lessons (ephemeral)

Active probe observations — surviving chars, reflection context type, DOM sources, form shapes,
framework detection — are captured as in-memory `Lesson` objects and injected directly into the
generation prompt for that scan. They are discarded when the scan ends; nothing is written to disk.

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

# List all curated findings
axss --memory-list

# Show finding counts by context type
axss --memory-stats

# Export knowledge base to a portable YAML file
axss --memory-export ~/axss-knowledge.yaml

# Import findings from a YAML file (e.g. shared knowledge base)
axss --memory-import ~/axss-knowledge.yaml

# Delete all saved reports
axss --clear-reports

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
| `--memory-list` | — | List all curated findings in the knowledge base |
| `--memory-stats` | — | Show finding counts by context type |
| `--memory-export PATH` | — | Export all curated findings to a YAML file |
| `--memory-import PATH` | — | Import curated findings from a YAML file |
| `--clear-reports` | — | Delete all saved reports from `~/.axss/reports/` |
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

## Knowledge base (`~/.axss/knowledge.db`)

SQLite database, single curated table. Each finding captures:
- `context_type`, `sink_type`, `bypass_family`, `surviving_chars`
- `payload`, `test_vector`, `explanation`
- `waf_name`, `delivery_mode`, `frameworks`, `auth_required`
- `confidence`, `source`, `curated_at`

All findings are globally scoped and transfer across targets.

```bash
# Inspect the store
axss --memory-list
axss --memory-stats

# Share / back up / restore
axss --memory-export ~/axss-knowledge.yaml
axss --memory-import ~/axss-knowledge.yaml

# Populate with hand-curated lab knowledge
python xssy/seed_expert.py
python xssy/seed_adept.py
python xssy/seed_master.py

# Extract findings from xssy.uk labs via the curation pipeline
# (requires xssy.uk access; see xssy_jwt in ~/.axss/keys)
python xssy/learn.py
```

---

## Known limitations

- **DOM XSS (fragment/hash):** Client-side sinks driven by `location.hash` without a server round-trip are not yet covered.
- **Blind XSS:** No callback server. `--sink-url` covers self-visible stored XSS; payloads rendered only in admin panels or other users' sessions require out-of-band confirmation (planned).
- **Stored XSS scope:** The post-injection sweep covers all pages visited during the crawl. Payloads stored and rendered outside the crawl boundary require `--sink-url`.
- **SPA crawl coverage:** `--browser-crawl` discovers routes visible after initial load and user-triggered navigation. Deep lazy-loaded routes may require higher `--depth`.
