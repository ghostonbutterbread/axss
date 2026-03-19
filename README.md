# axss

AI-assisted XSS scanning for authorized testing. `axss` crawls a target, probes each candidate sink, generates context-matched payloads, and confirms execution in a real browser.

## What it does

- Reflected XSS: GET parameter discovery, probing, deterministic context-specific payloads, programmatic mutations, AI-assisted generation, browser confirmation
- Stored XSS: POST form submission, sink auto-discovery, sink-context override before generation
- DOM XSS: runtime source→sink discovery with AI-generated payloads and static fallbacks
- Blind XSS: OOB token injection for payloads that execute out-of-band (admin panels, logs, emails) — **requires `--blind-callback URL`**; disabled by default
- href/formaction bypass: detects `javascript:` URI injection points (e.g. `<a href="javascript:...">`) and clicks them post-navigation to confirm execution
- Deterministic-first generation: context-specific payloads fire before any AI call; programmatic mutations run before cloud API spend
- Scan artifact caching: sitemap and probe results cached 24 h so re-runs reuse prior work

## Setup

```bash
./setup.sh
axss --help
```

`setup.sh` creates the virtualenv, installs dependencies, installs Chromium for Playwright, writes `~/.axss/config.json`, and links `axss` into `~/.local/bin` when possible.

## Quick start

```bash
# Default (normal mode) — deterministic + mutation + lightweight cloud, all XSS types
axss scan -u "https://target.tld"

# Fast mode — HTTP pre-filter, broad-spectrum payloads, no probe (best for large URL lists)
axss scan -u "https://target.tld" --fast

# Deep mode — full probe + exhaustive per-param investigation (best for 1-2 high-value pages)
axss scan -u "https://target.tld" --deep

# URL list scan (normal mode by default)
axss scan --urls urls.txt

# Stored XSS only
axss scan -u "https://target.tld" --stored

# DOM XSS only
axss scan -u "https://target.tld" --dom

# Ignore all caches, re-collect everything from scratch
axss scan -u "https://target.tld" --fresh
```

## Scan modes

| Flag | Probe | Payload pipeline | Best for |
|------|-------|-----------------|----------|
| *(default)* / Normal | partial | Tier 1 (deterministic) → Tier 1.5 (mutations) → Tier 3 (cloud seed scout) | URL lists, broad coverage — reflected + stored + DOM light |
| `--fast` | skip | Pre-generated broad-spectrum set, HTTP pre-filter before Playwright | Large URL lists (35k+), speed over depth |
| `--deep` | full | Tier 1 → Tier 1.5 → Tier 2 (local triage) → Tier 3 (cloud constraint-aware mutation) | 1-2 high-value pages, exhaustive investigation |

### Payload pipeline (Normal + Deep)

Payloads are generated in tiers before any cloud API spend:

```
Tier 1 — Deterministic
  Context-specific generators fire first (html_body, html_attr_url, js_string, etc.)
  Payloads filtered by probe-confirmed surviving chars (deep mode) or unfiltered (normal)
        ↓ hit → done (source: phase1_deterministic)
        ↓ miss

Tier 1.5 — Programmatic Mutations
  GenXSS-style transforms on best Tier 1 seeds: case randomisation,
  space replacement, encoding variants, event handler rotation, quote swaps
  Free, no API cost
        ↓ hit → done (source: phase1_deterministic)
        ↓ miss

Tier 2 — Local Triage Gate (Deep only)
  Local model decides whether cloud spend is justified
  Input: context_type, surviving_chars, WAF, delivery_mode — no raw HTML
        ↓ should_escalate=False → stop
        ↓ should_escalate=True

Tier 3 — Cloud
  Normal: lightweight seed mutation scout (3 payloads, encoding-heavy)
  Deep: constraint-aware mutation from top failed payloads + blocked chars
        ↓ hit → done (source: cloud_model)
        ↓ miss → no finding for this param
```

## Visual flow

```text
axss scan

  Pre-flight
  - strip tracking params
  - path-shape dedup (collapses /tag/nyc, /tag/london → one representative)
  - liveness filter (HEAD-check, drop 404/410/DNS failure, keep 401/403/5xx)
         |
         v
  check sitemap cache (~/.axss/cache/<host>/sitemap_*.json)
  - hit: skip crawl, use cached CrawlResult
  - miss: crawl / enumerate → write cache
         |
         v
  check probe cache per URL (~/.axss/cache/<host>/probe_*.json)
  - hit: skip probe, use real reflection contexts at zero cost
  - --fast: synthesize fast_omni (no probe)
  - miss: probe target behavior
    - reflection context + surviving chars
    - DOM taint source → sink
    - stored sink discovery
    → write cache
         |
         v
  payload pipeline (per injectable param)
  - Tier 1: deterministic context-specific payloads
  - Tier 1.5: programmatic seed mutations
  - Tier 2: local model triage gate (deep only)
  - Tier 3: cloud seed mutation
         |
         v
  execute in Playwright
  - click javascript: href/formaction elements post-injection
         |
         v
  confirm execution
  - dialog / console / network / DOM runtime
```

## Cache behavior

Scan artifacts are stored under `~/.axss/cache/<netloc>/` and expire after **24 hours**.

- **Sitemap cache**: reused when the same seed URL + scope is scanned again — skips full BFS re-crawl.
- **Probe cache**: reused per URL+params. When a `--fast` scan finds a probe cache entry from a prior normal scan, it uses real reflection contexts instead of the synthetic broad-spectrum fallback — better-targeted generation at zero extra network cost.
- **`--fresh`**: bypass both caches and re-collect everything from scratch.
- `--urls FILE` mode never writes or reads the sitemap cache (URL list was pre-enumerated by the user).

## Useful commands

```bash
# Knowledge base management
axss memory

# List available local models
axss models list

# Validate API keys
axss models check-keys

# Validate local model triage capability before a deep scan
axss models --test-triage

# Resume the latest interrupted scan for a target
axss scan -u "https://target.tld" --resume

# Scan a SPA with browser crawl
axss scan -u "https://target.tld" --browser-crawl

# Blind XSS — requires an OOB callback URL you control
# (Interactsh, Burp Collaborator, webhook.site, or your own server)
axss scan -u "https://target.tld" --blind-callback "https://abc123.oast.pro"

# Check which blind tokens have fired since the scan
axss --poll-blind ~/.axss/reports/<report-dir>/blind_tokens.json \
     --blind-callback "https://abc123.oast.pro"

# Deep scan, bypass local triage gate (use when local model is unavailable)
axss scan -u "https://target.tld" --deep --skip-triage

# Force fresh scan, ignore all cached artifacts
axss scan -u "https://target.tld" --fresh

# Generate AI-ranked payloads without browser execution
axss generate -u "https://target.tld/search?q=test"
```

## Recommended workflow for large target sets

```bash
# Step 1: Fast sweep across all URLs
axss scan --urls all_urls.txt --fast

# Step 2: Score remaining URLs for interest (static URL analysis)
axss scan --urls all_urls.txt --interesting

# Step 3: Normal scan on filtered high-interest URLs
axss scan --urls interesting_urls.txt

# Step 4: Deep scan on specific high-value targets
axss scan -u "https://target.tld/specific-page" --deep
```

## Scope enforcement

`--scope` tells the crawler and scanner which hosts are in-bounds. It accepts several formats:

```bash
# Auto-derive from the seed URL (default)
axss scan -u "https://target.tld"

# Bug bounty platform — pulls scope directly from the API
axss scan --urls urls.txt --scope h1:twitter
axss scan --urls urls.txt --scope bc:tesla
axss scan --urls urls.txt --scope ig:superdrug

# Full program URL — platform is auto-detected, API is tried first,
# falls back to Playwright render + LLM parse if credentials aren't configured
axss scan --urls urls.txt --scope "https://app.intigriti.com/programs/aswatson/superdrug/detail"
axss scan --urls urls.txt --scope "https://hackerone.com/twitter"
axss scan --urls urls.txt --scope "https://bugcrowd.com/tesla"

# Any other URL — rendered with Playwright and LLM-parsed for scope info
axss scan --urls urls.txt --scope "https://example.com/security/scope.html"

# Manual list
axss scan --urls urls.txt --scope "target.tld,*.target.tld,!admin.target.tld"
```

Platform API credentials are stored in `~/.axss/keys` (written by `setup.sh`):

```
h1_username        = your-h1-username
h1_token           = your-h1-api-token
bugcrowd_api_key   = your-bc-key
intigriti_api_token = your-ig-token
```

When a program URL is given but credentials are missing, axss automatically falls back to rendering the page with Playwright and using an LLM to extract the scope.

## Rate limiting

`--rate N` caps the global request rate across **all** phases — pre-flight liveness checks, crawling, and active scan workers all share the same token bucket. Use this when a target is aggressive about IP-banning scanners:

```bash
# 2 requests per second across the entire session
axss scan --urls urls.txt -r 2

# Uncapped (default)
axss scan -u "https://target.tld"
```

## Notes

- Use only on systems you are authorized to test.
- `--sink-url` is still supported as a manual override for stored XSS, but it is no longer required for common same-session sinks.
- Reports are written under `~/.axss/reports/`.
- Cache files live under `~/.axss/cache/` — safe to delete manually to free space.

If you're an agent, refer to [AGENT_README.md](AGENT_README.md).
