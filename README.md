# axss

AI-assisted XSS scanning for authorized testing. `axss` crawls a target, probes each candidate sink, generates context-matched payloads, and confirms execution in a real browser.

## What it does

- Reflected XSS: GET parameter discovery, probing, payload generation, browser confirmation
- Stored XSS: POST form submission, sink auto-discovery, sink-context override before generation
- DOM XSS: runtime source→sink discovery with AI-generated payloads and static fallbacks
- Blind XSS: OOB token injection for payloads that execute out-of-band (admin panels, logs, emails) — **requires `--blind-callback URL`**; disabled by default
- href/formaction bypass: detects `javascript:` URI injection points (e.g. `<a href="javascript:...">`) and clicks them post-navigation to confirm execution
- Fast-by-default generation: compact scout prompts first, deeper phased prompts only when needed
- Scan artifact caching: sitemap and probe results cached 24 h so re-runs reuse prior work

## Setup

```bash
./setup.sh
axss --help
```

`setup.sh` creates the virtualenv, installs dependencies, installs Chromium for Playwright, writes `~/.axss/config.json`, and links `axss` into `~/.local/bin` when possible.

## Quick start

```bash
# Default — broad-spectrum Gen XSS, no probe (fast is the default)
axss -u "https://target.tld" --active

# Full probe + 3-phase targeted generation — finds context-specific injections
axss -u "https://target.tld" --active --deep

# Maximum coverage: no probe + full 3-phase broad-spectrum
axss -u "https://target.tld" --active --obliterate

# Stored XSS only
axss -u "https://target.tld" --stored

# DOM XSS only
axss -u "https://target.tld" --dom

# Ignore all caches, re-collect everything from scratch
axss -u "https://target.tld" --active --fresh
```

## Visual flow

```text
active scan

  check sitemap cache (~/.axss/cache/<host>/sitemap_*.json)
  - hit: skip crawl, use cached CrawlResult
  - miss: crawl / enumerate → write cache
         |
         v
  check probe cache per URL (~/.axss/cache/<host>/probe_*.json)
  - hit: skip probe, use real reflection contexts at zero cost
  - --fast / --obliterate: use cache if present, else synthesize fast_omni
  - miss: probe target behavior
    - reflection context + surviving chars
    - DOM taint source → sink
    - stored sink discovery
    → write cache
         |
         v
  build compact AI context
  - context envelope
  - seed payloads
  - success / failure memory
         |
         v
  generate payloads
  - default: fast scout round, escalate on failure
  - --deep: full 3-phase (scout → contextual → research) on every attempt
  - --fast: broad-spectrum single call, no probe context needed
  - --obliterate: broad-spectrum + full 3-phase (maximum throughput + depth)
         |
         v
  execute in Playwright
  - click javascript: href/formaction elements post-injection
         |
         v
  confirm execution
  - dialog / console / network / DOM runtime
```

## Scan modes

| Flag | Probe | Phases | Best for |
|------|-------|--------|----------|
| *(default)* / `--fast` | skip | 1 broad-spectrum | general use — fast Gen XSS across all contexts |
| `--deep` | full | 3 phases targeted | thorough assessment, context-specific injections (JS strings, attr breakouts, href bypass) |
| `--obliterate` | skip | 3 phases broad-spectrum | maximum payload variety at full speed |

## Cache behavior

Scan artifacts are stored under `~/.axss/cache/<netloc>/` and expire after **24 hours**.

- **Sitemap cache**: reused when the same seed URL + scope is scanned again — skips full BFS re-crawl.
- **Probe cache**: reused per URL+params. When a `--fast` or `--obliterate` scan finds a probe cache entry from a prior normal scan, it uses real reflection contexts instead of the synthetic broad-spectrum fallback — better-targeted generation at zero extra network cost.
- **`--fresh`**: bypass both caches and re-collect everything from scratch.
- `--urls FILE` mode never writes or reads the sitemap cache (URL list was pre-enumerated by the user).

## Useful commands

```bash
# Auth manager
axss auth

# Show knowledge base counts
axss --memory-stats

# Resume the latest interrupted scan for a target
axss -u "https://target.tld" --active --resume

# Scan a SPA with browser crawl
axss -u "https://target.tld" --active --browser-crawl

# Blind XSS — requires an OOB callback URL you control
# (Interactsh, Burp Collaborator, webhook.site, or your own server)
axss -u "https://target.tld" --active --blind-callback "https://abc123.oast.pro"

# Check which blind tokens have fired since the scan
axss --poll-blind ~/.axss/reports/<report-dir>/blind_tokens.json \
     --blind-callback "https://abc123.oast.pro"

# Re-scan without re-crawling (probe cache still applies)
axss -u "https://target.tld" --active --fast

# Force full fresh scan — ignore all cached artifacts
axss -u "https://target.tld" --active --obliterate --fresh
```

## Notes

- Use only on systems you are authorized to test.
- `--sink-url` is still supported as a manual override for stored XSS, but it is no longer required for common same-session sinks.
- Reports are written under `~/.axss/reports/`.
- Cache files live under `~/.axss/cache/` — safe to delete manually to free space.

If you're an agent, refer to [AGENT_README.md](AGENT_README.md).
