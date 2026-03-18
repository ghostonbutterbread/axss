# Agent README

This document is for LLMs, scripts, and other automation that need the current `axss` workflow and command patterns without reverse-engineering the codebase.

## Core workflow

```text
input
  - URL / URL list / local HTML
  - mode: --active or --generate

          |
          v

1. discover surface
  - crawl unless --no-crawl
  - find GET params, POST forms, uploads, DOM candidates

2. probe
  - classify reflection context
  - measure surviving chars
  - discover DOM source -> sink paths
  - for stored flows, discover sink pages when possible

3. build prompt context
  - compact context envelope
  - planning envelope for deeper phases
  - few-shot seeds
  - success / failure memory
  - similar findings

4. generate payloads
  - default: fast scout-only rounds first
  - deep escalation only after scout attempts fail
  - --deep restores scout -> contextual -> research on every attempt

5. execute
  - Playwright browser execution for active mode
  - confirm via dialog, console, network, or DOM runtime

6. feedback
  - successful payloads become few-shot references
  - failed rounds become lessons for later attempts
```

## Mode summary

`--generate`
- parse / probe if needed
- generate and rank payloads
- no browser confirmation

`--active`
- discover -> probe -> generate -> execute -> feedback

## Current generation behavior

- Fast by default: scout prompt is intentionally small.
- Deep prompting is conditional unless `--deep` is set.
- Scout uses context-matched seeds from payload metadata, not hardcoded seed lists.
- Similar successful findings are shown as few-shot examples in deeper phases.
- Success memory is shown before failure memory.

## Stored XSS behavior

- Manual `--sink-url` always wins if provided.
- Otherwise stored sink discovery is:
  1. redirect `Location`
  2. crawled-page canary sweep
- When a sink page is discovered, its rendering context overrides the POST response context before payload generation.

## DOM XSS behavior

- Runtime taint discovery builds the DOM context:
  - `source_type`
  - `source_name`
  - `sink`
  - `code_location`
- DOM payload generation is AI-first.
- Static sink payloads are used as reference seeds and final fallback.

## Practical command patterns

```bash
# Full scan
axss scan -u "https://target.tld"

# Fast-first active scan with two scout attempts before deep escalation
axss scan -u "https://target.tld" --attempts 2

# Force deep mode
axss scan -u "https://target.tld" --deep

# Stored XSS with optional manual sink override
axss scan -u "https://target.tld/settings" --stored
axss scan -u "https://target.tld/settings" --stored --sink-url "https://target.tld/profile"

# DOM-only scan
axss scan -u "https://target.tld" --dom

# Browser crawl for SPA targets
axss scan -u "https://target.tld" --browser-crawl

# Payload generation only
axss generate -u "https://target.tld/search?q=test"

# Scope from bug bounty platform (API)
axss scan --urls urls.txt --scope h1:twitter
axss scan --urls urls.txt --scope bc:tesla
axss scan --urls urls.txt --scope ig:superdrug

# Scope from a full program URL (platform auto-detected; API tried first, LLM fallback if no creds)
axss scan --urls urls.txt --scope "https://app.intigriti.com/programs/aswatson/superdrug/detail"
axss scan --urls urls.txt --scope "https://hackerone.com/twitter"

# Rate-limited scan (shared across all phases including pre-flight)
axss scan --urls urls.txt -r 2
```

## Scope resolution order

When `--scope` is a URL for a known bug bounty platform:
1. Extract the program handle from the URL path
2. Call the platform API using credentials from `~/.axss/keys`
3. If credentials are missing → render the page with Playwright and LLM-parse the scope

When `--scope` is any other URL:
- Render with Playwright (handles SPAs), extract visible text, LLM-parse the scope

## Rate limiting

`--rate N` is a **global** token bucket shared across all request-making phases:
- Pre-flight liveness probes
- HTTP crawl
- Active scan worker requests

Deduplication and other in-memory operations are never rate-limited. Set `--rate 0` to uncap (default).

## Operational notes

- CLI help is the source of truth for flags: `axss scan --help`, `axss generate --help`
- Running `axss scan` or `axss generate` with no arguments prints the subcommand help
- Auth profiles are managed via `axss memory`
- Reports go to `~/.axss/reports/`
- Config lives in `~/.axss/config.json`
- Keys live in `~/.axss/keys` — includes slots for H1, Bugcrowd, and Intigriti API credentials

## Automation guidance

- Prefer `axss scan` for real confirmation.
- Prefer `--browser-crawl` for SPA targets.
- Prefer default fast mode first; add `--deep` only when the target is stubborn or you explicitly want maximum model spend.
- Do not assume `--sink-url` is required for stored XSS anymore.
- When scanning targets that IP-ban aggressively, always set `--rate`.
