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
axss -u "https://target.tld" --active

# Fast-first active scan with two scout attempts before deep escalation
axss -u "https://target.tld" --active --attempts 2

# Force deep mode
axss -u "https://target.tld" --active --deep

# Stored XSS with optional manual sink override
axss -u "https://target.tld/settings" --stored
axss -u "https://target.tld/settings" --stored --sink-url "https://target.tld/profile"

# DOM-only scan
axss -u "https://target.tld" --dom

# Browser crawl for SPA targets
axss -u "https://target.tld" --active --browser-crawl

# Payload generation only
axss -u "https://target.tld/search?q=test" --generate
```

## Operational notes

- CLI help is the source of truth for flags: `axss --help`
- Auth profiles are managed via `axss auth`
- Reports go to `~/.axss/reports/`
- Config lives in `~/.axss/config.json`
- Keys live in `~/.axss/keys`

## Automation guidance

- Prefer `--active` for real confirmation.
- Prefer `--browser-crawl` for SPA targets.
- Prefer default fast mode first; add `--deep` only when the target is stubborn or you explicitly want maximum model spend.
- Do not assume `--sink-url` is required for stored XSS anymore.
