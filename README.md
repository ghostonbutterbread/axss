# axss

AI-assisted XSS scanning for authorized testing. `axss` crawls a target, probes each candidate sink, generates context-matched payloads, and confirms execution in a real browser.

## What it does

- Reflected XSS: GET parameter discovery, probing, payload generation, browser confirmation
- Stored XSS: POST form submission, sink auto-discovery, sink-context override before generation
- DOM XSS: runtime source->sink discovery with AI-generated payloads and static fallbacks
- Fast-by-default generation: compact scout prompts first, deeper phased prompts only when needed

## Setup

```bash
./setup.sh
axss --help
```

`setup.sh` creates the virtualenv, installs dependencies, installs Chromium for Playwright, writes `~/.axss/config.json`, and links `axss` into `~/.local/bin` when possible.

## Quick start

```bash
# Full active scan
axss -u "https://target.tld" --active

# Generate payloads only
axss -u "https://target.tld/search?q=test" --generate

# Stored XSS only
axss -u "https://target.tld/account" --stored

# DOM XSS only
axss -u "https://target.tld" --dom

# Force deep phased prompting on every attempt
axss -u "https://target.tld" --active --deep
```

## Visual flow

```text
active scan

  crawl / enumerate
         |
         v
  probe target behavior
  - reflection context
  - surviving chars
  - DOM taint source -> sink
  - stored sink discovery
         |
         v
  build compact AI context
  - context envelope
  - seed payloads
  - success / failure memory
         |
         v
  generate payloads
  - default: fast scout rounds
  - optional: deeper contextual / research escalation
         |
         v
  execute in Playwright
         |
         v
  confirm execution
  - dialog
  - console
  - network
  - DOM runtime
```

## Current behavior

- Default mode is fast-first. Scout prompts run first and deep escalation happens only after scout attempts fail.
- `--deep` restores full phased generation on every attempt.
- Stored XSS no longer depends on `--sink-url`; redirects and crawled-page canary sweeps are used automatically when possible.
- DOM XSS is AI-first. Static sink payloads are now seeds and fallbacks, not the primary strategy.

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
```

## Notes

- Use only on systems you are authorized to test.
- `--sink-url` is still supported as a manual override for stored XSS, but it is no longer required for common same-session sinks.
- Reports are written under `~/.axss/reports/`.

If you're an agent, refer to [AGENT_README.md](AGENT_README.md).
