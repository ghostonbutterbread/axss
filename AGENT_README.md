# Agent README

This document is for LLMs, scripts, and other automation that need the current `axss` workflow and command patterns without reverse-engineering the codebase.

## Core workflow

```text
input
  - URL / URL list / local HTML
  - mode: normal (default), --fast, or --deep

          |
          v

1. pre-flight
  - strip tracking params
  - path-shape dedup (collapse /tag/nyc, /tag/london → one representative URL)
  - liveness filter (HEAD-check all URLs; drop 404/410/connection errors; keep 401/403/5xx)

2. discover surface
  - crawl unless --no-crawl or --urls
  - find GET params, POST forms, uploads, DOM candidates

3. probe (normal + deep; skipped for fast)
  - classify reflection context (html_body, html_attr_url, js_string_dq, etc.)
  - measure surviving chars (deep mode: full char probe)
  - discover DOM source -> sink paths
  - for stored flows, discover sink pages when possible

4. payload pipeline (per injectable param)
  - Tier 1: deterministic context-specific payloads
      payloads_for_context(context_type, surviving_chars) routes to the correct
      generator. surviving_chars=None in normal mode (no probe → full candidate list).
      HTTP reflection pre-rank for normal mode (top 3 reflecting payloads become seeds).
      Hit → ConfirmedFinding(source="phase1_deterministic"), stop.
  - Tier 1.5: programmatic seed mutations (GenXSS-style)
      mutate_seeds(seeds, surviving_chars) applies 5 transforms:
      case randomisation, space replacement, encoding variants (alert/confirm/prompt),
      event handler rotation, quote swap. Up to 15 variants per seed set.
      Hit → ConfirmedFinding(source="phase1_deterministic"), stop.
  - Tier 2: local model triage gate (deep only)
      Input: context_type, surviving_chars (frozenset), waf, delivery_mode — no raw HTML.
      Output: score (1-10), should_escalate (bool), reason.
      should_escalate=False → skip this param, no cloud spend.
  - Tier 3: cloud (normal + deep, different prompts)
      Normal: generate_normal_scout() — seeds + "mutate with encoding" — 3 payloads.
      Deep: constraint-aware mutation — top 5 failed payloads + blocked_on per payload — 8 payloads.
      Hit → ConfirmedFinding(source="cloud_model"), stop.

5. execute
  - Playwright browser execution
  - click javascript: href/formaction elements post-injection
  - confirm via dialog, console, network, or DOM runtime

6. feedback
  - successful payloads become few-shot references
  - failed rounds become lessons for later attempts
```

## Mode summary

| Mode | Flag | Probe | Pipeline | Best for |
|------|------|-------|----------|----------|
| Normal | *(default)* | partial | Tier 1 → 1.5 → Tier 3 scout | URL lists, broad coverage |
| Fast | `--fast` | none | Pre-generated set + HTTP pre-filter | Large URL lists, speed |
| Deep | `--deep` | full | Tier 1 → 1.5 → Tier 2 triage → Tier 3 mutation | 1-2 pages, exhaustive |

**Fast mode is unchanged by the pipeline restructure** — it uses a pre-generated broad-spectrum payload set with an HTTP pre-filter before Playwright. No deterministic dispatch, no local triage.

## Generation behavior

- **Deterministic first:** Context-specific generators always fire before any AI call. These are structured payloads matched to the injection context (html_body, html_attr_url, js_string_dq, etc.).
- **Mutation before cloud:** GenXSS-style programmatic transforms run on the best Tier 1 seeds before any API spend. No cloud call needed for mutations.
- **Seed mutation, not cold generation:** Cloud prompts receive the top failed seeds and instructions to mutate aggressively — not cold generation from scratch.
- **Deep mode triage:** Local model scores the injection surface before cloud escalation. Structured labels only — the local model does not parse raw HTML.
- **`generate_fast_batch` only in fast mode:** Normal mode no longer runs an upfront AI batch call. Per-param scout calls only.

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
- Normal mode: URL params only for DOM taint discovery.
- Deep mode: all 6 DOM sources probed.

## Practical command patterns

```bash
# Default normal mode scan
axss scan -u "https://target.tld"

# Fast sweep for large URL lists
axss scan --urls all_urls.txt --fast

# Deep scan on specific high-value page
axss scan -u "https://target.tld/app" --deep

# Deep scan, bypass local triage gate (when local model is slow or unavailable)
axss scan -u "https://target.tld/app" --deep --skip-triage

# Validate local model triage before deep scanning
axss models --test-triage

# Tier summary per param (which tiers fired, confirmed or blocked)
axss scan -u "https://target.tld" -v

# Real-time per-tier lines with payload counts and top seed (good for tmux)
axss scan -u "https://target.tld" -vv

# Deep scan with full pipeline visibility
axss scan -u "https://target.tld" --deep -vv

# Stored XSS with optional manual sink override
axss scan -u "https://target.tld/settings" --stored
axss scan -u "https://target.tld/settings" --stored --sink-url "https://target.tld/profile"

# DOM-only scan
axss scan -u "https://target.tld" --dom

# Browser crawl for SPA targets
axss scan -u "https://target.tld" --browser-crawl

# Payload generation only (no browser)
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

## Recommended workflow for large target sets

```
1. axss scan --urls all_urls.txt --fast         # broad sweep
2. axss scan --urls all_urls.txt --interesting  # score URLs (static analysis)
3. axss scan --urls interesting.txt             # normal mode on filtered set
4. axss scan -u "https://target.tld/page" --deep  # exhaustive on high-value pages
```

## Debug flags

`-v` (any mode)
- Prints one summary line per (param, context_type) combination after that context's pipeline completes
- Format: `[>] GET ?{param} [{context_type}] {tier_chain}`
- `tier_chain` is ` → `-joined tokens: `T1:CONFIRMED`, `T1:miss`, `T1.5:miss`, `triage:escalate`, `triage:block(score=N)`, `triage:skip(fast)`, `triage:skip(flag)`, `triage:skip(omni)`, `T3-scout:CONFIRMED/miss`, `Deep-T3:CONFIRMED/miss`, `timeout`
- No payload content — shows which tier succeeded or where the pipeline stopped
- Use for quick audits: did every param reach triage? Did cloud fire? Which params were blocked?

`-vv` (any mode)
- Prints inline lines at each tier boundary in real time (suitable for tmux splits)
- Format: `[.] GET ?{param} [{ctx}] Tier 1: {n} candidates | top: "{payload50}"`
- Shows: candidate counts, pre-rank reflect ratio, fired/confirmed counts, triage score+reason, cloud payload count
- All variable-length fields truncated to stay readable in narrow panes
- Stacks with `-v`: both levels print simultaneously

Tier chain token reference:

| Token | Meaning |
|---|---|
| `T1:CONFIRMED` | Tier 1 deterministic payload confirmed XSS |
| `T1:miss` | All Tier 1 payloads fired, none confirmed |
| `T1:skip(no-cands)` | `payloads_for_context()` returned empty — context not dispatched |
| `T1.5:CONFIRMED` | Tier 1.5 mutation confirmed XSS |
| `T1.5:miss` | All Tier 1.5 mutations fired, none confirmed |
| `triage:escalate` | Local model scored high enough — escalating to cloud |
| `triage:block(score=N)` | Local model blocked escalation (score N, should_escalate=False) |
| `triage:skip(fast)` | Normal mode auto-escalates (no triage gate) |
| `triage:skip(flag)` | `--skip-triage` bypassed triage gate |
| `triage:skip(omni)` | `fast_omni` context bypasses triage entirely |
| `T3-scout:CONFIRMED/miss` | Normal mode Tier 3 cloud scout result |
| `Deep-T3:CONFIRMED/miss` | Deep mode Tier 3 constraint-aware cloud mutation result |
| `timeout` | Pipeline was still running when the per-URL time limit hit |

`--skip-triage` (deep mode only)
- Bypasses the local model triage gate after Tier 1 + 1.5 miss
- Goes directly to Tier 3 cloud mutation
- No-op in fast and normal mode
- Use when local model is unavailable or producing unreliable decisions

`axss models --test-triage`
- Fires a synthetic example through the simplified triage prompt
- Prints: exact JSON sent to local model, raw response, parsed result
- Synthetic input: `context_type=html_attr_url`, `surviving_chars=['"', ' ', 'javascript:']`, `waf=null`
- Exit code 1 if local model returns malformed JSON or score outside 1-10

## ConfirmedFinding source values

| Value | Meaning |
|-------|---------|
| `phase1_transform` | Existing transform-based hit |
| `phase1_waf_fallback` | WAF-specific deterministic fallback |
| `phase1_deterministic` | Context-specific generator or mutation hit (Tier 1 or 1.5) |
| `local_model` | Local model generation hit (deep mode) |
| `cloud_model` | Cloud generation hit (normal scout or deep mutation) |
| `dom_xss_runtime` | DOM taint analysis hit |

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

- CLI help is the source of truth for flags: `axss scan --help`, `axss generate --help`, `axss models --help`
- Running a subcommand with no arguments prints the subcommand help
- Knowledge base is managed via `axss memory`
- Models are managed via `axss models`
- Reports go to `~/.axss/reports/`
- Config lives in `~/.axss/config.json`
- Keys live in `~/.axss/keys` — includes slots for H1, Bugcrowd, and Intigriti API credentials

## Automation guidance

- Prefer `axss scan` for real confirmation.
- Prefer `--browser-crawl` for SPA targets.
- Use `--fast` for initial sweeps of large URL lists; `--deep` only on specific high-value pages.
- Normal mode is the default — it's the right choice for most URL list scans.
- Do not assume `--sink-url` is required for stored XSS anymore.
- When scanning targets that IP-ban aggressively, always set `--rate`.
- Before running deep mode scans, use `axss models --test-triage` to confirm the local model is functional.
