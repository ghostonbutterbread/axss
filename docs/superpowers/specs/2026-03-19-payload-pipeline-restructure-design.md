# Payload Pipeline Restructure: Deterministic-First + Mode-Aware AI Generation

**Date:** 2026-03-19
**Status:** Approved
**Scope:** `active/worker.py`, `models.py`, `active/generator.py`, `active/orchestrator.py`, `cli.py`

---

## Summary

Restructure the deep and normal mode payload pipelines to use a deterministic
context-specific first pass before any AI generation, followed by a GenXSS-style
programmatic mutation layer (Tier 1.5) that encodes and varies the best Tier 1
seeds before touching the cloud. Simplify the local triage gate input for deep
mode, and reframe all cloud prompts from cold generation to seed mutation —
the cloud receives the payloads that came closest and mutates them aggressively.
Two debug flags are added to help users validate and bypass the local triage gate.

---

## Mode Philosophy

| Mode | Target Use Case | AI Role |
|------|----------------|---------|
| **Fast** | Large URL lists, reflected XSS sweep | Unchanged — pre-generated payload set, HTTP pre-filter |
| **Normal** | URL lists, broad coverage (reflected + stored + DOM light) | Seed mutation — Tier 1 seeds → programmatic mutations → cloud mutates best seeds |
| **Deep** | 1-2 specific high-value pages, exhaustive investigation | Probe → local triage → cloud mutation with failure evidence |

**Fast mode is unchanged by this spec.**

---

## Section 1: Payload Tier Architecture

### Tier 1 — Deterministic (Normal + Deep)

`generator.py` context-specific generators run first, before any AI call.

- Entry point: new `payloads_for_context(context_type, surviving_chars)` dispatch
  function added to `generator.py`
- Signature: `def payloads_for_context(context_type: str, surviving_chars: frozenset[str] | None) -> list[PayloadCandidate]`
- Routes to the correct context generator:
  `html_body_payloads`, `html_attr_url_payloads`, `html_attr_value_payloads`,
  `js_string_payloads`, `js_code_payloads`, `html_attr_event_payloads`
- When `surviving_chars` is `None`, filtering is bypassed and the full candidate
  list is returned (equivalent to treating all chars as surviving). Normal mode
  passes `None`; deep mode passes the probe-confirmed frozenset.
- Payloads sorted by `risk_score` descending (existing field on `PayloadCandidate`)
- If any payload confirms execution → `ConfirmedFinding(source="phase1_deterministic")`, pipeline stops

**Normal mode:** Tier 1 proceeds to Tier 1.5 if deterministic misses.
**Deep mode:** Tier 1 proceeds to local triage if deterministic misses.

### Tier 1.5 — Programmatic Seed Mutation (Normal + Deep)

GenXSS-style systematic transforms applied to the top Tier 1 seeds. Free, fast,
no API cost. Runs before any cloud call.

**Seed selection:** Before firing Tier 1, a single lightweight HTTP reflection
check (reusing `_http_reflects_payload()`) identifies which Tier 1 payloads have
at least partial reflection in the response body. Payloads with partial reflection
rank highest as seeds — they got furthest through the filter. Payloads with no
reflection at all rank lowest.

**Transforms applied to each seed (in order):**
1. `random_upper()` — randomize case on tag names and event handler names
   (already in `generator.py`, reused here)
2. Space replacement variants — substitute spaces with `/`, `%09`, `%0a`, `/**/`
3. Encoding variants on the JS expression — HTML entity (`&#x61;lert`),
   URL-encode (`%61lert`), hex (`\x61lert`), unicode (`\u0061lert`)
4. Event handler rotation — cycle through compatible handlers:
   `onerror` → `ontoggle` → `onpointerenter` → `onfocus`
5. Quote style variants — double → single → none → backtick where applicable

**Output:** Up to 15 mutated candidates per seed, sorted by transform confidence.
`ConfirmedFinding(source="phase1_deterministic")` used for hits (same as Tier 1 —
both are deterministic, non-AI paths).

**Normal mode:** Proceeds to Tier 3 cloud if Tier 1.5 misses.
**Deep mode:** Proceeds to local triage if Tier 1.5 misses.

### Tier 2 — Local Triage Gate (Deep only)

Runs only when Tier 1 missed. Decides whether cloud API spend is justified.

See Section 3 for simplified input format.

### Tier 3 — Cloud Generation (Normal + Deep, different prompts)

See Section 4 for prompt designs per mode.

---

## Section 2: Full Pipeline Per Mode

### Normal Mode Pipeline (per injectable param)

The upfront `generate_fast_batch` call in `orchestrator.py` is **removed from
the normal mode path** — it is retained for fast mode only. Normal mode AI
generation moves entirely to per-param scout calls in `worker.py`.

```
Parser-detected context_type
        ↓
HTTP reflection check on Tier 1 candidates (reuse _http_reflects_payload)
→ rank seeds by partial reflection (most surviving fragments = best seed)
        ↓
[Tier 1] payloads_for_context(context_type, surviving_chars=None)
         fire top seeds via executor
        ↓ hit → ConfirmedFinding(source="phase1_deterministic"), done
        ↓ miss
[Tier 1.5] Programmatic mutations of best seeds
           (case, encoding, space, handler rotation — up to 15 variants)
           fire via executor
        ↓ hit → ConfirmedFinding(source="phase1_deterministic"), done
        ↓ miss
[Tier 3] generate_normal_scout(context_type, waf, frameworks, seeds) → 3 payloads
         input: top 3 seeds that came closest + context
         instruction: seed mutation, encoding-heavy, assume angle brackets blocked
         fire via executor
        ↓ hit → ConfirmedFinding(source="cloud_model"), done
        ↓ miss → no finding for this param
```

### Deep Mode Pipeline (per injectable param)

```
Probe result (context_type, surviving_chars confirmed, waf)
        ↓
[Tier 1] payloads_for_context(context_type, surviving_chars)
         filtered by confirmed surviving chars, sorted by risk_score desc
         fire top candidates via executor
        ↓ hit → ConfirmedFinding(source="phase1_deterministic"), done
        ↓ miss
[Tier 1.5] Programmatic mutations of best Tier 1 seeds
           (case, encoding, space, handler rotation — up to 15 variants)
           surviving_chars used to skip mutations requiring blocked chars
           fire via executor
        ↓ hit → ConfirmedFinding(source="phase1_deterministic"), done
        ↓ miss
[Tier 2] Local triage (structured labels only)
         input: context_type, surviving_chars set, waf, delivery_mode
         output: score (1-10), should_escalate (bool), reason (one sentence)
        ↓ should_escalate=False → stop, no cloud spend
        ↓ should_escalate=True
[Tier 3] Cloud mutation prompt
         input: context_type, surviving_chars, blocked_chars, waf,
                top 5 failed Tier 1 payloads with blocked_on per payload
         instruction: mutate aggressively, avoid blocked chars
         output: 8 payloads
         fire via executor
        ↓ hit → ConfirmedFinding(source="cloud_model"), done
        ↓ miss → no finding for this param
```

---

## Section 3: Triage Simplification (Deep Mode)

### Current input (removed fields)

`param_name`, `context_type`, `surviving_chars`, **`reflection_snippet` (dropped)**,
`waf`, `delivery_mode`

### New input — structured labels only

```json
{
  "context_type": "html_attr_url",
  "surviving_chars": ["\"", " ", "javascript:"],
  "waf": "cloudflare",
  "delivery_mode": "get"
}
```

`reflection_snippet` is removed entirely. The probe already classifies context
into structured labels — the local model should not re-parse raw HTML.
`param_name` is also removed from the prompt input; it added no value to scoring.

The existing `triage_probe_result()` in `models.py` has its signature changed:
`reflection_snippet: str` and `param_name: str` are dropped as parameters.
The call site in `_triage_with_local_model` (`worker.py:213–238`) is updated
to stop collecting `snippet` and `param_name` before calling `triage_probe_result`.

The existing prompt's scoring guide table is also removed — with structured label
input, the local model does not need a rubric to interpret raw HTML; the simpler
instruction is sufficient and performs better on small models.

### New triage prompt instruction

> "You are a triage gate for an XSS scanner. Given a reflection context, score
> its XSS potential 1-10 and decide if cloud API spend is justified.
> Reply only with valid JSON: score, should_escalate, reason."

### `LocalTriageResult` — unchanged

```python
@dataclass
class LocalTriageResult:
    score: int           # 1-10
    should_escalate: bool
    reason: str          # one sentence
    context_notes: str   # hints forwarded to cloud (kept for future use)
```

---

## Section 4: Cloud Prompt Designs

### Normal Mode — Seed Mutation Scout

The cloud does not generate payloads from scratch. It receives the top seeds
from Tier 1 (the payloads that came closest based on partial reflection) and
mutates them with encoding techniques that programmatic transforms can't produce.

**Input:**
```json
{
  "context_type": "html_attr_url",
  "waf": "cloudflare",
  "frameworks": ["angular"],
  "seeds": [
    "javascript:alert(1)",
    "jaVasCript:alert(1)",
    "&#106;avascript:alert(1)"
  ],
  "note": "no probe data — assume angle brackets blocked, seeds had partial reflection"
}
```

**Instruction:**
> "These seed payloads had partial reflection but did not execute. Mutate them
> with creative encoding: multi-layer entity encoding, mixed encoding schemes,
> whitespace/null-byte injection, unicode normalization tricks, scheme fragmentation.
> Assume angle brackets are filtered. Generate 3 novel mutations.
> Return only valid JSON array of payload strings."

**Output:** 3 payloads. Structurally derived from seeds — not cold generation.

`generate_normal_scout` signature:
`def generate_normal_scout(context_type: str, waf: str | None, frameworks: list[str], seeds: list[str]) -> list[str]`

---

### Deep Mode — Constraint-Aware Mutation

**Input:**
```json
{
  "context_type": "html_attr_url",
  "surviving_chars": ["javascript:", "\"", " "],
  "blocked_chars": ["<", ">"],
  "waf": "cloudflare",
  "failed_payloads": [
    {"payload": "<a href=\"javascript:alert(1)\">x</a>", "blocked_on": "<"},
    {"payload": "jaVasCript:alert(1)", "blocked_on": null},
    {"payload": "&#106;avascript:alert(1)", "blocked_on": null},
    {"payload": "java\tscript:alert(1)", "blocked_on": null},
    {"payload": "javascript\x0a:alert(1)", "blocked_on": null}
  ]
}
```

**Instruction:**
> "These payloads failed against this filter. Surviving chars are confirmed.
> Mutate aggressively — generate 8 novel variants that avoid blocked chars
> while preserving execution. Return only valid JSON array."

**`blocked_on` assembly:** `blocked_on` is inferred statically in `worker.py`
by intersecting each Tier 1 payload's character set with the known blocked chars
(complement of `surviving_chars` from the probe). The first blocked required
character is used as the `blocked_on` value. `null` means no blocked character
was identified in the payload — the failure was not char-based (e.g. WAF pattern
match or sanitizer stripping the whole construct).

**Failure ranking:** Top 5 from Tier 1 ranked by fewest blocked chars
(payloads that came closest to clearing the filter rank highest). Payloads with
`blocked_on=null` rank below those with an identified blocker since the failure
reason is less actionable for mutation.

**Output:** 8 payloads, fired in confidence order.

---

## Section 5: Debug Flags

### `axss scan --skip-triage` (deep mode only)

- Bypasses the local model triage gate
- After Tier 1 miss → goes directly to Tier 3 cloud mutation
- Use case: local model unavailable, slow, or producing unreliable decisions
- No-op in fast and normal mode

### `axss models --test-triage`

- Fires a synthetic example through the simplified triage prompt
- Prints: exact JSON sent to local model, raw response, parsed `LocalTriageResult`
- Synthetic input: `context_type=html_attr_url`, `surviving_chars=["\"", " ", "javascript:"]`, `waf=null`
- Lets user validate local model capability before running a real deep scan
- Exit code 1 if local model returns malformed JSON or score outside 1-10

---

## Section 6: `ConfirmedFinding.source` Values

| Value | Meaning |
|-------|---------|
| `"phase1_transform"` | Existing transform-based hit (unchanged) |
| `"phase1_waf_fallback"` | Existing WAF fallback hit (unchanged) |
| `"phase1_deterministic"` | New — context-specific generator hit (Tier 1) |
| `"local_model"` | Local model generation hit (existing, deep mode) |
| `"cloud_model"` | Cloud generation hit (existing label, now used by both normal scout and deep mutation) |
| `"dom_xss_runtime"` | DOM taint analysis hit (unchanged) |

`reporter.py` source-label display mapping must be updated to include
`"phase1_deterministic"` alongside the existing entries.

---

## Section 7: Files Changed

| File | Change |
|------|--------|
| `ai_xss_generator/active/generator.py` | Add `payloads_for_context(context_type, surviving_chars)` dispatch function; add `mutate_seeds(seeds, surviving_chars)` for Tier 1.5 programmatic mutations |
| `ai_xss_generator/active/worker.py` | Wire Tier 1 + Tier 1.5 for normal + deep; HTTP reflection pre-check for seed ranking (normal mode); drop `snippet`/`param_name` from `_triage_with_local_model`; add `skip_triage` path; assemble `blocked_on` for failure set |
| `ai_xss_generator/models.py` | Add `generate_normal_scout(context_type: str, waf: str \| None, frameworks: list[str]) -> list[str]`; restructure deep cloud prompt to mutation framing; drop `reflection_snippet` and `param_name` from `triage_probe_result()` signature |
| `ai_xss_generator/active/orchestrator.py` | Add `skip_triage: bool = False` to `ActiveScanConfig`; pass through to worker kwargs; remove `generate_fast_batch` from `mode == "normal"` path (retain for `mode == "fast"` only) |
| `ai_xss_generator/active/reporter.py` | Add `"phase1_deterministic"` to source-label display mapping |
| `ai_xss_generator/cli.py` | Add `--skip-triage` to `axss scan`; add `--test-triage` to `axss models` |

---

## Section 8: Future Considerations (Out of Scope)

- **Per-mode model configuration:** Allow users to set different models for
  normal scout vs deep mutation in the config. Normal mode benefits from a
  cheap/fast model (Haiku, GPT-4o-mini); deep mutation benefits from a
  frontier model. To be added as a config feature after core pipeline is stable.

- **Normal mode triage gate:** Not added now due to scale (3,000-5,000 URLs
  would serialize on local model latency). Revisit if normal mode scan times
  become a concern at smaller URL set sizes.

- **Active recon mode (`--interesting --fetch`):** Enhance `--interesting` from
  static URL string analysis to a lightweight active recon pass. For each URL:
  fetch the page (HTTP, no Playwright), run `parser.py` for sink/param detection,
  optionally fire a canary string per param to confirm reflection, then feed real
  page context to the AI scorer instead of raw URL strings. This would produce
  dramatically more accurate interesting scores and serve a dual purpose: automated
  pre-filtering for normal/deep mode AND a recon report for manual researchers
  providing full contextual understanding of the application (frameworks, sinks,
  reflected params, form surfaces). Designed as a standalone spec.
