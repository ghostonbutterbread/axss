# Payload Pipeline Restructure: Deterministic-First + Mode-Aware AI Generation

**Date:** 2026-03-19
**Status:** Approved
**Scope:** `active/worker.py`, `models.py`, `active/generator.py`, `cli.py`

---

## Summary

Restructure the deep and normal mode payload pipelines to use a deterministic
context-specific first pass before any AI generation, simplify the local triage
gate input, and reframe the deep mode cloud prompt from open-ended generation to
constraint-aware mutation. Normal mode gains lightweight cloud-based encoding-biased
generation for params the deterministic pass misses. Two debug flags are added to
help users validate and bypass the local triage gate.

---

## Mode Philosophy

| Mode | Target Use Case | AI Role |
|------|----------------|---------|
| **Fast** | Large URL lists, reflected XSS sweep | Unchanged — pre-generated payload set, HTTP pre-filter |
| **Normal** | URL lists, broad coverage (reflected + stored + DOM light) | Encoding-biased cloud scout (1 call per missed param) |
| **Deep** | 1-2 specific high-value pages, exhaustive investigation | Probe → local triage → cloud mutation with failure evidence |

**Fast mode is unchanged by this spec.**

---

## Section 1: Payload Tier Architecture

### Tier 1 — Deterministic (Normal + Deep)

`generator.py` context-specific generators run first, before any AI call.

- Entry point: new `payloads_for_context(context_type, surviving_chars)` dispatch
  function added to `generator.py`
- Routes to the correct context generator:
  `html_body_payloads`, `html_attr_url_payloads`, `html_attr_value_payloads`,
  `js_string_payloads`, `js_code_payloads`, `html_attr_event_payloads`
- All output filtered by `surviving_chars` (deep mode has probe data; normal mode
  uses parser-detected context without confirmed surviving chars — full set fires)
- Payloads ranked by confidence tier, highest first
- If any payload confirms execution → `ConfirmedFinding(source="phase1_deterministic")`, pipeline stops

**Normal mode:** Tier 1 only proceeds to cloud if deterministic misses.
**Deep mode:** Tier 1 only proceeds to local triage if deterministic misses.

### Tier 2 — Local Triage Gate (Deep only)

Runs only when Tier 1 missed. Decides whether cloud API spend is justified.

See Section 3 for simplified input format.

### Tier 3 — Cloud Generation (Normal + Deep, different prompts)

See Section 4 for prompt designs per mode.

---

## Section 2: Full Pipeline Per Mode

### Normal Mode Pipeline (per injectable param)

```
Parser-detected context_type
        ↓
[Tier 1] payloads_for_context(context_type, surviving_chars=None)
         fire via executor
        ↓ hit → ConfirmedFinding(source="phase1_deterministic"), done
        ↓ miss
[Tier 3] Lightweight cloud scout call
         input: context_type, waf, frameworks
         instruction: encoding-biased, assume angle brackets blocked
         output: 3 payloads
         fire via executor
        ↓ hit → ConfirmedFinding(source="cloud_model"), done
        ↓ miss → no finding for this param
```

### Deep Mode Pipeline (per injectable param)

```
Probe result (context_type, surviving_chars confirmed, waf)
        ↓
[Tier 1] payloads_for_context(context_type, surviving_chars)
         filtered by confirmed surviving chars
         fire top candidates via executor
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

### Normal Mode — Encoding-Biased Scout

**Input:**
```json
{
  "context_type": "html_attr_url",
  "waf": "cloudflare",
  "frameworks": ["angular"],
  "note": "no probe data — assume angle brackets blocked"
}
```

**Instruction:**
> "Generate 3 XSS payloads for this context. Assume angle brackets are filtered.
> Prioritize encoding-heavy variants: HTML entities, URL encoding, unicode escapes,
> hex encoding, whitespace injection, mixed case. Avoid raw `<` or `>`.
> Return only valid JSON array of payload strings."

**Output:** 3 payloads. No strategy object required. Fast and cheap.

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

**Failure ranking:** Top 5 from Tier 1 ranked by fewest blocked chars
(payloads that came closest to clearing the filter rank highest).

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
| `"phase1_deterministic"` | New — context-specific generator hit (Tier 1) |
| `"local_model"` | Local model generation hit (existing, deep mode) |
| `"cloud_model"` | Cloud generation hit (existing label, now used by both normal scout and deep mutation) |
| `"dom_xss_runtime"` | DOM taint analysis hit (unchanged) |

---

## Section 7: Files Changed

| File | Change |
|------|--------|
| `ai_xss_generator/active/generator.py` | Add `payloads_for_context()` dispatch function |
| `ai_xss_generator/active/worker.py` | Wire Tier 1 for normal + deep; simplify triage input; add `--skip-triage` path |
| `ai_xss_generator/models.py` | Add `generate_normal_scout()`; restructure deep cloud prompt to mutation framing; simplify `triage_probe_result()` input |
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
