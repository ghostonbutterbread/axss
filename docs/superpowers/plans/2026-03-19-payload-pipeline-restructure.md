# Payload Pipeline Restructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic-first + GenXSS-style mutation tier to normal and deep mode, simplify the deep mode triage gate input, and reframe all cloud prompts from cold generation to seed mutation.

**Architecture:** Six tasks in dependency order — generator dispatch and mutation functions first (no dependencies), then worker wiring (depends on generator), then models changes (independent of worker), then orchestrator (depends on models), then CLI flags, then reporter label. Each task is independently testable and committable.

**Tech Stack:** Python 3.11+, pytest, `ai_xss_generator/active/generator.py`, `active/worker.py`, `models.py`, `active/orchestrator.py`, `active/reporter.py`, `cli.py`

---

## File Map

| File | What changes |
|------|-------------|
| `ai_xss_generator/active/generator.py` | Add `payloads_for_context()` dispatch + `mutate_seeds()` |
| `ai_xss_generator/active/worker.py` | Wire Tier 1 + Tier 1.5 for normal/deep; HTTP reflection pre-rank; simplified triage input; `skip_triage` path; `blocked_on` assembly |
| `ai_xss_generator/models.py` | Add `generate_normal_scout()`; restructure deep cloud prompt; drop `reflection_snippet`/`param_name` from `triage_probe_result()` |
| `ai_xss_generator/active/orchestrator.py` | Add `skip_triage: bool = False` to `ActiveScanConfig`; pass to worker kwargs; remove `generate_fast_batch` from normal mode path |
| `ai_xss_generator/active/reporter.py` | Add `"phase1_deterministic"` to source-label display mapping |
| `ai_xss_generator/cli.py` | Add `--skip-triage` to `axss scan`; add `--test-triage` to `axss models` |
| `tests/test_payload_pipeline.py` | New test file — all new behaviour in Tasks 1-5 |
| `tests/test_scan_modes.py` | Extend with `skip_triage` config tests |
| `tests/test_cli_help.py` | Extend with new flag presence tests |

---

## Task 1: `payloads_for_context()` and `mutate_seeds()` in `generator.py`

**Files:**
- Modify: `ai_xss_generator/active/generator.py` (append to end of file)
- Create: `tests/test_payload_pipeline.py`

These two functions are the foundation everything else builds on. No dependencies on other tasks.

**`payloads_for_context(context_type, surviving_chars)`** — routes to the right existing context generator. The tricky part: the existing generators each have slightly different signatures (some take `param_name`, `attr_name`, `quote_char`, `context_before`). When called from the pipeline without probe data (normal mode), use sensible defaults.

**`mutate_seeds(seeds, surviving_chars)`** — takes a list of payload strings (not `PayloadCandidate` objects — just strings), applies 5 systematic transforms, returns a deduplicated `list[str]`. Up to 15 variants total. When `surviving_chars` is not `None`, skip mutations that require chars not in the set (e.g. skip `<img>` variant if `<` not in surviving_chars).

- [ ] **Step 1.1: Write failing tests for `payloads_for_context`**

```python
# tests/test_payload_pipeline.py
from __future__ import annotations
import pytest
from ai_xss_generator.active.generator import payloads_for_context, mutate_seeds


class TestPayloadsForContext:
    def test_html_body_returns_candidates(self):
        results = payloads_for_context("html_body", None)
        assert len(results) > 0
        assert all(hasattr(c, "payload") for c in results)

    def test_html_attr_url_returns_candidates(self):
        results = payloads_for_context("html_attr_url", None)
        assert len(results) > 0

    def test_html_attr_value_returns_candidates(self):
        results = payloads_for_context("html_attr_value", None)
        assert len(results) > 0

    def test_js_string_dq_returns_candidates(self):
        results = payloads_for_context("js_string_dq", None)
        assert len(results) > 0

    def test_js_string_sq_returns_candidates(self):
        results = payloads_for_context("js_string_sq", None)
        assert len(results) > 0

    def test_js_code_returns_candidates(self):
        results = payloads_for_context("js_code", None)
        assert len(results) > 0

    def test_html_attr_event_returns_candidates(self):
        results = payloads_for_context("html_attr_event", None)
        assert len(results) > 0

    def test_unknown_context_returns_empty(self):
        results = payloads_for_context("unknown_context_type", None)
        assert results == []

    def test_none_surviving_chars_bypasses_filter(self):
        # With None, even payloads requiring < should be returned
        results = payloads_for_context("html_body", None)
        payloads = [c.payload for c in results]
        assert any("<" in p for p in payloads)

    def test_empty_surviving_chars_filters_tag_payloads(self):
        # frozenset with no < should exclude html_body tag-injection payloads
        results = payloads_for_context("html_body", frozenset())
        payloads = [c.payload for c in results]
        assert not any("<" in p for p in payloads)

    def test_sorted_by_risk_score_descending(self):
        results = payloads_for_context("html_attr_url", None)
        scores = [c.risk_score for c in results]
        assert scores == sorted(scores, reverse=True)
```

- [ ] **Step 1.2: Run tests to verify they fail**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/test_payload_pipeline.py::TestPayloadsForContext -v 2>&1 | head -30
```

Expected: `ImportError: cannot import name 'payloads_for_context'`

- [ ] **Step 1.3: Implement `payloads_for_context`**

Add to the **end** of `ai_xss_generator/active/generator.py`:

```python
# ---------------------------------------------------------------------------
# Pipeline dispatch — unified entry point for Tier 1
# ---------------------------------------------------------------------------

def payloads_for_context(
    context_type: str,
    surviving_chars: "frozenset[str] | None",
    *,
    param_name: str = "_p",
    attr_name: str = "href",
    quote_char: str = '"',
    context_before: str = "",
) -> "list[PayloadCandidate]":
    """Return context-specific PayloadCandidate list for Tier 1 of the pipeline.

    Routes to the correct existing generator based on *context_type*.

    *surviving_chars* is ``None`` in normal mode (no probe — bypass filtering,
    return full candidate list). Deep mode passes a ``frozenset`` from the probe.

    Unknown context types return an empty list (no error).
    """
    # Normalise: strip trailing subcontext detail (e.g. "html_body:div" → "html_body")
    base = (context_type or "").strip().lower().split(":")[0]

    # When surviving_chars is None, pass an all-permissive frozenset to existing
    # generators so their internal char-filtering is bypassed.
    chars: frozenset[str]
    if surviving_chars is None:
        # Include all chars the generators check for
        chars = frozenset("<>\"'`/=;:(){}[]\\-+*&^%$#@!?., \t\n")
    else:
        chars = surviving_chars

    if base in ("html_body", "html_comment"):
        return html_body_payloads(chars, param_name)
    if base == "html_attr_url":
        return html_attr_url_payloads(chars, param_name, attr_name)
    if base == "html_attr_value":
        return html_attr_value_payloads(chars, param_name, attr_name)
    if base in ("js_string_dq", "js_string_sq", "js_string_bt", "js_string"):
        qc = '"' if "dq" in base else ("'" if "sq" in base else "`")
        return js_string_payloads(chars, param_name, qc, context_before, base)
    if base == "js_code":
        return js_code_payloads(chars, param_name)
    if base in ("html_attr_event", "html_attr_event_value"):
        return html_attr_event_payloads(chars, param_name, attr_name)
    return []
```

- [ ] **Step 1.4: Run `payloads_for_context` tests**

```bash
pytest tests/test_payload_pipeline.py::TestPayloadsForContext -v
```

Expected: all PASS

- [ ] **Step 1.5: Write failing tests for `mutate_seeds`**

```python
class TestMutateSeeds:
    def test_returns_list_of_strings(self):
        results = mutate_seeds(["javascript:alert(1)"], None)
        assert isinstance(results, list)
        assert all(isinstance(s, str) for s in results)

    def test_empty_seeds_returns_empty(self):
        assert mutate_seeds([], None) == []

    def test_produces_case_variants(self):
        results = mutate_seeds(["<img src=x onerror=alert(1)>"], None)
        # At least one result should differ in case from the original
        assert any(r != "<img src=x onerror=alert(1)>" for r in results)

    def test_produces_encoding_variants(self):
        results = mutate_seeds(["javascript:alert(1)"], None)
        # Should include at least one entity-encoded or hex variant
        has_encoded = any("&#" in r or "\\x" in r or "\\u" in r or "%"  in r for r in results)
        assert has_encoded

    def test_deduplicates_output(self):
        results = mutate_seeds(["alert(1)", "alert(1)"], None)
        assert len(results) == len(set(results))

    def test_surviving_chars_filters_mutations(self):
        # No < in surviving_chars — mutations requiring < should be excluded
        seeds = ["<img src=x onerror=alert(1)>"]
        results = mutate_seeds(seeds, frozenset("abcdefghijklmnopqrstuvwxyz()1\"' "))
        assert not any("<" in r for r in results)

    def test_max_fifteen_variants(self):
        results = mutate_seeds(["javascript:alert(1)"], None)
        assert len(results) <= 15

    def test_original_seed_not_in_output(self):
        # mutate_seeds returns mutations only, not the original seed itself
        seed = "javascript:alert(1)"
        results = mutate_seeds([seed], None)
        assert seed not in results
```

- [ ] **Step 1.6: Run to verify they fail**

```bash
pytest tests/test_payload_pipeline.py::TestMutateSeeds -v 2>&1 | head -20
```

Expected: `ImportError: cannot import name 'mutate_seeds'`

- [ ] **Step 1.7: Implement `mutate_seeds`**

Add after `payloads_for_context` in `generator.py`:

```python
def mutate_seeds(
    seeds: "list[str]",
    surviving_chars: "frozenset[str] | None",
) -> "list[str]":
    """Apply GenXSS-style systematic transforms to *seeds* and return deduplicated mutations.

    Returns up to 15 mutation strings. The original seed strings are NOT included
    in the output — only transformed variants. When *surviving_chars* is not None,
    mutations that introduce a character not in the set are skipped.

    Transforms applied (in order):
    1. random_upper() — case randomisation on the full payload string
    2. Space replacement — substitute space with /  %09  %0a  %0d  /**/
    3. Encoding variants on JS expression tokens — HTML entity, URL, hex, unicode
    4. Event handler rotation — swap onerror/ontoggle/onpointerenter/onfocus
    5. Quote style variants — swap " for ' or none where applicable
    """
    import html as _html
    from urllib.parse import quote as _url_quote

    def _allowed(s: str) -> bool:
        if surviving_chars is None:
            return True
        return all(ch in surviving_chars for ch in s if not ch.isascii() or ch in surviving_chars)

    def _chars_ok(s: str) -> bool:
        if surviving_chars is None:
            return True
        return all(c in surviving_chars for c in s)

    seen: set[str] = set(seeds)
    results: list[str] = []

    def _add(s: str) -> None:
        if s and s not in seen and len(results) < 15:
            if surviving_chars is None or _chars_ok(s):
                seen.add(s)
                results.append(s)

    for seed in seeds:
        if not seed:
            continue

        # Transform 1: case randomisation (3 variants per seed)
        for _ in range(3):
            _add(random_upper(seed))

        # Transform 2: space replacement
        for sub in ("/", "%09", "%0a", "%0d", "/**/"):
            _add(seed.replace(" ", sub))

        # Transform 3: encoding variants on 'alert' token
        for target, encoded in (
            ("alert", "&#97;&#108;&#101;&#114;&#116;"),
            ("alert", "%61%6c%65%72%74"),
            ("alert", "\\x61lert"),
            ("alert", "\\u0061lert"),
        ):
            if target in seed:
                _add(seed.replace(target, encoded, 1))

        # Transform 4: event handler rotation
        for old, new in (
            ("onerror", "ontoggle"),
            ("onerror", "onpointerenter"),
            ("ontoggle", "onerror"),
            ("ontoggle", "onpointerenter"),
            ("onmouseover", "onpointerenter"),
            ("onmouseover", "onfocus"),
        ):
            if old in seed.lower():
                import re as _re
                _add(_re.sub(_re.escape(old), new, seed, flags=_re.IGNORECASE))

        # Transform 5: quote style swap
        if '"' in seed:
            _add(seed.replace('"', "'"))
        elif "'" in seed:
            _add(seed.replace("'", '"'))

        if len(results) >= 15:
            break

    return results
```

- [ ] **Step 1.8: Run all Task 1 tests**

```bash
pytest tests/test_payload_pipeline.py -v
```

Expected: all PASS

- [ ] **Step 1.9: Commit**

```bash
git add ai_xss_generator/active/generator.py tests/test_payload_pipeline.py
git commit -m "feat: add payloads_for_context() and mutate_seeds() to generator.py"
```

---

## Task 2: `generate_normal_scout()` and updated `triage_probe_result()` in `models.py`

**Files:**
- Modify: `ai_xss_generator/models.py`
- Modify: `tests/test_payload_pipeline.py` (add new test class)

Two independent changes in `models.py`:
1. **New function** `generate_normal_scout()` — lightweight cloud call returning 3 seed mutation payloads
2. **Signature simplification** on `triage_probe_result()` — drop `reflection_snippet` and `param_name`

These can be done in one commit since they're in the same file and have no ordering dependency.

- [ ] **Step 2.1: Write failing tests**

```python
# Append to tests/test_payload_pipeline.py

class TestGenerateNormalScout:
    def test_signature_accepts_seeds(self):
        """generate_normal_scout must accept a seeds parameter."""
        import inspect
        from ai_xss_generator.models import generate_normal_scout
        sig = inspect.signature(generate_normal_scout)
        assert "seeds" in sig.parameters

    def test_signature(self):
        import inspect
        from ai_xss_generator.models import generate_normal_scout
        sig = inspect.signature(generate_normal_scout)
        params = list(sig.parameters.keys())
        assert "context_type" in params
        assert "waf" in params
        assert "frameworks" in params
        assert "seeds" in params

    def test_returns_list(self):
        """generate_normal_scout returns list[str] even when model unavailable."""
        from ai_xss_generator.models import generate_normal_scout
        # Should return empty list gracefully when no model configured, not raise
        result = generate_normal_scout(
            context_type="html_attr_url",
            waf=None,
            frameworks=[],
            seeds=["javascript:alert(1)"],
            model="__nonexistent_model__",
        )
        assert isinstance(result, list)


class TestTriageProbeResultSignature:
    def test_no_reflection_snippet_param(self):
        """triage_probe_result must NOT accept reflection_snippet."""
        import inspect
        from ai_xss_generator.models import triage_probe_result
        sig = inspect.signature(triage_probe_result)
        assert "reflection_snippet" not in sig.parameters

    def test_no_param_name_param(self):
        """triage_probe_result must NOT accept param_name."""
        import inspect
        from ai_xss_generator.models import triage_probe_result
        sig = inspect.signature(triage_probe_result)
        assert "param_name" not in sig.parameters

    def test_required_params_present(self):
        import inspect
        from ai_xss_generator.models import triage_probe_result
        sig = inspect.signature(triage_probe_result)
        assert "context_type" in sig.parameters
        assert "surviving_chars" in sig.parameters
        assert "waf" in sig.parameters
        assert "delivery_mode" in sig.parameters
```

- [ ] **Step 2.2: Run to verify they fail**

```bash
pytest tests/test_payload_pipeline.py::TestGenerateNormalScout tests/test_payload_pipeline.py::TestTriageProbeResultSignature -v 2>&1 | head -30
```

Expected: `ImportError` for `generate_normal_scout`; `AssertionError` for signature tests

- [ ] **Step 2.3: Add `generate_normal_scout` to `models.py`**

Find the end of the existing generation functions in `models.py` (near the `generate_payloads` / `triage_probe_result` area) and add:

```python
def generate_normal_scout(
    context_type: str,
    waf: str | None,
    frameworks: list[str],
    seeds: list[str],
    *,
    model: str = "",
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
    timeout: int = 30,
) -> list[str]:
    """Lightweight cloud scout for normal mode — seed mutation, not cold generation.

    Sends top seeds from Tier 1 to the cloud with instruction to mutate using
    creative encoding. Returns up to 3 payload strings. Returns [] on any error
    so the caller can fall through gracefully.

    The cloud prompt instructs seed mutation (encoding-heavy, assume angle brackets
    blocked) rather than cold generation. This is the Tier 3 normal mode call.
    """
    if not seeds:
        return []

    seed_list = "\n".join(f"- {s}" for s in seeds[:3])
    frameworks_str = ", ".join(frameworks[:3]) if frameworks else "unknown"
    waf_str = waf or "none detected"

    prompt = (
        f"Context: {context_type}\n"
        f"WAF: {waf_str}\n"
        f"Frameworks: {frameworks_str}\n"
        f"Seed payloads (had partial reflection, did not execute):\n{seed_list}\n\n"
        "These seed payloads had partial reflection but did not execute. "
        "Mutate them with creative encoding: multi-layer entity encoding, mixed encoding schemes, "
        "whitespace/null-byte injection, unicode normalization tricks, scheme fragmentation. "
        "Assume angle brackets are filtered. Generate 3 novel mutations. "
        'Return ONLY a valid JSON array of payload strings, e.g. ["payload1","payload2","payload3"]'
    )

    resolved_model = model or OPENAI_FALLBACK_MODEL

    try:
        raw = _call_model_simple(
            prompt=prompt,
            model=resolved_model,
            ai_backend=ai_backend,
            cli_tool=cli_tool,
            cli_model=cli_model,
            timeout=timeout,
        )
        import json as _json
        # Strip markdown fences if present
        text = raw.strip()
        if text.startswith("```"):
            text = text.split("```")[1].lstrip("json").strip()
        parsed = _json.loads(text)
        if isinstance(parsed, list):
            return [str(p).strip() for p in parsed if str(p).strip()][:3]
    except Exception as exc:
        log.debug("generate_normal_scout error: %s", exc)
    return []
```

> **Note on `_call_model_simple`:** Check whether a simple single-prompt model call helper already exists in `models.py`. If one exists (e.g. a function that takes prompt + model + backend and returns raw string), reuse it. If not, implement it as a thin wrapper around the existing Ollama/OpenAI/OpenRouter call pattern already used in `triage_probe_result`.

- [ ] **Step 2.4: Update `triage_probe_result` signature**

Find `triage_probe_result` in `models.py`. Remove `reflection_snippet: str` and `param_name: str` parameters from the function signature and from the prompt construction inside it. The prompt JSON input should now only contain `context_type`, `surviving_chars`, `waf`, `delivery_mode` — matching the spec's simplified format.

The scoring guide table inside the existing prompt should also be removed. Replace the full prompt with:

```python
prompt_data = {
    "context_type": context_type,
    "surviving_chars": list(surviving_chars) if surviving_chars else [],
    "waf": waf or None,
    "delivery_mode": delivery_mode,
}
system = "You are a triage gate for an XSS scanner. Given a reflection context, score its XSS potential 1-10 and decide if cloud API spend is justified. Reply only with valid JSON: score, should_escalate, reason."
user = json.dumps(prompt_data)
```

- [ ] **Step 2.5: Run Task 2 tests**

```bash
pytest tests/test_payload_pipeline.py::TestGenerateNormalScout tests/test_payload_pipeline.py::TestTriageProbeResultSignature -v
```

Expected: all PASS

- [ ] **Step 2.6: Run full test suite to catch regressions**

```bash
pytest tests/ -x -q 2>&1 | tail -20
```

Any test that passes `reflection_snippet` or `param_name` to `triage_probe_result` will now fail — fix those call sites (primarily in `worker.py`, but check with `grep -n "triage_probe_result" ai_xss_generator/active/worker.py`).

- [ ] **Step 2.7: Commit**

```bash
git add ai_xss_generator/models.py tests/test_payload_pipeline.py
git commit -m "feat: add generate_normal_scout(); simplify triage_probe_result() signature"
```

---

## Task 3: Wire Tier 1 + Tier 1.5 in `worker.py`

**Files:**
- Modify: `ai_xss_generator/active/worker.py`
- Modify: `tests/test_payload_pipeline.py` (add new test classes)

This is the largest task. The worker currently goes: probe → transform batch → local model → cloud. The new flow is: probe → Tier 1 (deterministic) → HTTP reflection pre-rank → Tier 1.5 (mutations) → triage → cloud mutation.

The key function to find is the GET scan path in `run_worker` (or equivalent). Search for where transforms are fired and local model payloads are fired — that block gets restructured.

For normal mode: `_http_reflects_payload()` is imported from `executor.py` and already used in the fast mode path. Reuse it for seed pre-ranking.

For `blocked_on` assembly (deep mode Tier 3 input): after Tier 1 + 1.5 miss, compute `blocked_on` per failed payload by intersecting the payload's characters against the complement of `surviving_chars`.

- [ ] **Step 3.1: Write failing tests for `blocked_on` assembly**

```python
class TestBlockedOnAssembly:
    def test_blocked_on_identifies_blocked_char(self):
        from ai_xss_generator.active.worker import _blocked_on_char
        surviving = frozenset("abcdefghijklmnopqrstuvwxyz()1\"' ")
        payload = "<img src=x onerror=alert(1)>"
        result = _blocked_on_char(payload, surviving)
        assert result == "<"  # first char in payload not in surviving

    def test_blocked_on_null_when_all_survive(self):
        from ai_xss_generator.active.worker import _blocked_on_char
        surviving = frozenset("<>abcdefghijklmnopqrstuvwxyz()1\"' =")
        payload = "<img src=x onerror=alert(1)>"
        result = _blocked_on_char(payload, surviving)
        assert result is None

    def test_blocked_on_null_for_empty_surviving(self):
        # Empty surviving_chars means we can't determine what's blocked
        from ai_xss_generator.active.worker import _blocked_on_char
        result = _blocked_on_char("alert(1)", frozenset())
        # Can't determine — no surviving chars to diff against
        assert result is None or isinstance(result, str)
```

- [ ] **Step 3.2: Write failing test for `skip_triage` wire-through**

```python
class TestSkipTriageWorkerPath:
    def test_worker_accepts_skip_triage_kwarg(self):
        """run_worker (or equivalent) must accept skip_triage parameter."""
        import inspect
        from ai_xss_generator.active.worker import run_worker
        sig = inspect.signature(run_worker)
        assert "skip_triage" in sig.parameters
```

- [ ] **Step 3.3: Run to verify they fail**

```bash
pytest tests/test_payload_pipeline.py::TestBlockedOnAssembly tests/test_payload_pipeline.py::TestSkipTriageWorkerPath -v 2>&1 | head -20
```

- [ ] **Step 3.4: Add `_blocked_on_char` helper to `worker.py`**

Add near the top of `worker.py` (after imports, before dataclasses):

```python
def _blocked_on_char(payload: str, surviving_chars: frozenset[str]) -> str | None:
    """Return the first character in *payload* that is not in *surviving_chars*.

    Used to annotate failed Tier 1/1.5 payloads for the deep mode cloud mutation
    prompt. Returns None when all characters survive (failure was not char-based)
    or when surviving_chars is empty (can't determine).
    """
    if not surviving_chars:
        return None
    for ch in payload:
        if ch not in surviving_chars:
            return ch
    return None
```

- [ ] **Step 3.5: Wire Tier 1 into the GET scan path**

Find the section in `run_worker` (or the internal GET scan function) where transforms are built and fired. Before the existing transform/local model block, add a Tier 1 pass:

```python
# --- Tier 1: deterministic context-specific payloads ---
from ai_xss_generator.active.generator import payloads_for_context, mutate_seeds

tier1_candidates = payloads_for_context(
    context_type=probe_result.context_type or "",
    surviving_chars=probe_surviving_chars,  # frozenset or None depending on mode
)

# HTTP reflection pre-rank for normal mode (no probe data → surviving_chars is None)
if config.mode == "normal" and tier1_candidates:
    from ai_xss_generator.active.executor import _http_reflects_payload
    ranked = []
    for candidate in tier1_candidates[:10]:  # check top 10 only to limit requests
        reflects = _http_reflects_payload(
            url_with_param,
            payload=candidate.payload,
            auth_headers=config.auth_headers or {},
        )
        ranked.append((reflects is True, candidate))
    ranked.sort(key=lambda x: (x[0], x[1].risk_score), reverse=True)
    tier1_candidates = [c for _, c in ranked]

tier1_seeds = [c.payload for c in tier1_candidates[:3]]

# Fire Tier 1
for candidate in tier1_candidates:
    result = executor.fire(url, param_name, candidate.payload, all_params, "tier1_deterministic")
    if result.confirmed:
        # Record as phase1_deterministic finding and return early
        ...
```

The exact wiring point depends on the structure of `run_worker`. Search for where `executor.fire()` is called for the first time in the GET path — that's the anchor point.

- [ ] **Step 3.6: Wire Tier 1.5 after Tier 1 miss**

After the Tier 1 loop exits without a hit, add:

```python
# --- Tier 1.5: programmatic seed mutations ---
tier15_payloads = mutate_seeds(tier1_seeds, probe_surviving_chars)

for payload_str in tier15_payloads:
    result = executor.fire(url, param_name, payload_str, all_params, "tier1_deterministic")
    if result.confirmed:
        ...
```

- [ ] **Step 3.7: Update `_triage_with_local_model` call site**

Find `_triage_with_local_model` in `worker.py` (around lines 213-238 per spec). Remove the code that builds `snippet` and `param_name` before the call. The call should now pass only the structured labels:

```python
triage_result = _triage_with_local_model(
    probe_result=probe_result,
    model=config.local_model,
    waf=waf_hint,
    delivery_mode=delivery_mode,
)
```

And inside `_triage_with_local_model`, remove the `snippet`/`param_name` collection block — the function now only extracts `context_type`, `surviving_chars`, `waf`, `delivery_mode` from `probe_result` before calling `triage_probe_result`.

- [ ] **Step 3.8: Wire `skip_triage` into the deep mode path**

Add `skip_triage: bool = False` to the `run_worker` signature (and wherever worker kwargs are built). In the deep mode path, after Tier 1 + 1.5 miss:

```python
if config.mode == "deep":
    if not skip_triage:
        triage = _triage_with_local_model(...)
        if not triage.should_escalate:
            continue  # skip this param
    # proceed to Tier 3 cloud mutation
```

- [ ] **Step 3.9: Build `blocked_on` failure set for deep Tier 3**

After Tier 1 + 1.5 have all fired and missed, assemble the failure set:

```python
all_failed = [
    {"payload": p, "blocked_on": _blocked_on_char(p, probe_surviving_chars)}
    for p in (tier1_seeds + tier15_payloads)
]
# Sort: payloads with a known blocker first, then by blocked_on specificity
all_failed.sort(key=lambda x: (x["blocked_on"] is None, x["payload"]))
top5_failed = all_failed[:5]
```

- [ ] **Step 3.10: Run Task 3 tests + full suite**

```bash
pytest tests/test_payload_pipeline.py -v && pytest tests/ -x -q 2>&1 | tail -20
```

- [ ] **Step 3.11: Commit**

```bash
git add ai_xss_generator/active/worker.py tests/test_payload_pipeline.py
git commit -m "feat: wire Tier 1 + Tier 1.5 into worker.py; add skip_triage path; blocked_on assembly"
```

---

## Task 4: `ActiveScanConfig.skip_triage` + remove `generate_fast_batch` from normal mode

**Files:**
- Modify: `ai_xss_generator/active/orchestrator.py`
- Modify: `tests/test_scan_modes.py`

Two changes in orchestrator:
1. Add `skip_triage: bool = False` to `ActiveScanConfig` and pass through to worker kwargs
2. Remove `generate_fast_batch` from the `mode in ("fast", "normal")` branch — keep it for fast only

- [ ] **Step 4.1: Write failing tests**

```python
# Append to tests/test_scan_modes.py

class TestSkipTriageConfig:
    def test_skip_triage_default_false(self):
        from ai_xss_generator.active.orchestrator import ActiveScanConfig
        cfg = ActiveScanConfig()
        assert cfg.skip_triage is False

    def test_skip_triage_settable(self):
        from ai_xss_generator.active.orchestrator import ActiveScanConfig
        cfg = ActiveScanConfig(skip_triage=True)
        assert cfg.skip_triage is True


class TestFastBatchNormalModeRemoval:
    def test_normal_mode_does_not_call_generate_fast_batch(self):
        """generate_fast_batch must only be called for fast mode, not normal."""
        import ast, inspect
        from ai_xss_generator.active import orchestrator
        src = inspect.getsource(orchestrator)
        tree = ast.parse(src)
        # Find the if-branch containing generate_fast_batch
        # It should check mode == "fast" only, not mode in ("fast", "normal")
        assert 'mode in ("fast", "normal")' not in src or \
               src.count('generate_fast_batch') == 0 or \
               'mode == "fast"' in src, \
               "generate_fast_batch should only run in fast mode"
```

- [ ] **Step 4.2: Run to verify they fail**

```bash
pytest tests/test_scan_modes.py::TestSkipTriageConfig tests/test_scan_modes.py::TestFastBatchNormalModeRemoval -v 2>&1 | head -20
```

- [ ] **Step 4.3: Add `skip_triage` to `ActiveScanConfig`**

Find the `ActiveScanConfig` dataclass in `orchestrator.py` and add:

```python
skip_triage: bool = False
```

Then find where worker kwargs are assembled and passed to `run_worker` — add `skip_triage=config.skip_triage` there.

- [ ] **Step 4.4: Remove `generate_fast_batch` from normal mode path**

Find in `orchestrator.py`:
```python
if config.mode in ("fast", "normal") and url_list:
```

Change to:
```python
if config.mode == "fast" and url_list:
```

The `fast_batch` variable referenced downstream from this block may also need adjustment — any code that passes `fast_batch` to normal mode workers should be removed or guarded with `if config.mode == "fast"`.

- [ ] **Step 4.5: Run Task 4 tests + full suite**

```bash
pytest tests/test_scan_modes.py -v && pytest tests/ -x -q 2>&1 | tail -20
```

- [ ] **Step 4.6: Commit**

```bash
git add ai_xss_generator/active/orchestrator.py tests/test_scan_modes.py
git commit -m "feat: add skip_triage to ActiveScanConfig; remove generate_fast_batch from normal mode"
```

---

## Task 5: `reporter.py` source label + `tests/test_payload_pipeline.py` label test

**Files:**
- Modify: `ai_xss_generator/active/reporter.py`
- Modify: `tests/test_payload_pipeline.py`

Small task. Find the source-label display mapping in `reporter.py` and add `"phase1_deterministic"`.

- [ ] **Step 5.1: Find the label mapping**

```bash
grep -n "phase1_transform\|source.*label\|source_label\|display.*source" /home/ryushe/tools/axss/ai_xss_generator/active/reporter.py | head -20
```

- [ ] **Step 5.2: Write failing test**

```python
class TestPhase1DeterministicLabel:
    def test_phase1_deterministic_has_display_label(self):
        """reporter must have a display label for phase1_deterministic findings."""
        import inspect
        from ai_xss_generator.active import reporter
        src = inspect.getsource(reporter)
        assert "phase1_deterministic" in src
```

- [ ] **Step 5.3: Run to verify it fails**

```bash
pytest tests/test_payload_pipeline.py::TestPhase1DeterministicLabel -v 2>&1 | head -10
```

- [ ] **Step 5.4: Add the label**

In `reporter.py`, find the dict/mapping where `"phase1_transform"` is defined (e.g. `_SOURCE_LABELS` or equivalent) and add:

```python
"phase1_deterministic": "Deterministic (context-matched)",
```

- [ ] **Step 5.5: Run test**

```bash
pytest tests/test_payload_pipeline.py::TestPhase1DeterministicLabel -v
```

- [ ] **Step 5.6: Commit**

```bash
git add ai_xss_generator/active/reporter.py tests/test_payload_pipeline.py
git commit -m "feat: add phase1_deterministic source label to reporter"
```

---

## Task 6: CLI flags — `--skip-triage` and `--test-triage`

**Files:**
- Modify: `ai_xss_generator/cli.py`
- Modify: `tests/test_cli_help.py`

Two additions:
1. `axss scan --skip-triage` — boolean flag, sets `ActiveScanConfig.skip_triage=True`, no-op outside deep mode
2. `axss models --test-triage` — subcommand action, fires synthetic triage example, prints result

- [ ] **Step 6.1: Write failing tests**

```python
# Append to tests/test_cli_help.py

class TestNewFlags:
    def test_skip_triage_in_scan_help(self):
        import subprocess, sys
        result = subprocess.run(
            [sys.executable, "axss.py", "scan", "--help"],
            capture_output=True, text=True,
            cwd="/home/ryushe/tools/axss"
        )
        assert "--skip-triage" in result.stdout

    def test_test_triage_in_models_help(self):
        import subprocess, sys
        result = subprocess.run(
            [sys.executable, "axss.py", "models", "--help"],
            capture_output=True, text=True,
            cwd="/home/ryushe/tools/axss"
        )
        assert "--test-triage" in result.stdout
```

- [ ] **Step 6.2: Run to verify they fail**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/test_cli_help.py::TestNewFlags -v 2>&1 | head -20
```

- [ ] **Step 6.3: Add `--skip-triage` to `axss scan`**

Find the `axss scan` argument parser block in `cli.py`. Add:

```python
scan_parser.add_argument(
    "--skip-triage",
    action="store_true",
    default=False,
    help=(
        "Deep mode only: bypass the local model triage gate and escalate directly "
        "to cloud mutation after Tier 1 + Tier 1.5 miss. "
        "Use when the local model is unavailable or producing unreliable decisions."
    ),
)
```

Then find where `ActiveScanConfig` is constructed from `args` and add:

```python
skip_triage=getattr(args, "skip_triage", False),
```

- [ ] **Step 6.4: Add `--test-triage` to `axss models`**

Find the `axss models` argument parser block. Add:

```python
models_parser.add_argument(
    "--test-triage",
    action="store_true",
    default=False,
    help=(
        "Fire a synthetic example through the local model triage prompt and "
        "print the raw response and parsed result. "
        "Use to verify your local model handles the triage input correctly."
    ),
)
```

Then in the `axss models` handler, add the `--test-triage` execution path:

```python
if getattr(args, "test_triage", False):
    from ai_xss_generator.models import triage_probe_result
    import json as _json

    synthetic_input = {
        "context_type": "html_attr_url",
        "surviving_chars": ['"', " ", "javascript:"],
        "waf": None,
        "delivery_mode": "get",
    }
    print("=== Triage Test ===")
    print("Input sent to local model:")
    print(_json.dumps(synthetic_input, indent=2))
    print()
    try:
        result = triage_probe_result(
            context_type=synthetic_input["context_type"],
            surviving_chars=frozenset(synthetic_input["surviving_chars"]),
            waf=synthetic_input["waf"],
            delivery_mode=synthetic_input["delivery_mode"],
            model=ai_config.local_model,
        )
        print("Parsed result:")
        print(_json.dumps(result, indent=2))
        score = result.get("score", 0)
        if not isinstance(score, int) or not (1 <= score <= 10):
            print("WARNING: score is outside valid range 1-10")
            raise SystemExit(1)
        print("\nLocal model triage: OK")
    except Exception as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1)
    return
```

- [ ] **Step 6.5: Run CLI tests**

```bash
pytest tests/test_cli_help.py -v && pytest tests/ -x -q 2>&1 | tail -20
```

- [ ] **Step 6.6: Smoke test the flags manually**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate
python3 axss.py scan --help | grep -E "skip-triage"
python3 axss.py models --help | grep -E "test-triage"
```

Expected: both flags appear in their respective help outputs.

- [ ] **Step 6.7: Commit**

```bash
git add ai_xss_generator/cli.py tests/test_cli_help.py
git commit -m "feat: add --skip-triage to axss scan; add --test-triage to axss models"
```

---

## Final Verification

- [ ] **Run full test suite**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/ -v 2>&1 | tail -40
```

Expected: all existing tests pass + new tests pass. Zero regressions.

- [ ] **Verify fast mode unchanged**

```bash
python3 axss.py scan --fast --help | grep -v "skip-triage"
# skip-triage should be visible but documented as deep-only no-op
```

- [ ] **Final commit if any cleanup needed**

```bash
git add -p  # stage only intentional changes
git commit -m "chore: post-integration cleanup for payload pipeline restructure"
```
