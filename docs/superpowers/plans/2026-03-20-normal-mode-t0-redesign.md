# Normal Mode T0 Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace normal mode's synthetic `fast_omni` probe with a lightweight T0 context detection step (one HTTP request per param) so the T1→T1.5→T3-scout pipeline runs with real injection context instead of blind AI.

**Architecture:** Add `probe_param_context()` to `probe.py` — fetches the target URL with a canary injected, calls the existing `_classify_context_at()` to detect where the canary lands, and returns a real `ProbeResult` with `context_type`. Normal mode in `worker.py` calls this per param instead of `make_fast_probe_result()`. The T1/T1.5/T3-scout code block already exists and is gated on `context_type != "fast_omni"` — wiring T0 unlocks it automatically. `_v_steps` verbose output and non-empty context envelopes in cloud prompts are automatic side effects.

**Tech Stack:** `scrapling.fetchers.FetcherSession` (existing HTTP fetch layer), `probe._classify_context_at()` (existing context classifier), `probe._clone_reflection_context()` (existing helper), `pytest`, `unittest.mock.patch`

---

## Background: What Is Broken and Why

Normal mode calls `make_fast_probe_result()` for every param (same as fast mode). This creates a synthetic `ProbeResult` with `context_type="fast_omni"`. The T1 deterministic pipeline in `worker.py:1302` is gated on `context_type != "fast_omni"`, so it is entirely skipped. Three cascading effects:

1. `_v_steps` is never populated → no `-v`/`-vv` verbose summary from GET workers
2. The cloud call hits `_get_fast_omni_payloads()` (blind, application-agnostic) instead of `generate_normal_scout()` (context-aware seed mutation)
3. The context envelope in cloud prompts is `{}` — AI generates blind

**After this plan:** normal mode fires one scrapling HTTP request per param to detect context, then runs the full T1→T1.5→T3-scout chain with real context data. Fast mode is unchanged.

**Intentional behavior change:** The current code also checks `get_probe()` for normal mode — if a prior deep scan cached real probe data for a URL, normal mode would reuse it for free. Task 3 deliberately removes this cache lookup from the normal mode branch. Rationale: T0 is cheap (one curl_cffi request), cached deep probe data may be stale, and the architectural clarity of "normal mode always runs T0" is worth the cost. The deep mode branch retains its own cache write after probing.

---

## Out of Scope

- Shallow crawl for `--urls` batch mode (follow-on work)
- `--interesting` crawl/ai subcommand (captured in spec stub update — Task 4)
- Surviving-char detection in normal mode (that stays deep-only)
- **POST worker T0 integration** (`worker.py` `_run_post` function has the identical `if mode in ("fast", "normal"):` pattern at ~line 4000) — deferred, same fix applies but tracked separately

## Known Gap: WAF JS-Challenge Evasion for T0

`probe_param_context()` uses scrapling with `impersonate="chrome"`, which handles TLS-fingerprint WAFs. It does **not** handle JS-rendered challenges (Akamai Bot Manager, Cloudflare JS challenge, PerimeterX). When a JS challenge is returned, the canary will not appear in the response and T0 silently returns `None` — the param is skipped entirely.

**Planned follow-up:** Add a tiered fallback to `probe_param_context()`:
1. Scrapling first (current implementation)
2. On `_CHALLENGE_BODY_MARKERS` hit → retry via a shared Playwright browser context passed in from the worker (one browser launch per scan session, reused across T0 calls)

Lightpanda (`github.com/lightpanda-io/browser`) is a candidate long-term replacement for the Playwright fallback (lighter, faster) but is not yet mature enough for reliable WAF fingerprint bypass. Revisit when it has stable Python bindings and proven Akamai/Cloudflare evasion.

---

## File Map

| File | Change |
|------|--------|
| `ai_xss_generator/probe.py` | **Add** `probe_param_context()` + module-level constant `_NORMAL_T0_ASSUMED_SURVIVING` |
| `ai_xss_generator/active/worker.py` | **Modify** `if mode in ("fast", "normal"):` block — split into separate fast vs normal branches |
| `tests/test_normal_mode_t0.py` | **Create** — unit tests for `probe_param_context()` |
| `tests/test_active_worker_order.py` | **Modify** — add T0 guard (monkeypatch POOL_PATH) + add normal-mode T1 pipeline test |
| `~/.axss/seed_pool.jsonl` | **Data fix** — scrub test artifacts (not a code file) |
| `docs/superpowers/specs/future-active-recon-interesting.md` | **Update** spec with new `--interesting [crawl] [ai]` design |

---

## Task 1: Scrub Seed Pool Contamination

Test mock payloads (`ai-html`, `cloud-pass-2`, `cloud-pass-1`) were written to
`~/.axss/seed_pool.jsonl` during test runs on 2026-03-16 and 2026-03-18.
These appear in cloud prompt seed sections for Normal and Deep mode.

**Files:**
- Data fix: `~/.axss/seed_pool.jsonl`
- Modify: `tests/test_active_worker_order.py`

- [ ] **Step 1: Scrub test artifacts from the live seed pool**

```bash
python3 -c "
import json, pathlib
path = pathlib.Path.home() / '.axss' / 'seed_pool.jsonl'
TEST_ARTIFACTS = {'ai-html', 'cloud-pass-1', 'cloud-pass-2'}
lines = path.read_text().splitlines()
clean = [l for l in lines if l.strip() and json.loads(l).get('payload') not in TEST_ARTIFACTS]
path.write_text('\n'.join(clean) + '\n')
print(f'Removed {len(lines) - len(clean)} test artifact(s). {len(clean)} entries remain.')
"
```

Expected output: `Removed N test artifact(s). M entries remain.`

- [ ] **Step 2: Add SeedPool path guard to worker order tests**

In `tests/test_active_worker_order.py`, add a session-scoped autouse fixture that redirects `SeedPool.POOL_PATH` to a temp file so test runs never write to the real pool:

```python
# near the top of the file, after existing imports
import tempfile
import pytest

@pytest.fixture(autouse=True)
def _isolate_seed_pool(tmp_path, monkeypatch):
    """Redirect SeedPool writes to a temp file so tests never touch ~/.axss/seed_pool.jsonl."""
    import ai_xss_generator.seed_pool as _sp
    fake_path = tmp_path / "seed_pool.jsonl"
    fake_path.touch()
    monkeypatch.setattr(_sp, "POOL_PATH", fake_path)
```

- [ ] **Step 3: Run existing worker order tests to confirm nothing broke**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate
pytest tests/test_active_worker_order.py -v --tb=short 2>&1 | tail -20
```

Expected: all tests pass (same as before).

- [ ] **Step 4: Commit**

```bash
git add tests/test_active_worker_order.py
git commit -m "test: isolate SeedPool writes from live pool in worker order tests"
```

---

## Task 2: Implement `probe_param_context()` in `probe.py`

This is the T0 function: one scrapling HTTP GET with a canary injected into the
target param, `_classify_context_at()` to detect where the canary lands, and
`_clone_reflection_context()` to attach an optimistic `surviving_chars` set so
`is_injectable` returns `True` (normal mode doesn't filter on surviving chars —
only deep mode does).

**Files:**
- Modify: `ai_xss_generator/probe.py`
- Create: `tests/test_normal_mode_t0.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_normal_mode_t0.py`:

```python
"""Tests for probe_param_context() — the T0 lightweight context detector."""
from __future__ import annotations
from unittest.mock import MagicMock, patch
import pytest

from ai_xss_generator.probe import probe_param_context


def _mock_session(html: str):
    """Return a context-manager mock whose .get() returns a response with html."""
    resp = MagicMock()
    resp.text = html
    session = MagicMock()
    session.__enter__ = MagicMock(return_value=session)
    session.__exit__ = MagicMock(return_value=False)
    session.get = MagicMock(return_value=resp)
    return session


def _patch_session(html: str):
    session = _mock_session(html)
    return patch("scrapling.fetchers.FetcherSession", return_value=session)


def test_html_body_reflection():
    """Canary in plain HTML content → html_body context, is_injectable=True."""
    with _patch_session("<html><body><p>Hello CANARY</p></body></html>") as mock:
        # Intercept the canary value by capturing what get() is called with
        canary_holder: list[str] = []
        original_get = mock.return_value.__enter__.return_value.get

        def capture_get(url, **kwargs):
            import urllib.parse as _up
            params = dict(_up.parse_qsl(_up.urlparse(url).query))
            canary_holder.append(params.get("q", ""))
            resp = MagicMock()
            resp.text = f"<html><body><p>Hello {params.get('q', '')}</p></body></html>"
            return resp

        mock.return_value.__enter__.return_value.get = capture_get

        result = probe_param_context("http://example.test/search?q=test", "q", "test")

    assert result is not None
    assert result.param_name == "q"
    assert result.probe_mode == "normal_t0"
    assert len(result.reflections) == 1
    assert result.reflections[0].context_type == "html_body"
    assert result.is_injectable  # html_body + assumed surviving chars includes <


def test_js_string_reflection():
    """Canary inside a double-quoted JS string → js_string_dq context."""
    def capture_get(url, **kwargs):
        import urllib.parse as _up
        params = dict(_up.parse_qsl(_up.urlparse(url).query))
        canary = params.get("q", "")
        resp = MagicMock()
        resp.text = f'<script>var x = "{canary}";</script>'
        return resp

    session = _mock_session("")
    session.__enter__.return_value.get = capture_get

    with patch("scrapling.fetchers.FetcherSession", return_value=session):
        result = probe_param_context("http://example.test/search?q=test", "q", "test")

    assert result is not None
    assert result.reflections[0].context_type == "js_string_dq"
    assert result.is_injectable


def test_no_reflection_returns_none():
    """Canary not found in response → returns None."""
    with _patch_session("<html><body><p>Nothing here</p></body></html>"):
        result = probe_param_context("http://example.test/search?q=test", "q", "test")
    assert result is None


def test_network_error_returns_none():
    """scrapling exception → returns None gracefully."""
    session = MagicMock()
    session.__enter__ = MagicMock(return_value=session)
    session.__exit__ = MagicMock(return_value=False)
    session.get = MagicMock(side_effect=Exception("connection refused"))

    with patch("scrapling.fetchers.FetcherSession", return_value=session):
        result = probe_param_context("http://example.test/search?q=test", "q", "test")
    assert result is None


def test_inert_context_returns_none():
    """Canary inside <textarea> (inert context) → returns None."""
    def capture_get(url, **kwargs):
        import urllib.parse as _up
        params = dict(_up.parse_qsl(_up.urlparse(url).query))
        canary = params.get("q", "")
        resp = MagicMock()
        resp.text = f"<html><body><textarea>{canary}</textarea></body></html>"
        return resp

    session = _mock_session("")
    session.__enter__.return_value.get = capture_get

    with patch("scrapling.fetchers.FetcherSession", return_value=session):
        result = probe_param_context("http://example.test/search?q=test", "q", "test")
    assert result is None


def test_assumed_surviving_chars_set():
    """T0 result carries the optimistic surviving_chars so is_injectable works
    for all exploitable context types regardless of actual char filtering."""
    def capture_get(url, **kwargs):
        import urllib.parse as _up
        params = dict(_up.parse_qsl(_up.urlparse(url).query))
        canary = params.get("q", "")
        resp = MagicMock()
        resp.text = f"<html><body><p>{canary}</p></body></html>"
        return resp

    session = _mock_session("")
    session.__enter__.return_value.get = capture_get

    with patch("scrapling.fetchers.FetcherSession", return_value=session):
        result = probe_param_context("http://example.test/search?q=test", "q", "test")

    assert result is not None
    assert "<" in result.reflections[0].surviving_chars
    assert ">" in result.reflections[0].surviving_chars
    assert '"' in result.reflections[0].surviving_chars
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate
pytest tests/test_normal_mode_t0.py -v 2>&1 | tail -15
```

Expected: `ImportError` or `AttributeError` — `probe_param_context` does not exist yet.

- [ ] **Step 3: Implement `probe_param_context()` in `probe.py`**

Add after the `make_fast_probe_result` function (around line 1918):

```python
# Optimistic surviving-chars set for T0 (normal mode): we don't test char
# survival — normal mode T1 bypasses char filtering anyway (_t1_surviving=None).
# We need *some* chars here so is_exploitable returns True for html_body etc.
_NORMAL_T0_ASSUMED_SURVIVING: frozenset[str] = frozenset('<>"\'`=;/()')


def probe_param_context(
    url: str,
    param_name: str,
    param_value: str,
    auth_headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> "ProbeResult | None":
    """Lightweight T0 context detection for normal mode.

    Fires one scrapling HTTP GET with a short canary injected into *param_name*
    and classifies where the canary lands in the response HTML using the existing
    _classify_context_at() logic.  Returns a ProbeResult with a real context_type
    and optimistic surviving_chars, or None if the param is not reflected or the
    request fails.

    Costs: one HTTP request, no Playwright.
    Does NOT test surviving chars — that is deep mode's job.
    """
    import secrets
    import urllib.parse as _up

    canary = "axsst0" + secrets.token_hex(4)

    parsed = _up.urlparse(url)
    params = dict(_up.parse_qsl(parsed.query))
    params[param_name] = canary
    probe_url_str = _up.urlunparse(parsed._replace(query=_up.urlencode(params)))

    try:
        from scrapling.fetchers import FetcherSession
        with FetcherSession(
            impersonate="chrome",
            stealthy_headers=True,
            timeout=timeout,
            follow_redirects=True,
            retries=0,
        ) as session:
            resp = session.get(
                probe_url_str,
                headers={**(auth_headers or {}), "User-Agent": "Mozilla/5.0"},
            )
            html: str = getattr(resp, "text", None) or ""
    except Exception:
        return None

    idx = html.find(canary)
    if idx == -1:
        return None

    ctx = _classify_context_at(html, idx, canary)
    if ctx is None:
        # Inert context (textarea, style, title) — not exploitable
        return None

    # Attach optimistic surviving_chars so is_injectable returns True.
    # Normal mode T1 ignores these chars for filtering anyway.
    ctx_with_chars = _clone_reflection_context(
        ctx, surviving_chars=_NORMAL_T0_ASSUMED_SURVIVING
    )

    return ProbeResult(
        param_name=param_name,
        original_value=param_value,
        reflections=[ctx_with_chars],
        probe_mode="normal_t0",
    )
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_normal_mode_t0.py -v 2>&1 | tail -15
```

Expected: all 6 tests PASS.

- [ ] **Step 5: Run full suite to check for regressions**

```bash
pytest --ignore=tests/test_probe_browser.py -x -q 2>&1 | tail -20
```

Expected: same pass count as before (242 tests).

- [ ] **Step 6: Commit**

```bash
git add ai_xss_generator/probe.py tests/test_normal_mode_t0.py
git commit -m "feat: add probe_param_context() — T0 lightweight context detection for normal mode"
```

---

## Task 3: Wire T0 into Normal Mode Worker

Replace the combined `if mode in ("fast", "normal"):` block with separate branches.
Normal mode calls `probe_param_context()` per param; fast mode keeps `make_fast_probe_result()`.
The T1 pipeline (`if mode in ("normal", "deep") and context_type != "fast_omni"`) is already
gated correctly — giving normal mode real context types unlocks it automatically.

**Files:**
- Modify: `ai_xss_generator/active/worker.py`
- Modify: `tests/test_active_worker_order.py`

- [ ] **Step 1: Write a failing test for normal mode T1 pipeline activation**

Add to `tests/test_active_worker_order.py`:

```python
def test_normal_mode_uses_t0_probe_not_fast_omni():
    """Normal mode should call probe_param_context per param (T0), not make_fast_probe_result.
    When T0 returns a real context_type, payloads_for_context (T1) must be called."""
    url = "https://example.test/search?q=x"
    t0_result = ProbeResult(
        param_name="q",
        original_value="x",
        reflections=[
            ReflectionContext(
                context_type="html_body",
                surviving_chars=frozenset({"<", ">", '"', "'"}),
            )
        ],
        probe_mode="normal_t0",
    )

    t1_calls: list[str] = []
    fire_calls: list[str] = []
    results: list[WorkerResult] = []

    class FakeExecutor:
        def __init__(self, auth_headers=None, mode="normal"):
            pass
        def start(self): pass
        def stop(self): pass
        def fire(self, **kwargs):
            fire_calls.append(kwargs["payload"])
            return SimpleNamespace(
                confirmed=False, method="", detail="",
                transform_name=kwargs["transform_name"],
                payload=kwargs["payload"], fired_url=kwargs["url"],
            )

    def fake_payloads_for_context(context_type, surviving, **kwargs):
        t1_calls.append(context_type)
        from ai_xss_generator.types import PayloadCandidate
        return [PayloadCandidate(
            payload="<script>alert(1)</script>",
            title="T1 basic",
            tags=["html"],
            risk_score=8,
            bypass_family="raw",
        )]

    with (
        patch("ai_xss_generator.probe.probe_param_context", return_value=t0_result),
        patch("ai_xss_generator.cache.get_probe", return_value=None),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_context(url)),
        patch("scrapling.fetchers.FetcherSession", _FakeFetcherSession),
        patch("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor),
        patch(
            "ai_xss_generator.active.transforms.all_variants_for_probe",
            return_value=[("q", "html_body", [])],
        ),
        patch("ai_xss_generator.active.generator.payloads_for_context",
              side_effect=fake_payloads_for_context),
        patch("ai_xss_generator.active.generator.mutate_seeds", return_value=[]),
        patch("ai_xss_generator.active.worker._get_local_payloads", return_value=[]),
        patch("ai_xss_generator.active.worker.generate_normal_scout", return_value=[]),
        patch("ai_xss_generator.seed_pool.SeedPool.add_survived"),
    ):
        _run(
            url=url, rate=25.0, waf_hint=None, model="", cloud_model="",
            use_cloud=False, timeout_seconds=30, result_queue=None,
            dedup_registry={}, dedup_lock=threading.Lock(),
            findings_lock=threading.Lock(), start_time=time.monotonic(),
            put_result=results.append, auth_headers=None, sink_url=None,
            ai_backend="api", cli_tool="claude", cli_model=None,
        )

    # T1 must have been called with the real context type from T0
    assert "html_body" in t1_calls, f"T1 not called with html_body; got {t1_calls}"
    # T1 candidate must have been fired
    assert "<script>alert(1)</script>" in fire_calls


def test_normal_mode_skips_param_when_t0_returns_none():
    """When T0 finds no reflection for a param, that param is skipped entirely."""
    url = "https://example.test/search?q=x"
    fire_calls: list[str] = []
    results: list[WorkerResult] = []

    class FakeExecutor:
        def __init__(self, auth_headers=None, mode="normal"):
            pass
        def start(self): pass
        def stop(self): pass
        def fire(self, **kwargs):
            fire_calls.append(kwargs["payload"])
            return SimpleNamespace(
                confirmed=False, method="", detail="",
                transform_name=kwargs["transform_name"],
                payload=kwargs["payload"], fired_url=kwargs["url"],
            )

    with (
        patch("ai_xss_generator.probe.probe_param_context", return_value=None),
        patch("ai_xss_generator.cache.get_probe", return_value=None),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_context(url)),
        patch("scrapling.fetchers.FetcherSession", _FakeFetcherSession),
        patch("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor),
    ):
        _run(
            url=url, rate=25.0, waf_hint=None, model="", cloud_model="",
            use_cloud=False, timeout_seconds=30, result_queue=None,
            dedup_registry={}, dedup_lock=threading.Lock(),
            findings_lock=threading.Lock(), start_time=time.monotonic(),
            put_result=results.append, auth_headers=None, sink_url=None,
            ai_backend="api", cli_tool="claude", cli_model=None,
        )

    assert fire_calls == [], f"No payloads should fire if T0 finds no reflection; got {fire_calls}"
```

- [ ] **Step 2: Run the new tests to confirm they fail**

```bash
pytest tests/test_active_worker_order.py::test_normal_mode_uses_t0_probe_not_fast_omni \
       tests/test_active_worker_order.py::test_normal_mode_skips_param_when_t0_returns_none \
       -v 2>&1 | tail -15
```

Expected: both FAIL (normal mode still uses `make_fast_probe_result`).

- [ ] **Step 3: Split fast vs normal probe setup in `worker.py`**

Locate the block at `worker.py:1054` that reads:
```python
if mode in ("fast", "normal"):
    from ai_xss_generator.cache import get_probe
    from ai_xss_generator.probe import make_fast_probe_result
    _cached_probe = None if fresh else get_probe(url, list(flat_params.keys()))
    if _cached_probe is not None:
        probe_results = _cached_probe
        injectable = [r for r in probe_results if r.is_injectable]
        reflected  = [r for r in probe_results if r.is_reflected]
        log.info(...)
    else:
        for _pn, _pv in flat_params.items():
            if _pn.lower() not in testable_params:
                continue
            probe_results.append(make_fast_probe_result(_pn, _pv))
        injectable = list(probe_results)
        reflected = list(probe_results)
```

Replace with:

```python
if mode == "fast":
    from ai_xss_generator.cache import get_probe
    from ai_xss_generator.probe import make_fast_probe_result
    _cached_probe = None if fresh else get_probe(url, list(flat_params.keys()))
    if _cached_probe is not None:
        probe_results = _cached_probe
        injectable = [r for r in probe_results if r.is_injectable]
        reflected  = [r for r in probe_results if r.is_reflected]
        log.info(
            "Probe cache hit for %s — using real context, skipping network probe", url
        )
    else:
        for _pn, _pv in flat_params.items():
            if _pn.lower() not in testable_params:
                continue
            probe_results.append(make_fast_probe_result(_pn, _pv))
        injectable = list(probe_results)
        reflected = list(probe_results)

elif mode == "normal":
    # T0: one HTTP request per param to detect injection context.
    # Gives real context_type so T1 deterministic payloads can dispatch correctly.
    # Does not test surviving chars — T1 in normal mode ignores char filtering anyway.
    from ai_xss_generator.probe import probe_param_context
    for _pn, _pv in flat_params.items():
        if _pn.lower() not in testable_params:
            continue
        t0_result = probe_param_context(
            url, _pn, _pv, auth_headers=auth_headers
        )
        if t0_result is not None:
            probe_results.append(t0_result)
    injectable = [r for r in probe_results if r.is_injectable]
    reflected  = [r for r in probe_results if r.is_reflected]
```

- [ ] **Step 4: Run new tests — should pass**

```bash
pytest tests/test_active_worker_order.py::test_normal_mode_uses_t0_probe_not_fast_omni \
       tests/test_active_worker_order.py::test_normal_mode_skips_param_when_t0_returns_none \
       -v 2>&1 | tail -15
```

Expected: both PASS.

- [ ] **Step 5: Fix existing tests broken by the normal mode branch split**

The following tests in `tests/test_active_worker_order.py` inject probe results for normal mode via `patch("ai_xss_generator.cache.get_probe", return_value=[probe_result])`. After Task 3, the `get_probe` lookup no longer runs for normal mode, so that patch stops working and `probe_param_context` gets called for real. Each of these tests needs `patch("ai_xss_generator.probe.probe_param_context", return_value=<their ProbeResult>)` added to its `with (...)` context manager block. The `probe_result` variable already defined at the top of each test is the correct value to use.

Affected tests (by function name):

- `test_get_worker_runs_local_model_per_context_before_any_fallback` — has `patch("ai_xss_generator.cache.get_probe", return_value=[probe_result])`, add: `patch("ai_xss_generator.probe.probe_param_context", return_value=probe_result)`
- `test_get_worker_retries_cloud_with_feedback_before_fallback` — patches `probe_url` only; add: `patch("ai_xss_generator.probe.probe_param_context", return_value=probe_result)` and remove or keep the `probe_url` patch (probe_url is not called in normal mode)
- `test_get_worker_keep_searching_collects_multiple_distinct_local_variants` — same pattern; add the `probe_param_context` patch
- `test_get_worker_uses_deterministic_fallback_only_after_local_and_cloud_fail` — same pattern
- `test_get_worker_forwards_payload_candidate_strategy_to_executor` — same pattern

For every test where the `ProbeResult` has multiple reflections (e.g. `html_body` + `js_string_dq`), `probe_param_context` can only return one `ProbeResult` per call (one param). If the test expects two context types to be processed, the test fixture likely passes one probe result covering multiple reflections — use `side_effect=[probe_result]` (list) rather than `return_value=probe_result` so the mock is called once per param.

After patching all five tests:

```bash
pytest --ignore=tests/test_probe_browser.py -x -q 2>&1 | tail -20
```

Expected: same pass count as before Task 3 (plus the two new tests added in Step 1).

- [ ] **Step 6: Commit**

```bash
git add ai_xss_generator/active/worker.py tests/test_active_worker_order.py
git commit -m "feat: wire T0 context detection into normal mode — replaces synthetic fast_omni probes"
```

---

## Task 4: Integration Verification

Run a real scan on a known-easy lab to confirm the tier chain fires end-to-end
and verbose output appears.

**Files:** none (read-only verification)

- [ ] **Step 1: Run normal mode on Basic Reflective XSS with `-vv`**

```bash
source venv/bin/activate && python3 axss.py scan \
  -u https://4ua2fzgq.xssy.uk/ -vv 2>&1 | grep -E "^\[>\]|CONFIRM|T1:|T1\.5:|triage:|scout:"
```

Expected output should include a line like:
```
[>] GET ?name [html_body] T1:miss → T1.5:miss → triage:escalate → T3-scout:CONFIRMED
```
or
```
[>] GET ?name [html_body] T1:CONFIRMED
```

If the `[>]` line appears with real tier tokens, T0 is working correctly.

- [ ] **Step 2: Confirm context envelope is populated in cloud call**

```bash
source venv/bin/activate && python3 axss.py scan \
  -u https://4ua2fzgq.xssy.uk/ -vv 2>&1 | grep -A 5 "CONTEXT ENVELOPE"
```

Expected: `CONTEXT ENVELOPE:` section should have real values (not `{}`).

- [ ] **Step 3: Run the remaining 5 labs from the original batch**

```bash
source venv/bin/activate
for url in \
  https://smnamns4.xssy.uk/ \
  https://7axgjmar.xssy.uk/ \
  https://js2i6iof.xssy.uk/ \
  https://4t64ubva.xssy.uk/ \
  https://euhyngyk.xssy.uk/; do
  echo "=== $url ==="
  python3 axss.py scan -u "$url" -vv 2>&1 | grep -E "^\[>\]|CONFIRM|no execution" | head -5
done
```

Record which labs confirm in normal mode and which need deep. Labs that miss in
normal with real tier chain output are candidates for `axss scan -u <url> --deep`.

---

## Task 5: Update `--interesting` Spec Stub

Capture the agreed interface design so it's not lost before implementation.

**Files:**
- Modify: `docs/superpowers/specs/future-active-recon-interesting.md`

- [ ] **Step 1: Append the new design to the spec**

Add the following section to `docs/superpowers/specs/future-active-recon-interesting.md`:

```markdown
---

## Revised Interface Design (2026-03-20)

### CLI Shape

`--interesting` accepts zero or more mode keywords via `nargs='*'`:

```
axss scan --urls targets.txt --interesting
axss scan --urls targets.txt --interesting ai
axss scan --urls targets.txt --interesting crawl
axss scan --urls targets.txt --interesting crawl ai
```

Modes are additive. Omitting all keywords = regex-only (current behavior, no change).

### Mode Descriptions

| Mode | Behavior |
|------|----------|
| *(bare)* | Regex scoring on input URL list — param names, path shape, known sinks |
| `ai` | Regex pass + AI triage: one batched call ranks URLs by injection likelihood; useful even without crawl |
| `crawl` | BFS crawl from seed URLs to discover the full surface; regex filters noise from crawled corpus |
| `crawl ai` | Full power: crawl + regex + AI golden target ranking |

### Output Format

Regardless of mode, `--interesting` output carries context hints:

```json
{
  "url": "https://example.com/search?q=test",
  "param": "q",
  "context_type_hint": "html_body",
  "score": 87,
  "evidence": "param reflects in <p> body content"
}
```

When `context_type_hint` is present, normal mode can skip the T0 probe for that
param and go straight to T1 — zero extra HTTP requests at scan time.

### Workflow Integration

```
--interesting crawl ai  →  scored list with context hints
                         ↓
normal mode scan        →  reads context_type_hint → skips T0 → T1 straight away
```

### Implementation Notes (future)

- `crawl` BFS should respect the existing `MAX_PAGES` cap
- `ai` pass: batch all URLs into one AI call with a structured prompt — do not call per URL
- Context hints from `--interesting` should be serialised into the `--urls` input file
  format (or a companion `.hints.json` sidecar) so normal mode can consume them
- `crawl` without `ai` is the cheapest way to find stored XSS surfaces and upload endpoints
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/future-active-recon-interesting.md
git commit -m "docs: update --interesting spec with crawl/ai subcommand design and context hint output"
```

---

## Final Check

```bash
pytest --ignore=tests/test_probe_browser.py -q 2>&1 | tail -5
```

All tests should pass. If count has increased from baseline (242), that is expected — we added new tests.
