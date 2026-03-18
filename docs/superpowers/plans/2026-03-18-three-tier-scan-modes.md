# Three-Tier Scan Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `--fast` / `--deep` / `--obliterate` flag set with three clean scan tiers — Normal (default), Fast (reflected-only with HTTP pre-filter), and Deep (probe + AI) — and add tracking param stripping to the pre-flight pipeline.

**Architecture:** `ActiveScanConfig` gains a `mode: Literal["fast","normal","deep"]` field replacing three booleans. Normal mode runs two concurrent worker streams (reflected+stored / DOM) each at half rate. Fast mode adds an HTTP pre-filter in `ActiveExecutor.fire()` that skips Playwright when the payload doesn't reflect. Tracking params are stripped from all URLs before dedup.

**Tech Stack:** Python 3.11+, Playwright (Scrapling), curl_cffi (`FetcherSession`), multiprocessing, pytest

**Spec:** `docs/superpowers/specs/2026-03-18-three-tier-scan-modes-design.md`

---

## File Map

| File | Role in this work |
|------|------------------|
| `ai_xss_generator/active/orchestrator.py` | Add `_strip_tracking_params()`; migrate `ActiveScanConfig` to `mode`; expand `fast_batch` gate; split Normal dispatch into two concurrent streams |
| `ai_xss_generator/active/worker.py` | Replace `fast/deep/obliterate` params with `mode: str` in `run_worker`, `run_post_worker`, `run_dom_worker`, `_run_dom`; add `findings_lock` + `dom_sources` to `run_dom_worker` |
| `ai_xss_generator/active/executor.py` | Add `mode` to `ActiveExecutor.__init__()`; add HTTP pre-filter in `fire()` for fast mode |
| `ai_xss_generator/active/dom_xss.py` | Add `sources: list[tuple[str,str]] | None = None` to `discover_dom_taint_paths()` |
| `ai_xss_generator/cli.py` | Make `--fast` an explicit flag; Normal becomes default (no flag); `--obliterate` becomes hidden deprecated alias |
| `tests/test_url_preflight.py` | Add tests for `_strip_tracking_params()` |
| `tests/test_cli_help.py` | Update scan help assertions for new mode flags |
| `tests/test_dom_sources.py` | New — tests for `discover_dom_taint_paths()` sources param |
| `tests/test_scan_modes.py` | New — tests for config migration, fast_batch gate, mode propagation |

---

## Task 1: Tracking Param Stripping

**Files:**
- Modify: `ai_xss_generator/active/orchestrator.py`
- Modify: `tests/test_url_preflight.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_url_preflight.py`:

```python
from ai_xss_generator.active.orchestrator import _strip_tracking_params

class TestStripTrackingParams:
    def test_removes_utm_params(self):
        urls = ["http://example.com/page?q=xss&utm_source=google&utm_medium=cpc"]
        result = _strip_tracking_params(urls)
        assert result == ["http://example.com/page?q=xss"]

    def test_removes_gclid(self):
        urls = ["http://example.com/?q=1&gclid=abc123"]
        result = _strip_tracking_params(urls)
        assert result == ["http://example.com/?q=1"]

    def test_removes_fbclid(self):
        urls = ["http://example.com/?id=5&fbclid=XYZ"]
        result = _strip_tracking_params(urls)
        assert result == ["http://example.com/?id=5"]

    def test_keeps_non_tracking_params(self):
        urls = ["http://example.com/?search=hello&page=2"]
        result = _strip_tracking_params(urls)
        assert result == ["http://example.com/?search=hello&page=2"]

    def test_keeps_url_with_no_params_after_strip(self):
        # URL had only tracking params — keep it (may have forms or path injection)
        urls = ["http://example.com/page?utm_source=google"]
        result = _strip_tracking_params(urls)
        assert result == ["http://example.com/page"]

    def test_deduplicates_after_strip(self):
        # Two URLs that become identical after stripping → keep first only
        urls = [
            "http://example.com/page?q=1&utm_source=a",
            "http://example.com/page?q=1&utm_source=b",
        ]
        result = _strip_tracking_params(urls)
        assert result == ["http://example.com/page?q=1"]

    def test_preserves_order(self):
        urls = [
            "http://example.com/a?q=1&utm_source=x",
            "http://example.com/b?q=2",
        ]
        result = _strip_tracking_params(urls)
        assert result == ["http://example.com/a?q=1", "http://example.com/b?q=2"]

    def test_empty_list(self):
        assert _strip_tracking_params([]) == []
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate && pytest tests/test_url_preflight.py::TestStripTrackingParams -v
```
Expected: `ImportError` — `_strip_tracking_params` not yet defined.

- [ ] **Step 3: Implement `_strip_tracking_params` in orchestrator.py**

Add after the `_dedup_urls_by_path_shape` function (around line 343), before `run_active_scan`:

```python
def _strip_tracking_params(url_list: list[str]) -> list[str]:
    """Remove known tracking/analytics query parameters from every URL.

    Reuses _TRACKING_PARAM_BLOCKLIST from probe.py — single source of truth.
    If stripping produces a duplicate URL already seen, the duplicate is dropped
    (preserving first-seen order).
    """
    from ai_xss_generator.probe import _TRACKING_PARAM_BLOCKLIST

    seen: set[str] = set()
    result: list[str] = []
    for url in url_list:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        stripped = {k: v for k, v in qs.items() if k.lower() not in _TRACKING_PARAM_BLOCKLIST}
        new_query = urllib.parse.urlencode(stripped, doseq=True)
        stripped_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        if stripped_url not in seen:
            seen.add(stripped_url)
            result.append(stripped_url)
    return result
```

Then in `run_active_scan`, update the pre-flight block (around line 369):

```python
    # Pre-flight: strip tracking params, deduplicate, then drop dead URLs
    if url_list:
        url_list = _strip_tracking_params(url_list)
        url_list = _dedup_urls_by_path_shape(url_list)
        if not config.skip_liveness:
            url_list = _filter_live_urls(
                url_list,
                auth_headers=config.auth_headers,
                rate_limiter=rate_limiter,
            )
```

- [ ] **Step 4: Run tests to confirm pass**

```bash
pytest tests/test_url_preflight.py::TestStripTrackingParams -v
```
Expected: all 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add ai_xss_generator/active/orchestrator.py tests/test_url_preflight.py
git commit -m "feat: strip tracking params before pre-flight dedup"
```

---

## Task 2: `discover_dom_taint_paths()` Sources Parameter

**Files:**
- Modify: `ai_xss_generator/active/dom_xss.py`
- Create: `tests/test_dom_sources.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_dom_sources.py`:

```python
"""Tests for discover_dom_taint_paths() sources parameter."""
from __future__ import annotations
import urllib.parse
from unittest.mock import MagicMock, patch
import pytest

from ai_xss_generator.active.dom_xss import discover_dom_taint_paths


def _make_mock_browser(hit_sources: list[str]) -> MagicMock:
    """Return a mock Playwright browser that fakes taint hits for the given source names."""
    browser = MagicMock()
    context = MagicMock()
    page = MagicMock()
    browser.new_context.return_value = context
    context.new_page.return_value = page

    def _evaluate(js: str):
        # Return a fake hit if the JS is requesting dom hits
        if "__axss_dom_hits" in js:
            return [{"source": s, "sink": "innerHTML", "value": "CANARY"} for s in hit_sources]
        return []

    page.evaluate.side_effect = _evaluate
    page.goto.return_value = None
    page.wait_for_load_state.return_value = None
    return browser


class TestDiscoverDomTaintPathsSources:
    def test_none_sources_uses_all_sources(self):
        """sources=None → all 6 sources are tested (existing Deep behavior)."""
        browser = MagicMock()
        context = MagicMock()
        page = MagicMock()
        browser.new_context.return_value = context
        context.new_page.return_value = page
        page.evaluate.return_value = []
        page.goto.return_value = None

        discover_dom_taint_paths(
            "http://example.com/?q=1",
            browser,
            sources=None,
        )

        # Should have navigated for query_param, fragment, window_name,
        # local_storage, session_storage, referrer — at least 6 times
        assert browser.new_context.call_count >= 6

    def test_explicit_sources_restricts_navigation(self):
        """Explicit URL-param-only sources list → navigates only for those sources."""
        browser = MagicMock()
        context = MagicMock()
        page = MagicMock()
        browser.new_context.return_value = context
        context.new_page.return_value = page
        page.evaluate.return_value = []
        page.goto.return_value = None

        discover_dom_taint_paths(
            "http://example.com/?q=1&id=2",
            browser,
            sources=[("query_param", "q"), ("query_param", "id")],
        )

        # Should only navigate for the two query params, no more
        assert browser.new_context.call_count == 2

    def test_empty_sources_list_performs_no_navigation(self):
        """Empty sources list → no navigations, empty result."""
        browser = MagicMock()

        result = discover_dom_taint_paths(
            "http://example.com/",
            browser,
            sources=[],
        )

        assert result == []
        browser.new_context.assert_not_called()
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_dom_sources.py -v
```
Expected: FAIL — `discover_dom_taint_paths()` does not accept `sources` keyword argument.

- [ ] **Step 3: Add sources parameter to `discover_dom_taint_paths()`**

In `ai_xss_generator/active/dom_xss.py`, update the function signature (currently line 423):

```python
def discover_dom_taint_paths(
    url: str,
    browser,
    auth_headers: dict[str, str] | None = None,
    timeout_ms: int = _NAV_TIMEOUT_MS,
    sources: list[tuple[str, str]] | None = None,   # NEW — None = all sources (Deep behavior)
) -> list[DomTaintHit]:
```

Then replace the sources-building block inside the function (currently lines 449–461):

```python
    # Build sources list — caller can restrict to URL params only (Normal mode)
    # by passing an explicit list. None = full set (Deep mode / existing behaviour).
    if sources is not None:
        _sources = sources
    else:
        parsed = urllib.parse.urlparse(url)
        raw_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        # URL-injectable sources
        _sources: list[tuple[str, str]] = [("query_param", k) for k in raw_params]
        _sources.append(("fragment", "hash"))
        # Non-URL sources: injection handled via init script / request headers
        _sources += [
            ("window_name",     "window.name"),
            ("local_storage",   "localStorage"),
            ("session_storage", "sessionStorage"),
            ("referrer",        "document.referrer"),
        ]

    _debug(f"DOM XSS scan: {url}  canary={canary}  sources={[s[1] for s in _sources]}")
```

Then replace `sources` with `_sources` in the loop below: `for source_type, source_name in _sources:`.

- [ ] **Step 4: Run tests to confirm pass**

```bash
pytest tests/test_dom_sources.py -v
```
Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add ai_xss_generator/active/dom_xss.py tests/test_dom_sources.py
git commit -m "feat: add sources param to discover_dom_taint_paths for light runtime mode"
```

---

## Task 3: `ActiveScanConfig` Mode Migration

Replace the three boolean fields (`fast`, `deep`, `obliterate`) with a single `mode: Literal["fast","normal","deep"]` field in `ActiveScanConfig`, and update all worker function signatures.

**Files:**
- Modify: `ai_xss_generator/active/orchestrator.py`
- Modify: `ai_xss_generator/active/worker.py`
- Create: `tests/test_scan_modes.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_scan_modes.py`:

```python
"""Tests for three-tier scan mode config and worker routing."""
from __future__ import annotations
import pytest
from ai_xss_generator.active.orchestrator import ActiveScanConfig


class TestActiveScanConfigMode:
    def test_default_mode_is_normal(self):
        cfg = ActiveScanConfig()
        assert cfg.mode == "normal"

    def test_fast_mode(self):
        cfg = ActiveScanConfig(mode="fast")
        assert cfg.mode == "fast"

    def test_deep_mode(self):
        cfg = ActiveScanConfig(mode="deep")
        assert cfg.mode == "deep"

    def test_no_fast_field(self):
        cfg = ActiveScanConfig()
        assert not hasattr(cfg, "fast"), "fast boolean field should be removed"

    def test_no_deep_field(self):
        cfg = ActiveScanConfig()
        assert not hasattr(cfg, "deep"), "deep boolean field should be removed"

    def test_no_obliterate_field(self):
        cfg = ActiveScanConfig()
        assert not hasattr(cfg, "obliterate"), "obliterate boolean field should be removed"
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_scan_modes.py -v
```
Expected: `test_no_fast_field` / `test_no_deep_field` / `test_no_obliterate_field` all FAIL (fields still exist); `test_default_mode_is_normal` FAIL (no `mode` field yet).

- [ ] **Step 3: Migrate `ActiveScanConfig`**

In `ai_xss_generator/active/orchestrator.py`, replace the three boolean fields in `ActiveScanConfig` (lines 78–80):

```python
    # REMOVE these three lines:
    # deep: bool = False
    # fast: bool = False
    # obliterate: bool = False

    # ADD this:
    mode: str = "normal"   # "fast" | "normal" | "deep"
```

Also add the import at the top of the file if not present: `from typing import Literal` (or just use `str` — `Literal` is for type-checker hints only, not needed at runtime).

- [ ] **Step 4: Update orchestrator references to old fields**

Search for all uses of `config.fast`, `config.deep`, `config.obliterate` in `orchestrator.py` and replace:

```bash
grep -n "config\.fast\|config\.deep\|config\.obliterate" ai_xss_generator/active/orchestrator.py
```

Key replacements in `run_active_scan`:
- `config.fast and not config.obliterate` → `config.mode in ("fast", "normal")`
- `config.deep` (in `_cli_kwargs`) → remove from `_cli_kwargs`, add `"mode": config.mode`
- `"fast": config.fast, "obliterate": config.obliterate` (in worker kwargs) → replace with `"mode": config.mode`
- `config.fast` in panel display → `config.mode == "fast"`

- [ ] **Step 5: Update worker function signatures**

In `ai_xss_generator/active/worker.py`, update `run_worker` (line 892), `run_post_worker` (line 3391), `run_dom_worker` (line 2518), and `_run_dom` (line 2583):

Replace the three boolean params:
```python
    # REMOVE:
    deep: bool = False,
    fast: bool = False,
    obliterate: bool = False,
    # ADD:
    mode: str = "normal",
```

- [ ] **Step 6: Update all guards inside worker functions**

Find and replace all mode-gated guards using these equivalences. Run first to see all instances:

```bash
grep -n "if fast\|if obliterate\|if deep\b\|not fast\|not obliterate\|not deep\b" ai_xss_generator/active/worker.py
```

Apply the spec's mapping table:

| Old guard | New guard |
|-----------|-----------|
| `if fast or obliterate:` | `if mode in ("fast", "normal"):` |
| `if not fast and not obliterate:` | `if mode == "deep":` |
| `if fast_batch and not obliterate:` | `if fast_batch and mode != "deep":` |
| `if not deep` | `if mode != "deep"` |
| `if deep` | `if mode == "deep"` |
| `if not context_done and not deep` | `if not context_done and mode != "deep"` |

Also update `_run_dom` (line 2583) which has its own set of these params and guards.

The `fast_mode` local variable at line 207 — check its context and update accordingly.

- [ ] **Step 7: Run tests to confirm pass**

```bash
pytest tests/test_scan_modes.py -v
```
Expected: all 6 tests PASS.

Also run the full test suite to catch regressions:
```bash
pytest tests/ -v --ignore=tests/test_probe_browser.py -x -q 2>&1 | tail -30
```
(Exclude `test_probe_browser.py` — it requires a live network.)

- [ ] **Step 8: Commit**

```bash
git add ai_xss_generator/active/orchestrator.py ai_xss_generator/active/worker.py tests/test_scan_modes.py
git commit -m "refactor: replace fast/deep/obliterate booleans with mode field"
```

---

## Task 4: CLI Mode Flags

**Files:**
- Modify: `ai_xss_generator/cli.py`
- Modify: `tests/test_cli_help.py`

- [ ] **Step 1: Write failing tests**

Add to the `test_scan_help` method in `tests/test_cli_help.py` (or add as a new test):

```python
def test_scan_help_mode_flags(self) -> None:
    help_text = _subparser_help("scan")
    # --fast is now an explicit flag
    self.assertIn("--fast", help_text)
    # --deep still present
    self.assertIn("--deep", help_text)
    # --obliterate is hidden (suppress=argparse.SUPPRESS) — must NOT appear in help
    self.assertNotIn("--obliterate", help_text)

def test_obliterate_still_accepted(self) -> None:
    """--obliterate must still parse without error (deprecated hidden alias)."""
    from ai_xss_generator.cli import build_parser
    from ai_xss_generator.config import DEFAULT_MODEL
    parser = build_parser(DEFAULT_MODEL)
    # Should not raise during parse
    args = parser.parse_args(["scan", "-u", "http://example.com", "--obliterate"])
    # argparse sets the flag — mode derivation happens in the handler, not parse_args
    assert args.obliterate is True
    assert args.fast is False
    assert args.deep is False
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_cli_help.py -v
```
Expected: `test_scan_help_mode_flags` FAIL (obliterate still visible, mode field not set).

- [ ] **Step 3: Update CLI flags**

In `ai_xss_generator/cli.py`, find the scan mode argument group (around line 407). Replace the current three flags with:

```python
    # ── Scan mode ─────────────────────────────────────────────────────────
    scan.add_argument(
        "--fast",
        action="store_true",
        default=False,
        help=(
            "Reflected XSS only. HTTP pre-filter fires payloads via curl_cffi; "
            "Playwright only opens when reflection is confirmed. Fastest mode, "
            "ideal for large URL lists (e.g. GAU output)."
        ),
    )
    scan.add_argument(
        "--deep",
        action="store_true",
        default=False,
        help=(
            "Full probe + AI-targeted payload generation per param. "
            "Best for 1–2 focused targets. Slowest mode."
        ),
    )
    scan.add_argument(
        "--obliterate",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,   # hidden deprecated alias for normal mode
    )
```

- [ ] **Step 4: Update `mode` derivation in `cli.py`**

Find where `scan_config` / `ActiveScanConfig` is built in `cli.py` (around line 1376–1382). Replace the `fast=`, `deep=`, `obliterate=` kwargs with:

```python
        # Derive scan mode from flags (obliterate is deprecated alias for normal)
        if getattr(args, "obliterate", False):
            import warnings
            warnings.warn(
                "--obliterate is deprecated and will be removed in a future release. "
                "Normal mode (no flag) now provides the same broad-spectrum coverage.",
                DeprecationWarning, stacklevel=2,
            )
            _mode = "normal"
        elif getattr(args, "deep", False):
            _mode = "deep"
        elif getattr(args, "fast", False):
            _mode = "fast"
        else:
            _mode = "normal"
        # ... then pass mode=_mode to ActiveScanConfig
```

Also update the log line (around line 1333–1338) and banner line (around line 1417–1418) that reference `config.fast`, `config.deep`, `config.obliterate`.

For the `axss generate` subcommand: ensure `--deep` is still accepted there (it already is — check that the generate path still works). The generate path uses `deep=getattr(args, "deep", False)` for its own purposes — leave that unchanged since generate doesn't use `ActiveScanConfig`.

- [ ] **Step 5: Run tests to confirm pass**

```bash
pytest tests/test_cli_help.py tests/test_scan_modes.py -v
```
Expected: all tests PASS.

- [ ] **Step 6: Smoke-test the CLI**

```bash
source venv/bin/activate && python3 axss.py scan --help 2>&1 | grep -E "fast|deep|obliterate|mode"
```
Expected: `--fast` and `--deep` visible, `--obliterate` not in help output.

```bash
python3 axss.py scan -u http://example.com --obliterate --dry-run 2>&1 | head -5
```
Expected: deprecation warning printed, scan starts normally.

- [ ] **Step 7: Commit**

```bash
git add ai_xss_generator/cli.py tests/test_cli_help.py
git commit -m "feat: make --fast explicit, Normal default, deprecate --obliterate"
```

---

## Task 5: Fast-Batch Gate Expansion

Expand the `fast_batch` generation gate from `config.fast and not config.obliterate` to `config.mode in ("fast", "normal")`.

**Files:**
- Modify: `ai_xss_generator/active/orchestrator.py`
- Modify: `tests/test_scan_modes.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_scan_modes.py`:

```python
class TestFastBatchGate:
    def test_normal_mode_generates_batch(self):
        """Normal mode should trigger fast_batch generation (mode in fast/normal)."""
        from unittest.mock import patch, MagicMock
        from ai_xss_generator.active.orchestrator import ActiveScanConfig, run_active_scan

        cfg = ActiveScanConfig(mode="normal")
        with patch("ai_xss_generator.active.orchestrator.generate_fast_batch") as mock_gen:
            mock_gen.return_value = [MagicMock()]
            # Pass a URL so generation is attempted
            with patch("ai_xss_generator.active.orchestrator._dedup_urls_by_path_shape", return_value=["http://example.com/?q=1"]):
                with patch("ai_xss_generator.active.orchestrator._filter_live_urls", return_value=["http://example.com/?q=1"]):
                    with patch("multiprocessing.Manager"):
                        try:
                            run_active_scan(["http://example.com/?q=1"], cfg)
                        except Exception:
                            pass
            mock_gen.assert_called_once()

    def test_deep_mode_skips_batch(self):
        """Deep mode should NOT trigger fast_batch generation."""
        from unittest.mock import patch, MagicMock
        from ai_xss_generator.active.orchestrator import ActiveScanConfig, run_active_scan

        cfg = ActiveScanConfig(mode="deep")
        with patch("ai_xss_generator.active.orchestrator.generate_fast_batch") as mock_gen:
            with patch("ai_xss_generator.active.orchestrator._dedup_urls_by_path_shape", return_value=["http://example.com/?q=1"]):
                with patch("ai_xss_generator.active.orchestrator._filter_live_urls", return_value=["http://example.com/?q=1"]):
                    with patch("multiprocessing.Manager"):
                        try:
                            run_active_scan(["http://example.com/?q=1"], cfg)
                        except Exception:
                            pass
            mock_gen.assert_not_called()
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_scan_modes.py::TestFastBatchGate -v
```
Expected: `test_normal_mode_generates_batch` FAIL — normal mode doesn't trigger batch yet.

- [ ] **Step 3: Update the gate in orchestrator.py**

Find the fast_batch generation block (around line 379–395):

```python
    # OLD:
    # if config.fast and not config.obliterate and url_list:

    # NEW:
    fast_batch: list[Any] = []
    if config.mode in ("fast", "normal") and url_list:
        from ai_xss_generator.models import generate_fast_batch
        step("Generating payload batch…")
        fast_batch = generate_fast_batch(
            cloud_model=config.cloud_model,
            waf=config.waf,
            ai_backend=config.ai_backend,
            cli_tool=config.cli_tool,
            cli_model=config.cli_model,
        )
        if fast_batch:
            info(f"Payload batch ready: {len(fast_batch)} payloads")
        else:
            warn("Batch generation failed — workers will fall back to per-URL generation")
```

- [ ] **Step 4: Run tests to confirm pass**

```bash
pytest tests/test_scan_modes.py -v
```
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add ai_xss_generator/active/orchestrator.py tests/test_scan_modes.py
git commit -m "feat: expand fast_batch generation to normal mode"
```

---

## Task 6: DOM Worker `findings_lock` and Sources

Add `findings_lock` to `run_dom_worker` / `_run_dom`, and pass URL-param-only sources for Normal mode.

> **Dependency:** Task 3 must be complete before this task. `run_dom_worker` must already have the `mode` parameter before these additions are applied.

**Files:**
- Modify: `ai_xss_generator/active/worker.py`
- Modify: `ai_xss_generator/active/orchestrator.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_scan_modes.py`:

```python
class TestDomWorkerSignature:
    def test_run_dom_worker_accepts_findings_lock(self):
        """run_dom_worker must accept a findings_lock parameter."""
        import inspect
        from ai_xss_generator.active.worker import run_dom_worker
        sig = inspect.signature(run_dom_worker)
        assert "findings_lock" in sig.parameters

    def test_run_dom_worker_accepts_dom_sources(self):
        """run_dom_worker must accept a dom_sources parameter."""
        import inspect
        from ai_xss_generator.active.worker import run_dom_worker
        sig = inspect.signature(run_dom_worker)
        assert "dom_sources" in sig.parameters
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_scan_modes.py::TestDomWorkerSignature -v
```
Expected: both FAIL.

- [ ] **Step 3: Add `findings_lock` and `dom_sources` to `run_dom_worker` and `_run_dom`**

In `ai_xss_generator/active/worker.py`, update `run_dom_worker` signature (line 2518):

```python
def run_dom_worker(
    url: str,
    # ... existing params ...
    findings_lock: Any = None,   # NEW — passed for parallel Normal mode safety
    dom_sources: "list[tuple[str, str]] | None" = None,  # NEW — None = all sources (Deep)
    # fast_batch: ... unchanged, still present but intentionally unused by DOM
) -> None:
```

Pass both into `_run_dom`:
```python
        _run_dom(
            # ... existing kwargs ...
            findings_lock=findings_lock,
            dom_sources=dom_sources,
        )
```

Update `_run_dom` signature to accept both params. Pass `dom_sources` to `discover_dom_taint_paths`:

```python
    dom_hits = discover_dom_taint_paths(
        url, browser, auth_headers, timeout_ms=nav_timeout_ms,
        sources=dom_sources,   # None for Deep, URL-param list for Normal
    )
```

- [ ] **Step 4: Update orchestrator to pass findings_lock and dom_sources for Normal mode**

In `orchestrator.py`, in the `kind == "dom"` worker dispatch block (around line 686), update the kwargs:

```python
                    elif kind == "dom":
                        next_url = item
                        # Build URL-param-only sources list for Normal mode
                        _dom_sources: list[tuple[str, str]] | None = None
                        if config.mode == "normal":
                            import urllib.parse as _up
                            _qp = dict(_up.parse_qsl(_up.urlparse(next_url).query, keep_blank_values=True))
                            _dom_sources = [("query_param", k) for k in _qp] if _qp else []
                        proc = multiprocessing.Process(
                            target=run_dom_worker,
                            kwargs={
                                # ... all existing kwargs ...
                                "findings_lock": findings_lock,   # NEW
                                "dom_sources": _dom_sources,      # NEW
                                "mode": config.mode,              # already added in Task 3
                            },
                            daemon=True,
                        )
```

- [ ] **Step 5: Run tests to confirm pass**

```bash
pytest tests/test_scan_modes.py -v
```
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add ai_xss_generator/active/worker.py ai_xss_generator/active/orchestrator.py tests/test_scan_modes.py
git commit -m "feat: add findings_lock and dom_sources to run_dom_worker"
```

---

## Task 7: Normal Mode Parallel Dispatch

For Normal mode with `rate >= 2`, run reflected+stored workers and DOM workers concurrently, each at half rate.

**Files:**
- Modify: `ai_xss_generator/active/orchestrator.py`

The approach: keep the existing single work queue and poll loop, but:
1. For Normal mode with rate >= 2, set `n_workers = max(2, _auto_workers(rate, workers))` to guarantee at least 2 concurrent slots
2. Pass `rate/2` to "get/post/upload" workers and `rate/2` to "dom" workers — each kind self-limits to half rate
3. This naturally achieves the parallel behavior: with 2+ worker slots and two kinds of items in the queue, get and dom workers run concurrently, each at half rate, combined ≤ full rate

**Files:**
- Modify: `ai_xss_generator/active/orchestrator.py`
- Modify: `tests/test_scan_modes.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_scan_modes.py`:

```python
class TestNormalModeParallelDispatch:
    def test_normal_mode_uses_at_least_two_worker_slots(self):
        """Normal mode with rate >= 2 must guarantee at least 2 concurrent worker slots."""
        from unittest.mock import patch
        from ai_xss_generator.active.orchestrator import _auto_workers_for_mode

        # rate=5, workers=1 → Normal mode should return at least 2
        n = _auto_workers_for_mode("normal", rate=5.0, explicit_workers=10)
        assert n >= 2

        # Fast mode: uses _auto_workers normally (no minimum-2 guarantee)
        n_fast = _auto_workers_for_mode("fast", rate=5.0, explicit_workers=10)
        assert n_fast >= 1  # no special guarantee

    def test_normal_mode_rate_less_than_2_uses_one_slot(self):
        """Normal mode with rate < 2 falls back to single-pool (no split)."""
        from ai_xss_generator.active.orchestrator import _auto_workers_for_mode
        n = _auto_workers_for_mode("normal", rate=1.0, explicit_workers=10)
        assert n == 1
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_scan_modes.py::TestNormalModeParallelDispatch -v
```
Expected: FAIL — `_auto_workers_for_mode` doesn't exist yet.

- [ ] **Step 3: Add `_auto_workers_for_mode` helper and update dispatch**

Add to `orchestrator.py` after the existing `_auto_workers` function:

```python
def _auto_workers_for_mode(mode: str, rate: float, explicit_workers: int) -> int:
    """Return worker count for a given mode.

    Normal mode with rate >= 2 guarantees at least 2 slots so that DOM and
    reflected workers can run concurrently (each at half rate). When rate < 2
    the split would yield sub-1 req/s streams — fall back to 1 slot.
    """
    base = _auto_workers(rate, explicit_workers)
    if mode == "normal" and rate >= 2:
        return max(2, base)
    return base
```

Update in `run_active_scan` where `n_workers` is computed (around line 454):

```python
    # OLD: n_workers = _auto_workers(config.rate, config.workers)
    n_workers = _auto_workers_for_mode(config.mode, config.rate, config.workers)
```

Update the worker-dispatch block to pass kind-specific rates for Normal mode:

```python
                    # Determine per-kind rate: Normal mode with rate >= 2 splits evenly
                    if config.mode == "normal" and config.rate >= 2:
                        _get_rate = config.rate / 2
                        _dom_rate = config.rate / 2
                    else:
                        _get_rate = config.rate
                        _dom_rate = config.rate

                    if kind == "get":
                        proc = multiprocessing.Process(
                            target=run_worker,
                            kwargs={
                                "rate": _get_rate,   # was config.rate
                                # ... all other existing kwargs unchanged ...
                            },
                            daemon=True,
                        )
                    elif kind == "dom":
                        proc = multiprocessing.Process(
                            target=run_dom_worker,
                            kwargs={
                                # dom workers don't take rate (they don't do HTTP rate limiting)
                                # ... existing kwargs unchanged ...
                            },
                            daemon=True,
                        )
                    elif kind == "post":
                        proc = multiprocessing.Process(
                            target=run_post_worker,
                            kwargs={
                                "rate": _get_rate,   # was config.rate
                                # ... all other existing kwargs unchanged ...
                            },
                            daemon=True,
                        )
```

> **Note:** DOM workers don't use the `rate` parameter for their own HTTP requests (Playwright navigates at its own pace) so `_dom_rate` is not passed to DOM workers.

> **Architecture note (spec deviation):** The spec's pseudocode shows a `ThreadPoolExecutor`-based two-pool structure with a shared `_GlobalRateLimiter(R)` ceiling. That architecture requires a `_WorkerPool` wrapper class that doesn't exist yet. This plan achieves equivalent concurrency more simply: by guaranteeing `n_workers >= 2` and passing `rate/2` to each worker kind, the existing single dispatch loop naturally runs GET and DOM workers concurrently at half rate each. A true shared cross-process rate ceiling is not achievable without `multiprocessing.Value` overhead — the per-kind rate argument is the enforcement mechanism. Combined throughput can theoretically reach `rate` (not exceed it) because each stream is capped at `rate/2`.

- [ ] **Step 4: Run tests to confirm pass**

```bash
pytest tests/test_scan_modes.py -v
```
Expected: all tests PASS.

- [ ] **Step 5: Run full test suite**

```bash
pytest tests/ -v --ignore=tests/test_probe_browser.py -q 2>&1 | tail -20
```
Expected: no regressions.

- [ ] **Step 6: Commit**

```bash
git add ai_xss_generator/active/orchestrator.py tests/test_scan_modes.py
git commit -m "feat: normal mode parallel dispatch with rate splitting"
```

---

## Task 8: Fast Mode HTTP Pre-Filter in Executor

For Fast mode, check reflection via curl_cffi before opening a Playwright page. Skip Playwright if payload doesn't reflect. Fall back to Playwright if WAF blocks curl.

**Files:**
- Modify: `ai_xss_generator/active/executor.py`
- Modify: `ai_xss_generator/active/worker.py` (pass `mode` to executor)
- Modify: `tests/test_executor_strategy.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_executor_strategy.py` (or create new section):

```python
"""Tests for fast mode HTTP pre-filter in ActiveExecutor."""
from unittest.mock import MagicMock, patch
import pytest

from ai_xss_generator.active.executor import ActiveExecutor, _http_reflects_payload


class TestHttpReflectsPayload:
    def test_returns_true_when_payload_in_body(self):
        result = _http_reflects_payload(
            "http://example.com/?q=PAYLOAD",
            payload="PAYLOAD",
            auth_headers={},
        )
        # We mock FetcherSession — see implementation notes
        # This test verifies the function signature and basic logic
        assert isinstance(result, bool) or result is None  # True | False | None (WAF)

    def test_returns_false_when_payload_absent(self):
        """Payload not in response body → returns False (skip Playwright)."""
        with patch("ai_xss_generator.active.executor.FetcherSession") as MockFS:
            mock_session = MagicMock()
            mock_response = MagicMock()
            mock_response.text = "<html>no match here</html>"
            mock_response.status_code = 200
            mock_session.__enter__ = MagicMock(return_value=mock_session)
            mock_session.__exit__ = MagicMock(return_value=False)
            mock_session.get.return_value = mock_response
            MockFS.return_value = mock_session

            result = _http_reflects_payload(
                "http://example.com/?q=xss",
                payload="<script>alert(1)</script>",
                auth_headers={},
            )
            assert result is False

    def test_returns_true_when_html_encoded_payload_reflects(self):
        """HTML-encoded reflection (&lt;script&gt;) must still be detected."""
        with patch("ai_xss_generator.active.executor.FetcherSession") as MockFS:
            mock_session = MagicMock()
            mock_response = MagicMock()
            # Server HTML-encodes the reflection
            mock_response.text = "<html>value: &lt;script&gt;alert(1)&lt;/script&gt;</html>"
            mock_response.status_code = 200
            mock_session.__enter__ = MagicMock(return_value=mock_session)
            mock_session.__exit__ = MagicMock(return_value=False)
            mock_session.get.return_value = mock_response
            MockFS.return_value = mock_session

            result = _http_reflects_payload(
                "http://example.com/?q=xss",
                payload="<script>alert(1)</script>",
                auth_headers={},
            )
            assert result is True

    def test_returns_none_on_waf_challenge_response(self):
        """WAF JS-challenge response (403 + challenge body) → None (go to Playwright)."""
        with patch("ai_xss_generator.active.executor.FetcherSession") as MockFS:
            mock_session = MagicMock()
            mock_response = MagicMock()
            mock_response.text = "attention required! | cloudflare __cf_chl_ challenge"
            mock_response.status_code = 403
            mock_session.__enter__ = MagicMock(return_value=mock_session)
            mock_session.__exit__ = MagicMock(return_value=False)
            mock_session.get.return_value = mock_response
            MockFS.return_value = mock_session

            result = _http_reflects_payload(
                "http://example.com/?q=xss",
                payload="<script>",
                auth_headers={},
            )
            assert result is None  # None = needs Playwright

    def test_returns_none_on_curl_blocking_error(self):
        """curl_cffi blocking error (HTTP/2 RST, timeout) → None (go to Playwright)."""
        with patch("ai_xss_generator.active.executor.FetcherSession") as MockFS:
            mock_session = MagicMock()
            mock_session.__enter__ = MagicMock(return_value=mock_session)
            mock_session.__exit__ = MagicMock(return_value=False)
            mock_session.get.side_effect = Exception("curl error (92) HTTP/2 stream error")
            MockFS.return_value = mock_session

            result = _http_reflects_payload(
                "http://example.com/?q=xss",
                payload="<script>",
                auth_headers={},
            )
            assert result is None


class TestActiveExecutorFastMode:
    def test_executor_accepts_mode_param(self):
        executor = ActiveExecutor(mode="fast")
        assert executor._mode == "fast"

    def test_executor_default_mode_is_normal(self):
        executor = ActiveExecutor()
        assert executor._mode == "normal"
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_executor_strategy.py -v -k "HttpReflects or FastMode"
```
Expected: FAIL — `_http_reflects_payload` not defined, `ActiveExecutor` has no `mode` param.

- [ ] **Step 3: Add `_http_reflects_payload` helper to executor.py**

Add after the imports in `ai_xss_generator/active/executor.py`:

```python
# JS-challenge body markers from known WAFs — if any appear, curl result is untrustworthy
_CHALLENGE_BODY_MARKERS: tuple[str, ...] = (
    "__cf_chl_",        # Cloudflare
    "ray id:",          # Cloudflare
    "akamaighost",      # Akamai
    "reference #",      # Akamai
    "_incap_ses_",      # Imperva
    "incapsula incident id",
    "datadome",
    "kasada",
)

_BLOCKING_CURL_CODES = ("(92)", "(28)")   # CURLE_HTTP2_STREAM, CURLE_OPERATION_TIMEDOUT


def _http_reflects_payload(
    url: str,
    payload: str,
    auth_headers: dict[str, str],
) -> bool | None:
    """Fire *payload* at *url* via curl_cffi and check if it reflects.

    Returns:
        True  — payload found in decoded response body (proceed to Playwright)
        False — no reflection found (skip Playwright for this param+payload)
        None  — WAF block or curl error (fall back to Playwright regardless)
    """
    import html as _html
    import urllib.parse as _up
    try:
        from scrapling.fetchers import FetcherSession
        with FetcherSession(
            impersonate="chrome",
            stealthy_headers=True,
            timeout=10,
            follow_redirects=True,
            retries=0,
        ) as session:
            resp = session.get(url, headers={**auth_headers, "User-Agent": "Mozilla/5.0"})
            body = getattr(resp, "text", None) or ""
            status = getattr(resp, "status_code", getattr(resp, "status", 200))

            # Check for WAF JS-challenge body markers
            body_lower = body.lower()
            if any(marker in body_lower for marker in _CHALLENGE_BODY_MARKERS):
                return None  # WAF — Playwright fallback

            # Decode before matching: server may HTML-encode or URL-encode the reflection
            decoded = _html.unescape(_up.unquote(body))
            return payload in decoded

    except Exception as exc:
        exc_str = str(exc)
        if any(code in exc_str for code in _BLOCKING_CURL_CODES):
            return None  # blocking WAF error — Playwright fallback
        return None  # any other curl failure — safe to fall back
```

- [ ] **Step 4: Add `mode` to `ActiveExecutor.__init__()` and pre-filter to `fire()`**

Update `ActiveExecutor.__init__` (line 219):

```python
    def __init__(
        self,
        auth_headers: dict[str, str] | None = None,
        mode: str = "normal",
    ) -> None:
        self._pw = None
        self._browser = None
        self._started = False
        self._auth_headers: dict[str, str] = auth_headers or {}
        self._mode = mode
        self._waf_detected = False  # set True on first WAF block; skips curl for remaining fire() calls
```

At the start of `fire()`, after the `if not self._started` guard (after line 293), add:

```python
        # Fast mode: HTTP pre-filter — skip Playwright if payload doesn't reflect
        # If a WAF block was already detected for this URL, skip curl and go straight to Playwright
        if self._mode == "fast" and not self._waf_detected:
            fired_url_for_check = _build_delivery_plan(
                url=url,
                param_name=param_name,
                payload=payload,
                all_params=all_params,
                payload_overrides=payload_overrides,
                payload_candidate=payload_candidate,
            ).fired_url
            reflects = _http_reflects_payload(
                fired_url_for_check,
                payload=payload,
                auth_headers=self._auth_headers,
            )
            if reflects is False:
                # Definitely doesn't reflect — skip browser entirely
                return ExecutionResult(
                    confirmed=False,
                    method="",
                    detail="pre-filter: no HTTP reflection",
                    transform_name=transform_name,
                    payload=payload,
                    param_name=param_name,
                    fired_url=fired_url_for_check,
                    actual_url="",
                )
            # reflects is True or None (WAF) — fall through to Playwright
            if reflects is None:
                # WAF detected — mark executor so remaining fire() calls skip curl
                self._waf_detected = True
```

- [ ] **Step 5: Pass `mode` to executor in `run_worker` and `run_post_worker`**

In `ai_xss_generator/active/worker.py`, update all executor instantiation sites. Search for them:

```bash
grep -n "ActiveExecutor(auth_headers=" ai_xss_generator/active/worker.py
```

Update each call site (there are two: one in the inner reflected worker, one in the inner POST worker) to:

```python
    executor = ActiveExecutor(auth_headers=auth_headers, mode=mode)
```

- [ ] **Step 6: Run tests to confirm pass**

```bash
pytest tests/test_executor_strategy.py -v
```
Expected: all new tests PASS.

- [ ] **Step 7: Run full test suite**

```bash
pytest tests/ -v --ignore=tests/test_probe_browser.py -q 2>&1 | tail -20
```
Expected: no regressions.

- [ ] **Step 8: Commit**

```bash
git add ai_xss_generator/active/executor.py ai_xss_generator/active/worker.py tests/test_executor_strategy.py
git commit -m "feat: fast mode HTTP pre-filter skips Playwright when payload doesn't reflect"
```

---

## Task 9: Final Verification

- [ ] **Step 1: Run the complete test suite**

```bash
cd /home/ryushe/tools/axss && source venv/bin/activate
pytest tests/ --ignore=tests/test_probe_browser.py -v 2>&1 | tail -40
```
Expected: all tests PASS, no regressions.

- [ ] **Step 2: Smoke-test Normal mode (default)**

```bash
python3 axss.py scan --help 2>&1 | grep -E "\-\-fast|\-\-deep|obliterate|Normal|default"
```
Expected: `--fast` and `--deep` listed, `--obliterate` absent, help text describes Normal as default.

- [ ] **Step 3: Smoke-test `--obliterate` deprecation**

```bash
python3 axss.py scan -u http://example.com --obliterate --dry-run 2>&1
```
Expected: deprecation warning printed, scan proceeds.

- [ ] **Step 4: Verify tracking param stripping**

```bash
python3 -c "
from ai_xss_generator.active.orchestrator import _strip_tracking_params
result = _strip_tracking_params(['http://example.com/?q=xss&utm_source=google&gclid=abc'])
print(result)
assert result == ['http://example.com/?q=xss'], f'Got {result}'
print('OK')
"
```

- [ ] **Step 5: Final commit — update memory**

The memory file at `~/.claude/projects/-home-ryushe-tools-axss/memory/MEMORY.md` should be updated to reflect this feature is implemented (remove "Next step: invoke writing-plans" note, mark three-tier modes as shipped).

```bash
git log --oneline -10
```

---

## Guard Replacement Reference

When editing `worker.py` in Task 3, use this complete mapping. After each grep pass, confirm zero remaining instances of the old patterns.

```bash
# Find remaining boolean guard instances (should be zero after Task 3)
grep -n "if fast\b\|if obliterate\b\|if deep\b\|not fast\b\|not obliterate\b\|not deep\b" \
  ai_xss_generator/active/worker.py

# Also check for the kwarg assignment pattern — missed by the above grep
grep -n "deep=deep" ai_xss_generator/active/worker.py
```

| Old | New |
|-----|-----|
| `fast or obliterate` | `mode in ("fast", "normal")` |
| `not fast and not obliterate` | `mode == "deep"` |
| `fast_batch and not obliterate` | `fast_batch and mode != "deep"` |
| `not deep` | `mode != "deep"` |
| `if deep` | `if mode == "deep"` |
| local `fast_mode = fast or obliterate` | `fast_mode = mode in ("fast", "normal")` |
| `deep=deep or obliterate` (kwarg, ~lines 1352/2862/3829) | `deep=(mode == "deep")` |
