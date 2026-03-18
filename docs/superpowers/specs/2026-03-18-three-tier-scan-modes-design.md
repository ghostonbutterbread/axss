# Three-Tier Scan Mode Design

**Date:** 2026-03-18
**Status:** Approved for implementation

---

## Overview

Replace the current `--fast` / `--deep` / `--obliterate` flag set with a clean three-tier scan mode structure. The goal is to make scan speed vs. coverage a conscious, predictable choice — and to make Normal mode fast enough for large URL lists while still catching all three XSS types.

---

## Tiers

### Normal (default — no flag)

The default mode. Designed for bulk URL lists (e.g. GAU output, subfinder results).

- **Scan types:** Reflected + Stored + DOM
- **Payload strategy:** Pre-generated batch upfront (one LLM call or static pool), no per-URL AI during scan. Same `fast_batch` generation path currently gated to `config.fast` — gate expands to `mode in ("fast", "normal")`.
- **Reflected + Stored:** Worker pool A iterates the URL list top→down. If a URL has a form, stored payloads are fired into it in the same worker pass (no separate stored stream — existing behavior preserved).
- **DOM:** Worker pool B iterates the URL list top→down concurrently with pool A. Light runtime: one browser navigation per URL, sinks hooked, canary injected into **URL params only** (not referrer, hash, window.name, localStorage, sessionStorage, cookie). Both `discover_dom_taint_paths()` and `attempt_dom_payloads()` run — this is a source-scope reduction, not a step skip.
- **Parallelism:** The orchestrator launches two concurrent worker pools for Normal mode. Each pool gets `max(1, workers // 2)` worker slots. This guarantees parallel execution regardless of the `--workers` value — it does not depend on the user specifying `--workers >= 2`.
- **Rate:** The user's `--rate` is split evenly. Pool A gets `rate / 2`, pool B gets `rate / 2`. Each pool enforces its own half-rate sub-limiter. The shared `_GlobalRateLimiter` is also set to the full rate as a ceiling, so combined throughput cannot exceed `--rate` even if sub-limiter timing drifts.
- **Rate edge case:** If `rate < 2`, skip the parallel split — run reflected (pool A) at full rate, then DOM (pool B) at full rate sequentially.
- **`findings_lock`:** Passed to `run_dom_worker` as well as `run_worker` and `run_post_worker` to prevent race conditions on findings writes during parallel execution.

### Fast (`--fast`)

Designed for speed over coverage. Reflected XSS only.

- **Scan types:** Reflected only. DOM and stored workers are not dispatched.
- **Payload strategy:** Pre-generated batch (same `fast_batch` as Normal, no per-URL AI during scan).
- **HTTP pre-filter:** Before opening any Playwright page, fire each payload into each parameter individually via `FetcherSession(impersonate="chrome")`. Check whether the payload string appears in the HTTP response body using a URL-decoded + HTML-entity-decoded comparison (e.g. `&lt;` → `<`) — raw substring match on the encoded response will miss reflections that the server HTML-encodes. If the payload does not appear (after decoding), skip Playwright for that param+payload combination entirely.
- **Per-param targeting:** Each payload is injected into one parameter at a time (not all params simultaneously). The pre-filter fires `len(params) × len(batch)` HTTP requests, then Playwright only opens pages for the subset that reflected.
- **Response body:** Full response body is read (no size cap). Streaming is handled by Scrapling's existing response handling.
- **Playwright:** Only launched when a payload reflects. Confirms actual JS execution (alert / console / network beacon) via `ActiveExecutor`. The executor's existing browser-reuse behavior is unchanged — one Chromium instance per worker process.
- **WAF handling:** curl_cffi already impersonates Chrome TLS fingerprint. If curl gets a blocking error (HTTP/2 RST, silent timeout), fall back to Playwright for that URL — same pattern as `spiders.py`. No regression for WAF-protected targets.
- **Single worker pool, full rate.**

### Deep (`--deep`)

Designed for narrow scope (1–2 URLs). Quality over speed.

- **Scan types:** Reflected + Stored + DOM (full runtime).
- **Payload strategy:** Probe first (`probe_url` / `probe_post_form`), then AI generates targeted payloads per param based on reflection/injection context.
- **DOM:** Full runtime taint analysis — all 6 sources tested (`location.href/search/hash`, `document.referrer`, `window.name`, `localStorage`, `sessionStorage`, `document.cookie`), SPA stabilization (networkidle + Angular testabilities), both `discover_dom_taint_paths()` and `attempt_dom_payloads()`.
- **Single worker pool, full rate, no split.**

---

## Internal Config Migration

`ActiveScanConfig` gains a `mode: Literal["fast", "normal", "deep"]` field. The existing `fast`, `deep`, and `obliterate` boolean fields are removed. All guards in `worker.py` and `orchestrator.py` currently gating on `if config.fast`, `if config.deep`, `if config.obliterate` are updated to use `config.mode`.

Example mapping:

| Old condition | New condition |
|---|---|
| `if fast or obliterate:` | `if config.mode in ("fast", "normal"):` |
| `if not fast and not obliterate:` | `if config.mode == "deep":` |
| `if fast_batch and not obliterate:` | `if fast_batch and config.mode != "deep":` |

`cli.py` sets `mode` based on flags:
- No flag → `mode = "normal"`
- `--fast` → `mode = "fast"`
- `--deep` → `mode = "deep"`

---

## Deprecations

### `--obliterate`

Obliterate originally combined fast probe-skip with broad-spectrum generation — behavior now covered by Normal mode.

1. Kept as a **hidden deprecated alias** — sets `mode = "normal"` internally
2. Prints a deprecation warning on use: `"--obliterate is deprecated and will be removed in a future release. Use no flag (normal mode) instead."`
3. Removed entirely in a future release

---

## Rate Splitting — Detail

```
user --rate R
  shared _GlobalRateLimiter(R)           # hard ceiling across all streams
  if R >= 2:
    pool_a_limiter = _GlobalRateLimiter(R / 2)   # reflected stream
    pool_b_limiter = _GlobalRateLimiter(R / 2)   # DOM stream
    run pool A and pool B concurrently
  else:
    run pool A at rate R, then pool B at rate R sequentially
```

`_GlobalRateLimiter` already accepts any rate — no new class needed. Each pool gets its own `_GlobalRateLimiter(R / 2)` instance. The shared global limiter at rate `R` acts as a safety ceiling in case sub-limiter timing drift causes combined throughput to exceed `--rate`.

## Normal Mode Dispatch Loop Restructure

The current `run_active_scan` in `orchestrator.py` uses a single sequential `work_iter` loop that feeds all work kinds (get, post, upload, dom) through one process pool. For Normal mode this must be split into two concurrent pools:

```python
if config.mode == "normal" and rate >= 2:
    reflected_items = [i for i in work_items if i.kind in ("get", "post", "upload")]
    dom_items       = [i for i in work_items if i.kind == "dom"]

    pool_a = _WorkerPool(max(1, workers // 2), rate=rate / 2)
    pool_b = _WorkerPool(max(1, workers // 2), rate=rate / 2)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as tex:
        fut_a = tex.submit(pool_a.run, reflected_items, findings_lock)
        fut_b = tex.submit(pool_b.run, dom_items, findings_lock)
        concurrent.futures.wait([fut_a, fut_b])

    results = pool_a.results + pool_b.results
else:
    # single pool — Deep, Fast, or Normal with rate < 2
    results = _single_pool(work_items, workers=workers, rate=rate, findings_lock=findings_lock)
```

Results from both pools are merged into the same `results` list before reporting. The `findings_lock` is passed to both pools, ensuring DOM and reflected findings writes are serialized.

## DOM `discover_dom_taint_paths()` API Change

The current signature builds its own sources list internally. For Normal mode's source-scope restriction, the function gains an explicit `sources` parameter:

```python
# dom_xss.py
def discover_dom_taint_paths(
    page,
    canary: str,
    sources: list[tuple[str, str]] | None = None,   # NEW — None = all sources (Deep behavior)
) -> list[TaintPath]: ...
```

- `sources=None` → existing behavior (all 6 sources, used by Deep mode)
- `sources=[("query_param", name) for name in url_params]` → URL query params only (used by Normal mode). **No fragment, no referrer, no window.name, no localStorage, no sessionStorage, no cookie** — strictly the URL's `?key=value` parameters.

`run_dom_worker` constructs the sources list from the URL's parsed query params and passes it in. **`light: bool` is not used** — `dom_xss.py` must not import or reference scan mode concepts.

## DOM Worker and `fast_batch`

In Normal mode the DOM worker receives `fast_batch` (existing behavior — it is already passed through in the orchestrator). The DOM worker does **not** use `fast_batch` for payload selection — `attempt_dom_payloads()` always uses `_SINK_PAYLOADS` (the static DOM-specific payload list). This is unchanged. The `fast_batch` parameter in `run_dom_worker` remains unused for now; it is not removed in this work to avoid a signature mismatch, but it should be explicitly documented as intentionally unused.

---

## What Does Not Change

- `ActiveExecutor` browser reuse — one Chromium instance per worker process, already in place
- WAF detection and fallback logic in `spiders.py`
- Probe + AI reasoning pipeline in Deep mode — unchanged
- `--rate`, `--workers`, `--timeout`, and all other flags — unchanged
- Stored XSS folded into reflected pass — existing behavior, no new worker type needed
- `discover_dom_taint_paths()` and `attempt_dom_payloads()` API in `dom_xss.py` — unchanged; Normal mode's "light runtime" is achieved purely by restricting the sources list passed in, not by skipping steps

---

## Key Files Affected

| File | Change |
|------|--------|
| `ai_xss_generator/cli.py` | Add `--fast` flag (was default, now explicit), make Normal the default, hide `--obliterate` with deprecation warning, set `config.mode` |
| `ai_xss_generator/active/orchestrator.py` | Launch two concurrent pools for Normal mode; split rate; pass `findings_lock` to `run_dom_worker`; expand `fast_batch` gate to Normal |
| `ai_xss_generator/active/executor.py` | Add HTTP pre-filter step in `fire()` for Fast mode |
| `ai_xss_generator/active/worker.py` | Replace `fast`/`deep`/`obliterate` bool guards with `config.mode` checks; Fast mode skips DOM and stored dispatch; add `findings_lock` parameter to `run_dom_worker` signature |
| `ai_xss_generator/active/dom_xss.py` | Add `sources: list[tuple[str, str]] | None = None` parameter to `discover_dom_taint_paths()`; `None` = all sources (Deep), explicit list = URL params only (Normal) |
| `ai_xss_generator/active/orchestrator.py` | Remove `fast`, `deep`, `obliterate` fields from `ActiveScanConfig`; add `mode: Literal["fast", "normal", "deep"]` (dataclass lives entirely in this file, not in `types.py`) |

---

## Success Criteria

- `axss scan --urls big-list.txt` (Normal, default) scans reflected + stored + DOM without any flags
- `axss scan --fast --urls big-list.txt` completes dramatically faster than current fast mode — no Playwright navigations for params that don't reflect in the HTTP response
- `axss scan --deep -u https://target.com/page?q=1` behaves identically to current deep mode
- `--rate 5` results in ≤5 req/s combined across all parallel streams
- `--obliterate` still works but prints a deprecation warning and behaves as Normal
- DOM findings from parallel Normal mode scans are written correctly with no data races
