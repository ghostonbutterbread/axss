"""Active scan orchestrator — spawns per-URL worker processes and aggregates results.

Rate limiting:
  - Global: a single token bucket at `rate` req/s is shared across ALL phases —
    pre-flight liveness checks, dedup crawl fetches, and active scan workers.
  - Global cap: total concurrent workers capped at `workers`.
  - Workers auto-scale based on rate (floor(rate / 5) workers, min 1), but
    never exceed the explicit --workers cap.

Deduplication:
  - cloud escalation calls are deduplicated by a shared Manager dict.
  - Key includes URL endpoint + param name, so different endpoints / params
    on the same domain always get their own cloud call.

Findings writes:
  - A shared Manager Lock is passed to every worker so concurrent writes
    to ~/.axss/findings/ are serialised.
"""
from __future__ import annotations

import logging
import math
import multiprocessing
import re
import signal
import threading
import time
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Sequence, TYPE_CHECKING

if TYPE_CHECKING:
    from ai_xss_generator.types import PostFormTarget, UploadTarget

from ai_xss_generator.active.worker import (
    WorkerResult,
    active_worker_timeout_budget,
    run_dom_worker,
    run_upload_worker,
    run_worker,
)
from ai_xss_generator.console import (
    fmt_duration, info, setup_panel, step, success,
    teardown_panel, update_panel, warn,
    BOLD, CYAN, DIM, GREEN, RESET,
)
from ai_xss_generator.probe import _TRACKING_PARAM_BLOCKLIST

log = logging.getLogger(__name__)

_BLIND_MANIFEST_FILENAME = "blind_tokens.json"


@dataclass
class ActiveScanConfig:
    rate: float = 5.0
    workers: int = 1
    model: str = "qwen3.5:9b"
    cloud_model: str = "anthropic/claude-3-5-sonnet"
    use_cloud: bool = True
    waf: str | None = None
    timeout_seconds: int = 300     # 5 minutes per URL
    output_path: str | None = None  # markdown report output; None = auto
    auth_headers: dict[str, str] = field(default_factory=dict)
    sink_url: str | None = None    # manual sink page for stored XSS (--sink-url)
    # XSS type selectors — control which scan types run
    scan_reflected: bool = True   # GET parameter injection (reflected XSS)
    scan_stored: bool = True      # POST form injection (stored XSS)
    scan_uploads: bool = True     # multipart upload / artifact workflows
    scan_dom: bool = True         # DOM source/sink analysis (DOM XSS)
    # AI backend for cloud escalation
    ai_backend: str = "api"       # "api" | "cli"
    cli_tool: str = "claude"      # "claude" | "codex" (when ai_backend="cli")
    cli_model: str | None = None  # model passed to CLI (None = CLI default)
    cloud_attempts: int = 1       # recursive cloud reasoning rounds per context
    mode: Literal["fast", "normal", "deep"] = "normal"
    fresh: bool = False           # ignore all caches, re-collect from scratch
    blind_callback: str | None = None  # OOB callback URL for blind XSS payloads
    waf_source: str | None = None # local path to open-source WAF/filter code for planning hints
    keep_searching: bool = False
    extreme: bool = False
    research: bool = False
    skip_liveness: bool = False   # skip pre-flight HEAD checks (default for --urls lists)
    skip_triage: bool = False     # bypass local triage model, go straight to cloud


def _auto_workers(rate: float, explicit_workers: int) -> int:
    """Scale workers with rate but never exceed the explicit cap."""
    auto = max(1, math.floor(rate / 5.0))
    return min(auto, explicit_workers)


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


def _domain(url: str) -> str:
    return urllib.parse.urlparse(url).netloc or url


def _work_item_url(kind: str, item: Any) -> str:
    return item if kind in {"get", "dom"} else item.action_url


def _work_item_key(kind: str, item: Any) -> str:
    return f"{kind}:{_work_item_url(kind, item)}"


# ---------------------------------------------------------------------------
# Pre-flight: liveness filter
# ---------------------------------------------------------------------------

_LIVENESS_TIMEOUT = 5          # seconds per HEAD/GET
_LIVENESS_SLOW_THRESHOLD = 3.0 # seconds; URLs slower than this are dropped as "too slow to scan"
_LIVENESS_WORKERS = 50         # max concurrent connections (further capped by rate)
_LIVENESS_MIN_LIST  = 2        # skip check for tiny lists
_DOMAIN_CHECK_TIMEOUT = 5      # seconds per domain root probe


class _GlobalRateLimiter:
    """Thread-safe leaky-bucket rate limiter shared across all phases.

    Calling acquire() blocks until the caller is allowed to send a request.
    rate=0 means uncapped — acquire() returns immediately.
    """

    def __init__(self, rate: float) -> None:
        self._interval = (1.0 / rate) if rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next_allowed = time.monotonic()

    def acquire(self) -> None:
        if self._interval == 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._next_allowed - now
            if wait > 0:
                self._next_allowed += self._interval
            else:
                self._next_allowed = now + self._interval
        if wait > 0:
            time.sleep(wait)

    @property
    def uncapped(self) -> bool:
        return self._interval == 0


class _SharedRateLimiter:
    """Cross-process leaky-bucket rate limiter using shared memory.

    A single instance is created in the orchestrator and passed to every worker
    process so the aggregate HTTP request rate never exceeds *rate* req/s
    regardless of how many workers run concurrently.

    Uses multiprocessing.Value + multiprocessing.Lock so the next-allowed
    timestamp is visible and updated atomically across all worker processes.
    """

    def __init__(self, rate: float) -> None:
        self._interval = (1.0 / rate) if rate > 0 else 0.0
        self._next_allowed: Any = multiprocessing.Value('d', 0.0)
        self._lock: Any = multiprocessing.Lock()

    @property
    def uncapped(self) -> bool:
        return self._interval == 0.0

    def acquire(self) -> None:
        if self._interval == 0.0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                if now >= self._next_allowed.value:
                    self._next_allowed.value = now + self._interval
                    return
                wait_time = self._next_allowed.value - now
            time.sleep(min(wait_time, 0.05))


def _filter_live_urls(
    url_list: list[str],
    auth_headers: dict[str, str] | None = None,
    rate_limiter: _GlobalRateLimiter | None = None,
) -> list[str]:
    """HEAD-check every URL concurrently; drop URLs that are dead or too slow to scan.

    "Dead" means:
      - The host is unreachable (DNS failure, connection refused, timeout)
      - The server returned 404 Not Found or 410 Gone

    "Too slow" means the HEAD/GET response took ≥ _LIVENESS_SLOW_THRESHOLD seconds.
    Slow URLs would stall per-param probe fetches (20s timeout each) and waste the
    entire worker budget without producing useful results.

    Everything else is treated as alive.  In particular:
      - 401/403 — server is up; auth or a WAF JS challenge is gating it.
        The Playwright worker can handle JS challenges; plain requests cannot.
      - 429 — rate-limited but alive
      - 5xx — server error, but the endpoint exists

    Falls back from HEAD to GET on 405.  Auth headers are forwarded so
    token-protected endpoints aren't falsely flagged as gone.
    """
    if len(url_list) < _LIVENESS_MIN_LIST:
        return url_list

    import requests
    from requests.exceptions import RequestException

    # Use a browser-like UA so WAFs don't immediately 403 the probe itself
    req_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }
    req_headers.update(auth_headers or {})

    # Only these status codes mean the URL itself is gone
    _GONE_STATUSES = {404, 410}

    limiter = rate_limiter or _GlobalRateLimiter(0)

    def _check(url: str) -> tuple[str, bool, str, float]:
        limiter.acquire()
        t0 = time.monotonic()
        try:
            r = requests.head(url, headers=req_headers,
                              timeout=_LIVENESS_TIMEOUT, allow_redirects=True)
            if r.status_code == 405:
                # Server doesn't support HEAD — try a streaming GET
                limiter.acquire()
                r = requests.get(url, headers=req_headers,
                                 timeout=_LIVENESS_TIMEOUT,
                                 allow_redirects=True, stream=True)
                r.close()
            elapsed = time.monotonic() - t0
            alive = r.status_code not in _GONE_STATUSES
            return url, alive, str(r.status_code), elapsed
        except RequestException as exc:
            return url, False, str(exc), time.monotonic() - t0

    # Cap concurrent connections to rate when rate-limited so we never
    # burst more threads than the token bucket allows per second.
    if limiter.uncapped:
        n_workers = min(_LIVENESS_WORKERS, len(url_list))
    else:
        rate_ceil = math.ceil(1.0 / limiter._interval)
        n_workers = min(rate_ceil, _LIVENESS_WORKERS, len(url_list))

    step(f"Pre-flight liveness check: probing {len(url_list)} URL(s)…")
    results: list[tuple[str, bool, str, float]] = []
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = {pool.submit(_check, u): u for u in url_list}
        for fut in as_completed(futures):
            results.append(fut.result())

    dead = [(u, reason) for u, ok, reason, _ in results if not ok]
    slow = [
        (u, elapsed)
        for u, ok, _, elapsed in results
        if ok and elapsed >= _LIVENESS_SLOW_THRESHOLD
    ]
    live_set = {u for u, ok, _, elapsed in results if ok and elapsed < _LIVENESS_SLOW_THRESHOLD}
    # Preserve original order
    live = [u for u in url_list if u in live_set]

    if dead:
        warn(f"Pre-flight: removed {len(dead)} dead URL(s)")
        for dead_url, reason in dead[:5]:
            warn(f"  dead  {dead_url}  →  {reason}")
        if len(dead) > 5:
            warn(f"  … and {len(dead) - 5} more")
    if slow:
        warn(
            f"Pre-flight: removed {len(slow)} slow URL(s) "
            f"(response time ≥ {_LIVENESS_SLOW_THRESHOLD:.0f}s — likely stalled or rate-limiting)"
        )
        for slow_url, elapsed in slow[:5]:
            warn(f"  slow  {slow_url}  →  {elapsed:.1f}s")
        if len(slow) > 5:
            warn(f"  … and {len(slow) - 5} more")
    if not dead and not slow:
        info(f"Pre-flight: all {len(live)} URL(s) alive")
    else:
        info(f"Pre-flight: {len(live)} of {len(url_list)} URL(s) will be scanned")

    return live


# ---------------------------------------------------------------------------
# Pre-flight: domain reachability filter
# ---------------------------------------------------------------------------

def _filter_dead_domains(
    url_list: list[str],
    auth_headers: dict[str, str] | None = None,
) -> list[str]:
    """Probe the root of each unique domain; drop ALL URLs for domains that are
    unreachable at the network level.

    Only network-level failures are considered dead:
      - DNS resolution failure (ERR_NAME_NOT_RESOLVED)
      - Connection refused
      - Timeout (no response within _DOMAIN_CHECK_TIMEOUT seconds)

    Any HTTP response — even 401, 403, 429, 5xx — means the domain is up.
    Those status codes indicate auth walls or WAF JS challenges that Playwright
    can handle; plain requests cannot, so we must not drop them.

    This is the right pre-check for --urls mode where per-URL liveness is
    skipped but a completely downed domain would otherwise waste every worker
    budget spawned against it.
    """
    import requests
    from requests.exceptions import RequestException

    req_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }
    req_headers.update(auth_headers or {})

    # One probe per unique (scheme, netloc)
    domains: dict[str, str] = {}  # root_url → representative domain key
    for url in url_list:
        p = urllib.parse.urlparse(url)
        key = f"{p.scheme}://{p.netloc}"
        if key not in domains:
            domains[key] = key

    if not domains:
        return url_list

    step(f"Domain reachability check: probing {len(domains)} domain(s)…")

    dead_domains: set[str] = set()

    def _probe(root_url: str) -> tuple[str, bool, str]:
        try:
            r = requests.head(
                root_url, headers=req_headers,
                timeout=_DOMAIN_CHECK_TIMEOUT, allow_redirects=True,
            )
            # Any HTTP response = domain is reachable (even error codes)
            return root_url, True, str(r.status_code)
        except RequestException as exc:
            return root_url, False, str(exc)

    n_workers = min(len(domains), _LIVENESS_WORKERS)
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = {pool.submit(_probe, root): root for root in domains}
        for fut in as_completed(futures):
            root, alive, reason = fut.result()
            if not alive:
                dead_domains.add(root)
                warn(f"Domain unreachable (dropping all its URLs): {root}  →  {reason}")
            else:
                log.debug("Domain reachable: %s (%s)", root, reason)

    if not dead_domains:
        info(f"Domain check: all {len(domains)} domain(s) reachable")
        return url_list

    result = [
        u for u in url_list
        if f"{urllib.parse.urlparse(u).scheme}://{urllib.parse.urlparse(u).netloc}"
        not in dead_domains
    ]
    dropped = len(url_list) - len(result)
    warn(
        f"Domain check: dropped {dropped} URL(s) across {len(dead_domains)} dead domain(s) "
        f"({len(result)} remaining)"
    )
    return result


# ---------------------------------------------------------------------------
# Pre-flight: path-shape deduplication
# ---------------------------------------------------------------------------

_RE_PURE_DIGITS  = re.compile(r'^\d+$')
_RE_UUID         = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)
# slug-with-trailing-number: word-123, product-v2, etc.
_RE_ENDS_DIGIT   = re.compile(r'^[a-z0-9]+(-[a-z0-9]+)*-\d+$', re.IGNORECASE)
# three-or-more hyphen-separated words: a-b-c, foo-bar-baz-qux
_RE_MULTI_HYPHEN = re.compile(r'^[a-z0-9]+(-[a-z0-9]+){2,}$', re.IGNORECASE)

_SIBLING_THRESHOLD = 3   # N siblings at same parent → last segment is parametric


def _segment_is_parametric(seg: str) -> bool:
    return bool(
        _RE_PURE_DIGITS.match(seg)
        or _RE_UUID.match(seg)
        or _RE_ENDS_DIGIT.match(seg)
        or _RE_MULTI_HYPHEN.match(seg)
    )


def _path_shape(path: str) -> str:
    """Replace obviously parametric segments with '*'."""
    parts = [s for s in path.split('/') if s]
    return '/' + '/'.join('*' if _segment_is_parametric(s) else s for s in parts)


def _dedup_urls_by_path_shape(url_list: list[str]) -> list[str]:
    """Collapse URLs that share the same path shape into one representative.

    Two-pass strategy:
    1. Content-based: digits, UUIDs, slugs-with-trailing-numbers, 3+ word slugs
       → replaced with '*' immediately.
    2. Sibling-based: if ≥ SIBLING_THRESHOLD URLs share the same (netloc,
       parent-path) after pass 1, the varying last segment is also '*'.

    The first URL encountered for each shape is kept as the representative so
    session resume and report URLs stay meaningful.
    """
    if len(url_list) <= 1:
        return url_list

    # Pass 1 — content normalization
    entries: list[tuple[str, str, str]] = []  # (original, netloc, norm_path)
    for url in url_list:
        p = urllib.parse.urlparse(url)
        norm = _path_shape(p.path)
        entries.append((url, p.netloc, norm))

    # Pass 2 — multi-depth sibling detection
    # For each URL and each non-parametric segment position j, build a "masked key"
    # where position j is replaced with '*' and everything else is preserved.
    # If ≥ SIBLING_THRESHOLD URLs share the same masked key, position j is parametric
    # for all of them.  This handles middle-segment variation (e.g. /tag/*/feed)
    # not just last-segment variation that the old parent-group approach covered.
    position_groups: dict[tuple, list[tuple[int, int]]] = defaultdict(list)
    for i, (_, netloc, norm_path) in enumerate(entries):
        parts = [s for s in norm_path.split('/') if s]
        for j, seg in enumerate(parts):
            if seg == '*':          # already parametric from pass 1
                continue
            masked = tuple(parts[:j]) + ('*',) + tuple(parts[j + 1:])
            position_groups[(netloc, masked)].append((i, j))

    # Collect (url_idx, seg_pos) pairs that are parametric by sibling count
    parametric_positions: set[tuple[int, int]] = set()
    for url_pos_pairs in position_groups.values():
        if len(url_pos_pairs) >= _SIBLING_THRESHOLD:
            parametric_positions.update(url_pos_pairs)

    # Build final shape keys and pick representatives
    seen_shapes: dict[str, str] = {}   # final_shape_key → representative URL
    collapsed_count = 0
    collapsed_examples: list[str] = []

    for i, (url, netloc, norm_path) in enumerate(entries):
        parts = [s for s in norm_path.split('/') if s]
        final_parts = [
            '*' if (seg == '*' or (i, j) in parametric_positions) else seg
            for j, seg in enumerate(parts)
        ]
        norm_path = '/' + '/'.join(final_parts)

        p = urllib.parse.urlparse(url)
        shape_key = f"{p.scheme}://{netloc}{norm_path}"

        if shape_key not in seen_shapes:
            seen_shapes[shape_key] = url
        else:
            collapsed_count += 1
            if len(collapsed_examples) < 3:
                collapsed_examples.append(url)

    result = list(seen_shapes.values())

    if collapsed_count:
        info(
            f"Path-shape dedup: {collapsed_count} redundant URL(s) collapsed "
            f"→ {len(result)} distinct endpoint(s) to test"
        )
        for ex in collapsed_examples:
            info(f"  skipped  {ex}")
        if collapsed_count > len(collapsed_examples):
            info(f"  … and {collapsed_count - len(collapsed_examples)} more")

    return result


def _strip_tracking_params(url_list: list[str]) -> list[str]:
    """Remove known tracking/analytics query parameters from every URL.

    Reuses _TRACKING_PARAM_BLOCKLIST from probe.py — single source of truth.
    If stripping produces a duplicate URL already seen, the duplicate is dropped
    (preserving first-seen order).
    """
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
    if len(result) < len(url_list):
        dropped = len(url_list) - len(result)
        info(f"Tracking-param strip: {dropped} URL(s) collapsed → {len(result)} remaining")
    return result


def _filter_urls_with_params(url_list: list[str]) -> list[str]:
    """Drop URLs that have no query parameters.

    These can never be reflected-XSS targets, and in normal mode DOM scanning
    also only exercises query-param sources — so they would always produce a
    no_params result without firing a single payload.
    """
    result = [u for u in url_list if urllib.parse.urlparse(u).query]
    dropped = len(url_list) - len(result)
    if dropped:
        warn(
            f"Pre-flight: removed {dropped} URL(s) with no query parameters "
            f"({len(result)} remaining)"
        )
    return result


def run_active_scan(
    urls: Sequence[str],
    config: ActiveScanConfig,
    post_forms: "Sequence[PostFormTarget]" = (),
    upload_targets: "Sequence[UploadTarget]" = (),
    crawled_pages: Sequence[str] = (),
    session: "Any | None" = None,
) -> list[WorkerResult]:
    """Spawn isolated worker processes for each URL and collect results.

    Workers run up to `config.workers` at a time. A shared Manager provides:
      - dedup_registry: dict  — cloud escalation deduplication
      - dedup_lock:     Lock  — guards dedup_registry
      - findings_lock:  Lock  — serialises findings store writes
    """
    from ai_xss_generator.active.worker import run_post_worker
    url_list = [u.strip() for u in urls if u and u.strip()]
    post_form_list = list(post_forms)
    upload_target_list = list(upload_targets)
    crawled_pages_list = list(crawled_pages)

    # Pre-flight liveness checks use a thread-local rate limiter (process-local).
    rate_limiter = _GlobalRateLimiter(config.rate)
    # Scan workers share a single cross-process rate limiter so the aggregate
    # HTTP request rate never exceeds config.rate regardless of worker count.
    scan_rate_limiter = _SharedRateLimiter(config.rate)

    # Pre-flight: strip tracking params, deduplicate parametric path variants, then drop dead URLs
    if url_list:
        url_list = _strip_tracking_params(url_list)
        url_list = _dedup_urls_by_path_shape(url_list)
        if not config.skip_liveness:
            url_list = _filter_live_urls(
                url_list,
                auth_headers=config.auth_headers,
                rate_limiter=rate_limiter,
            )
        else:
            # Per-URL liveness skipped (--urls mode), but still probe each unique
            # domain root so a completely downed host doesn't burn worker budgets.
            url_list = _filter_dead_domains(
                url_list,
                auth_headers=config.auth_headers,
            )

    # Split into param-bearing URLs (for reflected GET and normal-mode DOM) vs all URLs
    # (for deep-mode DOM, which can test non-query-param sources like fragment/referrer).
    # Filtering happens even when scan_reflected is off so the DOM list stays clean in
    # normal mode where _dom_sources would be empty for no-param URLs anyway.
    url_list_with_params: list[str] = (
        _filter_urls_with_params(url_list)
        if url_list and config.mode != "deep"
        else url_list
    )

    # Fast mode: generate one payload batch upfront for all workers to share.
    # Normal and deep modes use per-URL/per-param generation; fast mode shares an upfront batch.
    fast_batch: list[Any] = []
    if config.mode == "fast" and url_list_with_params:
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

    # Build work items filtered by enabled scan types.
    # GET and DOM items are interleaved per URL so the two concurrent worker slots
    # are consumed by both pass-types of the *same* URL rather than two different
    # URLs running in parallel.  This keeps the full rate budget focused on one
    # URL at a time instead of spreading it thin across the entire list.
    #
    # GET (reflected) always uses param-bearing URLs only.
    # DOM uses param-bearing URLs in fast/normal mode (only query-param sources tested);
    # in deep mode DOM can test non-query-param sources so the full url_list is used.
    _dom_url_list = url_list if config.mode == "deep" else url_list_with_params
    get_items: list[tuple[str, Any]] = [("get", u) for u in url_list_with_params] if config.scan_reflected else []
    dom_items: list[tuple[str, Any]] = [("dom", u) for u in _dom_url_list] if config.scan_dom else []
    paired = [item for pair in zip(get_items, dom_items) for item in pair]
    paired += get_items[len(dom_items):]   # remainder when scan_dom is off
    paired += dom_items[len(get_items):]   # remainder when scan_reflected is off
    work_items: list[tuple[str, Any]] = paired
    if config.scan_stored:
        work_items += [("post", pf) for pf in post_form_list]
    if config.scan_uploads:
        work_items += [("upload", ut) for ut in upload_target_list]

    # Session resume: filter out already-completed work items and restore
    # prior results so _print_summary / write_report include all findings.
    prior_results: list[WorkerResult] = []
    if session is not None:
        from ai_xss_generator.session import completed_urls as _completed_urls, restore_results
        done_urls = _completed_urls(session)
        if done_urls:
            before = len(work_items)
            work_items = [
                (kind, item) for kind, item in work_items
                if _work_item_key(kind, item) not in done_urls
            ]
            skipped = before - len(work_items)
            if skipped:
                step(f"Session resume: {skipped} item(s) already done, {len(work_items)} remaining")
        prior_results = restore_results(session)

    if not work_items:
        # Explain why there's nothing to do rather than silently returning
        _reasons = []
        if session is not None and prior_results:
            # All items already done from a prior session
            info("Session complete — all work items were already finished in a prior run.")
            _print_summary(prior_results)
            return prior_results
        if config.scan_reflected and not url_list_with_params:
            _reasons.append("no GET URLs with testable query parameters")
        if config.scan_stored and not post_form_list:
            _reasons.append("no POST forms discovered (try without --no-crawl)")
        if config.scan_uploads and not upload_target_list:
            _reasons.append("no upload forms discovered (uploads require crawl discovery or explicit targets)")
        if _reasons:
            info(f"Active scan: nothing to test — {'; '.join(_reasons)}")
        return []

    _active_types = " + ".join(filter(None, [
        "reflected" if config.scan_reflected else None,
        "stored" if config.scan_stored else None,
        "uploads" if config.scan_uploads else None,
        "dom" if config.scan_dom else None,
    ]))
    n_get = sum(1 for kind, _ in work_items if kind == "get")
    n_post = sum(1 for kind, _ in work_items if kind == "post")
    n_upload = sum(1 for kind, _ in work_items if kind == "upload")

    n_workers = _auto_workers_for_mode(config.mode, config.rate, config.workers)
    step(
        f"Active scan [{_active_types}]: {n_get} GET URL(s) + {n_post} POST form(s) + {n_upload} upload form(s) | "
        f"{n_workers} worker(s) | "
        f"{config.rate:g} req/s rate | "
        f"{config.timeout_seconds}s timeout"
    )

    manager = multiprocessing.Manager()
    dedup_registry = manager.dict()
    dedup_lock = manager.Lock()
    findings_lock = manager.Lock()
    result_queue: multiprocessing.Queue = manager.Queue()

    # Start with results from a prior session run (empty list on fresh scan)
    results: list[WorkerResult] = list(prior_results)
    # (proc, label, kind, started_at, result_url)
    active_procs: list[tuple[multiprocessing.Process, str, str, float, str]] = []
    work_iter = iter(work_items)
    total_count = len(work_items)
    completed = 0
    # Seed confirmed_count from prior results so the panel shows cumulative total
    confirmed_count = sum(
        len(r.confirmed_findings) for r in prior_results if r.status == "confirmed"
    )
    scan_start = time.monotonic()
    # Graceful-pause state — modified by signal handler
    _pause_requested = False
    _pause_announced = False

    def _build_panel() -> tuple[str, str, str]:
        """Build the three panel line strings from current scan state."""
        import shutil as _sh
        cols = _sh.get_terminal_size(fallback=(80, 24)).columns
        elapsed = time.monotonic() - scan_start

        # ── Separator ──────────────────────────────────────────────────────
        sep = f"  {DIM}{'─' * max(cols - 4, 10)}{RESET}"

        # ── Progress bar ───────────────────────────────────────────────────
        BAR_W = 28
        safe_total = max(total_count, 1)
        pct = int(completed * 100 / safe_total)
        filled = int(completed * BAR_W / safe_total)
        empty = BAR_W - filled
        if completed > 0 and elapsed > 0:
            eta_secs = (elapsed / completed) * (total_count - completed)
            eta_str = fmt_duration(eta_secs)
        else:
            eta_str = "--:--"
        bar = (
            f"  {DIM}[{RESET}"
            f"{GREEN}{'█' * filled}{RESET}"
            f"{DIM}{'░' * empty}]{RESET}"
            f"  {BOLD}{pct}%{RESET}"
            f"  {DIM}{completed}/{total_count}{RESET}"
            f"  {fmt_duration(elapsed)} elapsed"
            f"  {DIM}ETA {eta_str}{RESET}"
        )

        # ── Workers + confirmed + active label ─────────────────────────────
        pills: list[str] = []
        _MAGENTA = "\033[35m"
        for _, _lbl, _kind, _, _ in active_procs:
            if _kind == "get":
                pills.append(f"{GREEN}GET●{RESET}")
            elif _kind == "post":
                pills.append(f"{CYAN}POST●{RESET}")
            elif _kind == "upload":
                pills.append(f"{GREEN}UP●{RESET}")
            else:
                pills.append(f"{_MAGENTA}DOM●{RESET}")
        for _ in range(max(0, n_workers - len(active_procs))):
            pills.append(f"{DIM}idle○{RESET}")
        pills_str = "  ".join(pills)

        conf_str = (
            f"{GREEN}{BOLD}✓ {confirmed_count}{RESET}"
            if confirmed_count else f"{DIM}✓ 0{RESET}"
        )

        max_label = max(cols - 56, 12)
        if active_procs:
            raw = active_procs[0][1]
            if len(raw) > max_label:
                raw = "…" + raw[-(max_label - 1):]
            label_part = f"  {DIM}│{RESET}  {DIM}{raw}{RESET}"
        else:
            label_part = ""

        workers = f"  {pills_str}   {DIM}│{RESET}  {conf_str} confirmed{label_part}"
        return sep, bar, workers

    def _record_result(r: WorkerResult) -> None:
        nonlocal confirmed_count
        results.append(r)
        _log_result(r)
        if r.status == "confirmed":
            confirmed_count += len(r.confirmed_findings)
        if session is not None:
            from ai_xss_generator.session import checkpoint as _checkpoint
            _checkpoint(session, r.url, r)

    def _drain_queue() -> None:
        import queue as _queue
        while True:
            try:
                r = result_queue.get(timeout=0.05)
                _record_result(r)
            except _queue.Empty:
                break
            except Exception:
                break

    def _reap_finished() -> None:
        nonlocal active_procs, completed
        still_running = []
        now = time.monotonic()
        for proc, plabel, pkind, started_at, result_url in active_procs:
            elapsed = now - started_at
            worker_budget = active_worker_timeout_budget(
                config.timeout_seconds,
                config.use_cloud,
                config.ai_backend,
                config.cloud_attempts,
            )
            if proc.is_alive() and elapsed > worker_budget:
                warn(f"[worker] timeout after {worker_budget}s → {plabel}")
                proc.kill()
                proc.join(timeout=1)
                completed += 1
                _record_result(WorkerResult(
                    url=result_url,
                    status="error",
                    error=f"Worker timed out after {worker_budget}s",
                    kind=pkind,
                ))
                continue
            if not proc.is_alive():
                proc.join(timeout=1)
                completed += 1
                info(f"[worker] done ({elapsed:.0f}s) → {plabel}  [{completed}/{total_count}]")
            else:
                still_running.append((proc, plabel, pkind, started_at, result_url))
        active_procs = still_running

    # Install SIGINT handler for two-stage graceful pause.
    # First Ctrl+C: stop accepting new work, let in-flight workers finish.
    # Second Ctrl+C: kill all workers immediately.
    _original_sigint = signal.getsignal(signal.SIGINT)

    def _sigint_handler(sig: int, frame: Any) -> None:
        nonlocal _pause_requested, _pause_announced
        if _pause_requested:
            # Second Ctrl+C — kill everything now
            warn("Force-kill: terminating all workers immediately...")
            for proc, _, _, _, _ in active_procs:
                proc.kill()
            raise KeyboardInterrupt
        _pause_requested = True

    signal.signal(signal.SIGINT, _sigint_handler)

    setup_panel()
    update_panel(*_build_panel())
    _scan_completed_cleanly = False
    try:
        while completed < total_count:
            _drain_queue()
            _reap_finished()

            if _pause_requested:
                if not _pause_announced:
                    _pause_announced = True
                    warn(
                        "Scan paused — letting in-flight workers finish. "
                        "Ctrl+C again to kill immediately."
                    )
                    if session is not None:
                        from ai_xss_generator.session import mark_status as _mark_status
                        _mark_status(session, "paused")
                # Don't start new workers; wait for active ones to drain
                if not active_procs:
                    break
            else:
                # Fill up to n_workers slots
                _cli_kwargs = {
                    "ai_backend": config.ai_backend,
                    "cli_tool": config.cli_tool,
                    "cli_model": config.cli_model,
                    "cloud_attempts": config.cloud_attempts,
                    "mode": config.mode,
                }
                while len(active_procs) < n_workers:
                    try:
                        kind, item = next(work_iter)
                    except StopIteration:
                        break

                    if kind == "get":
                        next_url = item
                        proc = multiprocessing.Process(
                            target=run_worker,
                            kwargs={
                                "url": next_url,
                                "rate": config.rate,
                                "shared_rate_limiter": scan_rate_limiter,
                                "waf_hint": config.waf,
                                "model": config.model,
                                "cloud_model": config.cloud_model,
                                "use_cloud": config.use_cloud,
                                "timeout_seconds": config.timeout_seconds,
                                "result_queue": result_queue,
                                "dedup_registry": dedup_registry,
                                "dedup_lock": dedup_lock,
                                "findings_lock": findings_lock,
                                "auth_headers": config.auth_headers,
                                "sink_url": config.sink_url,
                                "crawled_pages": crawled_pages_list,
                                "fresh": config.fresh,
                                "waf_source": config.waf_source,
                                "keep_searching": config.keep_searching,
                                "extreme": config.extreme,
                                "research": config.research,
                                "fast_batch": fast_batch or None,
                                "skip_triage": config.skip_triage,
                                **_cli_kwargs,
                            },
                            daemon=True,
                        )
                        log_label = next_url
                    elif kind == "dom":
                        next_url = item
                        # Build URL-param-only sources list for Normal mode
                        _dom_sources: "list[tuple[str, str]] | None" = None
                        if config.mode == "normal":
                            _qp = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(next_url).query, keep_blank_values=True))
                            _dom_sources = [("query_param", k) for k in _qp] if _qp else []
                        proc = multiprocessing.Process(
                            target=run_dom_worker,
                            kwargs={
                                "url": next_url,
                                "waf_hint": config.waf,
                                "model": config.model,
                                "cloud_model": config.cloud_model,
                                "use_cloud": config.use_cloud,
                                "timeout_seconds": config.timeout_seconds,
                                "result_queue": result_queue,
                                "dedup_registry": dedup_registry,
                                "dedup_lock": dedup_lock,
                                "auth_headers": config.auth_headers,
                                "waf_source": config.waf_source,
                                "keep_searching": config.keep_searching,
                                "extreme": config.extreme,
                                "research": config.research,
                                "fast_batch": fast_batch or None,
                                "findings_lock": findings_lock,
                                "dom_sources": _dom_sources,
                                "skip_triage": config.skip_triage,
                                **_cli_kwargs,
                            },
                            daemon=True,
                        )
                        log_label = f"[DOM] {next_url}"
                    elif kind == "upload":
                        ut = item
                        proc = multiprocessing.Process(
                            target=run_upload_worker,
                            kwargs={
                                "upload_target": ut,
                                "waf_hint": config.waf,
                                "timeout_seconds": config.timeout_seconds,
                                "result_queue": result_queue,
                                "auth_headers": config.auth_headers,
                                "sink_url": config.sink_url,
                            },
                            daemon=True,
                        )
                        log_label = f"[UPLOAD] {ut.action_url}"
                    else:
                        pf = item
                        proc = multiprocessing.Process(
                            target=run_post_worker,
                            kwargs={
                                "post_form": pf,
                                "rate": config.rate,
                                "shared_rate_limiter": scan_rate_limiter,
                                "waf_hint": config.waf,
                                "model": config.model,
                                "cloud_model": config.cloud_model,
                                "use_cloud": config.use_cloud,
                                "timeout_seconds": config.timeout_seconds,
                                "result_queue": result_queue,
                                "dedup_registry": dedup_registry,
                                "dedup_lock": dedup_lock,
                                "findings_lock": findings_lock,
                                "auth_headers": config.auth_headers,
                                "crawled_pages": crawled_pages_list,
                                "sink_url": config.sink_url,
                                "fresh": config.fresh,
                                "waf_source": config.waf_source,
                                "keep_searching": config.keep_searching,
                                "extreme": config.extreme,
                                "research": config.research,
                                "fast_batch": fast_batch or None,
                                "skip_triage": config.skip_triage,
                                **_cli_kwargs,
                            },
                            daemon=True,
                        )
                        log_label = f"[POST] {pf.action_url}"
                    proc.start()
                    result_url = _work_item_url(kind, item)
                    active_procs.append((proc, log_label, kind, time.monotonic(), result_url))
                    info(f"[worker] started → {log_label}")

            update_panel(*_build_panel())
            time.sleep(0.25)

        _scan_completed_cleanly = not _pause_requested

    except KeyboardInterrupt:
        # Only reached on second Ctrl+C (force kill raises this after proc.kill())
        warn("Workers killed.")
    finally:
        signal.signal(signal.SIGINT, _original_sigint)
        teardown_panel()
        # Final drain after all processes finish
        final_join_timeout = active_worker_timeout_budget(
            config.timeout_seconds,
            config.use_cloud,
            config.ai_backend,
            config.cloud_attempts,
        ) + 5
        for proc, _, _, _, _ in active_procs:
            proc.join(timeout=final_join_timeout)
        _drain_queue()
        manager.shutdown()
        # Mark session complete only on clean finish; paused/crashed stays in_progress
        if session is not None and _scan_completed_cleanly:
            from ai_xss_generator.session import mark_status as _mark_status
            _mark_status(session, "completed")

    if _pause_requested:
        remaining = total_count - completed
        if remaining > 0:
            info(
                f"Scan paused with {remaining} item(s) remaining. "
                f"Re-run with the same target to resume."
            )

    # ── Blind XSS injection pass ──────────────────────────────────────────────
    # Runs AFTER the main scan so it doesn't block reflected/stored detection.
    # Every GET URL param and POST form field gets blind OOB payloads injected.
    if config.blind_callback:
        _run_blind_pass(
            urls=url_list,
            post_forms=post_form_list,
            config=config,
            report_dir=Path(config.output_path).parent if config.output_path else Path("."),
        )

    _print_summary(results)
    return results


def _run_blind_pass(
    urls: list[str],
    post_forms: list[Any],
    config: "ActiveScanConfig",
    report_dir: "Path",
) -> None:
    """Fire blind XSS payloads across all injection points and save token manifest."""
    from ai_xss_generator.active.blind_xss import (
        BlindToken, BlindTokenManifest, blind_payloads_for_context, make_token,
    )
    from ai_xss_generator.active.executor import ActiveExecutor
    import urllib.parse as _up

    cb = config.blind_callback
    manifest_path = report_dir / _BLIND_MANIFEST_FILENAME
    manifest = BlindTokenManifest(manifest_path)
    executor = ActiveExecutor(auth_headers=config.auth_headers)

    try:
        executor.start()
    except Exception as exc:
        log.warning("Blind XSS: Playwright start failed: %s", exc)
        return

    injected = 0
    try:
        # GET URL params
        for url in urls:
            parsed = _up.urlparse(url)
            params = dict(_up.parse_qsl(parsed.query, keep_blank_values=True))
            for param_name in params:
                token = make_token()
                payloads = blind_payloads_for_context(token, cb, "html_text")
                for payload in payloads[:3]:  # top 3 per param to keep it lean
                    try:
                        test_params = {**params, param_name: payload}
                        new_query = _up.urlencode(test_params, quote_via=_up.quote)
                        fire_url = _up.urlunparse(parsed._replace(query=new_query))
                        executor.fire(
                            url=fire_url,
                            param_name=param_name,
                            payload=payload,
                            all_params=params,
                            transform_name="blind_xss",
                        )
                    except Exception:
                        pass
                manifest.record(BlindToken(
                    token=token, url=url, param=param_name,
                    delivery="get", context_type="html_text", callback_url=cb,
                ))
                injected += 1

        # POST form params
        for pf in post_forms:
            for param_name in getattr(pf, "param_names", []):
                token = make_token()
                payloads = blind_payloads_for_context(token, cb, "html_text")
                for payload in payloads[:3]:
                    try:
                        executor.fire_post(
                            source_page_url=pf.source_page_url,
                            action_url=pf.action_url,
                            param_name=param_name,
                            payload=payload,
                            all_param_names=pf.param_names,
                            csrf_field=getattr(pf, "csrf_field", None),
                            transform_name="blind_xss",
                        )
                    except Exception:
                        pass
                manifest.record(BlindToken(
                    token=token, url=pf.action_url, param=param_name,
                    delivery="post", context_type="html_text", callback_url=cb,
                ))
                injected += 1

        if injected:
            from ai_xss_generator.console import info as _info, success as _success
            _success(
                f"Blind XSS: {injected} token(s) injected — "
                f"manifest saved to {manifest_path}"
            )
            _info(
                f"Blind XSS: callbacks fire to {cb}?t=TOKEN&u=URL&c=COOKIES — "
                f"check your OOB server or run: axss --poll-blind {manifest_path}"
            )
    finally:
        try:
            executor.stop()
        except Exception:
            pass


def _log_result(r: WorkerResult) -> None:
    import urllib.parse as _up
    budget_note = (
        f" [tier={getattr(r, 'target_tier', '') or 'unknown'}"
        f" local={getattr(r, 'local_model_rounds', 0)}"
        f" cloud={getattr(r, 'cloud_model_rounds', 0)}"
        f" fallback={getattr(r, 'fallback_rounds', 0)}]"
    )
    if r.status == "confirmed":
        sources = {f.source for f in r.confirmed_findings}
        if len(sources) == 1:
            source_label = {
                "local_model": "local",
                "cloud_model": "cloud",
                "phase1_waf_fallback": "waf-fallback",
                "phase1_transform": "fallback",
                "dom_xss_runtime": "runtime",
            }.get(next(iter(sources)), "mixed")
        else:
            source_label = "mixed"
        success(
            f"[active] CONFIRMED {len(r.confirmed_findings)} finding(s) — {r.url} "
            f"({source_label}){budget_note}"
        )
        for f in r.confirmed_findings:
            # Unquote so full-width / half-width chars display as-is, not percent-encoded
            display_url = _up.unquote(f.fired_url)
            success(f"  ↳ [{f.param_name}] {display_url}")
            if f.ai_note:
                info(f"    {f.ai_note}")
    elif r.status == "no_execution":
        info(
            f"[active] no execution confirmed — {r.url} "
            f"({r.transforms_tried} payloads tried"
            + (", cloud escalated" if r.cloud_escalated else "")
            + f"){budget_note}"
        )
        if r.dead_reason:
            info(f"    {r.dead_reason}")
    elif r.status == "taint_only":
        info(
            f"[active] DOM taint confirmed, but no execution — {r.url} "
            f"({len(r.confirmed_findings)} sink hit(s)){budget_note}"
        )
        for f in r.confirmed_findings:
            display_url = _up.unquote(f.fired_url)
            info(f"  ↳ [{f.param_name}] {display_url}")
        if r.dead_reason:
            info(f"    {r.dead_reason}")
    elif r.status == "no_reflection":
        label = "dead target" if r.dead_target else "no reflection"
        info(f"[active] {label} — {r.url}{budget_note}")
        if r.dead_reason:
            info(f"    {r.dead_reason}")
    elif r.status == "no_params":
        info(f"[active] skip (no testable params) — {r.url}")
    elif r.status == "error":
        warn(f"[active] error — {r.url}: {r.error}{budget_note}")


def _print_summary(results: list[WorkerResult]) -> None:
    import urllib.parse as _up
    confirmed = [r for r in results if r.status == "confirmed"]
    taint_only = [r for r in results if r.status == "taint_only"]
    all_findings = [f for r in confirmed for f in r.confirmed_findings]
    taint_findings = [f for r in taint_only for f in r.confirmed_findings]
    errors = [r for r in results if r.status == "error"]
    tier_counts = {
        "hard_dead": 0,
        "soft_dead": 0,
        "live": 0,
        "high_value": 0,
        "unknown": 0,
    }
    local_rounds = 0
    cloud_rounds = 0
    fallback_rounds = 0
    for result in results:
        tier = str(getattr(result, "target_tier", "") or "").strip().lower() or "unknown"
        if tier not in tier_counts:
            tier = "unknown"
        tier_counts[tier] += 1
        local_rounds += int(getattr(result, "local_model_rounds", 0) or 0)
        cloud_rounds += int(getattr(result, "cloud_model_rounds", 0) or 0)
        fallback_rounds += int(getattr(result, "fallback_rounds", 0) or 0)

    info(f"\n{'─'*60}")
    info(f"Active scan complete: {len(results)} target(s) processed")
    info(
        "  • Pilot tiers: "
        f"hard-dead {tier_counts['hard_dead']}  "
        f"soft-dead {tier_counts['soft_dead']}  "
        f"live {tier_counts['live']}  "
        f"high-value {tier_counts['high_value']}"
    )
    info(
        "  • Budget: "
        f"local rounds {local_rounds}  "
        f"cloud rounds {cloud_rounds}  "
        f"fallback rounds {fallback_rounds}"
    )
    if all_findings:
        success(f"  ✅ Confirmed XSS: {len(all_findings)} finding(s) across {len(confirmed)} target(s)")
        info("")
        for i, f in enumerate(all_findings, 1):
            success(f"  Finding {i} — param: {f.param_name}  context: {f.context_type}  via: {f.execution_method}")
            success(f"  Payload:   {f.payload}")
            success(f"  URL:       {_up.unquote(f.fired_url)}")
            if i < len(all_findings):
                info(f"  {'─'*56}")
    else:
        info("  ➖ No confirmed XSS execution detected")
    if taint_findings:
        info(f"  • DOM taint reached a sink, but no payload executed: {len(taint_findings)} finding(s)")
    if errors:
        warn(f"  ⚠️  Errors: {len(errors)} target(s) failed")
    info(f"{'─'*60}\n")
