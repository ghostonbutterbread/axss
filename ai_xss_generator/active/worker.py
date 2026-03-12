"""Per-URL active scanner worker — runs as an isolated multiprocessing.Process.

Full lifecycle per URL:
  1. WAF detect (reuse existing helper)
  2. Fetch + surface-map the target page
  3. Probe all query parameters for reflection + surviving chars
  4. Build enriched reasoning context from parsed page state + probe lessons
  5. For each injectable param: ask the model for tailored payloads and fire those
  6. If model-driven attempts do not confirm execution: fall back to deterministic transforms
  7. Return WorkerResult to orchestrator via result_queue
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import urllib.parse
from dataclasses import dataclass, field
from multiprocessing.managers import DictProxy
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import multiprocessing
    from ai_xss_generator.types import PostFormTarget

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ConfirmedFinding:
    """A single confirmed XSS execution."""
    url: str
    param_name: str
    context_type: str
    sink_context: str
    payload: str
    transform_name: str
    execution_method: str    # "dialog" | "console" | "network" | "dom_xss" | "dom_taint"
    execution_detail: str
    waf: str | None
    surviving_chars: str
    fired_url: str
    source: str             # "phase1_transform" | "local_model" | "cloud_model" | "dom_xss_runtime"
    cloud_escalated: bool
    code_location: str = ""
    """JS call stack or script location where the sink was reached (DOM XSS only)."""


@dataclass
class WorkerResult:
    """Returned by a worker to the orchestrator via the result queue."""
    url: str
    status: str             # "confirmed" | "taint_only" | "no_execution" | "no_reflection" | "no_params" | "error"
    confirmed_findings: list[ConfirmedFinding] = field(default_factory=list)
    transforms_tried: int = 0
    cloud_escalated: bool = False
    waf: str | None = None
    error: str | None = None
    duration_seconds: float = 0.0
    # Summary counts for the report
    params_tested: int = 0
    params_reflected: int = 0
    # Work item type — used by session checkpointing
    kind: str = "get"       # "get" | "post"


# ---------------------------------------------------------------------------
# Deduplication key — includes endpoint + param so different endpoints/params
# are always treated as new targets even when WAF + filter profile match.
# ---------------------------------------------------------------------------

def _escalation_key(
    url: str,
    param_name: str,
    waf: str | None,
    surviving_chars: frozenset[str],
    context_type: str,
) -> str:
    """Stable key for cloud-escalation dedup.

    Intentionally excludes which transforms failed — two workers hitting the
    same endpoint+param+waf+char-profile should share the same cloud result
    regardless of which Phase 1 transforms each attempted.
    """
    parsed = urllib.parse.urlparse(url)
    endpoint = f"{parsed.netloc}{parsed.path}"
    fingerprint = {
        "endpoint": endpoint,
        "param": param_name,
        "waf": waf or "none",
        "chars": sorted(surviving_chars),
        "context": context_type,
    }
    return hashlib.sha256(
        json.dumps(fingerprint, sort_keys=True).encode()
    ).hexdigest()


# ---------------------------------------------------------------------------
# Worker entry point
# ---------------------------------------------------------------------------

def run_worker(
    url: str,
    rate: float,
    waf_hint: str | None,
    model: str,
    cloud_model: str,
    use_cloud: bool,
    timeout_seconds: int,
    result_queue: "multiprocessing.Queue",
    dedup_registry: DictProxy,
    dedup_lock: Any,
    findings_lock: Any,
    auth_headers: dict[str, str] | None = None,
    sink_url: str | None = None,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
) -> None:
    """Target function for multiprocessing.Process.

    All results are communicated back via *result_queue*.
    Exceptions are caught and returned as error WorkerResults — workers
    must never crash silently.
    """
    start_time = time.monotonic()

    def _put_result(result: WorkerResult) -> None:
        result.duration_seconds = time.monotonic() - start_time
        result_queue.put(result)

    try:
        _run(
            url=url,
            rate=rate,
            waf_hint=waf_hint,
            model=model,
            cloud_model=cloud_model,
            use_cloud=use_cloud,
            timeout_seconds=timeout_seconds,
            result_queue=result_queue,
            dedup_registry=dedup_registry,
            dedup_lock=dedup_lock,
            findings_lock=findings_lock,
            start_time=start_time,
            put_result=_put_result,
            auth_headers=auth_headers,
            sink_url=sink_url,
            ai_backend=ai_backend,
            cli_tool=cli_tool,
            cli_model=cli_model,
        )
    except Exception as exc:
        log.exception("Worker crashed for %s", url)
        _put_result(WorkerResult(url=url, status="error", error=str(exc)))


def _run(
    *,
    url: str,
    rate: float,
    waf_hint: str | None,
    model: str,
    cloud_model: str,
    use_cloud: bool,
    timeout_seconds: int,
    result_queue: Any,
    dedup_registry: DictProxy,
    dedup_lock: Any,
    findings_lock: Any,
    start_time: float,
    put_result: Any,
    auth_headers: dict[str, str] | None = None,
    sink_url: str | None = None,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
) -> None:
    deadline = start_time + timeout_seconds

    def _timed_out() -> bool:
        return time.monotonic() > deadline

    # ── Step 1: Parse URL params — early exit if none ─────────────────────────
    parsed = urllib.parse.urlparse(url)
    raw_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not raw_params:
        put_result(WorkerResult(url=url, status="no_params", waf=waf_hint))
        return

    flat_params = {k: v[0] for k, v in raw_params.items()}

    # Early exit if every param is a known tracking/analytics param — probe_url
    # would filter them all and return [], leading to a misleading "no_reflection"
    # status. Catch it here so the status and log message are accurate.
    from ai_xss_generator.probe import _TRACKING_PARAM_BLOCKLIST, probe_url
    testable_params = {k for k in flat_params if k.lower() not in _TRACKING_PARAM_BLOCKLIST}
    if not testable_params:
        put_result(WorkerResult(url=url, status="no_params", waf=waf_hint))
        return

    # ── Step 2: Pre-fetch URL cleanly — used for AI context (avoids a redundant
    # network round-trip in parse_target later). The probe requests use modified
    # URLs (canary injected), so this clean fetch is the only time we see the
    # real page content.
    _prefetched_html: str | None = None
    try:
        from scrapling.fetchers import FetcherSession as _FS
        with _FS(impersonate="chrome", stealthy_headers=True, timeout=20,
                 follow_redirects=True, retries=1) as _fs:
            _clean_resp = _fs.get(
                url,
                headers={**(auth_headers or {}),
                         "User-Agent": "axss/0.1 (+authorized security testing; scrapling)"},
            )
            _prefetched_html = _clean_resp.text or (
                _clean_resp.body.decode("utf-8", errors="replace")
                if _clean_resp.body else None
            )
    except Exception as _exc:
        log.debug("Pre-fetch of %s failed (parse_target will re-fetch): %s", url, _exc)

    # ── Step 3: Probe all params for reflection + char survival ──────────────
    probe_results = probe_url(url, rate=rate, waf=waf_hint, auth_headers=auth_headers, sink_url=sink_url)

    injectable = [r for r in probe_results if r.is_injectable]
    reflected  = [r for r in probe_results if r.is_reflected]

    # ── Step 4: Parse target HTML once — reused by local/cloud model helpers ─
    from ai_xss_generator.parser import parse_target as _parse_target
    _cached_context: Any = None
    try:
        _cached_context = _parse_target(
            url=url, html_value=None, waf=waf_hint, auth_headers=auth_headers,
            cached_html=_prefetched_html,
        )
    except Exception as exc:
        log.debug("Pre-parse of %s failed (will retry per-param): %s", url, exc)

    session_lessons: list[Any] = []
    try:
        from ai_xss_generator.learning import build_memory_profile
        from ai_xss_generator.lessons import build_mapping_lessons, build_probe_lessons

        memory_profile = build_memory_profile(
            context=_cached_context,
            waf_name=waf_hint,
            delivery_mode="get",
            target_host=parsed.netloc,
        )
        if auth_headers:
            memory_profile["auth_required"] = True
        if _cached_context is not None:
            session_lessons.extend(build_mapping_lessons(
                _cached_context,
                memory_profile=memory_profile,
            ))
        if reflected:
            session_lessons.extend(build_probe_lessons(
                reflected,
                memory_profile=memory_profile,
                delivery_mode="get",
            ))
    except Exception as exc:
        log.debug("Session lesson build failed for %s: %s", url, exc)

    if not reflected:
        put_result(WorkerResult(
            url=url,
            status="no_reflection",
            waf=waf_hint,
            params_tested=len(flat_params),
        ))
        return

    if not injectable:
        put_result(WorkerResult(
            url=url,
            status="no_reflection",
            waf=waf_hint,
            params_tested=len(flat_params),
            params_reflected=len(reflected),
        ))
        return

    # ── Step 5: Start Playwright executor (shared for all payload attempts) ──
    from ai_xss_generator.active.executor import ActiveExecutor
    executor = ActiveExecutor(auth_headers=auth_headers)
    try:
        executor.start()
    except Exception as exc:
        put_result(WorkerResult(url=url, status="error", error=f"Playwright start failed: {exc}", waf=waf_hint))
        return

    confirmed_findings: list[ConfirmedFinding] = []
    total_transforms_tried = 0
    cloud_escalated = False

    try:
        from ai_xss_generator.active.transforms import all_variants_for_probe

        # ── Step 5: Model-first execution per injectable param ────────────────
        for probe_result in injectable:
            if _timed_out():
                break

            param_name = probe_result.param_name
            param_variants = all_variants_for_probe(probe_result)

            for _pname, context_type, variants in param_variants:
                if _timed_out():
                    break

                context_probe_result = _probe_result_for_context(probe_result, context_type)
                # Track confirmation per context — a confirmed finding on one
                # param must not suppress escalation on a different param.
                context_confirmed = False

                # Ask the local model first using the enriched target context.
                # Only AI-origin payloads are returned here; heuristic payloads
                # still exist in generate_payloads() but stay out of active
                # execution so deterministic fallback remains explicit.
                if not context_confirmed and not _timed_out():
                    local_payloads = _get_local_payloads(
                        url=url,
                        probe_result=context_probe_result,
                        model=model,
                        waf=waf_hint,
                        base_context=_cached_context,
                        auth_headers=auth_headers,
                        delivery_mode="get",
                        session_lessons=session_lessons,
                    )

                    for lp in local_payloads:
                        if _timed_out():
                            break
                        total_transforms_tried += 1
                        result = executor.fire(
                            url=url,
                            param_name=param_name,
                            payload=lp,
                            all_params=flat_params,
                            transform_name="local_model",
                            sink_url=sink_url,
                        )
                        if result.confirmed:
                            finding = _make_finding(
                                url=url,
                                probe_result=context_probe_result,
                                context_type=context_type,
                                result=result,
                                waf=waf_hint,
                                source="local_model",
                                cloud_escalated=False,
                            )
                            confirmed_findings.append(finding)
                            context_confirmed = True
                            break

                # If the local model misses, try the cloud model before giving
                # up on dynamic reasoning for this reflection context.
                if not context_confirmed and use_cloud and not _timed_out():
                    # Each unique (endpoint + param + waf + char profile + context)
                    # combination gets exactly one cloud call.
                    surviving_chars = frozenset().union(
                        *(ctx.surviving_chars for ctx in context_probe_result.reflections)
                    )
                    ekey = _escalation_key(
                        url=url,
                        param_name=param_name,
                        waf=waf_hint,
                        surviving_chars=surviving_chars,
                        context_type=context_type,
                    )

                    cloud_payloads = _get_cloud_payloads(
                        url=url,
                        probe_result=context_probe_result,
                        cloud_model=cloud_model,
                        waf=waf_hint,
                        ekey=ekey,
                        dedup_registry=dedup_registry,
                        dedup_lock=dedup_lock,
                        base_context=_cached_context,
                        auth_headers=auth_headers,
                        ai_backend=ai_backend,
                        cli_tool=cli_tool,
                        cli_model=cli_model,
                        delivery_mode="get",
                        session_lessons=session_lessons,
                    )

                    if cloud_payloads:
                        cloud_escalated = True

                    for cp in cloud_payloads:
                        if _timed_out():
                            break
                        total_transforms_tried += 1
                        result = executor.fire(
                            url=url,
                            param_name=param_name,
                            payload=cp,
                            all_params=flat_params,
                            transform_name="cloud_model",
                            sink_url=sink_url,
                        )
                        if result.confirmed:
                            finding = _make_finding(
                                url=url,
                                probe_result=context_probe_result,
                                context_type=context_type,
                                result=result,
                                waf=waf_hint,
                                source="cloud_model",
                                cloud_escalated=True,
                            )
                            confirmed_findings.append(finding)
                            context_confirmed = True
                            break

                # Deterministic transforms are now a fallback stage instead of
                # the primary search strategy.
                if not context_confirmed and not _timed_out():
                    for variant in variants:
                        if _timed_out():
                            break

                        total_transforms_tried += 1
                        result = executor.fire(
                            url=url,
                            param_name=param_name,
                            payload=variant.payload,
                            all_params=flat_params,
                            transform_name=variant.transform_name,
                            sink_url=sink_url,
                        )

                        if result.confirmed:
                            finding = _make_finding(
                                url=url,
                                probe_result=context_probe_result,
                                context_type=context_type,
                                result=result,
                                waf=waf_hint,
                                source="phase1_transform",
                                cloud_escalated=False,
                            )
                            confirmed_findings.append(finding)
                            context_confirmed = True
                            break

    finally:
        executor.stop()

    status = "confirmed" if confirmed_findings else "no_execution"
    put_result(WorkerResult(
        url=url,
        status=status,
        confirmed_findings=confirmed_findings,
        transforms_tried=total_transforms_tried,
        cloud_escalated=cloud_escalated,
        waf=waf_hint,
        params_tested=len(flat_params),
        params_reflected=len(reflected),
        kind="get",
    ))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    url: str,
    probe_result: Any,
    context_type: str,
    result: Any,
    waf: str | None,
    source: str,
    cloud_escalated: bool,
) -> ConfirmedFinding:
    surviving = "".join(sorted(
        c for ctx in probe_result.reflections for c in ctx.surviving_chars
    ))
    return ConfirmedFinding(
        url=url,
        param_name=probe_result.param_name,
        context_type=context_type,
        sink_context=context_type,
        payload=result.payload,
        transform_name=result.transform_name,
        execution_method=result.method,
        execution_detail=result.detail,
        waf=waf,
        surviving_chars=surviving,
        fired_url=result.fired_url,
        source=source,
        cloud_escalated=cloud_escalated,
    )


def _probe_result_for_context(probe_result: Any, context_type: str) -> Any:
    """Return a lightweight probe result containing only one reflection context."""
    reflections = [
        ctx for ctx in getattr(probe_result, "reflections", [])
        if getattr(ctx, "context_type", "") == context_type
    ]
    if not reflections:
        reflections = list(getattr(probe_result, "reflections", []))
    return SimpleNamespace(
        param_name=getattr(probe_result, "param_name", ""),
        original_value=getattr(probe_result, "original_value", ""),
        reflections=reflections,
        error=getattr(probe_result, "error", None),
    )


def _get_local_payloads(
    url: str,
    probe_result: Any,
    model: str,
    waf: str | None,
    base_context: Any = None,
    auth_headers: dict[str, str] | None = None,
    delivery_mode: str = "get",
    session_lessons: list[Any] | None = None,
) -> list[str]:
    """Ask the local model for payloads. Returns raw payload strings.

    *base_context* is a pre-parsed ParsedContext for *url*. When provided it
    avoids a redundant HTTP fetch — enrich_context adds the probe-specific
    reflection data on top without mutating the original.
    """
    try:
        from ai_xss_generator.probe import enrich_context
        from ai_xss_generator.models import generate_payloads
        from ai_xss_generator.learning import build_memory_profile

        if base_context is None:
            from ai_xss_generator.parser import parse_target
            base_context = parse_target(url=url, html_value=None, waf=waf, auth_headers=auth_headers)

        context = enrich_context(base_context, [probe_result])
        memory_profile = build_memory_profile(
            context=context,
            waf_name=waf,
            delivery_mode=delivery_mode,
        )
        payloads, engine, *_ = generate_payloads(
            context=context,
            model=model,
            waf=waf,
            use_cloud=False,  # local only at this step
            memory_profile=memory_profile,
            past_lessons=session_lessons,
        )
        if engine == "heuristic":
            return []
        return [
            p.payload
            for p in payloads
            if p.payload and getattr(p, "source", "heuristic") != "heuristic"
        ]
    except Exception as exc:
        log.debug("Local model failed for %s param=%s: %s", url, probe_result.param_name, exc)
        return []


# ---------------------------------------------------------------------------
# DOM XSS worker entry point
# ---------------------------------------------------------------------------

def run_dom_worker(
    url: str,
    waf_hint: str | None,
    timeout_seconds: int,
    result_queue: "multiprocessing.Queue",
    auth_headers: dict[str, str] | None = None,
) -> None:
    """Worker entry point for DOM XSS runtime scanning.

    Runs as an isolated multiprocessing.Process.  Launches its own Playwright
    browser, calls scan_dom_xss(), converts results to ConfirmedFinding objects,
    and puts a WorkerResult onto result_queue.
    """
    start_time = time.monotonic()

    def _put_result(result: WorkerResult) -> None:
        result.duration_seconds = time.monotonic() - start_time
        result_queue.put(result)

    try:
        _run_dom(
            url=url,
            waf_hint=waf_hint,
            timeout_seconds=timeout_seconds,
            put_result=_put_result,
            auth_headers=auth_headers,
        )
    except Exception as exc:
        log.exception("DOM worker crashed for %s", url)
        _put_result(WorkerResult(url=url, status="error", error=str(exc), kind="dom"))


def _run_dom(
    *,
    url: str,
    waf_hint: str | None,
    timeout_seconds: int,
    put_result: Any,
    auth_headers: dict[str, str] | None = None,
) -> None:
    from playwright.sync_api import sync_playwright
    from ai_xss_generator.active.dom_xss import scan_dom_xss

    # Cap per-navigation timeout to 15 s regardless of the overall worker timeout
    nav_timeout_ms = min(timeout_seconds * 1_000, 15_000)

    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        try:
            dom_results = scan_dom_xss(url, browser, auth_headers, timeout_ms=nav_timeout_ms)
        finally:
            browser.close()
            pw.stop()
    except Exception as exc:
        put_result(WorkerResult(
            url=url, status="error", error=f"DOM XSS scan failed: {exc}", kind="dom",
        ))
        return

    findings: list[ConfirmedFinding] = []
    for dr in dom_results:
        findings.append(
            ConfirmedFinding(
                url=url,
                param_name=dr.source_name,
                context_type="dom_xss",
                sink_context=dr.sink,
                payload=dr.payload_fired or "",
                transform_name="dom_xss_runtime",
                # "dom_xss" = JS execution confirmed; "dom_taint" = taint proven but
                # real payload blocked (CSP etc.) — still a high-confidence finding.
                execution_method="dom_xss" if dr.confirmed_execution else "dom_taint",
                execution_detail=dr.detail,
                waf=waf_hint,
                surviving_chars="",
                fired_url=dr.fired_url,
                source="dom_xss_runtime",
                cloud_escalated=False,
                code_location=dr.code_location,
            )
        )

    if any(dr.confirmed_execution for dr in dom_results):
        status = "confirmed"
    elif findings:
        status = "taint_only"
    else:
        status = "no_execution"
    put_result(WorkerResult(
        url=url,
        status=status,
        confirmed_findings=findings,
        waf=waf_hint,
        kind="dom",
    ))


def _get_cloud_payloads(
    url: str,
    probe_result: Any,
    cloud_model: str,
    waf: str | None,
    ekey: str,
    dedup_registry: DictProxy,
    dedup_lock: Any,
    base_context: Any = None,
    auth_headers: dict[str, str] | None = None,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
    delivery_mode: str = "get",
    session_lessons: list[Any] | None = None,
) -> list[str]:
    """Check dedup registry; call cloud model if this is a novel fingerprint.

    *base_context* is a pre-parsed ParsedContext for *url*. When provided it
    avoids a redundant HTTP fetch.
    """
    with dedup_lock:
        if ekey in dedup_registry:
            log.debug("Dedup hit — reusing cloud result for key %s", ekey[:12])
            return dedup_registry[ekey]

    try:
        from ai_xss_generator.probe import enrich_context
        from ai_xss_generator.models import generate_cloud_payloads
        from ai_xss_generator.learning import build_memory_profile

        if base_context is None:
            from ai_xss_generator.parser import parse_target
            base_context = parse_target(url=url, html_value=None, waf=waf, auth_headers=auth_headers)

        context = enrich_context(base_context, [probe_result])
        memory_profile = build_memory_profile(
            context=context,
            waf_name=waf,
            delivery_mode=delivery_mode,
        )
        payloads, _ = generate_cloud_payloads(
            context=context,
            cloud_model=cloud_model,
            waf=waf,
            past_lessons=session_lessons,
            ai_backend=ai_backend,
            cli_tool=cli_tool,
            cli_model=cli_model,
            memory_profile=memory_profile,
        )
        result_strings = [p.payload for p in payloads if p.payload]
    except Exception as exc:
        log.debug("Cloud escalation failed for %s: %s", url, exc)
        result_strings = []

    with dedup_lock:
        dedup_registry[ekey] = result_strings

    return result_strings


# ---------------------------------------------------------------------------
# POST form worker entry point
# ---------------------------------------------------------------------------

def run_post_worker(
    post_form: "PostFormTarget",
    rate: float,
    waf_hint: str | None,
    model: str,
    cloud_model: str,
    use_cloud: bool,
    timeout_seconds: int,
    result_queue: "multiprocessing.Queue",
    dedup_registry: "DictProxy",
    dedup_lock: Any,
    findings_lock: Any,
    auth_headers: dict[str, str] | None = None,
    crawled_pages: list[str] | None = None,
    sink_url: str | None = None,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
) -> None:
    """Worker entry point for POST form targets. Mirrors run_worker() for GET URLs."""
    start_time = time.monotonic()

    def _put_result(result: WorkerResult) -> None:
        result.duration_seconds = time.monotonic() - start_time
        result_queue.put(result)

    try:
        _run_post(
            post_form=post_form,
            rate=rate,
            waf_hint=waf_hint,
            model=model,
            cloud_model=cloud_model,
            use_cloud=use_cloud,
            timeout_seconds=timeout_seconds,
            dedup_registry=dedup_registry,
            dedup_lock=dedup_lock,
            findings_lock=findings_lock,
            start_time=start_time,
            put_result=_put_result,
            auth_headers=auth_headers,
            crawled_pages=crawled_pages,
            sink_url=sink_url,
            ai_backend=ai_backend,
            cli_tool=cli_tool,
            cli_model=cli_model,
        )
    except Exception as exc:
        log.exception("POST worker crashed for %s", post_form.action_url)
        _put_result(WorkerResult(
            url=post_form.action_url, status="error", error=str(exc)
        ))


def _run_post(
    *,
    post_form: "PostFormTarget",
    rate: float,
    waf_hint: str | None,
    model: str,
    cloud_model: str,
    use_cloud: bool,
    timeout_seconds: int,
    dedup_registry: "DictProxy",
    dedup_lock: Any,
    findings_lock: Any,
    start_time: float,
    put_result: Any,
    auth_headers: dict[str, str] | None = None,
    crawled_pages: list[str] | None = None,
    sink_url: str | None = None,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
) -> None:
    from ai_xss_generator.probe import probe_post_form
    from ai_xss_generator.active.executor import ActiveExecutor
    from ai_xss_generator.active.transforms import all_variants_for_probe
    from ai_xss_generator.parser import parse_target as _parse_target

    deadline = start_time + timeout_seconds

    def _timed_out() -> bool:
        return time.monotonic() > deadline

    if not post_form.param_names:
        put_result(WorkerResult(url=post_form.action_url, status="no_params", waf=waf_hint))
        return

    # Probe all params for reflection
    probe_results = probe_post_form(
        action_url=post_form.action_url,
        source_page_url=post_form.source_page_url,
        param_names=post_form.param_names,
        csrf_field=post_form.csrf_field,
        hidden_defaults=post_form.hidden_defaults,
        rate=rate,
        waf=waf_hint,
        auth_headers=auth_headers,
        crawled_pages=crawled_pages,
        sink_url=sink_url,
    )

    injectable = [r for r in probe_results if r.is_injectable]
    reflected  = [r for r in probe_results if r.is_reflected]

    _cached_context: Any = None
    try:
        _cached_context = _parse_target(
            url=post_form.source_page_url,
            html_value=None,
            waf=waf_hint,
            auth_headers=auth_headers,
        )
    except Exception as exc:
        log.debug("Pre-parse of form source %s failed: %s", post_form.source_page_url, exc)

    post_session_lessons: list[Any] = []
    try:
        from ai_xss_generator.learning import build_memory_profile
        from ai_xss_generator.lessons import build_mapping_lessons, build_probe_lessons

        memory_profile = build_memory_profile(
            context=_cached_context,
            waf_name=waf_hint,
            delivery_mode="post",
            target_host=urllib.parse.urlparse(post_form.action_url).netloc,
        )
        if auth_headers:
            memory_profile["auth_required"] = True
        if _cached_context is not None:
            post_session_lessons.extend(build_mapping_lessons(
                _cached_context,
                memory_profile=memory_profile,
            ))
        if reflected:
            post_session_lessons.extend(build_probe_lessons(
                reflected,
                memory_profile=memory_profile,
                delivery_mode="post",
            ))
    except Exception as exc:
        log.debug("POST lesson build failed for %s: %s", post_form.action_url, exc)

    if not reflected:
        put_result(WorkerResult(
            url=post_form.action_url,
            status="no_reflection",
            waf=waf_hint,
            params_tested=len(post_form.param_names),
        ))
        return

    if not injectable:
        put_result(WorkerResult(
            url=post_form.action_url,
            status="no_reflection",
            waf=waf_hint,
            params_tested=len(post_form.param_names),
            params_reflected=len(reflected),
        ))
        return

    # Start Playwright executor
    executor = ActiveExecutor(auth_headers=auth_headers)
    try:
        executor.start()
    except Exception as exc:
        put_result(WorkerResult(
            url=post_form.action_url, status="error",
            error=f"Playwright start failed: {exc}", waf=waf_hint,
        ))
        return

    confirmed_findings: list[ConfirmedFinding] = []
    total_transforms_tried = 0
    cloud_escalated = False

    try:
        for probe_result in injectable:
            if _timed_out():
                break

            param_name = probe_result.param_name
            param_variants = all_variants_for_probe(probe_result)

            for _pname, context_type, variants in param_variants:
                if _timed_out():
                    break

                context_probe_result = _probe_result_for_context(probe_result, context_type)
                context_confirmed = False

                if not context_confirmed and not _timed_out():
                    local_payloads = _get_local_payloads(
                        url=post_form.source_page_url,
                        probe_result=context_probe_result,
                        model=model,
                        waf=waf_hint,
                        base_context=_cached_context,
                        auth_headers=auth_headers,
                        delivery_mode="post",
                        session_lessons=post_session_lessons,
                    )

                    for lp in local_payloads:
                        if _timed_out():
                            break
                        total_transforms_tried += 1
                        result = executor.fire_post(
                            source_page_url=post_form.source_page_url,
                            action_url=post_form.action_url,
                            param_name=param_name,
                            payload=lp,
                            all_param_names=post_form.param_names,
                            csrf_field=post_form.csrf_field,
                            transform_name="local_model",
                            sink_url=sink_url,
                        )
                        if result.confirmed:
                            finding = _make_finding(
                                url=post_form.action_url,
                                probe_result=context_probe_result,
                                context_type=context_type,
                                result=result,
                                waf=waf_hint,
                                source="local_model",
                                cloud_escalated=False,
                            )
                            confirmed_findings.append(finding)
                            context_confirmed = True
                            break

                if not context_confirmed and use_cloud and not _timed_out():
                    surviving_chars = frozenset().union(
                        *(ctx.surviving_chars for ctx in context_probe_result.reflections)
                    )
                    ekey = _escalation_key(
                        url=post_form.action_url,
                        param_name=param_name,
                        waf=waf_hint,
                        surviving_chars=surviving_chars,
                        context_type=context_type,
                    )
                    cloud_payloads = _get_cloud_payloads(
                        url=post_form.source_page_url,
                        probe_result=context_probe_result,
                        cloud_model=cloud_model,
                        waf=waf_hint,
                        ekey=ekey,
                        dedup_registry=dedup_registry,
                        dedup_lock=dedup_lock,
                        base_context=_cached_context,
                        auth_headers=auth_headers,
                        ai_backend=ai_backend,
                        cli_tool=cli_tool,
                        cli_model=cli_model,
                        delivery_mode="post",
                        session_lessons=post_session_lessons,
                    )
                    if cloud_payloads:
                        cloud_escalated = True

                    for cp in cloud_payloads:
                        if _timed_out():
                            break
                        total_transforms_tried += 1
                        result = executor.fire_post(
                            source_page_url=post_form.source_page_url,
                            action_url=post_form.action_url,
                            param_name=param_name,
                            payload=cp,
                            all_param_names=post_form.param_names,
                            csrf_field=post_form.csrf_field,
                            transform_name="cloud_model",
                            sink_url=sink_url,
                        )
                        if result.confirmed:
                            finding = _make_finding(
                                url=post_form.action_url,
                                probe_result=context_probe_result,
                                context_type=context_type,
                                result=result,
                                waf=waf_hint,
                                source="cloud_model",
                                cloud_escalated=True,
                            )
                            confirmed_findings.append(finding)
                            context_confirmed = True
                            break

                if not context_confirmed and not _timed_out():
                    for variant in variants:
                        if _timed_out():
                            break

                        total_transforms_tried += 1
                        result = executor.fire_post(
                            source_page_url=post_form.source_page_url,
                            action_url=post_form.action_url,
                            param_name=param_name,
                            payload=variant.payload,
                            all_param_names=post_form.param_names,
                            csrf_field=post_form.csrf_field,
                            transform_name=variant.transform_name,
                            sink_url=sink_url,
                        )

                        if result.confirmed:
                            finding = _make_finding(
                                url=post_form.action_url,
                                probe_result=context_probe_result,
                                context_type=context_type,
                                result=result,
                                waf=waf_hint,
                                source="phase1_transform",
                                cloud_escalated=False,
                            )
                            confirmed_findings.append(finding)
                            context_confirmed = True
                            break

    finally:
        executor.stop()

    status = "confirmed" if confirmed_findings else "no_execution"
    put_result(WorkerResult(
        url=post_form.action_url,
        status=status,
        confirmed_findings=confirmed_findings,
        transforms_tried=total_transforms_tried,
        cloud_escalated=cloud_escalated,
        waf=waf_hint,
        params_tested=len(post_form.param_names),
        params_reflected=len(reflected),
        kind="post",
    ))
