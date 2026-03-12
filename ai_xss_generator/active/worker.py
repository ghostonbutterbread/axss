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
import queue
import threading
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

_ACTIVE_LOCAL_MODEL_TIMEOUT_SECONDS = 60
_ACTIVE_CLOUD_GRACE_SECONDS = 60
_DOM_CLOUD_START_AFTER_SECONDS = 30


def active_worker_timeout_budget(timeout_seconds: int, use_cloud: bool) -> int:
    """Return the effective per-worker budget for staged local+cloud execution."""
    minimum = _ACTIVE_LOCAL_MODEL_TIMEOUT_SECONDS
    if use_cloud:
        minimum += _ACTIVE_CLOUD_GRACE_SECONDS
    return max(timeout_seconds, minimum)


def _start_async_payload_stage(fn: Any) -> tuple[threading.Thread, "queue.Queue[list[str]]"]:
    """Run a payload-generation callable in a daemon thread and capture its result."""
    out: "queue.Queue[list[str]]" = queue.Queue(maxsize=1)

    def _runner() -> None:
        try:
            payloads = fn() or []
        except Exception:
            payloads = []
        try:
            out.put_nowait(payloads)
        except queue.Full:
            pass

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    return thread, out


def _poll_async_payloads(out: "queue.Queue[list[str]]") -> tuple[bool, list[str]]:
    try:
        return True, out.get_nowait()
    except queue.Empty:
        return False, []


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
    deadline = start_time + active_worker_timeout_budget(timeout_seconds, use_cloud)
    local_model_timeout_seconds = _ACTIVE_LOCAL_MODEL_TIMEOUT_SECONDS

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
                        local_timeout_seconds=local_model_timeout_seconds,
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
    local_timeout_seconds: int = _ACTIVE_LOCAL_MODEL_TIMEOUT_SECONDS,
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
            local_timeout_seconds=local_timeout_seconds,
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


def _inject_dom_source(url: str, source_type: str, source_name: str, value: str) -> str:
    """Return *url* with *value* injected into the specified DOM-controlled source."""
    from ai_xss_generator.active.dom_xss import _inject_source
    return _inject_source(url, source_type, source_name, value)


def _build_dom_context(
    *,
    base_context: Any,
    url: str,
    source_type: str,
    source_name: str,
    sink: str,
    code_location: str = "",
    auth_headers: dict[str, str] | None = None,
) -> Any:
    """Build a ParsedContext focused on one DOM source → sink taint path."""
    from dataclasses import replace as dc_replace
    from ai_xss_generator.types import DomSink, ParsedContext

    if base_context is None:
        base_context = ParsedContext(source=url, source_type="url")

    source_sink = "location.hash" if source_type == "fragment" else "location.search"
    dom_note = (
        "[dom:TAINT] "
        + json.dumps({
            "source_type": source_type,
            "source_name": source_name,
            "sink": sink,
            "code_location": code_location,
        }, sort_keys=True)
    )
    extra_sinks = [
        DomSink(
            sink=sink,
            source=f"dom_runtime_taint:{source_type}:{source_name}",
            location=code_location or f"dom_runtime:{source_type}:{source_name}",
            confidence=0.99,
        ),
        DomSink(
            sink=f"dom_source:{source_sink}",
            source=f"dom_runtime_source:{source_name}",
            location=f"dom_runtime:{source_type}:{source_name}",
            confidence=0.99,
        ),
    ]

    auth_notes = list(getattr(base_context, "auth_notes", []) or [])
    if auth_headers and not auth_notes:
        auth_notes.append("Authenticated DOM scan context")

    return dc_replace(
        base_context,
        dom_sinks=extra_sinks + list(getattr(base_context, "dom_sinks", []) or []),
        notes=[dom_note, *list(getattr(base_context, "notes", []) or [])],
        auth_notes=auth_notes,
    )


def _get_dom_local_payloads(
    *,
    context: Any,
    model: str,
    waf: str | None,
    session_lessons: list[Any] | None = None,
    local_timeout_seconds: int = _ACTIVE_LOCAL_MODEL_TIMEOUT_SECONDS,
) -> list[str]:
    """Ask the local model for DOM XSS payloads for one tainted source → sink path."""
    try:
        from ai_xss_generator.models import generate_dom_local_payloads
        from ai_xss_generator.learning import build_memory_profile

        memory_profile = build_memory_profile(
            context=context,
            waf_name=waf,
            delivery_mode="dom",
        )
        payloads, engine = generate_dom_local_payloads(
            context=context,
            model=model,
            waf=waf,
            memory_profile=memory_profile,
            past_lessons=session_lessons,
            local_timeout_seconds=local_timeout_seconds,
        )
        return [
            p.payload
            for p in payloads
            if p.payload and getattr(p, "source", "heuristic") != "heuristic"
        ]
    except Exception as exc:
        log.debug("DOM local model failed for %s: %s", getattr(context, "source", "?"), exc)
        return []


def _get_dom_cloud_payloads(
    *,
    context: Any,
    cloud_model: str,
    waf: str | None,
    ekey: str,
    dedup_registry: DictProxy,
    dedup_lock: Any,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
    session_lessons: list[Any] | None = None,
) -> list[str]:
    """Call the cloud model once per unique DOM source → sink fingerprint."""
    with dedup_lock:
        if ekey in dedup_registry:
            log.debug("DOM dedup hit — reusing cloud result for key %s", ekey[:12])
            return dedup_registry[ekey]

    try:
        from ai_xss_generator.models import generate_cloud_payloads
        from ai_xss_generator.learning import build_memory_profile

        memory_profile = build_memory_profile(
            context=context,
            waf_name=waf,
            delivery_mode="dom",
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
        log.debug("DOM cloud model failed for %s: %s", getattr(context, "source", "?"), exc)
        result_strings = []

    with dedup_lock:
        dedup_registry[ekey] = result_strings
    return result_strings


# ---------------------------------------------------------------------------
# DOM XSS worker entry point
# ---------------------------------------------------------------------------

def run_dom_worker(
    url: str,
    waf_hint: str | None,
    model: str,
    cloud_model: str,
    use_cloud: bool,
    timeout_seconds: int,
    result_queue: "multiprocessing.Queue",
    dedup_registry: "DictProxy",
    dedup_lock: Any,
    auth_headers: dict[str, str] | None = None,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
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
            model=model,
            cloud_model=cloud_model,
            use_cloud=use_cloud,
            timeout_seconds=timeout_seconds,
            put_result=_put_result,
            dedup_registry=dedup_registry,
            dedup_lock=dedup_lock,
            auth_headers=auth_headers,
            ai_backend=ai_backend,
            cli_tool=cli_tool,
            cli_model=cli_model,
        )
    except Exception as exc:
        log.exception("DOM worker crashed for %s", url)
        _put_result(WorkerResult(url=url, status="error", error=str(exc), kind="dom"))


def _run_dom(
    *,
    url: str,
    waf_hint: str | None,
    model: str,
    cloud_model: str,
    use_cloud: bool,
    timeout_seconds: int,
    put_result: Any,
    dedup_registry: "DictProxy",
    dedup_lock: Any,
    auth_headers: dict[str, str] | None = None,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
) -> None:
    from playwright.sync_api import sync_playwright
    from ai_xss_generator.active.dom_xss import (
        attempt_dom_payloads,
        discover_dom_taint_paths,
        fallback_payloads_for_sink,
    )
    from ai_xss_generator.parser import parse_target as _parse_target

    started_at = time.monotonic()
    deadline = started_at + active_worker_timeout_budget(timeout_seconds, use_cloud)

    def _timed_out() -> bool:
        return time.monotonic() > deadline

    # Cap per-navigation timeout to 15 s regardless of the overall worker timeout
    nav_timeout_ms = min(timeout_seconds * 1_000, 15_000)
    local_model_timeout_seconds = _ACTIVE_LOCAL_MODEL_TIMEOUT_SECONDS
    _cached_context: Any = None
    try:
        _cached_context = _parse_target(
            url=url,
            html_value=None,
            waf=waf_hint,
            auth_headers=auth_headers,
        )
    except Exception as exc:
        log.debug("Pre-parse of DOM target %s failed: %s", url, exc)

    dom_session_lessons: list[Any] = []
    try:
        from ai_xss_generator.learning import build_memory_profile
        from ai_xss_generator.lessons import build_mapping_lessons

        memory_profile = build_memory_profile(
            context=_cached_context,
            waf_name=waf_hint,
            delivery_mode="dom",
        )
        if auth_headers:
            memory_profile["auth_required"] = True
        if _cached_context is not None:
            dom_session_lessons.extend(build_mapping_lessons(
                _cached_context,
                memory_profile=memory_profile,
            ))
    except Exception as exc:
        log.debug("DOM lesson build failed for %s: %s", url, exc)

    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        try:
            dom_hits = discover_dom_taint_paths(url, browser, auth_headers, timeout_ms=nav_timeout_ms)
        finally:
            browser.close()
            pw.stop()
    except Exception as exc:
        put_result(WorkerResult(
            url=url, status="error", error=f"DOM XSS scan failed: {exc}", kind="dom",
        ))
        return

    findings: list[ConfirmedFinding] = []
    cloud_escalated = False

    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        try:
            for hit in dom_hits:
                if _timed_out():
                    break
                dom_context = _build_dom_context(
                    base_context=_cached_context,
                    url=url,
                    source_type=hit.source_type,
                    source_name=hit.source_name,
                    sink=hit.sink,
                    code_location=hit.code_location,
                    auth_headers=auth_headers,
                )
                confirmed = False
                fired_payload = ""
                fired_url = hit.canary_url
                detail = (
                    f"DOM taint confirmed — canary reached sink '{hit.sink}' via "
                    f"{hit.source_type}:{hit.source_name!r}. "
                    f"Real payload did not execute (possible CSP or payload mismatch)."
                )
                source = "dom_xss_runtime"
                transform_name = "dom_xss_runtime"
                cloud_used_for_hit = False
                local_stage = None
                local_done = False
                local_payloads: list[str] = []
                local_payloads_tried = False
                cloud_stage = None
                cloud_done = False
                cloud_payloads: list[str] = []
                cloud_delay_deadline = time.monotonic() + _DOM_CLOUD_START_AFTER_SECONDS
                cloud_ekey = _escalation_key(
                    url=url,
                    param_name=hit.source_name,
                    waf=waf_hint,
                    surviving_chars=frozenset(),
                    context_type=f"dom:{hit.source_type}:{hit.sink}",
                )

                if not _timed_out():
                    local_stage = _start_async_payload_stage(lambda: _get_dom_local_payloads(
                        context=dom_context,
                        model=model,
                        waf=waf_hint,
                        session_lessons=dom_session_lessons,
                        local_timeout_seconds=local_model_timeout_seconds,
                    ))

                def _try_dom_payloads(payloads: list[str], stage_name: str) -> bool:
                    nonlocal confirmed, fired_payload, fired_url, detail
                    nonlocal source, transform_name, local_payloads_tried, cloud_used_for_hit, cloud_escalated
                    if not payloads or _timed_out():
                        return False
                    exec_ok, exec_payload, exec_detail = attempt_dom_payloads(
                        browser=browser,
                        url=url,
                        source_type=hit.source_type,
                        source_name=hit.source_name,
                        sink=hit.sink,
                        payloads=payloads,
                        auth_headers=auth_headers or {},
                        timeout_ms=nav_timeout_ms,
                    )
                    if stage_name == "local_model":
                        local_payloads_tried = True
                    if stage_name == "cloud_model":
                        cloud_used_for_hit = True
                        cloud_escalated = True
                    if exec_ok:
                        confirmed = True
                        fired_payload = exec_payload
                        fired_url = _inject_dom_source(url, hit.source_type, hit.source_name, exec_payload)
                        detail = exec_detail
                        source = stage_name
                        transform_name = stage_name
                        return True
                    return False

                while not confirmed and not _timed_out():
                    if local_stage is not None and not local_done:
                        local_ready, payloads = _poll_async_payloads(local_stage[1])
                        if local_ready:
                            local_done = True
                            local_payloads = payloads
                            if _try_dom_payloads(local_payloads, "local_model"):
                                break

                    if use_cloud and cloud_stage is None:
                        should_start_cloud = (
                            local_done
                        ) or (not local_done and time.monotonic() >= cloud_delay_deadline)
                        if should_start_cloud:
                            cloud_stage = _start_async_payload_stage(lambda: _get_dom_cloud_payloads(
                                context=dom_context,
                                cloud_model=cloud_model,
                                waf=waf_hint,
                                ekey=cloud_ekey,
                                dedup_registry=dedup_registry,
                                dedup_lock=dedup_lock,
                                ai_backend=ai_backend,
                                cli_tool=cli_tool,
                                cli_model=cli_model,
                                session_lessons=dom_session_lessons,
                            ))

                    if cloud_stage is not None and not cloud_done:
                        cloud_ready, payloads = _poll_async_payloads(cloud_stage[1])
                        if cloud_ready:
                            cloud_done = True
                            cloud_payloads = payloads
                            if _try_dom_payloads(cloud_payloads, "cloud_model"):
                                break

                    if local_done and cloud_done:
                        break
                    if local_done and local_payloads_tried and (not use_cloud or cloud_done):
                        break
                    if local_done and not local_payloads and not use_cloud:
                        break
                    time.sleep(0.05)

                if not confirmed and not _timed_out():
                    fallback_payloads = fallback_payloads_for_sink(hit.sink)
                    exec_ok, exec_payload, exec_detail = attempt_dom_payloads(
                        browser=browser,
                        url=url,
                        source_type=hit.source_type,
                        source_name=hit.source_name,
                        sink=hit.sink,
                        payloads=fallback_payloads,
                        auth_headers=auth_headers or {},
                        timeout_ms=nav_timeout_ms,
                    )
                    if exec_ok:
                        confirmed = True
                        fired_payload = exec_payload
                        fired_url = _inject_dom_source(url, hit.source_type, hit.source_name, exec_payload)
                        detail = exec_detail
                        source = "phase1_transform"
                        transform_name = "dom_static_fallback"

                findings.append(
                    ConfirmedFinding(
                        url=url,
                        param_name=hit.source_name,
                        context_type="dom_xss",
                        sink_context=hit.sink,
                        payload=fired_payload,
                        transform_name=transform_name,
                        execution_method="dom_xss" if confirmed else "dom_taint",
                        execution_detail=detail,
                        waf=waf_hint,
                        surviving_chars="",
                        fired_url=fired_url,
                        source=source,
                        cloud_escalated=cloud_used_for_hit,
                        code_location=hit.code_location,
                    )
                )
        finally:
            browser.close()
            pw.stop()
    except Exception as exc:
        put_result(WorkerResult(
            url=url, status="error", error=f"DOM XSS payload execution failed: {exc}", kind="dom",
        ))
        return

    if any(f.execution_method == "dom_xss" for f in findings):
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
        cloud_escalated=cloud_escalated,
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

    deadline = start_time + active_worker_timeout_budget(timeout_seconds, use_cloud)
    local_model_timeout_seconds = _ACTIVE_LOCAL_MODEL_TIMEOUT_SECONDS

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
                        local_timeout_seconds=local_model_timeout_seconds,
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
