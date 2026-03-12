"""Ephemeral probe-observation lessons — in-memory only, never persisted.

Lessons capture what the active probe observed about a target during a single
scan session: reflection context, filter behavior, form surface, framework
hints.  They are built once from probe results and passed directly to the
payload generator as few-shot context.  They are discarded when the scan ends.

Nothing in this module touches disk.
"""
from __future__ import annotations

from dataclasses import dataclass, field


LESSON_TYPE_MAPPING  = "mapping"
LESSON_TYPE_XSS_LOGIC = "xss_logic"
LESSON_TYPE_FILTER   = "filter"

VALID_LESSON_TYPES = {LESSON_TYPE_MAPPING, LESSON_TYPE_XSS_LOGIC, LESSON_TYPE_FILTER}

PROBE_CHARSET = frozenset('<>"\';\\/`(){}')


@dataclass
class Lesson:
    """An ephemeral observation from a single scan session."""
    lesson_type: str
    title: str
    summary: str
    sink_type: str = ""
    context_type: str = ""
    source_pattern: str = ""
    surviving_chars: str = ""
    blocked_chars: str = ""
    waf_name: str = ""
    delivery_mode: str = ""
    frameworks: list[str] = field(default_factory=list)
    auth_required: bool = False
    confidence: float = 0.0


# ---------------------------------------------------------------------------
# Prompt formatting
# ---------------------------------------------------------------------------

def lessons_prompt_section(lessons: list[Lesson]) -> str:
    if not lessons:
        return ""
    lines = [
        "Active probe observations for this target "
        "(use as reasoning context — these reflect what this target actually does):"
    ]
    for lesson in lessons:
        lines.append(
            f"  type={lesson.lesson_type}  title={lesson.title}  "
            f"context={lesson.context_type or '-'}  sink={lesson.sink_type or '-'}  "
            f"delivery={lesson.delivery_mode or '-'}"
        )
        lines.append(f"  summary: {lesson.summary}")
        if lesson.surviving_chars or lesson.blocked_chars:
            lines.append(
                f"  filter: surviving={lesson.surviving_chars or '-'} "
                f"blocked={lesson.blocked_chars or '-'}"
            )
        if lesson.frameworks or lesson.waf_name or lesson.auth_required:
            lines.append(
                f"  landscape: frameworks={','.join(lesson.frameworks) or '-'}  "
                f"waf={lesson.waf_name or '-'}  "
                f"auth_required={'yes' if lesson.auth_required else 'no'}"
            )
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Builder helpers
# ---------------------------------------------------------------------------

def _sorted_chars(chars: str | set[str] | frozenset[str]) -> str:
    return "".join(sorted(set(chars)))


def _logic_focus(context_type: str, attr_name: str = "") -> str:
    if context_type == "html_attr_url":
        if attr_name:
            return (
                f"Treat this as URL attribute logic in '{attr_name}': "
                "prioritize scheme control, URI rewriting, and tag-free execution paths."
            )
        return "Treat this as URL attribute logic: prioritize scheme control, URI rewriting, and tag-free execution paths."
    if context_type == "html_attr_value":
        return "Treat this as generic attribute logic: quote breakout or full-tag escape matters more than raw body payloads."
    if context_type == "html_attr_event":
        return "Treat this as event-handler logic: the value already lands in JavaScript-capable attribute space."
    if context_type == "html_body":
        return "Treat this as raw HTML reflection logic: element injection and event handlers are the primary execution paths."
    if context_type == "html_comment":
        return "Treat this as comment reflection logic: comment closure and HTML re-entry are the relevant pivots."
    if context_type.startswith("js_string_"):
        return "Treat this as JavaScript string logic: string breakout and statement recovery matter more than HTML tags."
    if context_type == "js_code":
        return "Treat this as JavaScript code logic: expression-level injection is the primary path."
    if context_type == "json_value":
        return "Treat this as JSON/value logic: structural escape or downstream HTML/JS consumers matter more than direct HTML tags."
    return "Treat this as a context-specific reflection and bias toward sink-aware testing rather than generic payloads."


def build_probe_lessons(
    probe_results: list[object],
    *,
    memory_profile: dict[str, object] | None = None,
    delivery_mode: str = "",
    **_kwargs: object,  # absorb legacy params (provenance, evidence_type, memory_tier)
) -> list[Lesson]:
    """Build ephemeral lessons from active probe results.

    One XSS_LOGIC lesson and one FILTER lesson per reflection context found.
    """
    memory_profile = memory_profile or {}
    lessons: list[Lesson] = []

    for result in probe_results:
        param_name = str(getattr(result, "param_name", "") or "")
        for reflection in getattr(result, "reflections", []):
            context_type = str(getattr(reflection, "context_type", "") or "")
            attr_name    = str(getattr(reflection, "attr_name", "") or "")
            surviving    = _sorted_chars(getattr(reflection, "surviving_chars", frozenset()))
            blocked      = _sorted_chars(PROBE_CHARSET.difference(set(surviving)))
            dm           = delivery_mode or str(memory_profile.get("delivery_mode", ""))
            sink_type    = f"probe:{context_type}" if context_type else ""
            waf          = str(memory_profile.get("waf_name", ""))
            fw           = [str(f).lower() for f in memory_profile.get("frameworks", [])]
            auth         = bool(memory_profile.get("auth_required", False))

            lessons.append(Lesson(
                lesson_type=LESSON_TYPE_XSS_LOGIC,
                title=f"{context_type or 'unknown'} reflection logic",
                summary=(
                    f"Parameter '{param_name}' reflected via {dm or 'unknown'} "
                    f"into {context_type}{f'({attr_name})' if attr_name else ''}. "
                    f"{_logic_focus(context_type, attr_name)}"
                ).strip(),
                sink_type=sink_type,
                context_type=context_type,
                source_pattern=f"{dm}:reflection",
                surviving_chars=surviving,
                blocked_chars=blocked,
                waf_name=waf,
                delivery_mode=dm,
                frameworks=fw,
                auth_required=auth,
                confidence=0.88,
            ))

            lessons.append(Lesson(
                lesson_type=LESSON_TYPE_FILTER,
                title=f"{context_type or 'unknown'} filter profile",
                summary=(
                    f"For {context_type or 'unknown'} reflections, the filter preserved "
                    f"{surviving or 'no critical chars'} and blocked "
                    f"{blocked or 'none of the probe charset'}. "
                    "Bias toward techniques that only require the surviving set."
                ),
                sink_type=sink_type,
                context_type=context_type,
                source_pattern=f"{dm}:reflection",
                surviving_chars=surviving,
                blocked_chars=blocked,
                waf_name=waf,
                delivery_mode=dm,
                frameworks=fw,
                auth_required=auth,
                confidence=0.92,
            ))

    return lessons


def build_mapping_lessons(
    context: object,
    *,
    memory_profile: dict[str, object] | None = None,
    **_kwargs: object,  # absorb legacy params (evidence_type, memory_tier, provenance)
) -> list[Lesson]:
    """Build ephemeral surface-mapping lessons from a parsed page context."""
    memory_profile = memory_profile or {}
    lessons: list[Lesson] = []
    forms      = list(getattr(context, "forms", []) or [])
    dom_sinks  = list(getattr(context, "dom_sinks", []) or [])
    frameworks = [str(f).lower() for f in getattr(context, "frameworks", []) if str(f).strip()]
    auth_notes = list(getattr(context, "auth_notes", []) or [])
    dm         = str(memory_profile.get("delivery_mode", "")).lower()
    waf        = str(memory_profile.get("waf_name", ""))
    auth       = bool(memory_profile.get("auth_required", False))

    if forms:
        post_forms = [f for f in forms if str(getattr(f, "method", "")).upper() == "POST"]
        summary = (
            f"Page exposes {len(forms)} form(s)"
            + (f", including {len(post_forms)} POST workflow(s)" if post_forms else "")
            + ". Map follow-up pages and state-changing routes; stored or session-backed "
              "reflections often render away from the source page."
        )
        lessons.append(Lesson(
            lesson_type=LESSON_TYPE_MAPPING,
            title="Form workflow surface",
            summary=summary,
            source_pattern="forms:post" if post_forms else "forms:get",
            waf_name=waf,
            delivery_mode=dm,
            frameworks=frameworks,
            auth_required=auth,
            confidence=0.64,
        ))

    dom_sources = sorted({
        str(getattr(sink, "sink", "")).split(":", 1)[1]
        for sink in dom_sinks
        if str(getattr(sink, "sink", "")).startswith("dom_source:")
    })
    if dom_sources:
        lessons.append(Lesson(
            lesson_type=LESSON_TYPE_MAPPING,
            title="Client-side source surface",
            summary=(
                f"Client-side sources detected ({', '.join(dom_sources)}). "
                "Inspect route state, fragment/query parsing, and JS-driven rendering "
                "before assuming only server reflections matter."
            ),
            source_pattern=f"dom-source:{','.join(dom_sources)}",
            waf_name=waf,
            delivery_mode=dm or "dom",
            frameworks=frameworks,
            auth_required=auth,
            confidence=0.72,
        ))

    if frameworks:
        lessons.append(Lesson(
            lesson_type=LESSON_TYPE_MAPPING,
            title="Framework rendering surface",
            summary=(
                f"Framework hints detected ({', '.join(frameworks)}). "
                "Bias mapping toward client templates, component props/state, dynamic routes, "
                "and framework-specific HTML insertion paths."
            ),
            source_pattern=f"framework:{','.join(frameworks)}",
            waf_name=waf,
            delivery_mode=dm,
            frameworks=frameworks,
            auth_required=auth,
            confidence=0.58,
        ))

    if auth_notes or auth:
        lessons.append(Lesson(
            lesson_type=LESSON_TYPE_MAPPING,
            title="Authenticated workflow surface",
            summary=(
                "Authenticated pages deserve follow-up mapping across profile, dashboard, "
                "settings, and other stateful flows; stored and privileged reflections often "
                "render after navigation rather than on the injection page."
            ),
            source_pattern="authenticated",
            waf_name=waf,
            delivery_mode=dm,
            frameworks=frameworks,
            auth_required=True,
            confidence=0.70,
        ))

    return lessons
