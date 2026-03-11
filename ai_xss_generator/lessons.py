from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ai_xss_generator.findings import (
    MEMORY_SOURCE_ALL,
    MEMORY_SOURCE_LABS,
    MEMORY_SOURCE_TARGETS,
    MEMORY_TIER_EXPERIMENTAL,
    REVIEW_STATUS_APPROVED,
    REVIEW_STATUS_PENDING,
    REVIEW_STATUS_REJECTED,
    TARGET_SCOPE_GLOBAL,
    TARGET_SCOPE_HOST,
    TRUSTED_MEMORY_TIERS,
    VALID_MEMORY_SOURCES,
    VALID_MEMORY_TIERS,
    VALID_REVIEW_STATUSES,
    VALID_TARGET_SCOPES,
)


LESSONS_DIR = Path.home() / ".axss" / "lessons"

LESSON_TYPE_MAPPING = "mapping"
LESSON_TYPE_XSS_LOGIC = "xss_logic"
LESSON_TYPE_FILTER = "filter"

VALID_LESSON_TYPES = {
    LESSON_TYPE_MAPPING,
    LESSON_TYPE_XSS_LOGIC,
    LESSON_TYPE_FILTER,
}

PROBE_CHARSET = frozenset('<>"\';\\/`(){}')


@dataclass
class Lesson:
    lesson_type: str
    title: str
    summary: str
    sink_type: str = ""
    context_type: str = ""
    source_pattern: str = ""
    surviving_chars: str = ""
    blocked_chars: str = ""
    target_host: str = ""
    target_scope: str = TARGET_SCOPE_GLOBAL
    waf_name: str = ""
    delivery_mode: str = ""
    frameworks: list[str] = field(default_factory=list)
    auth_required: bool = False
    evidence_type: str = ""
    memory_tier: str = MEMORY_TIER_EXPERIMENTAL
    provenance: str = ""
    confidence: float = 0.0
    review_status: str = REVIEW_STATUS_PENDING
    reviewed_by: str = ""
    reviewed_at: str = ""
    review_note: str = ""
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def normalize_lesson_type(value: str | None) -> str:
    lesson_type = (value or "").strip().lower()
    return lesson_type if lesson_type in VALID_LESSON_TYPES else LESSON_TYPE_MAPPING


def normalize_target_scope(value: str | None) -> str:
    scope = (value or "").strip().lower()
    return scope if scope in VALID_TARGET_SCOPES else TARGET_SCOPE_GLOBAL


def normalize_memory_tier(value: str | None) -> str:
    tier = (value or "").strip().lower()
    return tier if tier in VALID_MEMORY_TIERS else MEMORY_TIER_EXPERIMENTAL


def normalize_review_status(value: str | None, *, tier: str) -> str:
    status = (value or "").strip().lower()
    if status in VALID_REVIEW_STATUSES:
        return status
    if tier == MEMORY_TIER_EXPERIMENTAL:
        return REVIEW_STATUS_PENDING
    return REVIEW_STATUS_APPROVED


def lesson_id(lesson: Lesson) -> str:
    material = "|".join([
        lesson.lesson_type,
        lesson.title,
        lesson.sink_type,
        lesson.context_type,
        lesson.source_pattern,
        lesson.delivery_mode,
        lesson.target_scope,
        lesson.target_host,
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def _partition_path(lesson_type: str) -> Path:
    return LESSONS_DIR / f"{normalize_lesson_type(lesson_type)}.jsonl"


def _lesson_from_dict(data: dict[str, object]) -> Lesson:
    frameworks_raw = data.get("frameworks", [])
    frameworks = [str(item).lower() for item in frameworks_raw] if isinstance(frameworks_raw, list) else []
    return Lesson(
        lesson_type=normalize_lesson_type(str(data.get("lesson_type", ""))),
        title=str(data.get("title", "")),
        summary=str(data.get("summary", "")),
        sink_type=str(data.get("sink_type", "")),
        context_type=str(data.get("context_type", "")),
        source_pattern=str(data.get("source_pattern", "")),
        surviving_chars=str(data.get("surviving_chars", "")),
        blocked_chars=str(data.get("blocked_chars", "")),
        target_host=str(data.get("target_host", "")),
        target_scope=normalize_target_scope(str(data.get("target_scope", ""))),
        waf_name=str(data.get("waf_name", "")).lower(),
        delivery_mode=str(data.get("delivery_mode", "")).lower(),
        frameworks=list(dict.fromkeys(frameworks)),
        auth_required=bool(data.get("auth_required", False)),
        evidence_type=str(data.get("evidence_type", "")),
        memory_tier=normalize_memory_tier(str(data.get("memory_tier", ""))),
        provenance=str(data.get("provenance", "")),
        confidence=float(data.get("confidence", 0.0) or 0.0),
        review_status=normalize_review_status(
            str(data.get("review_status", "")),
            tier=normalize_memory_tier(str(data.get("memory_tier", ""))),
        ),
        reviewed_by=str(data.get("reviewed_by", "")),
        reviewed_at=str(data.get("reviewed_at", "")),
        review_note=str(data.get("review_note", "")),
        ts=str(data.get("ts", "")),
    )


def _load_partition(path: Path) -> list[Lesson]:
    if not path.exists():
        return []
    lessons: list[Lesson] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            lessons.append(_lesson_from_dict(json.loads(line)))
        except Exception:
            continue
    return lessons


def _write_partition(path: Path, lessons: list[Lesson]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not lessons:
        path.write_text("", encoding="utf-8")
        return
    path.write_text(
        "\n".join(json.dumps(asdict(lesson)) for lesson in lessons) + "\n",
        encoding="utf-8",
    )


def _same_identity(existing: Lesson, incoming: Lesson) -> bool:
    if (
        existing.lesson_type != incoming.lesson_type
        or existing.title != incoming.title
        or existing.sink_type != incoming.sink_type
        or existing.context_type != incoming.context_type
        or existing.source_pattern != incoming.source_pattern
        or existing.delivery_mode != incoming.delivery_mode
        or existing.target_scope != incoming.target_scope
    ):
        return False
    if existing.target_scope == TARGET_SCOPE_HOST:
        return existing.target_host == incoming.target_host
    return True


def _merge_lessons(existing: Lesson, incoming: Lesson) -> Lesson:
    return Lesson(
        lesson_type=existing.lesson_type,
        title=existing.title or incoming.title,
        summary=existing.summary if len(existing.summary) >= len(incoming.summary) else incoming.summary,
        sink_type=existing.sink_type or incoming.sink_type,
        context_type=existing.context_type or incoming.context_type,
        source_pattern=existing.source_pattern or incoming.source_pattern,
        surviving_chars=existing.surviving_chars or incoming.surviving_chars,
        blocked_chars=existing.blocked_chars or incoming.blocked_chars,
        target_host=existing.target_host or incoming.target_host,
        target_scope=existing.target_scope,
        waf_name=existing.waf_name or incoming.waf_name,
        delivery_mode=existing.delivery_mode or incoming.delivery_mode,
        frameworks=list(dict.fromkeys([*existing.frameworks, *incoming.frameworks])),
        auth_required=existing.auth_required or incoming.auth_required,
        evidence_type=existing.evidence_type or incoming.evidence_type,
        memory_tier=(
            incoming.memory_tier
            if VALID_MEMORY_TIERS and incoming.memory_tier in TRUSTED_MEMORY_TIERS and existing.memory_tier not in TRUSTED_MEMORY_TIERS
            else existing.memory_tier
        ),
        provenance=existing.provenance or incoming.provenance,
        confidence=max(existing.confidence, incoming.confidence),
        review_status=(
            incoming.review_status
            if incoming.memory_tier in TRUSTED_MEMORY_TIERS and existing.memory_tier not in TRUSTED_MEMORY_TIERS
            else existing.review_status
        ),
        reviewed_by=existing.reviewed_by or incoming.reviewed_by,
        reviewed_at=max(existing.reviewed_at or "", incoming.reviewed_at or ""),
        review_note=existing.review_note if len(existing.review_note) >= len(incoming.review_note) else incoming.review_note,
        ts=max(existing.ts or "", incoming.ts or ""),
    )


def save_lesson(lesson: Lesson) -> bool:
    path = _partition_path(lesson.lesson_type)
    existing = _load_partition(path)
    for i, current in enumerate(existing):
        if _same_identity(current, lesson):
            merged = _merge_lessons(current, lesson)
            if merged == current:
                return False
            existing[i] = merged
            _write_partition(path, existing)
            return True
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(lesson)) + "\n")
    return True


def load_lessons(lesson_type: str | None = None) -> list[Lesson]:
    if not LESSONS_DIR.exists():
        return []
    if lesson_type is not None:
        return _load_partition(_partition_path(lesson_type))
    lessons: list[Lesson] = []
    for path in sorted(LESSONS_DIR.glob("*.jsonl")):
        lessons.extend(_load_partition(path))
    return lessons


def lesson_memory_source(lesson: Lesson) -> str:
    evidence_type = (lesson.evidence_type or "").strip().lower()
    provenance = (lesson.provenance or "").strip().lower()
    if evidence_type.startswith("xssy_") or ".xssy.uk" in provenance or "xssy.uk" in provenance:
        return MEMORY_SOURCE_LABS
    return MEMORY_SOURCE_TARGETS


def _matches_memory_source(lesson: Lesson, memory_source: str) -> bool:
    source = (memory_source or MEMORY_SOURCE_ALL).strip().lower()
    if source not in VALID_MEMORY_SOURCES or source == MEMORY_SOURCE_ALL:
        return True
    return lesson_memory_source(lesson) == source


def review_queue(limit: int = 25, memory_source: str = MEMORY_SOURCE_ALL) -> list[Lesson]:
    candidates = [
        lesson for lesson in load_lessons()
        if lesson.memory_tier == MEMORY_TIER_EXPERIMENTAL
        and lesson.review_status == REVIEW_STATUS_PENDING
        and _matches_memory_source(lesson, memory_source)
    ]

    def _priority(lesson: Lesson) -> tuple[int, int, str]:
        score = 0
        if lesson.evidence_type == "active_probe":
            score += 2
        if lesson.evidence_type.startswith("xssy_"):
            score += 1
        score += int(round(lesson.confidence * 10))
        return (-score, -len(lesson.summary), lesson.ts)

    candidates.sort(key=_priority)
    return candidates[:limit]


def memory_stats(memory_source: str = MEMORY_SOURCE_ALL) -> dict[str, int]:
    lessons = [lesson for lesson in load_lessons() if _matches_memory_source(lesson, memory_source)]
    return {
        "total": len(lessons),
        "curated": sum(1 for lesson in lessons if lesson.memory_tier == "curated"),
        "verified_runtime": sum(1 for lesson in lessons if lesson.memory_tier == "verified-runtime"),
        "experimental": sum(1 for lesson in lessons if lesson.memory_tier == MEMORY_TIER_EXPERIMENTAL),
        "pending_review": sum(1 for lesson in lessons if lesson.review_status == REVIEW_STATUS_PENDING),
        "approved": sum(1 for lesson in lessons if lesson.review_status == REVIEW_STATUS_APPROVED),
        "rejected": sum(1 for lesson in lessons if lesson.review_status == REVIEW_STATUS_REJECTED),
    }


def find_lesson_by_id(lesson_id_value: str) -> Lesson | None:
    needle = lesson_id_value.strip().lower()
    for lesson in load_lessons():
        if lesson_id(lesson) == needle:
            return lesson
    return None


def _replace_lesson(target: Lesson, replacement: Lesson) -> bool:
    path = _partition_path(target.lesson_type)
    existing = _load_partition(path)
    changed = False
    for i, item in enumerate(existing):
        if lesson_id(item) == lesson_id(target):
            existing[i] = replacement
            changed = True
            break
    if changed:
        _write_partition(path, existing)
    return changed


def review_lesson(
    lesson_id_value: str,
    *,
    reviewer: str = "manual-review",
    note: str = "",
    promote_to: str | None = None,
    target_scope: str | None = None,
    reject: bool = False,
) -> Lesson:
    lesson = find_lesson_by_id(lesson_id_value)
    if lesson is None:
        raise KeyError(f"lesson {lesson_id_value!r} not found")

    if reject:
        updated = Lesson(
            **{
                **asdict(lesson),
                "review_status": REVIEW_STATUS_REJECTED,
                "reviewed_by": reviewer,
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
                "review_note": note,
            }
        )
    else:
        next_tier = promote_to or lesson.memory_tier
        if next_tier not in VALID_MEMORY_TIERS:
            raise ValueError(f"invalid memory tier: {next_tier}")
        next_scope = target_scope or lesson.target_scope
        if next_scope not in VALID_TARGET_SCOPES:
            raise ValueError(f"invalid target scope: {next_scope}")
        updated = Lesson(
            **{
                **asdict(lesson),
                "memory_tier": next_tier,
                "target_scope": next_scope,
                "review_status": REVIEW_STATUS_APPROVED,
                "reviewed_by": reviewer,
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
                "review_note": note,
            }
        )

    if not _replace_lesson(lesson, updated):
        raise RuntimeError(f"failed to update lesson {lesson_id_value}")
    return updated


def relevant_lessons(
    *,
    sink_type: str,
    context_type: str,
    surviving_chars: str,
    limit: int = 4,
    allowed_tiers: tuple[str, ...] = TRUSTED_MEMORY_TIERS,
    target_host: str = "",
    waf_name: str = "",
    delivery_mode: str = "",
    frameworks: tuple[str, ...] = (),
    auth_required: bool | None = None,
) -> list[Lesson]:
    all_lessons = load_lessons()
    if not all_lessons:
        return []

    surviving_set = set(surviving_chars)
    framework_set = {item.lower() for item in frameworks}
    scored: list[tuple[int, Lesson]] = []

    for lesson in all_lessons:
        if lesson.memory_tier not in allowed_tiers:
            continue
        if lesson.target_scope == TARGET_SCOPE_HOST and (not target_host or lesson.target_host != target_host):
            continue

        score = 0
        if sink_type and lesson.sink_type == sink_type:
            score += 4
        elif sink_type and lesson.sink_type and (sink_type in lesson.sink_type or lesson.sink_type in sink_type):
            score += 2
        if context_type and lesson.context_type == context_type:
            score += 4
        elif lesson.lesson_type == LESSON_TYPE_MAPPING:
            score += 1
        score += min(len(surviving_set & set(lesson.surviving_chars)), 2)
        if target_host and lesson.target_scope == TARGET_SCOPE_HOST and lesson.target_host == target_host:
            score += 4
        if delivery_mode and lesson.delivery_mode == delivery_mode.lower():
            score += 3
        if waf_name and lesson.waf_name == waf_name.lower():
            score += 2
        if framework_set and lesson.frameworks:
            score += min(len(framework_set & {item.lower() for item in lesson.frameworks}), 2)
        if auth_required is not None and lesson.auth_required == auth_required:
            score += 1
        score += int(round(lesson.confidence * 2))
        if score > 0:
            scored.append((score, lesson))

    scored.sort(key=lambda item: (-item[0], item[1].title))
    return [lesson for _, lesson in scored[:limit]]


def lessons_prompt_section(lessons: list[Lesson]) -> str:
    if not lessons:
        return ""
    lines = [
        "Past logic/filter lessons for similar targets "
        "(use these as reasoning hints; adapt them to the current page):"
    ]
    for lesson in lessons:
        lines.append(
            f"  type={lesson.lesson_type}  title={lesson.title}  "
            f"context={lesson.context_type or '-'}  sink={lesson.sink_type or '-'}  "
            f"delivery={lesson.delivery_mode or '-'}  tier={lesson.memory_tier}"
        )
        lines.append(f"  summary: {lesson.summary}")
        if lesson.surviving_chars or lesson.blocked_chars:
            lines.append(
                f"  filter: surviving={lesson.surviving_chars or '-'} blocked={lesson.blocked_chars or '-'}"
            )
        if lesson.frameworks or lesson.waf_name or lesson.auth_required:
            lines.append(
                f"  landscape: frameworks={','.join(lesson.frameworks) or '-'}  "
                f"waf={lesson.waf_name or '-'}  auth_required={'yes' if lesson.auth_required else 'no'}"
            )
        lines.append("")
    return "\n".join(lines)


def _logic_focus(context_type: str, attr_name: str = "") -> str:
    if context_type == "html_attr_url":
        if attr_name:
            return f"Treat this as URL attribute logic in '{attr_name}': prioritize scheme control, URI rewriting, and tag-free execution paths."
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


def _sorted_chars(chars: str | set[str] | frozenset[str]) -> str:
    return "".join(sorted(set(chars)))


def build_probe_lessons(
    probe_results: list[object],
    *,
    memory_profile: dict[str, object] | None = None,
    delivery_mode: str = "",
    provenance: str = "",
    evidence_type: str = "active_probe",
    memory_tier: str = "verified-runtime",
) -> list[Lesson]:
    memory_profile = memory_profile or {}
    lessons: list[Lesson] = []
    review_status = REVIEW_STATUS_PENDING if memory_tier == MEMORY_TIER_EXPERIMENTAL else REVIEW_STATUS_APPROVED

    for result in probe_results:
        param_name = str(getattr(result, "param_name", "") or "")
        for reflection in getattr(result, "reflections", []):
            context_type = str(getattr(reflection, "context_type", "") or "")
            attr_name = str(getattr(reflection, "attr_name", "") or "")
            surviving = _sorted_chars(getattr(reflection, "surviving_chars", frozenset()))
            blocked = _sorted_chars(PROBE_CHARSET.difference(set(surviving)))
            source_pattern = f"{delivery_mode or memory_profile.get('delivery_mode', '')}:reflection"
            sink_type = f"probe:{context_type}" if context_type else ""

            lessons.append(Lesson(
                lesson_type=LESSON_TYPE_XSS_LOGIC,
                title=f"{context_type or 'unknown'} reflection logic",
                summary=(
                    f"Parameter '{param_name}' reflected via {delivery_mode or memory_profile.get('delivery_mode', 'unknown')} "
                    f"into {context_type}{f'({attr_name})' if attr_name else ''}. "
                    f"{_logic_focus(context_type, attr_name)}"
                ).strip(),
                sink_type=sink_type,
                context_type=context_type,
                source_pattern=source_pattern,
                surviving_chars=surviving,
                blocked_chars=blocked,
                target_host=str(memory_profile.get("target_host", "")),
                target_scope=str(memory_profile.get("target_scope", TARGET_SCOPE_GLOBAL)),
                waf_name=str(memory_profile.get("waf_name", "")),
                delivery_mode=(delivery_mode or str(memory_profile.get("delivery_mode", ""))).lower(),
                frameworks=[str(item).lower() for item in memory_profile.get("frameworks", [])],
                auth_required=bool(memory_profile.get("auth_required", False)),
                evidence_type=evidence_type,
                memory_tier=memory_tier,
                provenance=provenance,
                confidence=0.88,
                review_status=review_status,
            ))

            lessons.append(Lesson(
                lesson_type=LESSON_TYPE_FILTER,
                title=f"{context_type or 'unknown'} filter profile",
                summary=(
                    f"For {context_type or 'unknown'} reflections, the filter preserved {surviving or 'no critical chars'} "
                    f"and blocked {blocked or 'none of the probe charset'}. "
                    "Bias toward techniques that only require the surviving set."
                ),
                sink_type=sink_type,
                context_type=context_type,
                source_pattern=source_pattern,
                surviving_chars=surviving,
                blocked_chars=blocked,
                target_host=str(memory_profile.get("target_host", "")),
                target_scope=str(memory_profile.get("target_scope", TARGET_SCOPE_GLOBAL)),
                waf_name=str(memory_profile.get("waf_name", "")),
                delivery_mode=(delivery_mode or str(memory_profile.get("delivery_mode", ""))).lower(),
                frameworks=[str(item).lower() for item in memory_profile.get("frameworks", [])],
                auth_required=bool(memory_profile.get("auth_required", False)),
                evidence_type=evidence_type,
                memory_tier=memory_tier,
                provenance=provenance,
                confidence=0.92,
                review_status=review_status,
            ))

    return lessons


def build_mapping_lessons(
    context: object,
    *,
    memory_profile: dict[str, object] | None = None,
    evidence_type: str = "parsed_context",
    memory_tier: str = MEMORY_TIER_EXPERIMENTAL,
    provenance: str = "",
) -> list[Lesson]:
    memory_profile = memory_profile or {}
    lessons: list[Lesson] = []
    review_status = REVIEW_STATUS_PENDING if memory_tier == MEMORY_TIER_EXPERIMENTAL else REVIEW_STATUS_APPROVED
    forms = list(getattr(context, "forms", []) or [])
    dom_sinks = list(getattr(context, "dom_sinks", []) or [])
    frameworks = [str(item).lower() for item in getattr(context, "frameworks", []) if str(item).strip()]
    auth_notes = list(getattr(context, "auth_notes", []) or [])
    delivery_mode = str(memory_profile.get("delivery_mode", "")).lower()

    if forms:
        post_forms = [form for form in forms if str(getattr(form, "method", "")).upper() == "POST"]
        summary = (
            f"Page exposes {len(forms)} form(s)"
            + (f", including {len(post_forms)} POST workflow(s)" if post_forms else "")
            + ". Map follow-up pages and state-changing routes; stored or session-backed reflections often render away from the source page."
        )
        lessons.append(Lesson(
            lesson_type=LESSON_TYPE_MAPPING,
            title="Form workflow surface",
            summary=summary,
            source_pattern="forms:post" if post_forms else "forms:get",
            target_host=str(memory_profile.get("target_host", "")),
            target_scope=str(memory_profile.get("target_scope", TARGET_SCOPE_GLOBAL)),
            waf_name=str(memory_profile.get("waf_name", "")),
            delivery_mode=delivery_mode,
            frameworks=frameworks,
            auth_required=bool(memory_profile.get("auth_required", False)),
            evidence_type=evidence_type,
            memory_tier=memory_tier,
            provenance=provenance,
            confidence=0.64,
            review_status=review_status,
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
                "Inspect route state, fragment/query parsing, and JS-driven rendering before assuming only server reflections matter."
            ),
            source_pattern=f"dom-source:{','.join(dom_sources)}",
            target_host=str(memory_profile.get("target_host", "")),
            target_scope=str(memory_profile.get("target_scope", TARGET_SCOPE_GLOBAL)),
            waf_name=str(memory_profile.get("waf_name", "")),
            delivery_mode=delivery_mode or "dom",
            frameworks=frameworks,
            auth_required=bool(memory_profile.get("auth_required", False)),
            evidence_type=evidence_type,
            memory_tier=memory_tier,
            provenance=provenance,
            confidence=0.72,
            review_status=review_status,
        ))

    if frameworks:
        lessons.append(Lesson(
            lesson_type=LESSON_TYPE_MAPPING,
            title="Framework rendering surface",
            summary=(
                f"Framework hints detected ({', '.join(frameworks)}). "
                "Bias mapping toward client templates, component props/state, dynamic routes, and framework-specific HTML insertion paths."
            ),
            source_pattern=f"framework:{','.join(frameworks)}",
            target_host=str(memory_profile.get("target_host", "")),
            target_scope=str(memory_profile.get("target_scope", TARGET_SCOPE_GLOBAL)),
            waf_name=str(memory_profile.get("waf_name", "")),
            delivery_mode=delivery_mode,
            frameworks=frameworks,
            auth_required=bool(memory_profile.get("auth_required", False)),
            evidence_type=evidence_type,
            memory_tier=memory_tier,
            provenance=provenance,
            confidence=0.58,
            review_status=review_status,
        ))

    if auth_notes or bool(memory_profile.get("auth_required", False)):
        lessons.append(Lesson(
            lesson_type=LESSON_TYPE_MAPPING,
            title="Authenticated workflow surface",
            summary=(
                "Authenticated pages deserve follow-up mapping across profile, dashboard, settings, and other stateful flows; "
                "stored and privileged reflections often render after navigation rather than on the injection page."
            ),
            source_pattern="authenticated",
            target_host=str(memory_profile.get("target_host", "")),
            target_scope=str(memory_profile.get("target_scope", TARGET_SCOPE_GLOBAL)),
            waf_name=str(memory_profile.get("waf_name", "")),
            delivery_mode=delivery_mode,
            frameworks=frameworks,
            auth_required=True,
            evidence_type=evidence_type,
            memory_tier=memory_tier,
            provenance=provenance,
            confidence=0.7,
            review_status=review_status,
        ))

    return lessons
