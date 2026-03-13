from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, replace
from typing import Any

from ai_xss_generator.types import ParsedContext


PROFILE_NOTE_PREFIX = "[behavior:PROFILE] "

_BROWSER_REQUIRED_WAFS = frozenset({
    "akamai", "cloudflare", "datadome", "kasada", "perimeterx",
})


@dataclass(slots=True)
class ParamBehavior:
    name: str
    discovery_style: str = ""
    reflection_transform: str = ""
    reflected: bool = False
    injectable: bool = False
    contexts: list[str] | None = None
    surviving_chars: str = ""
    probe_mode: str = ""
    tested_chars: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "discovery_style": self.discovery_style,
            "reflection_transform": self.reflection_transform,
            "reflected": self.reflected,
            "injectable": self.injectable,
            "contexts": list(self.contexts or []),
            "surviving_chars": self.surviving_chars,
            "probe_mode": self.probe_mode,
            "tested_chars": self.tested_chars,
        }


@dataclass(slots=True)
class TargetBehaviorProfile:
    delivery_mode: str
    target_host: str = ""
    target_path: str = ""
    waf_name: str = ""
    browser_required: bool = False
    auth_required: bool = False
    frameworks: list[str] | None = None
    reflected_params: int = 0
    injectable_params: int = 0
    reflection_contexts: list[str] | None = None
    reflection_transforms: list[str] | None = None
    discovery_styles: list[str] | None = None
    probe_modes: list[str] | None = None
    tested_charsets: list[str] | None = None
    dom_sources: list[str] | None = None
    dom_sinks: list[str] | None = None
    observations: list[str] | None = None
    params: list[ParamBehavior] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "delivery_mode": self.delivery_mode,
            "target_host": self.target_host,
            "target_path": self.target_path,
            "waf_name": self.waf_name,
            "browser_required": self.browser_required,
            "auth_required": self.auth_required,
            "frameworks": list(self.frameworks or []),
            "reflected_params": self.reflected_params,
            "injectable_params": self.injectable_params,
            "reflection_contexts": list(self.reflection_contexts or []),
            "reflection_transforms": list(self.reflection_transforms or []),
            "discovery_styles": list(self.discovery_styles or []),
            "probe_modes": list(self.probe_modes or []),
            "tested_charsets": list(self.tested_charsets or []),
            "dom_sources": list(self.dom_sources or []),
            "dom_sinks": list(self.dom_sinks or []),
            "observations": list(self.observations or []),
            "params": [item.to_dict() for item in (self.params or [])],
        }

    def to_note(self) -> str:
        return PROFILE_NOTE_PREFIX + json.dumps(self.to_dict(), sort_keys=True)


@dataclass(slots=True)
class AIEscalationPolicy:
    use_local: bool = True
    local_timeout_seconds: int = 60
    cloud_start_after_seconds: float | None = None
    note: str = ""


@dataclass(slots=True)
class TargetDisposition:
    tier: str = "live"
    is_dead: bool = False
    reason: str = ""


def build_target_behavior_profile(
    *,
    url: str,
    delivery_mode: str,
    waf_name: str | None = None,
    auth_required: bool = False,
    context: ParsedContext | None = None,
    probe_results: list[Any] | None = None,
    dom_hits: list[Any] | None = None,
) -> TargetBehaviorProfile:
    probe_results = probe_results or []
    dom_hits = dom_hits or []
    parsed = urllib.parse.urlparse(url)
    waf = (waf_name or "").lower()
    browser_required = waf in _BROWSER_REQUIRED_WAFS

    frameworks = [
        str(item).lower()
        for item in getattr(context, "frameworks", []) or []
        if str(item).strip()
    ]
    dom_sources = sorted({
        str(hit.source_type)
        for hit in dom_hits
        if str(getattr(hit, "source_type", "")).strip()
    })
    if context is not None:
        dom_sources = sorted(set(dom_sources).union({
            str(getattr(sink, "sink", "")).split(":", 1)[1]
            for sink in getattr(context, "dom_sinks", []) or []
            if str(getattr(sink, "sink", "")).startswith("dom_source:")
        }))

    dom_sinks = sorted({
        str(hit.sink)
        for hit in dom_hits
        if str(getattr(hit, "sink", "")).strip()
    })
    if context is not None:
        dom_sinks = sorted(set(dom_sinks).union({
            str(getattr(sink, "sink", ""))
            for sink in getattr(context, "dom_sinks", []) or []
            if str(getattr(sink, "sink", "")).strip() and not str(getattr(sink, "sink", "")).startswith("dom_source:")
        }))

    param_behaviors: list[ParamBehavior] = []
    reflection_contexts: set[str] = set()
    reflection_transforms: set[str] = set()
    discovery_styles: set[str] = set()
    probe_modes: set[str] = set()
    tested_charsets: set[str] = set()

    for result in probe_results:
        contexts = sorted({
            str(getattr(reflection, "context_type", "") or "")
            for reflection in getattr(result, "reflections", []) or []
            if str(getattr(reflection, "context_type", "") or "")
        })
        reflection_contexts.update(contexts)

        transform = str(getattr(result, "reflection_transform", "") or "")
        if transform:
            reflection_transforms.add(transform)

        discovery_style = str(getattr(result, "discovery_style", "") or "")
        if discovery_style:
            discovery_styles.add(discovery_style)
        probe_mode = str(getattr(result, "probe_mode", "") or "")
        if probe_mode:
            probe_modes.add(probe_mode)
        tested_chars = str(getattr(result, "tested_chars", "") or "")
        if tested_chars:
            tested_charsets.add(tested_chars)

        surviving_chars = "".join(sorted({
            char
            for reflection in getattr(result, "reflections", []) or []
            for char in getattr(reflection, "surviving_chars", frozenset()) or frozenset()
        }))
        param_behaviors.append(ParamBehavior(
            name=str(getattr(result, "param_name", "") or ""),
            discovery_style=discovery_style,
            reflection_transform=transform,
            reflected=bool(getattr(result, "is_reflected", False)),
            injectable=bool(getattr(result, "is_injectable", False)),
            contexts=contexts,
            surviving_chars=surviving_chars,
            probe_mode=probe_mode,
            tested_chars=tested_chars,
        ))

    observations: list[str] = []
    if browser_required:
        observations.append("Edge behavior required browser-native probing instead of direct HTTP fetches.")
    if auth_required:
        observations.append("Requests carry active authentication state; preserve cookies and session continuity.")
    if reflection_transforms:
        observations.append(
            "Observed reflection transforms: " + ", ".join(sorted(reflection_transforms)) + "."
        )
    if discovery_styles:
        observations.append(
            "Discovery probe styles in use: " + ", ".join(sorted(discovery_styles)) + "."
        )
    if probe_modes:
        observations.append(
            "Adaptive probe modes used: " + ", ".join(sorted(probe_modes)) + "."
        )
    if tested_charsets:
        observations.append(
            "Character probes tested these sets: "
            + ", ".join(sorted(tested_charsets)[:3])
            + "."
        )
    if reflection_contexts:
        observations.append(
            "Confirmed reflection contexts: " + ", ".join(sorted(reflection_contexts)) + "."
        )
    if dom_sources:
        observations.append(
            "Client-side sources in scope: " + ", ".join(dom_sources) + "."
        )
    if dom_sinks:
        observations.append(
            "Client-side sinks in scope: " + ", ".join(dom_sinks[:6]) + "."
        )

    return TargetBehaviorProfile(
        delivery_mode=delivery_mode,
        target_host=parsed.netloc,
        target_path=parsed.path or "/",
        waf_name=waf,
        browser_required=browser_required,
        auth_required=auth_required or bool(getattr(context, "auth_notes", []) or []),
        frameworks=list(dict.fromkeys(frameworks)),
        reflected_params=sum(1 for item in param_behaviors if item.reflected),
        injectable_params=sum(1 for item in param_behaviors if item.injectable),
        reflection_contexts=sorted(reflection_contexts),
        reflection_transforms=sorted(reflection_transforms),
        discovery_styles=sorted(discovery_styles),
        probe_modes=sorted(probe_modes),
        tested_charsets=sorted(tested_charsets),
        dom_sources=dom_sources,
        dom_sinks=dom_sinks,
        observations=observations,
        params=param_behaviors[:8],
    )


def extract_behavior_profile(context: ParsedContext | None) -> dict[str, Any]:
    if context is None:
        return {}
    for note in getattr(context, "notes", []) or []:
        if not note.startswith(PROFILE_NOTE_PREFIX):
            continue
        try:
            payload = json.loads(note[len(PROFILE_NOTE_PREFIX):])
        except Exception:
            return {}
        if isinstance(payload, dict):
            return payload
        return {}
    return {}


def derive_ai_escalation_policy(
    context: ParsedContext | None,
    *,
    delivery_mode: str,
    context_type: str = "",
    sink_context: str = "",
) -> AIEscalationPolicy:
    """Return a bounded AI escalation policy from observed target behavior."""
    profile = extract_behavior_profile(context)
    browser_required = bool(profile.get("browser_required", False))
    auth_required = bool(profile.get("auth_required", False))
    probe_modes = {str(item) for item in profile.get("probe_modes", []) or [] if str(item)}
    high_friction = browser_required or auth_required or "stealth" in probe_modes

    normalized_context = context_type.strip().lower()
    normalized_sink = sink_context.strip().lower()
    hard_reflection_contexts = {
        "html_attr_url",
        "js_string_dq",
        "js_string_sq",
        "js_string_bt",
        "js_code",
        "json_value",
    }
    hard_dom_sinks = {
        "document.write",
        "document.writeln",
        "eval",
        "function",
        "settimeout",
        "setinterval",
    }

    if delivery_mode == "dom" and normalized_sink in {"document.write", "document.writeln"}:
        return AIEscalationPolicy(
            use_local=False,
            cloud_start_after_seconds=0.0,
            note="Skipped local model for document.write DOM sink; prioritize cloud planning for rich subcontext handling.",
        )

    if high_friction and normalized_context in hard_reflection_contexts:
        return AIEscalationPolicy(
            use_local=False,
            note="Skipped local model on a high-friction target because this reflection context typically benefits from cloud planning first.",
        )

    if delivery_mode == "dom" and high_friction and normalized_sink in hard_dom_sinks:
        return AIEscalationPolicy(
            use_local=True,
            local_timeout_seconds=25,
            cloud_start_after_seconds=5.0,
            note="Reduced local DOM budget and accelerated cloud start because the sink is high-friction and execution-sensitive.",
        )

    if high_friction and normalized_context:
        return AIEscalationPolicy(
            use_local=True,
            local_timeout_seconds=25,
            note="Reduced local model budget because the target is operating in a stealth/high-friction probe mode.",
        )

    return AIEscalationPolicy()


def classify_target_disposition(
    context: ParsedContext | None,
    *,
    delivery_mode: str,
    reflected_params: int = 0,
    injectable_params: int = 0,
    dom_hits: int = 0,
    coordinated_attempts: int = 0,
) -> TargetDisposition:
    """Classify whether the current target is worth deeper model budget."""
    profile = extract_behavior_profile(context)
    reflection_contexts = list(profile.get("reflection_contexts", []) or [])
    probe_modes = list(profile.get("probe_modes", []) or [])
    reflection_transforms = list(profile.get("reflection_transforms", []) or [])

    if delivery_mode == "dom":
        if dom_hits <= 0:
            return TargetDisposition(
                tier="hard_dead",
                is_dead=True,
                reason="No DOM taint path was confirmed during runtime discovery.",
            )
        return TargetDisposition(
            tier="live",
            is_dead=False,
            reason="DOM taint reached at least one executable sink; worth deeper execution attempts.",
        )

    if reflected_params <= 0:
        return TargetDisposition(
            tier="hard_dead",
            is_dead=True,
            reason="No reflection was confirmed during bounded discovery.",
        )

    if injectable_params <= 0 and coordinated_attempts <= 0:
        transform_note = ""
        if reflection_transforms:
            transform_note = " Observed transforms: " + ", ".join(reflection_transforms) + "."
        context_note = ""
        if reflection_contexts:
            context_note = " Reflected contexts: " + ", ".join(reflection_contexts) + "."
        return TargetDisposition(
            tier="soft_dead",
            is_dead=True,
            reason=(
                "Reflection exists, but the currently tested charset and contexts did not yield an executable path."
                + transform_note
                + context_note
            ).strip(),
        )

    if "stealth" in probe_modes:
        return TargetDisposition(
            tier="high_value",
            is_dead=False,
            reason="Target required stealth-style probing but still produced exploitable signal.",
        )

    return TargetDisposition(
        tier="live",
        is_dead=False,
        reason="Target produced executable reflection signal during bounded discovery.",
    )


def attach_behavior_profile(
    context: ParsedContext | None,
    profile: TargetBehaviorProfile,
) -> ParsedContext | None:
    if context is None:
        return None
    notes = [
        note
        for note in list(getattr(context, "notes", []) or [])
        if not note.startswith(PROFILE_NOTE_PREFIX)
    ]
    return replace(context, notes=[profile.to_note(), *notes])
