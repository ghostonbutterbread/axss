"""Active parameter reflection prober for XSS surface mapping.

For each URL query parameter, sends two requests:
  1. Reflection probe  — a canary string to map where input appears in the response.
  2. Character probe   — canary + XSS-relevant chars to learn which survive filters.

Results are returned as ProbeResult objects that enrich the ParsedContext passed
to the AI generator, so payloads are targeted to confirmed contexts.
"""
from __future__ import annotations

import logging
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from itertools import cycle
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote as url_quote

log = logging.getLogger(__name__)

from scrapling.fetchers import FetcherSession

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
        attr_m = re.search(r"""([\w:-]+)\s*=\s*["']?[^"'<>]*$""", tag_content)
        if attr_m:
            attr_name = attr_m.group(1).lower()
            if attr_name.startswith("on"):
                return ReflectionContext(
                    context_type="html_attr_event", attr_name=attr_name, snippet=snippet
                )
            if attr_name in (
                "href", "src", "action", "formaction", "data",
                "xlink:href", "content", "srcdoc",
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
    auth_headers: dict[str, str] | None = None,
) -> ProbeResult:
    """Send two probe requests for one parameter and return a ProbeResult."""
    # Auth headers first; User-Agent from rotation always wins
    merged_headers: dict[str, str] = {**(auth_headers or {}), "User-Agent": next(ua_cycle)}
    req_kwargs: dict[str, Any] = {"headers": merged_headers}
    if proxy_cycle:
        req_kwargs["proxy"] = next(proxy_cycle)

    # Phase 1 — reflection mapping
    if delay > 0:
        time.sleep(delay)
    try:
        resp1 = _session_get(session, _rebuild_url(url, {**all_params, param_name: canary}), req_kwargs)
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
        resp2 = _session_get(session, _rebuild_url(url, {**all_params, param_name: char_probe}), req_kwargs)
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
                context_before=ctx.context_before,
            )
            for ctx in reflections
        ],
    )


def _probe_param_playwright(
    dyn_session: Any,
    url: str,
    param_name: str,
    original_value: str,
    all_params: dict[str, str],
    *,
    canary: str,
    delay: float,
    ua_cycle: Any,
    proxy_cycle: Any | None,
    auth_headers: dict[str, str] | None = None,
) -> ProbeResult:
    """Probe a single parameter using a shared Playwright browser session.

    Used when WAF detection indicates a real browser is required (akamai,
    cloudflare, datadome, etc.). The caller holds the DynamicSession context
    open across all parameter probes for the same URL so only one browser
    launch is needed.
    """
    extra_headers: dict[str, str] = {**(auth_headers or {}), "User-Agent": next(ua_cycle)}
    fetch_kwargs: dict[str, Any] = {"extra_headers": extra_headers}
    if proxy_cycle:
        fetch_kwargs["proxy"] = next(proxy_cycle)

    # Phase 1 — reflection mapping
    if delay > 0:
        time.sleep(delay)
    try:
        resp1 = dyn_session.fetch(
            _rebuild_url(url, {**all_params, param_name: canary}), **fetch_kwargs
        )
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
        resp2 = dyn_session.fetch(
            _rebuild_url(url, {**all_params, param_name: char_probe}), **fetch_kwargs
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
                context_before=ctx.context_before,
            )
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
        from scrapling.fetchers import DynamicSession
        with DynamicSession(headless=True, timeout=45_000) as dyn:
            for param_name, original_value in flat_params.items():
                result = _probe_param_playwright(
                    dyn, url, param_name, original_value, flat_params,
                    canary=canary, delay=delay, ua_cycle=ua_cycle, proxy_cycle=proxy_cycle,
                    auth_headers=auth_headers,
                )
                results.append(result)
                if on_result:
                    on_result(result)
    else:
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
                    auth_headers=auth_headers,
                )
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
) -> list[ProbeResult]:
    """Probe POST form parameters for XSS reflection.

    For each parameter in *param_names*:
      1. GETs *source_page_url* to fetch a fresh CSRF token value.
      2. POSTs *action_url* with the canary in the target param + real CSRF token.
      3. Classifies any reflections in the response.
      4. POSTs a second time with the char probe to measure surviving chars.

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
                resp1 = session.post(action_url, data=_build_post_body(canary), **req_kwargs)
                html1 = _resp_html(resp1)
            except Exception as exc:
                result = ProbeResult(
                    param_name=param_name, original_value="", error=str(exc)
                )
                results.append(result)
                if on_result:
                    on_result(result)
                continue

            reflections = _find_reflections(html1, canary)
            if not reflections:
                result = ProbeResult(param_name=param_name, original_value="")
                results.append(result)
                if on_result:
                    on_result(result)
                continue

            # --- Step 3: Char survival probe ---
            char_probe_val = canary + _PROBE_OPEN + PROBE_CHARS + _PROBE_CLOSE
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
                char_body[param_name] = char_probe_val

                resp2 = session.post(action_url, data=char_body, **req_kwargs)
                surviving = _analyze_char_survival(_resp_html(resp2), canary)
            except Exception:
                pass

            result = ProbeResult(
                param_name=param_name,
                original_value="",
                reflections=[
                    ReflectionContext(
                        context_type=ctx.context_type,
                        attr_name=ctx.attr_name,
                        surviving_chars=surviving,
                        snippet=ctx.snippet,
                        context_before=ctx.context_before,
                    )
                    for ctx in reflections
                ],
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
