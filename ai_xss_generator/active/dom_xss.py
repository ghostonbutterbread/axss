"""DOM XSS runtime scanner — Stage 2 of the hybrid detection pipeline.

Injects a JavaScript sink-hook init script *before* page navigation via
Playwright's add_init_script(), then drives the browser with canary strings
in every attacker-controllable source.  When a hooked sink receives the canary,
taint flow is confirmed and a real XSS payload is attempted in that same source.

Sources tested:
  - URL query parameters (each individually replaced with the canary)
  - URL fragment (location.hash)

Sinks hooked:
  - innerHTML, outerHTML, insertAdjacentHTML
  - eval, Function, setTimeout (string form), setInterval (string form)
  - document.write, document.writeln
"""
from __future__ import annotations

import logging
import os
import urllib.parse
from dataclasses import dataclass

log = logging.getLogger(__name__)

_NAV_TIMEOUT_MS = 10_000
_STABILIZE_TIMEOUT_MS = 3_000
_BLOCKED_RESOURCE_TYPES = {"image", "media", "font", "stylesheet"}

# Sink-appropriate XSS payloads.  Ordered most targeted → most generic.
_SINK_PAYLOADS: dict[str, list[str]] = {
    "innerHTML":          ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "<details open ontoggle=alert(1)>"],
    "outerHTML":          ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
    "insertAdjacentHTML": ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
    "document.write":     ["<img src=x onerror=alert(1)>", "<script>alert(1)<\\/script>"],
    "document.writeln":   ["<img src=x onerror=alert(1)>", "<script>alert(1)<\\/script>"],
    "eval":               ["alert(1)", "alert`1`"],
    "Function":           ["alert(1)", "alert`1`"],
    "setTimeout":         ["alert(1)", "alert`1`"],
    "setInterval":        ["alert(1)", "alert`1`"],
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
            window.__axss_dom_hits.push({sink: sink, snippet: s.slice(0, 300)});
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


def _make_canary() -> str:
    return "axss_" + os.urandom(4).hex()


def _build_hook_js(canary: str) -> str:
    return _HOOK_JS_TEMPLATE.replace("__CANARY__", repr(canary))


def _inject_source(url: str, source_type: str, source_name: str, value: str) -> str:
    """Return *url* with *value* placed in the specified attacker-controlled source."""
    parsed = urllib.parse.urlparse(url)
    if source_type == "fragment":
        return urllib.parse.urlunparse(parsed._replace(fragment=value))
    # query_param: replace the target param, preserve all others
    params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    params[source_name] = value
    new_query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _attempt_execution(
    browser,
    url: str,
    source_type: str,
    source_name: str,
    sink: str,
    payloads: list[str],
    auth_headers: dict[str, str],
    timeout_ms: int,
) -> tuple[bool, str, str]:
    """Try each payload in a fresh browser page.

    Returns (confirmed, payload_that_fired, detail_string).
    """
    for payload in payloads:
        payload_url = _inject_source(url, source_type, source_name, payload)
        ctx = browser.new_context(
            ignore_https_errors=True,
            extra_http_headers={**auth_headers, "Accept": "text/html,application/xhtml+xml"},
        )
        try:
            page = ctx.new_page()
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
                if not _confirmed:
                    _confirmed = True
                    _detail = (
                        f"DOM XSS confirmed via console.{msg.type}() — "
                        f"sink:{_s} source:{source_name!r} payload:{_p!r}"
                    )

            page.on("dialog", _on_dialog)
            page.on("console", _on_console)

            try:
                page.goto(payload_url, timeout=timeout_ms, wait_until="domcontentloaded")
            except Exception:
                pass
            try:
                page.wait_for_load_state("networkidle", timeout=_STABILIZE_TIMEOUT_MS)
            except Exception:
                pass

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


def scan_dom_xss(
    url: str,
    browser,
    auth_headers: dict[str, str] | None = None,
    timeout_ms: int = _NAV_TIMEOUT_MS,
) -> list[DomXssResult]:
    """Scan *url* for DOM XSS via runtime Playwright sink hooking.

    For each attacker-controllable source (query params + URL fragment):
      1. Create a fresh browser context with the sink-hook init script loaded.
      2. Navigate with the canary value injected into that source.
      3. Wait for SPA stabilization (catches Angular's async rendering).
      4. Inspect window.__axss_dom_hits for any sink that received the canary.
      5. For each tainted sink: attempt real XSS payloads in a separate page.

    Returns one DomXssResult per unique source → sink taint path found.
    """
    results: list[DomXssResult] = []
    canary = _make_canary()
    hook_js = _build_hook_js(canary)
    _auth = auth_headers or {}
    extra_headers = {**_auth, "Accept": "text/html,application/xhtml+xml"}

    parsed = urllib.parse.urlparse(url)
    raw_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

    # Each query param + the URL fragment are independent sources
    sources: list[tuple[str, str]] = [("query_param", k) for k in raw_params]
    sources.append(("fragment", "hash"))

    # Dedup: avoid reporting the same (source_name, sink) pair twice
    seen: set[tuple[str, str]] = set()

    for source_type, source_name in sources:
        canary_url = _inject_source(url, source_type, source_name, canary)
        ctx = browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=extra_headers,
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

            try:
                page.goto(canary_url, timeout=timeout_ms, wait_until="domcontentloaded")
            except Exception as nav_exc:
                log.debug("Canary nav error for %s: %s", canary_url, nav_exc)

            # Brief wait for SPA frameworks (Angular, React) to finish async init
            try:
                page.wait_for_load_state("networkidle", timeout=_STABILIZE_TIMEOUT_MS)
            except Exception:
                pass

            try:
                hits: list[dict] = page.evaluate("window.__axss_dom_hits || []")
            except Exception:
                hits = []

            for hit in hits:
                sink_name: str = hit.get("sink", "unknown")
                dedup_key = (source_name, sink_name)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                log.debug(
                    "DOM taint: source=%s/%s → sink=%s",
                    source_type, source_name, sink_name,
                )

                payloads = _SINK_PAYLOADS.get(sink_name, _DEFAULT_PAYLOADS)
                exec_ok, exec_payload, exec_detail = _attempt_execution(
                    browser=browser,
                    url=url,
                    source_type=source_type,
                    source_name=source_name,
                    sink=sink_name,
                    payloads=payloads,
                    auth_headers=_auth,
                    timeout_ms=timeout_ms,
                )

                if exec_ok:
                    fired_url = _inject_source(url, source_type, source_name, exec_payload)
                    detail = exec_detail
                else:
                    fired_url = canary_url
                    detail = (
                        f"DOM taint confirmed — canary reached sink '{sink_name}' via "
                        f"{source_type}:{source_name!r}. "
                        f"Real payload did not execute (possible CSP or payload mismatch)."
                    )

                results.append(
                    DomXssResult(
                        url=url,
                        source_type=source_type,
                        source_name=source_name,
                        sink=sink_name,
                        canary=canary,
                        confirmed_execution=exec_ok,
                        payload_fired=exec_payload if exec_ok else None,
                        detail=detail,
                        fired_url=fired_url,
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

    return results
