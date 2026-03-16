"""Content-Security-Policy detection and XSS execution impact analysis.

Usage:
    from ai_xss_generator.csp import csp_from_headers, csp_summary

    analysis = csp_from_headers(response.headers)
    if analysis and analysis.would_block:
        print("CSP enforced — XSS may not execute even if reflected")
        print(csp_summary(analysis))
        for hint in analysis.bypass_hints:
            print(f"  Bypass hint: {hint}")
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class CSPAnalysis:
    """Parsed Content-Security-Policy evaluation."""
    raw: str = ""
    report_only: bool = False           # CSP-Report-Only — logged but NOT enforced
    blocks_inline_scripts: bool = False
    blocks_eval: bool = False
    blocks_event_handlers: bool = False # same restriction as inline scripts
    nonce_required: bool = False
    hash_required: bool = False
    has_unsafe_inline: bool = False
    has_unsafe_eval: bool = False
    has_strict_dynamic: bool = False
    would_block: bool = False           # Summary: would this block a typical XSS payload?
    bypass_hints: list[str] = field(default_factory=list)


def parse_csp(header_value: str, *, report_only: bool = False) -> CSPAnalysis:
    """Parse a CSP header string and evaluate its impact on XSS."""
    analysis = CSPAnalysis(raw=header_value, report_only=report_only)
    if not header_value.strip():
        return analysis

    directives: dict[str, list[str]] = {}
    for directive in header_value.split(";"):
        parts = directive.strip().split()
        if parts:
            directives[parts[0].lower()] = [v.lower() for v in parts[1:]]

    # script-src falls back to default-src when absent
    script_src = directives.get("script-src") or directives.get("default-src") or []

    has_unsafe_inline = "'unsafe-inline'" in script_src
    has_unsafe_eval = "'unsafe-eval'" in script_src
    has_nonce = any(v.startswith("'nonce-") for v in script_src)
    has_hash = any(re.match(r"'sha(256|384|512)-", v) for v in script_src)
    has_strict_dynamic = "'strict-dynamic'" in script_src

    analysis.has_unsafe_inline = has_unsafe_inline
    analysis.has_unsafe_eval = has_unsafe_eval
    analysis.nonce_required = has_nonce
    analysis.hash_required = has_hash
    analysis.has_strict_dynamic = has_strict_dynamic

    # Inline scripts / event handlers are blocked unless unsafe-inline is present
    blocks_inline = bool(script_src) and not has_unsafe_inline
    analysis.blocks_inline_scripts = blocks_inline
    analysis.blocks_eval = bool(script_src) and not has_unsafe_eval
    analysis.blocks_event_handlers = blocks_inline

    # Report-Only headers are never enforced
    if report_only:
        analysis.would_block = False
        analysis.bypass_hints.append("CSP-Report-Only — not enforced, payloads execute normally")
        return analysis

    # No script-src / default-src → no restriction
    if not script_src:
        analysis.would_block = False
        return analysis

    # unsafe-inline present → inline execution allowed
    if has_unsafe_inline:
        analysis.would_block = False
        return analysis

    # Wildcard or overly broad origins in script-src → effectively bypassable
    broad = [v for v in script_src if v in ("*", "https:", "http:") or v.startswith("*.")]
    if broad:
        analysis.would_block = False
        analysis.bypass_hints.append(
            f"Broad script-src origin ({broad[0]}) — host payload on any matching origin"
        )
        return analysis

    # Reaches here: CSP would block inline scripts
    analysis.would_block = True

    if has_strict_dynamic and (has_nonce or has_hash):
        analysis.bypass_hints.append(
            "strict-dynamic + nonce/hash — look for DOM clobbering, Trusted Types bypass, or JSONP on allowed origins"
        )
    elif has_nonce:
        analysis.bypass_hints.append(
            "nonce-based CSP — check if nonce is static/predictable in HTML source; "
            "look for script injection via dangerouslySetInnerHTML or JSONP endpoints"
        )
    elif has_hash:
        analysis.bypass_hints.append(
            "hash-based CSP — payload must match an allowed hash; "
            "look for JSONP or user-controlled script on an allowed origin"
        )
    else:
        analysis.bypass_hints.append(
            "CSP blocks inline scripts — look for allowed-origin JSONP or script gadgets"
        )

    if analysis.blocks_eval:
        analysis.bypass_hints.append(
            "eval blocked — prototype pollution or postMessage DOM gadgets may still work"
        )

    return analysis


def csp_from_headers(headers: dict[str, str]) -> CSPAnalysis | None:
    """Extract and parse CSP from a response headers dict.

    Handles case-insensitive header names. Returns None when no CSP is present.
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}

    enforcing = headers_lower.get("content-security-policy")
    if enforcing:
        return parse_csp(enforcing, report_only=False)

    report_only = headers_lower.get("content-security-policy-report-only")
    if report_only:
        return parse_csp(report_only, report_only=True)

    return None


def csp_summary(analysis: CSPAnalysis) -> str:
    """One-line human-readable summary of the CSP analysis."""
    if not analysis.raw:
        return "No CSP"
    if analysis.report_only:
        return "CSP-Report-Only (not enforced)"
    if not analysis.would_block:
        if analysis.has_unsafe_inline:
            return "CSP present — unsafe-inline allows inline execution"
        if analysis.bypass_hints:
            return f"CSP present but bypassable: {analysis.bypass_hints[0]}"
        return "CSP present but does not block XSS"
    parts: list[str] = []
    if analysis.nonce_required:
        parts.append("nonce-required")
    if analysis.hash_required:
        parts.append("hash-required")
    if analysis.has_strict_dynamic:
        parts.append("strict-dynamic")
    if analysis.blocks_eval:
        parts.append("eval-blocked")
    label = ", ".join(parts) if parts else "blocks-inline"
    return f"CSP enforced ({label}) — reflected XSS may not execute"
