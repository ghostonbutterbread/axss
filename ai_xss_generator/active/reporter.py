"""Markdown report writer for active scan results.

Report structure:
  - Header: target, date, scan config
  - Confirmed findings (full detail per finding)
  - Reflected but not confirmed (summary table)
  - No reflection found (summary table)
  - Errors
  - Known limitations
"""
from __future__ import annotations

import datetime
import urllib.parse
from pathlib import Path
from typing import Sequence

from ai_xss_generator.active.worker import WorkerResult, ConfirmedFinding
from ai_xss_generator.config import CONFIG_DIR


_REPORTS_DIR = CONFIG_DIR / "reports"


def write_report(
    results: Sequence[WorkerResult],
    config_summary: str = "",
    output_path: str | None = None,
) -> str:
    """Write a markdown report of active scan results.

    Returns the path the report was written to.
    """
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if output_path is None:
        # Auto-name: first domain + timestamp
        domains = sorted({
            urllib.parse.urlparse(r.url).netloc
            for r in results if r.url
        })
        domain_slug = domains[0].replace(".", "_") if domains else "scan"
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(_REPORTS_DIR / f"{domain_slug}_{ts}.md")

    content = _build_report(results, config_summary)
    Path(output_path).write_text(content, encoding="utf-8")
    return output_path


def _build_report(results: Sequence[WorkerResult], config_summary: str) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    confirmed_results = [r for r in results if r.status == "confirmed"]
    error_results     = [r for r in results if r.status == "error"]

    all_findings: list[ConfirmedFinding] = [
        f for r in confirmed_results for f in r.confirmed_findings
    ]

    domains = sorted({urllib.parse.urlparse(r.url).netloc for r in results if r.url})

    lines: list[str] = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines += [
        "# axss Active Scan Report",
        "",
        f"**Generated:** {now}  ",
        f"**Targets scanned:** {len(results)} target(s) across {len(domains)} domain(s)  ",
        f"**Domains:** {', '.join(domains) if domains else 'n/a'}  ",
    ]
    if config_summary:
        lines.append(f"**Config:** {config_summary}  ")
    lines += ["", "---", ""]

    # ── Confirmed Findings ────────────────────────────────────────────────────
    if all_findings:
        lines += [
            f"## ✅ Confirmed Findings ({len(all_findings)})",
            "",
        ]
        for i, f in enumerate(all_findings, 1):
            lines += _format_finding(i, f)
    else:
        lines += [
            "## ✅ Confirmed Findings",
            "",
            "_No confirmed XSS execution was detected._",
            "",
            "---",
            "",
        ]

    # ── Errors ────────────────────────────────────────────────────────────────
    if error_results:
        lines += [
            f"## 🔴 Errors ({len(error_results)})",
            "",
            "| URL | Error |",
            "|-----|-------|",
        ]
        for r in error_results:
            err = (r.error or "unknown error").replace("|", "\\|")
            lines.append(f"| `{r.url}` | {err} |")
        lines.append("")

    # ── Known Limitations ─────────────────────────────────────────────────────
    lines += [
        "---",
        "",
        "## Known Limitations",
        "",
        "- **Stored XSS (partial):** Post-injection sweep checks all pages visited "
          "during crawl. Payloads stored and rendered on pages outside the crawl "
          "boundary (admin panels, other users' sessions) require `--sink-url` or "
          "blind XSS to detect.",
        "- **DOM XSS (fragment/hash):** Client-side sinks driven by `location.hash` or "
          "`location.search` without a server round-trip are not covered.",
        "- **Cloud model web search:** Bypass reasoning is based on the cloud model's "
          "training knowledge only. Novel WAF bypasses published after the training "
          "cutoff may be missed.",
        "",
    ]

    return "\n".join(lines)


def _format_finding(index: int, f: ConfirmedFinding) -> list[str]:
    parsed = urllib.parse.urlparse(f.url)
    endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    source_label = {
        "phase1_transform": "Phase 1 mechanical transform",
        "local_model":      "Local AI model payload",
        "cloud_model":      "Cloud model payload (escalated)",
    }.get(f.source, f.source)

    why = _explain_why(f)

    return [
        f"### Finding {index} — `{endpoint}`",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Parameter** | `{f.param_name}` |",
        f"| **Sink context** | `{f.context_type}` |",
        f"| **WAF** | {f.waf or '—'} |",
        f"| **Confirmed by** | {f.execution_method} ({f.execution_detail}) |",
        f"| **Source** | {source_label} |",
        f"| **Transform** | `{f.transform_name}` |",
        f"| **Surviving chars** | `{f.surviving_chars or '?'}` |",
        "",
        "**Payload:**",
        "```",
        f.payload,
        "```",
        "",
        f"**Test URL:**",
        f"```",
        f.fired_url,
        "```",
        "",
        f"**Why it worked:**",
        f"{why}",
        "",
        "---",
        "",
    ]


def _explain_why(f: ConfirmedFinding) -> str:
    """Generate a human-readable explanation of why the payload worked."""
    parts: list[str] = []

    ctx_explanations = {
        "html_body":       "Input was reflected directly into the HTML body, allowing tag injection.",
        "html_comment":    "Input was reflected inside an HTML comment and broke out of it.",
        "html_attr_value": "Input was reflected inside an HTML attribute value and escaped the attribute.",
        "html_attr_event": "Input was reflected directly inside a JavaScript event handler.",
        "html_attr_url":   "Input was reflected inside a URL-type attribute (href/src/action), allowing a javascript: URI.",
        "js_code":         "Input was reflected directly into a JavaScript code block.",
        "js_string_dq":    "Input was reflected inside a double-quoted JavaScript string and broke out.",
        "js_string_sq":    "Input was reflected inside a single-quoted JavaScript string and broke out.",
        "js_string_bt":    "Input was reflected inside a JavaScript template literal and broke out.",
        "json_value":      "Input was reflected inside a JSON value in a script block.",
    }
    if f.context_type in ctx_explanations:
        parts.append(ctx_explanations[f.context_type])

    if f.surviving_chars:
        parts.append(f"Characters that survived server-side filtering: `{f.surviving_chars}`.")

    transform_explanations = {
        "raw":              "The raw payload was not filtered.",
        "svg_tag":          "`<svg onload=...>` was not blocked by the WAF/filter.",
        "img_onerror":      "`<img src=x onerror=...>` bypassed tag or event filtering.",
        "mixed_case_tags":  "Mixed-case tag names (`<ScRiPt>`) bypassed case-sensitive pattern matching.",
        "mixed_case_ev":    "Mixed-case event handler names bypassed case-sensitive pattern matching.",
        "no_space":         "Removing spaces (e.g. `<svg/onload=...>`) bypassed whitespace-dependent filters.",
        "backtick_call":    "Backtick call syntax (alert`1`) bypassed parenthesis filters.",
        "url_encode":       "URL-encoding the payload bypassed string-level WAF pattern matching.",
        "double_url":       "Double URL-encoding bypassed a WAF that decodes only once.",
        "html_entity":      "HTML entity encoding of `<`/`>` bypassed character-level filters.",
        "full_width":       "Full-width Unicode characters bypassed ASCII-only WAF pattern matching.",
        "js_uri":           "`javascript:` URI scheme executed when injected into a URL-type attribute.",
        "autofocus":        "`onfocus` + `autofocus` attributes triggered execution without user interaction.",
        "details_toggle":   "`<details open ontoggle=...>` triggered execution on page load without clicks.",
        "local_model":      "The local AI model generated a payload tailored to this exact context.",
        "cloud_model":      "The cloud AI model generated a targeted bypass after local and mechanical approaches failed.",
    }
    if f.transform_name in transform_explanations:
        parts.append(transform_explanations[f.transform_name])

    if f.waf:
        parts.append(f"Target is protected by **{f.waf}** WAF. The winning technique evaded its detection.")

    return " ".join(parts) if parts else "See payload and context above for details."
