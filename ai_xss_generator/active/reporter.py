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
    auth_summary: str = "",
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

    content = _build_report(results, config_summary, auth_summary)
    Path(output_path).write_text(content, encoding="utf-8")
    return output_path


def _build_report(results: Sequence[WorkerResult], config_summary: str, auth_summary: str = "") -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    confirmed_results = [r for r in results if r.status == "confirmed"]
    taint_results     = [r for r in results if r.status == "taint_only"]
    error_results     = [r for r in results if r.status == "error"]
    dead_results      = [r for r in results if r.dead_target]

    all_findings: list[ConfirmedFinding] = [
        f
        for r in confirmed_results
        for f in r.confirmed_findings
        if f.execution_method != "dom_taint"
    ]
    taint_findings: list[ConfirmedFinding] = [
        f
        for r in (*confirmed_results, *taint_results)
        for f in r.confirmed_findings
        if f.execution_method == "dom_taint"
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
    if auth_summary:
        lines.append(f"**Auth:** {auth_summary}  ")
    lines += ["", "---", ""]

    pilot_summary = _pilot_summary(results)
    lines += [
        "## Pilot Summary",
        "",
        f"- Target tiers: hard-dead `{pilot_summary['hard_dead']}`, soft-dead `{pilot_summary['soft_dead']}`, live `{pilot_summary['live']}`, high-value `{pilot_summary['high_value']}`, unknown `{pilot_summary['unknown']}`",
        f"- Model rounds: local `{pilot_summary['local_rounds']}`, cloud `{pilot_summary['cloud_rounds']}`",
        f"- Deterministic fallback rounds: `{pilot_summary['fallback_rounds']}`",
        f"- Cloud-escalated targets: `{pilot_summary['cloud_targets']}` / `{len(results)}`",
        "",
    ]

    if results:
        lines += [
            f"## Pilot Budget By Target ({len(results)})",
            "",
            "| URL | Kind | Tier | Status | Local | Cloud | Fallback | Signal | Reasoning |",
            "|-----|------|------|--------|-------|-------|----------|--------|-----------|",
        ]
        for r in results:
            signal = _pilot_signal(r).replace("|", "\\|")
            reasoning = _pilot_reasoning(r).replace("|", "\\|")
            lines.append(
                f"| `{r.url}` | `{getattr(r, 'kind', 'get')}` | `{_result_tier(r)}` | `{r.status}` | "
                f"`{getattr(r, 'local_model_rounds', 0)}` | `{getattr(r, 'cloud_model_rounds', 0)}` | "
                f"`{getattr(r, 'fallback_rounds', 0)}` | {signal} | {reasoning} |"
            )
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

    # ── DOM taint without execution ──────────────────────────────────────────
    if taint_findings:
        lines += [
            f"## ℹ️ DOM Taint Only ({len(taint_findings)})",
            "",
            "| URL | Parameter | Sink | Detail | Test URL |",
            "|-----|-----------|------|--------|----------|",
        ]
        for f in taint_findings:
            detail = f.execution_detail.replace("|", "\\|")
            test_url = f.fired_url.replace("|", "\\|")
            lines.append(
                f"| `{f.url}` | `{f.param_name}` | `{f.sink_context}` | "
                f"{detail} | `{test_url}` |"
            )
        lines += ["", "---", ""]

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

    # ── Dead Targets ─────────────────────────────────────────────────────────
    if dead_results:
        lines += [
            f"## ⏹️ Dead Targets ({len(dead_results)})",
            "",
            "| URL | Status | Reason |",
            "|-----|--------|--------|",
        ]
        for r in dead_results:
            reason = (r.dead_reason or "No further technical signal justified more budget.").replace("|", "\\|")
            lines.append(f"| `{r.url}` | `{r.status}` | {reason} |")
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
        "- **DOM XSS (CSP-blocked payloads):** When taint flow is confirmed but "
          "execution fails (`dom_taint`), a strict Content Security Policy is the "
          "most likely cause. Manual verification with a CSP-aware payload is recommended.",
        "- **DOM XSS (external JS bundles):** The runtime hook covers inline scripts "
          "and dynamically evaluated code. Sinks inside lazy-loaded chunk bundles "
          "may not be reached if they load after the hook fires.",
        "- **Cloud model web search:** Bypass reasoning is based on the cloud model's "
          "training knowledge only. Novel WAF bypasses published after the training "
          "cutoff may be missed.",
        "",
    ]

    return "\n".join(lines)


def _result_tier(result: WorkerResult) -> str:
    tier = str(getattr(result, "target_tier", "") or "").strip().lower()
    return tier or "unknown"


def _pilot_summary(results: Sequence[WorkerResult]) -> dict[str, int]:
    summary = {
        "hard_dead": 0,
        "soft_dead": 0,
        "live": 0,
        "high_value": 0,
        "unknown": 0,
        "local_rounds": 0,
        "cloud_rounds": 0,
        "fallback_rounds": 0,
        "cloud_targets": 0,
    }
    for result in results:
        tier = _result_tier(result)
        if tier not in summary:
            tier = "unknown"
        summary[tier] += 1
        summary["local_rounds"] += int(getattr(result, "local_model_rounds", 0) or 0)
        summary["cloud_rounds"] += int(getattr(result, "cloud_model_rounds", 0) or 0)
        summary["fallback_rounds"] += int(getattr(result, "fallback_rounds", 0) or 0)
        if getattr(result, "cloud_escalated", False) or int(getattr(result, "cloud_model_rounds", 0) or 0) > 0:
            summary["cloud_targets"] += 1
    return summary


def _pilot_signal(result: WorkerResult) -> str:
    parts: list[str] = []
    params_tested = int(getattr(result, "params_tested", 0) or 0)
    params_reflected = int(getattr(result, "params_reflected", 0) or 0)
    if params_tested:
        parts.append(f"params {params_reflected}/{params_tested}")
    if result.status in {"confirmed", "taint_only"}:
        findings = len(getattr(result, "confirmed_findings", []) or [])
        if findings:
            parts.append(f"findings {findings}")
    if getattr(result, "dead_target", False):
        parts.append("dead-target stop")
    return "; ".join(parts) or "no explicit signal"


def _pilot_reasoning(result: WorkerResult) -> str:
    reasons = [str(item).strip() for item in getattr(result, "escalation_reasons", []) or [] if str(item).strip()]
    if reasons:
        preview = "; ".join(reasons[:2])
        if len(reasons) > 2:
            preview += f"; +{len(reasons) - 2} more"
        return preview
    if getattr(result, "dead_reason", ""):
        return str(result.dead_reason)
    return "No special escalation note recorded."


def _format_finding(index: int, f: ConfirmedFinding) -> list[str]:
    parsed = urllib.parse.urlparse(f.url)
    endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    is_dom = f.context_type == "dom_xss"
    source_label = {
        "phase1_transform": "Deterministic fallback transform",
        "local_model":      "Local AI model payload",
        "cloud_model":      "Cloud model payload (escalated)",
        "dom_xss_runtime":  "DOM XSS runtime sink hooking",
    }.get(f.source, f.source)

    why = _explain_why(f)

    lines = [
        f"### Finding {index} — `{endpoint}`",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Parameter / Source** | `{f.param_name}` |",
        f"| **Sink** | `{f.sink_context}` |",
        f"| **Context type** | `{f.context_type}` |",
        f"| **WAF** | {f.waf or '—'} |",
        f"| **Confirmed by** | `{f.execution_method}` |",
        f"| **Source** | {source_label} |",
    ]

    if f.ai_engine:
        lines.append(f"| **AI engine** | `{f.ai_engine}` |")
    if f.ai_note:
        lines.append(f"| **AI note** | {f.ai_note} |")

    if not is_dom:
        lines += [
            f"| **Transform** | `{f.transform_name}` |",
            f"| **Surviving chars** | `{f.surviving_chars or '?'}` |",
        ]

    lines += [""]

    if f.payload:
        lines += [
            "**Payload:**",
            "```",
            f.payload,
            "```",
            "",
        ]

    lines += [
        "**Test URL** _(paste into browser to reproduce)_:",
        "```",
        urllib.parse.unquote(f.fired_url),
        "```",
        "",
    ]

    # DOM XSS: show the JS call stack so the tester can locate the sink in source
    if is_dom and f.code_location:
        lines += [
            "**JS sink location** _(where in the page's JS the sink was reached)_:",
            "```",
            f.code_location,
            "```",
            "",
        ]

    lines += [
        "**Detail:**",
        f"{f.execution_detail}",
        "",
        "**Why it worked:**",
        f"{why}",
        "",
        "---",
        "",
    ]
    return lines


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
        "cloud_model":      "The cloud AI model generated a targeted bypass after the local model could not produce a working payload.",
    }
    if f.transform_name in transform_explanations:
        parts.append(transform_explanations[f.transform_name])

    if f.waf:
        parts.append(f"Target is protected by **{f.waf}** WAF. The winning technique evaded its detection.")

    return " ".join(parts) if parts else "See payload and context above for details."
