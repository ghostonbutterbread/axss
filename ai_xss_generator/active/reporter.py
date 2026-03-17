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
import html
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
    output = Path(output_path)
    output.write_text(content, encoding="utf-8")
    _write_html_report(output, results, config_summary, auth_summary)
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
    grouped_findings = _group_confirmed_findings(all_findings)

    if all_findings:
        area_count = len(grouped_findings)
        lines += [
            f"## ✅ Confirmed Findings ({area_count} area(s), {len(all_findings)} variant(s))",
            "",
        ]
        for i, findings in enumerate(grouped_findings, 1):
            lines += _format_grouped_finding(i, findings)
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


def _write_html_report(
    markdown_path: Path,
    results: Sequence[WorkerResult],
    config_summary: str,
    auth_summary: str,
) -> Path:
    html_path = markdown_path.with_suffix(".html")
    html_path.write_text(_build_html_report(results, config_summary, auth_summary), encoding="utf-8")
    return html_path


def _build_html_report(results: Sequence[WorkerResult], config_summary: str, auth_summary: str = "") -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    confirmed_results = [r for r in results if r.status == "confirmed"]
    taint_results = [r for r in results if r.status == "taint_only"]
    error_results = [r for r in results if r.status == "error"]
    dead_results = [r for r in results if r.dead_target]
    all_findings = [
        f
        for r in confirmed_results
        for f in r.confirmed_findings
        if f.execution_method != "dom_taint"
    ]
    taint_findings = [
        f
        for r in (*confirmed_results, *taint_results)
        for f in r.confirmed_findings
        if f.execution_method == "dom_taint"
    ]
    grouped_findings = _group_confirmed_findings(all_findings)
    domains = sorted({urllib.parse.urlparse(r.url).netloc for r in results if r.url})
    pilot_summary = _pilot_summary(results)

    parts = [
        "<!doctype html>",
        "<html lang='en'>",
        "<head>",
        "<meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<title>axss Active Scan Report</title>",
        "<style>",
        _HTML_REPORT_CSS,
        "</style>",
        "</head>",
        "<body>",
        "<main class='page'>",
        "<section class='hero card'>",
        "<div class='hero-title-row'>",
        "<h1>axss Active Scan Report</h1>",
        "<span class='badge badge-confirmed'>Active Scan</span>",
        "</div>",
        "<div class='meta-grid'>",
        f"<div><span class='meta-label'>Generated</span><span>{_h(now)}</span></div>",
        f"<div><span class='meta-label'>Targets scanned</span><span>{len(results)} target(s)</span></div>",
        f"<div><span class='meta-label'>Domains</span><span>{_h(', '.join(domains) if domains else 'n/a')}</span></div>",
        f"<div><span class='meta-label'>Config</span><span>{_h(config_summary or 'n/a')}</span></div>",
        f"<div><span class='meta-label'>Auth</span><span>{_h(auth_summary or 'none')}</span></div>",
        "</div>",
        "</section>",
        "<section class='card'>",
        "<h2>Pilot Summary</h2>",
        "<div class='summary-grid'>",
        _summary_tile("Hard Dead", str(pilot_summary["hard_dead"]), "dead"),
        _summary_tile("Soft Dead", str(pilot_summary["soft_dead"]), "soft"),
        _summary_tile("Live", str(pilot_summary["live"]), "live"),
        _summary_tile("High Value", str(pilot_summary["high_value"]), "value"),
        _summary_tile("Local Rounds", str(pilot_summary["local_rounds"]), "local"),
        _summary_tile("Cloud Rounds", str(pilot_summary["cloud_rounds"]), "cloud"),
        _summary_tile("Fallback Rounds", str(pilot_summary["fallback_rounds"]), "fallback"),
        _summary_tile("Cloud Targets", f"{pilot_summary['cloud_targets']} / {len(results)}", "cloud"),
        "</div>",
        "</section>",
    ]

    if results:
        parts += [
            "<section class='card'>",
            f"<h2>Pilot Budget By Target <span class='badge'>{len(results)}</span></h2>",
            "<div class='table-wrap'>",
            "<table>",
            "<thead><tr><th>URL</th><th>Kind</th><th>Tier</th><th>Status</th><th>Local</th><th>Cloud</th><th>Fallback</th><th>Signal</th><th>Reasoning</th></tr></thead>",
            "<tbody>",
        ]
        for result in results:
            parts.append(
                "<tr>"
                f"<td><code>{_h(result.url)}</code></td>"
                f"<td><code>{_h(getattr(result, 'kind', 'get'))}</code></td>"
                f"<td>{_tier_badge(_result_tier(result))}</td>"
                f"<td>{_status_badge(result.status)}</td>"
                f"<td><code>{int(getattr(result, 'local_model_rounds', 0) or 0)}</code></td>"
                f"<td><code>{int(getattr(result, 'cloud_model_rounds', 0) or 0)}</code></td>"
                f"<td><code>{int(getattr(result, 'fallback_rounds', 0) or 0)}</code></td>"
                f"<td>{_h(_pilot_signal(result))}</td>"
                f"<td>{_h(_pilot_reasoning(result))}</td>"
                "</tr>"
            )
        parts += ["</tbody></table></div></section>"]

    parts += [
        "<section class='card'>",
        f"<h2>Confirmed Findings <span class='badge badge-confirmed'>{len(grouped_findings)} area(s)</span> <span class='badge'>{len(all_findings)} variant(s)</span></h2>",
    ]
    if grouped_findings:
        for index, findings in enumerate(grouped_findings, 1):
            parts.append(_format_grouped_finding_html(index, findings))
    else:
        parts.append("<p class='empty'>No confirmed XSS execution was detected.</p>")
    parts.append("</section>")

    if taint_findings:
        parts += [
            "<section class='card'>",
            f"<h2>DOM Taint Only <span class='badge badge-soft'>{len(taint_findings)}</span></h2>",
            "<div class='table-wrap'>",
            "<table>",
            "<thead><tr><th>URL</th><th>Parameter</th><th>Sink</th><th>Detail</th><th>Test URL</th></tr></thead>",
            "<tbody>",
        ]
        for finding in taint_findings:
            parts.append(
                "<tr>"
                f"<td><code>{_h(finding.url)}</code></td>"
                f"<td><code>{_h(finding.param_name)}</code></td>"
                f"<td><code>{_h(finding.sink_context)}</code></td>"
                f"<td>{_h(finding.execution_detail)}</td>"
                f"<td><code>{_h(finding.fired_url)}</code></td>"
                "</tr>"
            )
        parts += ["</tbody></table></div></section>"]

    if error_results:
        parts += [
            "<section class='card'>",
            f"<h2>Errors <span class='badge badge-dead'>{len(error_results)}</span></h2>",
            "<div class='table-wrap'>",
            "<table>",
            "<thead><tr><th>URL</th><th>Error</th></tr></thead>",
            "<tbody>",
        ]
        for result in error_results:
            parts.append(
                "<tr>"
                f"<td><code>{_h(result.url)}</code></td>"
                f"<td>{_h(result.error or 'unknown error')}</td>"
                "</tr>"
            )
        parts += ["</tbody></table></div></section>"]

    if dead_results:
        parts += [
            "<section class='card'>",
            f"<h2>Dead Targets <span class='badge badge-dead'>{len(dead_results)}</span></h2>",
            "<div class='table-wrap'>",
            "<table>",
            "<thead><tr><th>URL</th><th>Status</th><th>Reason</th></tr></thead>",
            "<tbody>",
        ]
        for result in dead_results:
            parts.append(
                "<tr>"
                f"<td><code>{_h(result.url)}</code></td>"
                f"<td>{_status_badge(result.status)}</td>"
                f"<td>{_h(result.dead_reason or 'No further technical signal justified more budget.')}</td>"
                "</tr>"
            )
        parts += ["</tbody></table></div></section>"]

    parts += [
        "<section class='card'>",
        "<h2>Known Limitations</h2>",
        "<ul class='limitations'>",
        "<li><strong>Stored XSS (partial):</strong> Post-injection sweep checks all pages visited during crawl. Payloads stored and rendered on pages outside the crawl boundary require <code>--sink-url</code> or blind XSS to detect.</li>",
        "<li><strong>DOM XSS (CSP-blocked payloads):</strong> When taint flow is confirmed but execution fails (<code>dom_taint</code>), a strict Content Security Policy is the most likely cause. Manual verification with a CSP-aware payload is recommended.</li>",
        "<li><strong>DOM XSS (external JS bundles):</strong> The runtime hook covers inline scripts and dynamically evaluated code. Sinks inside lazy-loaded chunk bundles may not be reached if they load after the hook fires.</li>",
        "<li><strong>Cloud model web search:</strong> Bypass reasoning is based on the cloud model's training knowledge only. Novel WAF bypasses published after the training cutoff may be missed.</li>",
        "</ul>",
        "</section>",
        "</main>",
        "</body>",
        "</html>",
    ]
    return "".join(parts)


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


def _group_confirmed_findings(findings: Sequence[ConfirmedFinding]) -> list[list[ConfirmedFinding]]:
    grouped: dict[tuple[str, str, str, str], list[ConfirmedFinding]] = {}
    order: list[tuple[str, str, str, str]] = []
    for finding in findings:
        key = (finding.url, finding.param_name, finding.context_type, finding.sink_context)
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(finding)
    return [grouped[key] for key in order]


def _source_label(source: str) -> str:
    return {
        "phase1_transform": "Deterministic fallback transform",
        "phase1_waf_fallback": "WAF-specific deterministic fallback",
        "local_model": "Local AI model payload",
        "cloud_model": "Cloud model payload (escalated)",
        "dom_xss_runtime": "DOM XSS runtime sink hooking",
    }.get(source, source)


def _h(value: str) -> str:
    return html.escape(str(value), quote=True)


def _summary_tile(label: str, value: str, tone: str) -> str:
    return (
        f"<article class='summary-tile tone-{_h(tone)}'>"
        f"<span class='summary-label'>{_h(label)}</span>"
        f"<strong>{_h(value)}</strong>"
        "</article>"
    )


def _status_badge(status: str) -> str:
    tone = {
        "confirmed": "confirmed",
        "taint_only": "soft",
        "error": "dead",
        "no_execution": "neutral",
        "no_reflection": "dead",
        "no_params": "dead",
    }.get(status, "neutral")
    return f"<span class='badge badge-{tone}'>{_h(status)}</span>"


def _tier_badge(tier: str) -> str:
    tone = {
        "hard_dead": "dead",
        "soft_dead": "soft",
        "live": "live",
        "high_value": "value",
    }.get(tier, "neutral")
    return f"<span class='badge badge-{tone}'>{_h(tier)}</span>"


def _format_grouped_finding_html(index: int, findings: Sequence[ConfirmedFinding]) -> str:
    primary = findings[0]
    parsed = urllib.parse.urlparse(primary.url)
    endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    detail_rows = [
        ("Parameter / Source", primary.param_name),
        ("Sink", primary.sink_context),
        ("Context type", primary.context_type),
        ("WAF", primary.waf or "—"),
        ("Confirmed by", primary.execution_method),
        ("Source", _source_label(primary.source)),
    ]
    if primary.bypass_family:
        detail_rows.append(("Bypass family", primary.bypass_family))
    if primary.ai_engine:
        detail_rows.append(("AI engine", primary.ai_engine))
    if primary.ai_note:
        detail_rows.append(("AI note", primary.ai_note))
    if primary.context_type != "dom_xss":
        detail_rows.append(("Transform", primary.transform_name))
        detail_rows.append(("Surviving chars", primary.surviving_chars or "?"))

    details_html = "".join(
        f"<div class='detail-row'><span>{_h(label)}</span><code>{_h(value)}</code></div>"
        for label, value in detail_rows
    )

    parts = [
        "<article class='finding-card'>",
        "<div class='finding-head'>",
        f"<h3>Finding {index} <span class='endpoint'>{_h(endpoint)}</span></h3>",
        f"<div class='finding-badges'>{_status_badge('confirmed')}<span class='badge'>{len(findings)} variant(s)</span></div>",
        "</div>",
        "<div class='detail-grid'>",
        details_html,
        "</div>",
    ]

    if primary.payload:
        parts += [
            "<section class='block'>",
            "<h4>Primary Payload</h4>",
            f"<pre>{_h(primary.payload)}</pre>",
            "</section>",
        ]

    parts += [
        "<section class='block'>",
        "<h4>Test URL</h4>",
        f"<pre>{_h(urllib.parse.unquote(primary.fired_url))}</pre>",
        "</section>",
    ]

    if primary.context_type == "dom_xss" and primary.code_location:
        parts += [
            "<section class='block'>",
            "<h4>JS Sink Location</h4>",
            f"<pre>{_h(primary.code_location)}</pre>",
            "</section>",
        ]

    parts += [
        "<section class='callout'>",
        "<h4>Detail</h4>",
        f"<p>{_h(primary.execution_detail)}</p>",
        "<h4>Why it worked</h4>",
        f"<p>{_h(_explain_why(primary))}</p>",
        "</section>",
    ]

    if len(findings) > 1:
        parts += [
            "<section class='block'>",
            "<h4>Additional Confirmed Variants</h4>",
            "<div class='table-wrap'>",
            "<table>",
            "<thead><tr><th>Payload</th><th>Source</th><th>Confirmed by</th><th>Transform</th><th>Bypass family</th></tr></thead>",
            "<tbody>",
        ]
        for finding in findings[1:]:
            parts.append(
                "<tr>"
                f"<td><code>{_h(finding.payload or '—')}</code></td>"
                f"<td>{_h(_source_label(finding.source))}</td>"
                f"<td><code>{_h(finding.execution_method)}</code></td>"
                f"<td><code>{_h(finding.transform_name or '—')}</code></td>"
                f"<td><code>{_h(finding.bypass_family or '—')}</code></td>"
                "</tr>"
            )
        parts += ["</tbody></table></div></section>"]

    parts += ["</article>"]
    return "".join(parts)


_HTML_REPORT_CSS = """
:root {
  --bg: #f4efe4;
  --paper: #fffdf8;
  --ink: #182022;
  --muted: #5f6a6d;
  --line: #d8d0c2;
  --accent: #005f73;
  --confirmed: #1b7f5a;
  --soft: #8d6b19;
  --dead: #a33636;
  --live: #1d6d86;
  --value: #7b3fa0;
  --fallback: #8b5a2b;
  --local: #3c6e71;
  --cloud: #355070;
  --neutral: #6c757d;
  --code: #f1ede4;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
  color: var(--ink);
  background:
    radial-gradient(circle at top left, rgba(0,95,115,0.12), transparent 32%),
    linear-gradient(180deg, #efe8d8 0%, var(--bg) 100%);
}
.page {
  width: min(1200px, calc(100vw - 32px));
  margin: 24px auto 48px;
}
.card, .finding-card {
  background: var(--paper);
  border: 1px solid var(--line);
  border-radius: 18px;
  box-shadow: 0 12px 34px rgba(24, 32, 34, 0.08);
  padding: 20px 22px;
  margin-bottom: 18px;
}
.hero-title-row, .finding-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
}
h1, h2, h3, h4 {
  margin: 0 0 12px;
  font-family: "IBM Plex Serif", Georgia, serif;
}
h1 { font-size: 2rem; }
h2 { font-size: 1.4rem; margin-bottom: 14px; }
h3 { font-size: 1.1rem; }
h4 { font-size: 0.95rem; margin-bottom: 8px; }
.endpoint {
  display: inline-block;
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.85rem;
  color: var(--muted);
  margin-left: 8px;
}
.meta-grid, .summary-grid, .detail-grid {
  display: grid;
  gap: 12px;
}
.meta-grid { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
.summary-grid { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
.detail-grid { grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); margin-bottom: 16px; }
.meta-label, .summary-label, .detail-row span {
  display: block;
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
  margin-bottom: 4px;
}
.summary-tile {
  border-radius: 14px;
  padding: 14px 16px;
  border: 1px solid var(--line);
  background: #f8f4eb;
}
.summary-tile strong {
  font-size: 1.35rem;
  display: block;
}
.tone-dead { border-color: rgba(163,54,54,0.25); }
.tone-soft { border-color: rgba(141,107,25,0.25); }
.tone-live { border-color: rgba(29,109,134,0.25); }
.tone-value { border-color: rgba(123,63,160,0.25); }
.tone-local { border-color: rgba(60,110,113,0.25); }
.tone-cloud { border-color: rgba(53,80,112,0.25); }
.tone-fallback { border-color: rgba(139,90,43,0.25); }
.badge {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  border-radius: 999px;
  background: #ece7dc;
  color: var(--ink);
  font-size: 0.78rem;
  font-weight: 600;
  border: 1px solid var(--line);
}
.finding-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.badge-confirmed { background: rgba(27,127,90,0.12); color: var(--confirmed); border-color: rgba(27,127,90,0.25); }
.badge-soft { background: rgba(141,107,25,0.12); color: var(--soft); border-color: rgba(141,107,25,0.25); }
.badge-dead { background: rgba(163,54,54,0.12); color: var(--dead); border-color: rgba(163,54,54,0.25); }
.badge-live { background: rgba(29,109,134,0.12); color: var(--live); border-color: rgba(29,109,134,0.25); }
.badge-value { background: rgba(123,63,160,0.12); color: var(--value); border-color: rgba(123,63,160,0.25); }
.badge-neutral { background: rgba(108,117,125,0.12); color: var(--neutral); border-color: rgba(108,117,125,0.25); }
.detail-row {
  padding: 10px 12px;
  background: #faf6ee;
  border: 1px solid #ece4d6;
  border-radius: 12px;
}
.detail-row code, td code, pre, .endpoint {
  font-family: "IBM Plex Mono", monospace;
}
.block, .callout {
  margin-top: 14px;
}
.callout {
  border-left: 4px solid var(--accent);
  padding-left: 14px;
}
pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  background: var(--code);
  border: 1px solid #e3dccd;
  border-radius: 12px;
  padding: 12px 14px;
}
.table-wrap {
  overflow-x: auto;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.92rem;
}
th, td {
  text-align: left;
  vertical-align: top;
  padding: 10px 12px;
  border-bottom: 1px solid #e7e0d3;
}
thead th {
  background: #f6f0e4;
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted);
}
.empty {
  color: var(--muted);
}
.limitations {
  margin: 0;
  padding-left: 20px;
}
.limitations li {
  margin-bottom: 10px;
}
@media (max-width: 720px) {
  .page { width: min(100vw - 20px, 100%); margin-top: 12px; }
  .card, .finding-card { padding: 16px; border-radius: 14px; }
  .hero-title-row, .finding-head { flex-direction: column; }
}
"""


def _format_grouped_finding(index: int, findings: Sequence[ConfirmedFinding]) -> list[str]:
    primary = findings[0]
    parsed = urllib.parse.urlparse(primary.url)
    endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    lines = [
        f"### Finding {index} — `{endpoint}`",
        "",
    ]

    if len(findings) > 1:
        lines += [
            f"**Confirmed variants:** `{len(findings)}` distinct payload/result combinations for this same area.",
            "",
        ]

    lines += _format_finding_detail(primary, include_heading=False, include_separator=len(findings) == 1)

    if len(findings) > 1:
        lines += [
            "**Additional confirmed variants:**",
            "",
            "| Payload | Source | Confirmed by | Transform | Bypass family |",
            "|---------|--------|--------------|-----------|---------------|",
        ]
        for finding in findings[1:]:
            payload = finding.payload.replace("|", "\\|") if finding.payload else "—"
            source_label = _source_label(finding.source).replace("|", "\\|")
            transform = (finding.transform_name or "—").replace("|", "\\|")
            family = (finding.bypass_family or "—").replace("|", "\\|")
            lines.append(
                f"| `{payload}` | {source_label} | `{finding.execution_method}` | `{transform}` | `{family}` |"
            )
        lines += ["", "---", ""]

    return lines


def _format_finding(index: int, f: ConfirmedFinding) -> list[str]:
    return _format_finding_detail(f, include_heading=True, index=index, include_separator=True)


def _format_finding_detail(
    f: ConfirmedFinding,
    *,
    include_heading: bool,
    index: int = 0,
    include_separator: bool,
) -> list[str]:
    parsed = urllib.parse.urlparse(f.url)
    endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    is_dom = f.context_type == "dom_xss"
    source_label = _source_label(f.source)

    why = _explain_why(f)

    lines: list[str] = []
    if include_heading:
        lines += [
            f"### Finding {index} — `{endpoint}`",
            "",
        ]

    lines += [
        "| Field | Value |",
        "|-------|-------|",
        f"| **Parameter / Source** | `{f.param_name}` |",
        f"| **Sink** | `{f.sink_context}` |",
        f"| **Context type** | `{f.context_type}` |",
        f"| **WAF** | {f.waf or '—'} |",
        f"| **Confirmed by** | `{f.execution_method}` |",
        f"| **Source** | {source_label} |",
    ]
    if f.bypass_family:
        lines.append(f"| **Bypass family** | `{f.bypass_family}` |")

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
    ]
    if include_separator:
        lines += ["---", ""]
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
        "waf_payload":      "A bounded WAF-specific fallback candidate was executed before the generic transform layer.",
        "local_model":      "The local AI model generated a payload tailored to this exact context.",
        "cloud_model":      "The cloud AI model generated a targeted bypass after the local model could not produce a working payload.",
    }
    if f.transform_name in transform_explanations:
        parts.append(transform_explanations[f.transform_name])

    if f.waf:
        parts.append(f"Target is protected by **{f.waf}** WAF. The winning technique evaded its detection.")

    return " ".join(parts) if parts else "See payload and context above for details."
