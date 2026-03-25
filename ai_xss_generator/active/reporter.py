"""Markdown + HTML report writer for active scan results.

Report structure:
  - Header: target, date, scan config
  - Confirmed findings (full detail per finding)
  - DOM taint (sink reached but no execution)
  - Pilot budget by target
  - Errors / dead targets
  - Known limitations

Live reporting:
  write_live_report() rewrites the HTML in-place during the scan so findings
  are visible before the scan completes.  The final write_report() call at the
  end produces the same file in its finished state.
"""
from __future__ import annotations

import dataclasses
import datetime
import html
import json
import urllib.parse
from pathlib import Path
from typing import Sequence

from ai_xss_generator.active.worker import WorkerResult, ConfirmedFinding
from ai_xss_generator.config import CONFIG_DIR


_REPORTS_DIR = CONFIG_DIR / "reports"


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def _resolve_output_path(output_path: str | None, urls: Sequence[str]) -> Path:
    """Compute the report base path (no extension).

    If *output_path* is supplied it is used (extension stripped so we control
    .md / .html / .ndjson ourselves).  Otherwise an auto-name is generated
    from the first domain + timestamp, stored under ~/.axss/reports/.
    """
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if output_path:
        p = Path(output_path)
        return p.parent / p.stem
    domains = sorted({urllib.parse.urlparse(u).netloc for u in urls if u})
    domain_slug = domains[0].replace(".", "_") if domains else "scan"
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return _REPORTS_DIR / f"{domain_slug}_{ts}"


# ---------------------------------------------------------------------------
# NDJSON serialisation
# ---------------------------------------------------------------------------

def serialize_result(r: WorkerResult) -> str:
    """Serialise a WorkerResult to a single NDJSON line (no trailing newline)."""
    return json.dumps(dataclasses.asdict(r), default=str)


# ---------------------------------------------------------------------------
# Finding classification helpers
# ---------------------------------------------------------------------------

def _xss_type(finding: ConfirmedFinding) -> str:
    """High-level XSS category for sidebar filter chips."""
    em  = finding.execution_method or ""
    src = finding.source or ""
    ct  = finding.context_type or ""
    if "blind" in em or "blind" in src:
        return "blind"
    if ct == "dom_xss" or "dom" in em:
        return "dom"
    if "stored" in src:
        return "stored"
    return "reflected"


def _severity(finding: ConfirmedFinding) -> str:
    """Severity tier badge label."""
    ct = finding.context_type or ""
    if ct in ("js_code", "html_attr_event", "js_string_dq", "js_string_sq",
              "js_string_bt", "json_value"):
        return "high"
    if ct == "dom_xss":
        return "dom"
    if ct in ("html_body", "html_comment", "html_attr_value"):
        return "medium"
    if ct == "html_attr_url":
        return "low"
    return "medium"


# ---------------------------------------------------------------------------
# Public write API
# ---------------------------------------------------------------------------

def write_report(
    results: Sequence[WorkerResult],
    config_summary: str = "",
    auth_summary: str = "",
    base_path: Path | None = None,
    output_path: str | None = None,
) -> str:
    """Write the final markdown + HTML reports and return the .md path string.

    *base_path* (no extension) is supplied by the orchestrator when it has
    already resolved the path early.  *output_path* is the legacy CLI string
    (used when base_path is None).
    """
    if base_path is None:
        base_path = _resolve_output_path(output_path, [r.url for r in results if r.url])

    md_path = base_path.with_suffix(".md")
    md_path.write_text(_build_report(results, config_summary, auth_summary), encoding="utf-8")
    write_live_report(results, config_summary, auth_summary, base_path, scan_complete=True)
    return str(md_path)


def write_live_report(
    results: Sequence[WorkerResult],
    config_summary: str = "",
    auth_summary: str = "",
    base_path: Path | None = None,
    *,
    scan_complete: bool = False,
) -> None:
    """Rewrite the HTML report in-place with the current results snapshot.

    Called during the scan on every confirmed finding (and periodically for
    the pilot-budget table).  base_path is the stem without extension.
    """
    if base_path is None:
        return
    html_path = base_path.with_suffix(".html")
    html_path.write_text(
        _build_html_report(results, config_summary, auth_summary, scan_complete=scan_complete),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Markdown report builder (unchanged)
# ---------------------------------------------------------------------------

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

    grouped_findings = _group_confirmed_findings(all_findings)
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
            detail   = f.execution_detail.replace("|", "\\|")
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


# ---------------------------------------------------------------------------
# HTML report builder
# ---------------------------------------------------------------------------

def _build_html_report(
    results: Sequence[WorkerResult],
    config_summary: str,
    auth_summary: str = "",
    *,
    scan_complete: bool = False,
) -> str:
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
    grouped_findings = _group_confirmed_findings(all_findings)
    domains = sorted({urllib.parse.urlparse(r.url).netloc for r in results if r.url})
    pilot_summary = _pilot_summary(results)

    # --- Compute sidebar filter data ----------------------------------------
    type_counts: dict[str, int] = {"reflected": 0, "stored": 0, "dom": 0, "blind": 0}
    domain_counts: dict[str, int] = {}
    for f in all_findings:
        t = _xss_type(f)
        type_counts[t] = type_counts.get(t, 0) + 1
        d = urllib.parse.urlparse(f.url).netloc
        domain_counts[d] = domain_counts.get(d, 0) + 1

    total_findings = len(all_findings)

    # --- Sidebar -----------------------------------------------------------
    status_label = "Scan complete" if scan_complete else "Scan in progress\u2026"

    toc_items = [("section-summary", "Executive Summary", None)]
    toc_items.append(("section-findings", "Confirmed Findings", total_findings))
    if taint_findings:
        toc_items.append(("section-taint", "DOM Taint", len(taint_findings)))
    if results:
        toc_items.append(("section-budget", "Pilot Budget", len(results)))
    if error_results:
        toc_items.append(("section-errors", "Errors", len(error_results)))

    toc_html = "\n".join(
        f'<li><a href="#{anchor}">{_h(label)}'
        + (f' <span class="toc-badge">{count}</span>' if count is not None else "")
        + "</a></li>"
        for anchor, label, count in toc_items
    )

    def _type_chip(t: str, label: str) -> str:
        cnt = type_counts.get(t, 0)
        return (
            f'<button class="chip" data-type="{_h(t)}">'
            f'{_h(label)} <span class="chip-count">({cnt})</span>'
            f'</button>'
        )

    type_chips_html = (
        f'<button class="chip active" data-type="all">'
        f'All <span class="chip-count">({total_findings})</span></button>\n'
        + "\n".join([
            _type_chip("reflected", "Reflected"),
            _type_chip("stored", "Stored"),
            _type_chip("dom", "DOM"),
            _type_chip("blind", "Blind"),
        ])
    )

    domain_chips_html = (
        f'<button class="chip active" data-domain="all">All</button>\n'
        + "\n".join(
            f'<button class="chip" data-domain="{_h(d)}">'
            f'{_h(d)} <span class="chip-count">({cnt})</span></button>'
            for d, cnt in sorted(domain_counts.items())
        )
    )

    sidebar_html = f"""
<aside class="sidebar" id="sidebar">
  <div class="sidebar-inner">
    <div class="sidebar-brand">axss</div>
    <p class="sidebar-status {'status-complete' if scan_complete else 'status-running'}">{_h(status_label)}</p>
    <nav class="toc">
      <p class="sidebar-heading">Jump to</p>
      <ul>{toc_html}</ul>
    </nav>
    <div class="filter-section">
      <p class="sidebar-heading">XSS Type</p>
      <div class="chips" id="type-chips">{type_chips_html}</div>
    </div>
    <div class="filter-section">
      <p class="sidebar-heading">Domain</p>
      <div class="chips" id="domain-chips">{domain_chips_html}</div>
    </div>
    <p class="last-updated">Updated: {_h(now)}</p>
  </div>
</aside>"""

    # --- Hero / executive summary -------------------------------------------
    conf_cls = "hero-count-confirmed" if total_findings else "hero-count-zero"
    hero_html = f"""
<section id="section-summary" class="card hero">
  <div class="hero-top">
    <div>
      <h1>axss Scan Report</h1>
      <div class="meta-grid">
        <div><span class="meta-label">Generated</span><span>{_h(now)}</span></div>
        <div><span class="meta-label">Targets</span><span>{len(results)}</span></div>
        <div><span class="meta-label">Domains</span><span>{_h(', '.join(domains) if domains else 'n/a')}</span></div>
        {"" if not config_summary else f'<div><span class="meta-label">Config</span><span>{_h(config_summary)}</span></div>'}
        {"" if not auth_summary else f'<div><span class="meta-label">Auth</span><span>{_h(auth_summary)}</span></div>'}
      </div>
    </div>
    <div class="hero-stat-block">
      <div class="{conf_cls}">{total_findings}</div>
      <div class="hero-stat-label">confirmed finding{"s" if total_findings != 1 else ""}</div>
      {"" if not taint_findings else f'<div class="hero-stat-sub">{len(taint_findings)} DOM taint</div>'}
    </div>
  </div>
  <div class="pilot-tiles">
    {_summary_tile("Hard Dead", str(pilot_summary["hard_dead"]), "dead")}
    {_summary_tile("Soft Dead", str(pilot_summary["soft_dead"]), "soft")}
    {_summary_tile("Live", str(pilot_summary["live"]), "live")}
    {_summary_tile("High Value", str(pilot_summary["high_value"]), "value")}
    {_summary_tile("Local AI", str(pilot_summary["local_rounds"]), "local")}
    {_summary_tile("Cloud AI", str(pilot_summary["cloud_rounds"]), "cloud")}
    {_summary_tile("Fallback", str(pilot_summary["fallback_rounds"]), "fallback")}
    {_summary_tile("Cloud targets", f"{pilot_summary['cloud_targets']}/{len(results)}", "cloud")}
  </div>
</section>"""

    # --- Confirmed findings --------------------------------------------------
    if grouped_findings:
        finding_cards = []
        for i, findings in enumerate(grouped_findings, 1):
            primary = findings[0]
            xss_t  = _xss_type(primary)
            domain = urllib.parse.urlparse(primary.url).netloc
            sev    = _severity(primary)
            finding_cards.append(
                _format_grouped_finding_html(i, findings, xss_type=xss_t, domain=domain, severity=sev)
            )
        findings_inner = "\n".join(finding_cards)
        findings_html = f"""
<section id="section-findings" class="card">
  <h2>Confirmed Findings
    <span class="badge badge-confirmed">{len(grouped_findings)} area(s)</span>
    <span class="badge">{total_findings} variant(s)</span>
  </h2>
  {findings_inner}
  <p id="no-filter-results" class="empty" style="display:none">No findings match the current filter.</p>
</section>"""
    else:
        findings_html = f"""
<section id="section-findings" class="card">
  <h2>Confirmed Findings</h2>
  <p class="empty">No confirmed XSS execution was detected.</p>
</section>"""

    # --- DOM taint -----------------------------------------------------------
    taint_html = ""
    if taint_findings:
        rows = "".join(
            "<tr>"
            f"<td><code>{_h(f.url)}</code></td>"
            f"<td><code>{_h(f.param_name)}</code></td>"
            f"<td><code>{_h(f.sink_context)}</code></td>"
            f"<td>{_h(f.execution_detail)}</td>"
            f"<td><code>{_h(f.fired_url)}</code></td>"
            "</tr>"
            for f in taint_findings
        )
        taint_html = f"""
<section id="section-taint" class="card">
  <h2>DOM Taint Only <span class="badge badge-soft">{len(taint_findings)}</span></h2>
  <div class="table-wrap"><table>
    <thead><tr><th>URL</th><th>Parameter</th><th>Sink</th><th>Detail</th><th>Test URL</th></tr></thead>
    <tbody>{rows}</tbody>
  </table></div>
</section>"""

    # --- Pilot budget (collapsible) -----------------------------------------
    budget_html = ""
    if results:
        budget_rows = "".join(
            "<tr>"
            f"<td><code>{_h(r.url)}</code></td>"
            f"<td><code>{_h(getattr(r, 'kind', 'get'))}</code></td>"
            f"<td>{_tier_badge(_result_tier(r))}</td>"
            f"<td>{_status_badge(r.status)}</td>"
            f"<td><code>{int(getattr(r, 'local_model_rounds', 0) or 0)}</code></td>"
            f"<td><code>{int(getattr(r, 'cloud_model_rounds', 0) or 0)}</code></td>"
            f"<td><code>{int(getattr(r, 'fallback_rounds', 0) or 0)}</code></td>"
            f"<td>{_h(_pilot_signal(r))}</td>"
            f"<td>{_h(_pilot_reasoning(r))}</td>"
            "</tr>"
            for r in results
        )
        budget_html = f"""
<section id="section-budget" class="card">
  <details>
    <summary><h2>Pilot Budget <span class="badge">{len(results)} target(s)</span></h2></summary>
    <div class="table-wrap"><table>
      <thead><tr>
        <th>URL</th><th>Kind</th><th>Tier</th><th>Status</th>
        <th>Local</th><th>Cloud</th><th>Fallback</th><th>Signal</th><th>Reasoning</th>
      </tr></thead>
      <tbody>{budget_rows}</tbody>
    </table></div>
  </details>
</section>"""

    # --- Errors / dead -------------------------------------------------------
    errors_html = ""
    if error_results or dead_results:
        err_rows = "".join(
            "<tr>"
            f"<td><code>{_h(r.url)}</code></td>"
            f"<td>{_h(r.error or 'unknown error')}</td>"
            "</tr>"
            for r in error_results
        )
        dead_rows = "".join(
            "<tr>"
            f"<td><code>{_h(r.url)}</code></td>"
            f"<td>{_status_badge(r.status)}</td>"
            f"<td>{_h(r.dead_reason or 'No further technical signal justified more budget.')}</td>"
            "</tr>"
            for r in dead_results
        )
        errors_html = f"""
<section id="section-errors" class="card">
  {"" if not error_results else f'''<h2>Errors <span class="badge badge-dead">{len(error_results)}</span></h2>
  <div class="table-wrap"><table>
    <thead><tr><th>URL</th><th>Error</th></tr></thead>
    <tbody>{err_rows}</tbody>
  </table></div>'''}
  {"" if not dead_results else f'''<h2>Dead Targets <span class="badge badge-dead">{len(dead_results)}</span></h2>
  <div class="table-wrap"><table>
    <thead><tr><th>URL</th><th>Status</th><th>Reason</th></tr></thead>
    <tbody>{dead_rows}</tbody>
  </table></div>'''}
</section>"""

    # --- Known limitations ---------------------------------------------------
    limitations_html = """
<section class="card">
  <h2>Known Limitations</h2>
  <ul class="limitations">
    <li><strong>Stored XSS (partial):</strong> Post-injection sweep checks all pages visited during crawl.
        Payloads stored and rendered on pages outside the crawl boundary require <code>--sink-url</code>
        or blind XSS to detect.</li>
    <li><strong>DOM XSS (CSP-blocked payloads):</strong> When taint flow is confirmed but execution fails
        (<code>dom_taint</code>), a strict Content Security Policy is the most likely cause.
        Manual verification with a CSP-aware payload is recommended.</li>
    <li><strong>DOM XSS (external JS bundles):</strong> The runtime hook covers inline scripts and
        dynamically evaluated code. Sinks inside lazy-loaded chunk bundles may not be reached if
        they load after the hook fires.</li>
    <li><strong>Cloud model:</strong> Bypass reasoning is based on the cloud model\u2019s training
        knowledge only. Novel WAF bypasses published after the training cutoff may be missed.</li>
  </ul>
</section>"""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>axss Report \u2014 {_h(domains[0] if domains else 'scan')}</title>
  <style>{_HTML_REPORT_CSS}</style>
</head>
<body>
<div class="layout">
{sidebar_html}
<main class="content">
{hero_html}
{findings_html}
{taint_html}
{budget_html}
{errors_html}
{limitations_html}
</main>
</div>
<script>{_HTML_REPORT_JS}</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _result_tier(result: WorkerResult) -> str:
    tier = str(getattr(result, "target_tier", "") or "").strip().lower()
    return tier or "unknown"


def _pilot_summary(results: Sequence[WorkerResult]) -> dict[str, int]:
    summary = {
        "hard_dead": 0, "soft_dead": 0, "live": 0, "high_value": 0, "unknown": 0,
        "local_rounds": 0, "cloud_rounds": 0, "fallback_rounds": 0, "cloud_targets": 0,
    }
    for result in results:
        tier = _result_tier(result)
        if tier not in summary:
            tier = "unknown"
        summary[tier] += 1
        summary["local_rounds"]   += int(getattr(result, "local_model_rounds", 0) or 0)
        summary["cloud_rounds"]   += int(getattr(result, "cloud_model_rounds", 0) or 0)
        summary["fallback_rounds"] += int(getattr(result, "fallback_rounds", 0) or 0)
        if getattr(result, "cloud_escalated", False) or int(getattr(result, "cloud_model_rounds", 0) or 0) > 0:
            summary["cloud_targets"] += 1
    return summary


def _pilot_signal(result: WorkerResult) -> str:
    parts: list[str] = []
    params_tested    = int(getattr(result, "params_tested", 0) or 0)
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
        "phase1_transform":      "Deterministic fallback transform",
        "phase1_waf_fallback":   "WAF-specific deterministic fallback",
        "phase1_deterministic":  "Deterministic (context-matched)",
        "local_model":           "Local AI model payload",
        "cloud_model":           "Cloud model payload (escalated)",
        "dom_xss_runtime":       "DOM XSS runtime sink hooking",
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
        "confirmed":    "confirmed",
        "taint_only":   "soft",
        "error":        "dead",
        "no_execution": "neutral",
        "no_reflection":"dead",
        "no_params":    "dead",
    }.get(status, "neutral")
    return f"<span class='badge badge-{tone}'>{_h(status)}</span>"


def _tier_badge(tier: str) -> str:
    tone = {
        "hard_dead":  "dead",
        "soft_dead":  "soft",
        "live":       "live",
        "high_value": "value",
    }.get(tier, "neutral")
    return f"<span class='badge badge-{tone}'>{_h(tier)}</span>"


def _severity_badge(severity: str) -> str:
    tone = {"high": "sev-high", "medium": "sev-medium", "low": "sev-low", "dom": "sev-dom"}.get(severity, "neutral")
    label = severity.upper()
    return f"<span class='badge badge-{tone}'>{label}</span>"


# ---------------------------------------------------------------------------
# HTML finding card
# ---------------------------------------------------------------------------

def _code_block(content: str) -> str:
    """Wrap content in a copyable code block."""
    return (
        "<div class='code-wrap'>"
        "<button class='copy-btn' onclick='copyCode(this)'>Copy</button>"
        f"<pre>{_h(content)}</pre>"
        "</div>"
    )


def _format_grouped_finding_html(
    index: int,
    findings: Sequence[ConfirmedFinding],
    *,
    xss_type: str = "",
    domain: str = "",
    severity: str = "",
) -> str:
    primary = findings[0]
    parsed   = urllib.parse.urlparse(primary.url)
    endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    detail_rows = [
        ("Parameter / Source", primary.param_name),
        ("Sink",               primary.sink_context),
        ("Context type",       primary.context_type),
        ("WAF",                primary.waf or "\u2014"),
        ("Confirmed by",       primary.execution_method),
        ("Source",             _source_label(primary.source)),
    ]
    if primary.bypass_family:
        detail_rows.append(("Bypass family", primary.bypass_family))
    if primary.ai_engine:
        detail_rows.append(("AI engine", primary.ai_engine))
    if primary.ai_note:
        detail_rows.append(("AI note", primary.ai_note))
    if primary.context_type != "dom_xss":
        detail_rows.append(("Transform",        primary.transform_name))
        detail_rows.append(("Surviving chars",  primary.surviving_chars or "?"))

    details_html = "".join(
        f"<div class='detail-row'><span>{_h(label)}</span><code>{_h(value)}</code></div>"
        for label, value in detail_rows
    )

    sev_badge  = _severity_badge(severity) if severity else ""
    type_badge = f"<span class='badge badge-xss-{_h(xss_type)}'>{_h(xss_type)}</span>" if xss_type else ""

    parts = [
        f'<article class="finding-card" data-xss-type="{_h(xss_type)}" data-domain="{_h(domain)}">',
        "<div class='finding-head'>",
        f"<h3>Finding {index} <span class='endpoint'>{_h(endpoint)}</span></h3>",
        f"<div class='finding-badges'>{_status_badge('confirmed')}{sev_badge}{type_badge}"
        f"<span class='badge'>{len(findings)} variant(s)</span></div>",
        "</div>",
        "<div class='detail-grid'>",
        details_html,
        "</div>",
    ]

    if primary.payload:
        parts += [
            "<section class='block'>",
            "<h4>Primary Payload</h4>",
            _code_block(primary.payload),
            "</section>",
        ]

    parts += [
        "<section class='block'>",
        "<h4>Test URL</h4>",
        _code_block(urllib.parse.unquote(primary.fired_url)),
        "</section>",
    ]

    if primary.context_type == "dom_xss" and primary.code_location:
        parts += [
            "<section class='block'>",
            "<h4>JS Sink Location</h4>",
            _code_block(primary.code_location),
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
        var_rows = "".join(
            "<tr>"
            f"<td>{_code_block(f.payload or '\u2014')}</td>"
            f"<td>{_h(_source_label(f.source))}</td>"
            f"<td><code>{_h(f.execution_method)}</code></td>"
            f"<td><code>{_h(f.transform_name or '\u2014')}</code></td>"
            f"<td><code>{_h(f.bypass_family or '\u2014')}</code></td>"
            "</tr>"
            for f in findings[1:]
        )
        parts += [
            "<section class='block'>",
            "<h4>Additional Confirmed Variants</h4>",
            "<div class='table-wrap'><table>",
            "<thead><tr><th>Payload</th><th>Source</th><th>Confirmed by</th><th>Transform</th><th>Bypass family</th></tr></thead>",
            f"<tbody>{var_rows}</tbody>",
            "</table></div></section>",
        ]

    parts.append("</article>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Markdown finding formatters (unchanged)
# ---------------------------------------------------------------------------

def _format_grouped_finding(index: int, findings: Sequence[ConfirmedFinding]) -> list[str]:
    primary = findings[0]
    parsed  = urllib.parse.urlparse(primary.url)
    endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    lines = [f"### Finding {index} \u2014 `{endpoint}`", ""]

    if len(findings) > 1:
        lines += [f"**Confirmed variants:** `{len(findings)}` distinct payload/result combinations for this same area.", ""]

    lines += _format_finding_detail(primary, include_heading=False, include_separator=len(findings) == 1)

    if len(findings) > 1:
        lines += [
            "**Additional confirmed variants:**", "",
            "| Payload | Source | Confirmed by | Transform | Bypass family |",
            "|---------|--------|--------------|-----------|---------------|",
        ]
        for finding in findings[1:]:
            payload      = finding.payload.replace("|", "\\|") if finding.payload else "\u2014"
            source_label = _source_label(finding.source).replace("|", "\\|")
            transform    = (finding.transform_name or "\u2014").replace("|", "\\|")
            family       = (finding.bypass_family or "\u2014").replace("|", "\\|")
            lines.append(f"| `{payload}` | {source_label} | `{finding.execution_method}` | `{transform}` | `{family}` |")
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
    parsed   = urllib.parse.urlparse(f.url)
    endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    is_dom   = f.context_type == "dom_xss"
    source_label = _source_label(f.source)
    why = _explain_why(f)

    lines: list[str] = []
    if include_heading:
        lines += [f"### Finding {index} \u2014 `{endpoint}`", ""]

    lines += [
        "| Field | Value |",
        "|-------|-------|",
        f"| **Parameter / Source** | `{f.param_name}` |",
        f"| **Sink** | `{f.sink_context}` |",
        f"| **Context type** | `{f.context_type}` |",
        f"| **WAF** | {f.waf or '\u2014'} |",
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
        lines += ["**Payload:**", "```", f.payload, "```", ""]

    lines += [
        "**Test URL** _(paste into browser to reproduce)_:",
        "```",
        urllib.parse.unquote(f.fired_url),
        "```",
        "",
    ]

    if is_dom and f.code_location:
        lines += [
            "**JS sink location** _(where in the page\u2019s JS the sink was reached)_:",
            "```",
            f.code_location,
            "```",
            "",
        ]

    lines += ["**Detail:**", f"{f.execution_detail}", "", "**Why it worked:**", f"{why}", ""]
    if include_separator:
        lines += ["---", ""]
    return lines


def _explain_why(f: ConfirmedFinding) -> str:
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
        "raw":             "The raw payload was not filtered.",
        "svg_tag":         "`<svg onload=...>` was not blocked by the WAF/filter.",
        "img_onerror":     "`<img src=x onerror=...>` bypassed tag or event filtering.",
        "mixed_case_tags": "Mixed-case tag names (`<ScRiPt>`) bypassed case-sensitive pattern matching.",
        "mixed_case_ev":   "Mixed-case event handler names bypassed case-sensitive pattern matching.",
        "no_space":        "Removing spaces (e.g. `<svg/onload=...>`) bypassed whitespace-dependent filters.",
        "backtick_call":   "Backtick call syntax (alert\u0060\u00601\u0060\u0060) bypassed parenthesis filters.",
        "url_encode":      "URL-encoding the payload bypassed string-level WAF pattern matching.",
        "double_url":      "Double URL-encoding bypassed a WAF that decodes only once.",
        "html_entity":     "HTML entity encoding of `<`/`>` bypassed character-level filters.",
        "full_width":      "Full-width Unicode characters bypassed ASCII-only WAF pattern matching.",
        "js_uri":          "`javascript:` URI scheme executed when injected into a URL-type attribute.",
        "autofocus":       "`onfocus` + `autofocus` attributes triggered execution without user interaction.",
        "details_toggle":  "`<details open ontoggle=...>` triggered execution on page load without clicks.",
        "waf_payload":     "A bounded WAF-specific fallback candidate was executed before the generic transform layer.",
        "local_model":     "The local AI model generated a payload tailored to this exact context.",
        "cloud_model":     "The cloud AI model generated a targeted bypass after the local model could not produce a working payload.",
    }
    if f.transform_name in transform_explanations:
        parts.append(transform_explanations[f.transform_name])

    if f.waf:
        parts.append(f"Target is protected by **{f.waf}** WAF. The winning technique evaded its detection.")

    return " ".join(parts) if parts else "See payload and context above for details."


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_HTML_REPORT_CSS = """
:root {
  --bg: #f4efe4;
  --paper: #fffdf8;
  --ink: #182022;
  --muted: #5f6a6d;
  --line: #d8d0c2;
  --accent: #005f73;
  --sidebar-w: 272px;
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
  --sev-high: #a33636;
  --sev-medium: #8d6b19;
  --sev-low: #3c6e71;
  --sev-dom: #355070;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
  color: var(--ink);
  background: linear-gradient(180deg, #efe8d8 0%, var(--bg) 100%);
  min-height: 100vh;
}

/* ── Two-column layout ─────────────────────────────────────────────────── */
.layout {
  display: grid;
  grid-template-columns: var(--sidebar-w) 1fr;
  min-height: 100vh;
}

/* ── Sidebar ───────────────────────────────────────────────────────────── */
.sidebar {
  background: var(--paper);
  border-right: 1px solid var(--line);
  min-height: 100vh;
}
.sidebar-inner {
  position: sticky;
  top: 0;
  max-height: 100vh;
  overflow-y: auto;
  padding: 20px 16px 32px;
  scrollbar-width: thin;
}
.sidebar-brand {
  font-family: "IBM Plex Mono", monospace;
  font-size: 1.3rem;
  font-weight: 700;
  color: var(--accent);
  letter-spacing: 0.06em;
  margin-bottom: 4px;
}
.sidebar-status {
  font-size: 0.75rem;
  margin: 0 0 16px;
  padding: 3px 8px;
  border-radius: 999px;
  display: inline-block;
}
.status-complete { background: rgba(27,127,90,0.12); color: var(--confirmed); }
.status-running  { background: rgba(141,107,25,0.12); color: var(--soft); }
.sidebar-heading {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
  margin: 16px 0 6px;
  font-weight: 600;
}
.toc ul { margin: 0; padding: 0; list-style: none; }
.toc li { margin-bottom: 2px; }
.toc a {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 5px 8px;
  border-radius: 8px;
  text-decoration: none;
  color: var(--ink);
  font-size: 0.88rem;
  transition: background 0.15s;
}
.toc a:hover { background: rgba(0,95,115,0.08); }
.toc-badge {
  margin-left: auto;
  font-size: 0.72rem;
  background: #ece7dc;
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: 1px 6px;
  color: var(--muted);
}
.filter-section { margin-top: 4px; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip {
  font-size: 0.78rem;
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: #f4efe4;
  color: var(--ink);
  cursor: pointer;
  transition: background 0.15s, border-color 0.15s;
  font-family: inherit;
}
.chip:hover { background: #ece7dc; }
.chip.active {
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
}
.chip.active .chip-count { color: rgba(255,255,255,0.75); }
.chip-count { color: var(--muted); font-size: 0.72rem; }
.last-updated {
  margin-top: 20px;
  font-size: 0.72rem;
  color: var(--muted);
}

/* ── Main content ──────────────────────────────────────────────────────── */
.content {
  padding: 24px 28px 48px;
  min-width: 0;
}
.card {
  background: var(--paper);
  border: 1px solid var(--line);
  border-radius: 18px;
  box-shadow: 0 8px 24px rgba(24,32,34,0.07);
  padding: 22px 24px;
  margin-bottom: 18px;
}

/* ── Hero ──────────────────────────────────────────────────────────────── */
.hero-top {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
  margin-bottom: 20px;
}
h1 { font-family: "IBM Plex Serif", Georgia, serif; font-size: 1.8rem; margin: 0 0 12px; }
h2 { font-family: "IBM Plex Serif", Georgia, serif; font-size: 1.3rem; margin: 0 0 14px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
h3 { font-size: 1.05rem; margin: 0 0 12px; }
h4 { font-size: 0.9rem; margin: 0 0 8px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
.hero-stat-block { text-align: right; flex-shrink: 0; }
.hero-count-confirmed {
  font-size: 3.5rem;
  font-weight: 800;
  line-height: 1;
  color: var(--confirmed);
  font-family: "IBM Plex Serif", Georgia, serif;
}
.hero-count-zero {
  font-size: 3.5rem;
  font-weight: 800;
  line-height: 1;
  color: var(--muted);
  font-family: "IBM Plex Serif", Georgia, serif;
}
.hero-stat-label { font-size: 0.85rem; color: var(--muted); margin-top: 4px; }
.hero-stat-sub   { font-size: 0.78rem; color: var(--soft);  margin-top: 2px; }
.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 10px;
}
.meta-label {
  display: block;
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
  margin-bottom: 2px;
}
.pilot-tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 10px;
  margin-top: 4px;
}
.summary-tile {
  border-radius: 12px;
  padding: 12px 14px;
  border: 1px solid var(--line);
  background: #f8f4eb;
}
.summary-tile strong { font-size: 1.25rem; display: block; }
.summary-label {
  display: block;
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
  margin-bottom: 3px;
}
.tone-dead     { border-color: rgba(163,54,54,0.3); }
.tone-soft     { border-color: rgba(141,107,25,0.3); }
.tone-live     { border-color: rgba(29,109,134,0.3); }
.tone-value    { border-color: rgba(123,63,160,0.3); }
.tone-local    { border-color: rgba(60,110,113,0.3); }
.tone-cloud    { border-color: rgba(53,80,112,0.3); }
.tone-fallback { border-color: rgba(139,90,43,0.3); }

/* ── Badges ────────────────────────────────────────────────────────────── */
.badge {
  display: inline-flex;
  align-items: center;
  padding: 3px 9px;
  border-radius: 999px;
  background: #ece7dc;
  color: var(--ink);
  font-size: 0.75rem;
  font-weight: 600;
  border: 1px solid var(--line);
}
.finding-badges { display: flex; flex-wrap: wrap; gap: 6px; }
.badge-confirmed { background: rgba(27,127,90,0.12);  color: var(--confirmed); border-color: rgba(27,127,90,0.3); }
.badge-soft      { background: rgba(141,107,25,0.12); color: var(--soft);      border-color: rgba(141,107,25,0.3); }
.badge-dead      { background: rgba(163,54,54,0.12);  color: var(--dead);      border-color: rgba(163,54,54,0.3); }
.badge-live      { background: rgba(29,109,134,0.12); color: var(--live);      border-color: rgba(29,109,134,0.3); }
.badge-value     { background: rgba(123,63,160,0.12); color: var(--value);     border-color: rgba(123,63,160,0.3); }
.badge-neutral   { background: rgba(108,117,125,0.1); color: var(--neutral);   border-color: rgba(108,117,125,0.3); }
.badge-sev-high   { background: rgba(163,54,54,0.12);  color: var(--sev-high);   border-color: rgba(163,54,54,0.3); }
.badge-sev-medium { background: rgba(141,107,25,0.12); color: var(--sev-medium); border-color: rgba(141,107,25,0.3); }
.badge-sev-low    { background: rgba(60,110,113,0.12); color: var(--sev-low);    border-color: rgba(60,110,113,0.3); }
.badge-sev-dom    { background: rgba(53,80,112,0.12);  color: var(--sev-dom);    border-color: rgba(53,80,112,0.3); }
.badge-xss-reflected { background: rgba(163,54,54,0.08);  color: var(--dead);   border-color: rgba(163,54,54,0.2); }
.badge-xss-stored    { background: rgba(141,107,25,0.08); color: var(--soft);   border-color: rgba(141,107,25,0.2); }
.badge-xss-dom       { background: rgba(53,80,112,0.08);  color: var(--cloud);  border-color: rgba(53,80,112,0.2); }
.badge-xss-blind     { background: rgba(123,63,160,0.08); color: var(--value);  border-color: rgba(123,63,160,0.2); }

/* ── Finding cards ─────────────────────────────────────────────────────── */
.finding-card {
  background: var(--paper);
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 18px 20px;
  margin-bottom: 14px;
}
.finding-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
  margin-bottom: 14px;
}
.endpoint {
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.8rem;
  color: var(--muted);
  margin-left: 6px;
  font-weight: 400;
}
.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 8px;
  margin-bottom: 14px;
}
.detail-row {
  padding: 9px 11px;
  background: #faf6ee;
  border: 1px solid #ece4d6;
  border-radius: 10px;
}
.detail-row span {
  display: block;
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
  margin-bottom: 3px;
}
.detail-row code { font-family: "IBM Plex Mono", monospace; }
.block   { margin-top: 12px; }
.callout {
  margin-top: 12px;
  border-left: 3px solid var(--accent);
  padding-left: 14px;
}

/* ── Code blocks with copy ─────────────────────────────────────────────── */
.code-wrap {
  position: relative;
}
.copy-btn {
  position: absolute;
  top: 8px;
  right: 8px;
  padding: 3px 10px;
  font-size: 0.72rem;
  border-radius: 6px;
  border: 1px solid var(--line);
  background: var(--paper);
  color: var(--muted);
  cursor: pointer;
  font-family: inherit;
  opacity: 0;
  transition: opacity 0.15s, background 0.15s;
}
.code-wrap:hover .copy-btn { opacity: 1; }
.copy-btn.copied { background: rgba(27,127,90,0.12); color: var(--confirmed); border-color: rgba(27,127,90,0.3); }
pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  background: var(--code);
  border: 1px solid #e3dccd;
  border-radius: 10px;
  padding: 12px 14px;
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.88rem;
}

/* ── Tables ────────────────────────────────────────────────────────────── */
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
th, td { text-align: left; vertical-align: top; padding: 9px 11px; border-bottom: 1px solid #e7e0d3; }
thead th {
  background: #f6f0e4;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted);
  position: sticky;
  top: 0;
}
td code { font-family: "IBM Plex Mono", monospace; }

/* ── Pilot budget collapsible ──────────────────────────────────────────── */
details > summary {
  cursor: pointer;
  list-style: none;
  display: flex;
  align-items: center;
  gap: 8px;
}
details > summary::-webkit-details-marker { display: none; }
details > summary h2 { margin: 0; }
details > summary::before {
  content: "\u25b6";
  font-size: 0.7rem;
  color: var(--muted);
  transition: transform 0.2s;
  flex-shrink: 0;
}
details[open] > summary::before { transform: rotate(90deg); }
details > .table-wrap { margin-top: 14px; }

/* ── Misc ──────────────────────────────────────────────────────────────── */
.limitations { margin: 0; padding-left: 20px; }
.limitations li { margin-bottom: 10px; line-height: 1.55; }
.empty { color: var(--muted); font-style: italic; margin: 8px 0; }

/* ── Mobile ────────────────────────────────────────────────────────────── */
@media (max-width: 800px) {
  .layout { grid-template-columns: 1fr; }
  .sidebar { min-height: unset; border-right: none; border-bottom: 1px solid var(--line); }
  .sidebar-inner { max-height: unset; position: static; padding: 14px 16px 16px; }
  .content { padding: 16px 16px 40px; }
  .hero-top { flex-direction: column; }
  .hero-stat-block { text-align: left; }
  .finding-head { flex-direction: column; }
  h1 { font-size: 1.4rem; }
}
"""


# ---------------------------------------------------------------------------
# Inline JS
# ---------------------------------------------------------------------------

_HTML_REPORT_JS = """
/* ── Copy-to-clipboard ───────────────────────────────────────────────── */
function copyCode(btn) {
  var pre = btn.parentElement.querySelector('pre');
  var text = pre ? pre.textContent : '';
  if (!text) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function() { _flashCopied(btn); });
  } else {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus(); ta.select();
    try { document.execCommand('copy'); } catch(e) {}
    document.body.removeChild(ta);
    _flashCopied(btn);
  }
}
function _flashCopied(btn) {
  btn.textContent = 'Copied!';
  btn.classList.add('copied');
  setTimeout(function() { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
}

/* ── Finding filters ─────────────────────────────────────────────────── */
(function() {
  var activeType   = 'all';
  var activeDomain = 'all';

  function applyFilters() {
    var cards = document.querySelectorAll('.finding-card[data-xss-type]');
    var typeCounts   = {};
    var domainCounts = {};
    var totalVisible = 0;

    cards.forEach(function(card) {
      var t = card.dataset.xssType   || '';
      var d = card.dataset.domain    || '';
      typeCounts[t]   = (typeCounts[t]   || 0);
      domainCounts[d] = (domainCounts[d] || 0);

      var typeMatch   = activeType   === 'all' || t === activeType;
      var domainMatch = activeDomain === 'all' || d === activeDomain;
      var show = typeMatch && domainMatch;
      card.style.display = show ? '' : 'none';

      if (show) {
        totalVisible++;
        typeCounts[t]++;
        domainCounts[d]++;
      }
    });

    /* update type chip counts */
    document.querySelectorAll('#type-chips .chip').forEach(function(chip) {
      var t    = chip.dataset.type;
      var span = chip.querySelector('.chip-count');
      if (!span) return;
      if (t === 'all') span.textContent = '(' + cards.length + ')';
      else             span.textContent = '(' + (typeCounts[t] || 0) + ')';
    });

    /* update domain chip counts */
    document.querySelectorAll('#domain-chips .chip').forEach(function(chip) {
      var d    = chip.dataset.domain;
      var span = chip.querySelector('.chip-count');
      if (!span) return;
      if (d === 'all') span.textContent = '(' + cards.length + ')';
      else             span.textContent = '(' + (domainCounts[d] || 0) + ')';
    });

    var noResults = document.getElementById('no-filter-results');
    if (noResults) noResults.style.display = totalVisible === 0 && cards.length > 0 ? '' : 'none';
  }

  function bindChips(containerId, key) {
    document.querySelectorAll('#' + containerId + ' .chip').forEach(function(chip) {
      chip.addEventListener('click', function() {
        document.querySelectorAll('#' + containerId + ' .chip').forEach(function(c) {
          c.classList.remove('active');
        });
        chip.classList.add('active');
        if (key === 'type')   activeType   = chip.dataset.type;
        if (key === 'domain') activeDomain = chip.dataset.domain;
        applyFilters();
      });
    });
  }

  bindChips('type-chips',   'type');
  bindChips('domain-chips', 'domain');
  applyFilters();
})();
"""
