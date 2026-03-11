"""Active scan orchestrator — spawns per-URL worker processes and aggregates results.

Rate limiting:
  - Per-domain: each domain gets its own token bucket at `rate` req/s.
  - Global cap: total concurrent workers capped at `workers`.
  - Workers auto-scale based on rate (floor(rate / 5) workers, min 1), but
    never exceed the explicit --workers cap.

Deduplication:
  - cloud escalation calls are deduplicated by a shared Manager dict.
  - Key includes URL endpoint + param name, so different endpoints / params
    on the same domain always get their own cloud call.

Findings writes:
  - A shared Manager Lock is passed to every worker so concurrent writes
    to ~/.axss/findings/ are serialised.
"""
from __future__ import annotations

import logging
import math
import multiprocessing
import signal
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Sequence, TYPE_CHECKING

if TYPE_CHECKING:
    from ai_xss_generator.types import PostFormTarget

from ai_xss_generator.active.worker import WorkerResult, run_worker
from ai_xss_generator.console import (
    fmt_duration, info, setup_panel, step, success,
    teardown_panel, update_panel, warn,
    BOLD, CYAN, DIM, GREEN, RESET,
)

log = logging.getLogger(__name__)


@dataclass
class ActiveScanConfig:
    rate: float = 5.0
    workers: int = 1
    model: str = "qwen3.5:9b"
    cloud_model: str = "anthropic/claude-3-5-sonnet"
    use_cloud: bool = True
    waf: str | None = None
    timeout_seconds: int = 300     # 5 minutes per URL
    output_path: str | None = None  # markdown report output; None = auto
    auth_headers: dict[str, str] = field(default_factory=dict)
    sink_url: str | None = None    # manual sink page for stored XSS (--sink-url)
    # XSS type selectors — control which scan types run
    scan_reflected: bool = True   # GET parameter injection (reflected XSS)
    scan_stored: bool = True      # POST form injection (stored XSS)
    scan_dom: bool = True         # DOM source/sink analysis (DOM XSS)
    # AI backend for cloud escalation
    ai_backend: str = "api"       # "api" | "cli"
    cli_tool: str = "claude"      # "claude" | "codex" (when ai_backend="cli")
    cli_model: str | None = None  # model passed to CLI (None = CLI default)


def _auto_workers(rate: float, explicit_workers: int) -> int:
    """Scale workers with rate but never exceed the explicit cap."""
    auto = max(1, math.floor(rate / 5.0))
    return min(auto, explicit_workers)


def _domain(url: str) -> str:
    return urllib.parse.urlparse(url).netloc or url


def run_active_scan(
    urls: Sequence[str],
    config: ActiveScanConfig,
    post_forms: "Sequence[PostFormTarget]" = (),
    crawled_pages: Sequence[str] = (),
    session: "Any | None" = None,
) -> list[WorkerResult]:
    """Spawn isolated worker processes for each URL and collect results.

    Workers run up to `config.workers` at a time. A shared Manager provides:
      - dedup_registry: dict  — cloud escalation deduplication
      - dedup_lock:     Lock  — guards dedup_registry
      - findings_lock:  Lock  — serialises findings store writes
    """
    from ai_xss_generator.active.worker import run_post_worker
    url_list = [u.strip() for u in urls if u and u.strip()]
    post_form_list = list(post_forms)
    crawled_pages_list = list(crawled_pages)

    # Build work items filtered by enabled scan types
    work_items: list[tuple[str, Any]] = []
    if config.scan_reflected:
        work_items += [("get", u) for u in url_list]
    if config.scan_stored:
        work_items += [("post", pf) for pf in post_form_list]

    # DOM XSS: not yet implemented — always notify when requested
    if config.scan_dom:
        other_types_enabled = config.scan_reflected or config.scan_stored
        if not other_types_enabled:
            info("DOM XSS scanning is not yet implemented — coming soon.")
            return []
        else:
            info("DOM XSS scanning is not yet implemented — skipping; reflected/stored will still run.")

    # Session resume: filter out already-completed work items and restore
    # prior results so _print_summary / write_report include all findings.
    prior_results: list[WorkerResult] = []
    if session is not None:
        from ai_xss_generator.session import completed_urls as _completed_urls, restore_results
        done_urls = _completed_urls(session)
        if done_urls:
            before = len(work_items)
            work_items = [
                (kind, item) for kind, item in work_items
                if (item if kind == "get" else item.action_url) not in done_urls
            ]
            skipped = before - len(work_items)
            if skipped:
                step(f"Session resume: {skipped} item(s) already done, {len(work_items)} remaining")
        prior_results = restore_results(session)

    if not work_items:
        # Explain why there's nothing to do rather than silently returning
        _reasons = []
        if session is not None and prior_results:
            # All items already done from a prior session
            info("Session complete — all work items were already finished in a prior run.")
            _print_summary(prior_results)
            return prior_results
        if config.scan_reflected and not url_list:
            _reasons.append("no GET URLs with testable query parameters")
        if config.scan_stored and not post_form_list:
            _reasons.append("no POST forms discovered (try without --no-crawl)")
        if _reasons:
            info(f"Active scan: nothing to test — {'; '.join(_reasons)}")
        return []

    # Human-readable list of types that will actually run (dom excluded — not yet implemented)
    _active_types = " + ".join(filter(None, [
        "reflected" if config.scan_reflected else None,
        "stored" if config.scan_stored else None,
    ]))
    n_get = sum(1 for kind, _ in work_items if kind == "get")
    n_post = sum(1 for kind, _ in work_items if kind == "post")

    n_workers = _auto_workers(config.rate, config.workers)
    step(
        f"Active scan [{_active_types}]: {n_get} GET URL(s) + {n_post} POST form(s) | "
        f"{n_workers} worker(s) | "
        f"{config.rate:g} req/s rate | "
        f"{config.timeout_seconds}s timeout"
    )

    manager = multiprocessing.Manager()
    dedup_registry = manager.dict()
    dedup_lock = manager.Lock()
    findings_lock = manager.Lock()
    result_queue: multiprocessing.Queue = manager.Queue()

    # Start with results from a prior session run (empty list on fresh scan)
    results: list[WorkerResult] = list(prior_results)
    # (proc, label, kind) — kind is "get" or "post" for worker pill display
    active_procs: list[tuple[multiprocessing.Process, str, str]] = []
    work_iter = iter(work_items)
    total_count = len(work_items)
    completed = 0
    # Seed confirmed_count from prior results so the panel shows cumulative total
    confirmed_count = sum(
        len(r.confirmed_findings) for r in prior_results if r.status == "confirmed"
    )
    scan_start = time.monotonic()
    # Graceful-pause state — modified by signal handler
    _pause_requested = False
    _pause_announced = False

    def _build_panel() -> tuple[str, str, str]:
        """Build the three panel line strings from current scan state."""
        import shutil as _sh
        cols = _sh.get_terminal_size(fallback=(80, 24)).columns
        elapsed = time.monotonic() - scan_start

        # ── Separator ──────────────────────────────────────────────────────
        sep = f"  {DIM}{'─' * max(cols - 4, 10)}{RESET}"

        # ── Progress bar ───────────────────────────────────────────────────
        BAR_W = 28
        safe_total = max(total_count, 1)
        pct = int(completed * 100 / safe_total)
        filled = int(completed * BAR_W / safe_total)
        empty = BAR_W - filled
        if completed > 0 and elapsed > 0:
            eta_secs = (elapsed / completed) * (total_count - completed)
            eta_str = fmt_duration(eta_secs)
        else:
            eta_str = "--:--"
        bar = (
            f"  {DIM}[{RESET}"
            f"{GREEN}{'█' * filled}{RESET}"
            f"{DIM}{'░' * empty}]{RESET}"
            f"  {BOLD}{pct}%{RESET}"
            f"  {DIM}{completed}/{total_count}{RESET}"
            f"  {fmt_duration(elapsed)} elapsed"
            f"  {DIM}ETA {eta_str}{RESET}"
        )

        # ── Workers + confirmed + active label ─────────────────────────────
        pills: list[str] = []
        for _, _lbl, _kind in active_procs:
            if _kind == "get":
                pills.append(f"{GREEN}GET●{RESET}")
            else:
                pills.append(f"{CYAN}POST●{RESET}")
        for _ in range(max(0, n_workers - len(active_procs))):
            pills.append(f"{DIM}idle○{RESET}")
        pills_str = "  ".join(pills)

        conf_str = (
            f"{GREEN}{BOLD}✓ {confirmed_count}{RESET}"
            if confirmed_count else f"{DIM}✓ 0{RESET}"
        )

        max_label = max(cols - 56, 12)
        if active_procs:
            raw = active_procs[0][1]
            if len(raw) > max_label:
                raw = "…" + raw[-(max_label - 1):]
            label_part = f"  {DIM}│{RESET}  {DIM}{raw}{RESET}"
        else:
            label_part = ""

        workers = f"  {pills_str}   {DIM}│{RESET}  {conf_str} confirmed{label_part}"
        return sep, bar, workers

    def _drain_queue() -> None:
        nonlocal confirmed_count
        import queue as _queue
        while True:
            try:
                r = result_queue.get(timeout=0.05)
                results.append(r)
                _log_result(r)
                if r.status == "confirmed":
                    confirmed_count += len(r.confirmed_findings)
                # Checkpoint every completed result so a crash or pause is resumable
                if session is not None:
                    from ai_xss_generator.session import checkpoint as _checkpoint
                    _checkpoint(session, r.url, r)
            except _queue.Empty:
                break
            except Exception:
                break

    def _reap_finished() -> None:
        nonlocal active_procs, completed
        still_running = []
        for proc, plabel, pkind in active_procs:
            if not proc.is_alive():
                proc.join(timeout=1)
                completed += 1
                log.debug("Worker done for %s (%d/%d)", plabel, completed, total_count)
            else:
                still_running.append((proc, plabel, pkind))
        active_procs = still_running

    # Install SIGINT handler for two-stage graceful pause.
    # First Ctrl+C: stop accepting new work, let in-flight workers finish.
    # Second Ctrl+C: kill all workers immediately.
    _original_sigint = signal.getsignal(signal.SIGINT)

    def _sigint_handler(sig: int, frame: Any) -> None:
        nonlocal _pause_requested, _pause_announced
        if _pause_requested:
            # Second Ctrl+C — kill everything now
            warn("Force-kill: terminating all workers immediately...")
            for proc, _, _ in active_procs:
                proc.kill()
            raise KeyboardInterrupt
        _pause_requested = True

    signal.signal(signal.SIGINT, _sigint_handler)

    setup_panel()
    update_panel(*_build_panel())
    _scan_completed_cleanly = False
    try:
        while completed < total_count:
            _drain_queue()
            _reap_finished()

            if _pause_requested:
                if not _pause_announced:
                    _pause_announced = True
                    warn(
                        "Scan paused — letting in-flight workers finish. "
                        "Ctrl+C again to kill immediately."
                    )
                    if session is not None:
                        from ai_xss_generator.session import mark_status as _mark_status
                        _mark_status(session, "paused")
                # Don't start new workers; wait for active ones to drain
                if not active_procs:
                    break
            else:
                # Fill up to n_workers slots
                _cli_kwargs = {
                    "ai_backend": config.ai_backend,
                    "cli_tool": config.cli_tool,
                    "cli_model": config.cli_model,
                }
                while len(active_procs) < n_workers:
                    try:
                        kind, item = next(work_iter)
                    except StopIteration:
                        break

                    if kind == "get":
                        next_url = item
                        proc = multiprocessing.Process(
                            target=run_worker,
                            kwargs={
                                "url": next_url,
                                "rate": config.rate,
                                "waf_hint": config.waf,
                                "model": config.model,
                                "cloud_model": config.cloud_model,
                                "use_cloud": config.use_cloud,
                                "timeout_seconds": config.timeout_seconds,
                                "result_queue": result_queue,
                                "dedup_registry": dedup_registry,
                                "dedup_lock": dedup_lock,
                                "findings_lock": findings_lock,
                                "auth_headers": config.auth_headers,
                                "sink_url": config.sink_url,
                                **_cli_kwargs,
                            },
                            daemon=True,
                        )
                        log_label = next_url
                    else:
                        pf = item
                        proc = multiprocessing.Process(
                            target=run_post_worker,
                            kwargs={
                                "post_form": pf,
                                "rate": config.rate,
                                "waf_hint": config.waf,
                                "model": config.model,
                                "cloud_model": config.cloud_model,
                                "use_cloud": config.use_cloud,
                                "timeout_seconds": config.timeout_seconds,
                                "result_queue": result_queue,
                                "dedup_registry": dedup_registry,
                                "dedup_lock": dedup_lock,
                                "findings_lock": findings_lock,
                                "auth_headers": config.auth_headers,
                                "crawled_pages": crawled_pages_list,
                                "sink_url": config.sink_url,
                                **_cli_kwargs,
                            },
                            daemon=True,
                        )
                        log_label = f"[POST] {pf.action_url}"
                    proc.start()
                    active_procs.append((proc, log_label, kind))
                    info(f"[worker] started → {log_label}")

            update_panel(*_build_panel())
            time.sleep(0.25)

        _scan_completed_cleanly = not _pause_requested

    except KeyboardInterrupt:
        # Only reached on second Ctrl+C (force kill raises this after proc.kill())
        warn("Workers killed.")
    finally:
        signal.signal(signal.SIGINT, _original_sigint)
        teardown_panel()
        # Final drain after all processes finish
        for proc, _, _ in active_procs:
            proc.join(timeout=config.timeout_seconds + 5)
        _drain_queue()
        manager.shutdown()
        # Mark session complete only on clean finish; paused/crashed stays in_progress
        if session is not None and _scan_completed_cleanly:
            from ai_xss_generator.session import mark_status as _mark_status
            _mark_status(session, "completed")

    if _pause_requested:
        remaining = total_count - completed
        if remaining > 0:
            info(
                f"Scan paused with {remaining} item(s) remaining. "
                f"Re-run with the same target to resume."
            )

    _print_summary(results)
    return results


def _log_result(r: WorkerResult) -> None:
    import urllib.parse as _up
    if r.status == "confirmed":
        success(
            f"[active] CONFIRMED {len(r.confirmed_findings)} finding(s) — {r.url} "
            f"({'cloud' if r.cloud_escalated else 'local'})"
        )
        for f in r.confirmed_findings:
            # Unquote so full-width / half-width chars display as-is, not percent-encoded
            display_url = _up.unquote(f.fired_url)
            success(f"  ↳ [{f.param_name}] {display_url}")
    elif r.status == "no_execution":
        info(
            f"[active] no execution confirmed — {r.url} "
            f"({r.transforms_tried} payloads tried"
            + (", cloud escalated" if r.cloud_escalated else "")
            + ")"
        )
    elif r.status == "error":
        warn(f"[active] error — {r.url}: {r.error}")


def _print_summary(results: list[WorkerResult]) -> None:
    import urllib.parse as _up
    confirmed = [r for r in results if r.status == "confirmed"]
    all_findings = [f for r in confirmed for f in r.confirmed_findings]
    errors = [r for r in results if r.status == "error"]

    info(f"\n{'─'*60}")
    info(f"Active scan complete: {len(results)} target(s) processed")
    if all_findings:
        success(f"  ✅ Confirmed XSS: {len(all_findings)} finding(s) across {len(confirmed)} target(s)")
        info("")
        for i, f in enumerate(all_findings, 1):
            success(f"  Finding {i} — param: {f.param_name}  context: {f.context_type}  via: {f.execution_method}")
            success(f"  Payload:   {f.payload}")
            success(f"  URL:       {_up.unquote(f.fired_url)}")
            if i < len(all_findings):
                info(f"  {'─'*56}")
    else:
        info("  ➖ No confirmed XSS execution detected")
    if errors:
        warn(f"  ⚠️  Errors: {len(errors)} target(s) failed")
    info(f"{'─'*60}\n")
