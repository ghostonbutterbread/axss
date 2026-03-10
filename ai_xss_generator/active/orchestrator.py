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
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Sequence, TYPE_CHECKING

if TYPE_CHECKING:
    from ai_xss_generator.types import PostFormTarget

from ai_xss_generator.active.worker import WorkerResult, run_worker
from ai_xss_generator.console import (
    clear_status_bar, fmt_duration, info, set_status_bar,
    spin_char, step, success, update_status_bar, warn,
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
    if not url_list and not post_form_list:
        return []

    n_workers = _auto_workers(config.rate, config.workers)
    step(
        f"Active scan: {len(url_list)} GET URL(s) + {len(post_form_list)} POST form(s) | "
        f"{n_workers} worker(s) | "
        f"{config.rate:g} req/s rate | "
        f"{config.timeout_seconds}s timeout"
    )

    manager = multiprocessing.Manager()
    dedup_registry = manager.dict()
    dedup_lock = manager.Lock()
    findings_lock = manager.Lock()
    result_queue: multiprocessing.Queue = manager.Queue()

    results: list[WorkerResult] = []
    active_procs: list[tuple[multiprocessing.Process, str]] = []  # (proc, label)

    # Unified work queue: ('get', url_str) or ('post', PostFormTarget)
    work_items: list[tuple[str, Any]] = (
        [("get", u) for u in url_list]
        + [("post", pf) for pf in post_form_list]
    )
    work_iter = iter(work_items)
    total_count = len(work_items)
    completed = 0
    scan_start = time.monotonic()
    tick = 0  # spinner frame counter

    def _fmt_status() -> str:
        elapsed = time.monotonic() - scan_start
        remaining = total_count - completed
        if completed > 0:
            avg = elapsed / completed
            eta_str = f"ETA ~{fmt_duration(avg * remaining)}"
        else:
            eta_str = "ETA ~?"
        sp = spin_char(tick)
        return (
            f"\033[2m[~] {sp} Scanning | "
            f"{completed}/{total_count} targets done | "
            f"{len(active_procs)} active | "
            f"{fmt_duration(elapsed)} elapsed | "
            f"{eta_str}\033[0m"
        )

    def _drain_queue() -> None:
        # Use a short timeout rather than get_nowait() so results aren't lost
        # when a worker puts an item into the queue at the exact moment empty()
        # returns True.
        import queue as _queue
        while True:
            try:
                r = result_queue.get(timeout=0.05)
                results.append(r)
                _log_result(r)
            except _queue.Empty:
                break
            except Exception:
                break

    def _reap_finished() -> None:
        nonlocal active_procs, completed
        still_running = []
        for proc, plabel in active_procs:
            if not proc.is_alive():
                proc.join(timeout=1)
                completed += 1
                log.debug("Worker done for %s (%d/%d)", plabel, completed, total_count)
            else:
                still_running.append((proc, plabel))
        active_procs = still_running

    set_status_bar(_fmt_status())
    try:
        while completed < total_count:
            _drain_queue()
            _reap_finished()

            # Fill up to n_workers slots
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
                        },
                        daemon=True,
                    )
                    log_label = f"[POST] {pf.action_url}"
                proc.start()
                active_procs.append((proc, log_label))
                info(f"[worker] started → {log_label}")

            tick += 1
            update_status_bar(_fmt_status())
            time.sleep(0.25)

    except KeyboardInterrupt:
        warn("Scan interrupted — terminating workers...")
        for proc, _ in active_procs:
            proc.terminate()
    finally:
        clear_status_bar()
        # Final drain after all processes finish
        for proc, _ in active_procs:
            proc.join(timeout=config.timeout_seconds + 5)
        _drain_queue()
        manager.shutdown()

    _print_summary(results)
    return results


def _log_result(r: WorkerResult) -> None:
    if r.status == "confirmed":
        success(
            f"[active] CONFIRMED {len(r.confirmed_findings)} finding(s) — {r.url} "
            f"({'cloud' if r.cloud_escalated else 'local'})"
        )
    elif r.status == "no_reflection":
        info(f"[active] no reflection — {r.url}")
    elif r.status == "no_params":
        info(f"[active] no testable params — {r.url}")
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
    confirmed = [r for r in results if r.status == "confirmed"]
    total_findings = sum(len(r.confirmed_findings) for r in confirmed)
    errors = [r for r in results if r.status == "error"]

    info(f"\n{'─'*60}")
    info(f"Active scan complete: {len(results)} URL(s) processed")
    if total_findings:
        success(f"  ✅ Confirmed XSS: {total_findings} finding(s) across {len(confirmed)} URL(s)")
    else:
        info("  ➖ No confirmed XSS execution detected")
    if errors:
        warn(f"  ⚠️  Errors: {len(errors)} URL(s) failed")
    info(f"{'─'*60}\n")
