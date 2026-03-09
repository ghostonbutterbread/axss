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
from typing import Sequence

from ai_xss_generator.active.worker import WorkerResult, run_worker
from ai_xss_generator.console import info, step, success, warn

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
) -> list[WorkerResult]:
    """Spawn isolated worker processes for each URL and collect results.

    Workers run up to `config.workers` at a time. A shared Manager provides:
      - dedup_registry: dict  — cloud escalation deduplication
      - dedup_lock:     Lock  — guards dedup_registry
      - findings_lock:  Lock  — serialises findings store writes
    """
    url_list = [u.strip() for u in urls if u and u.strip()]
    if not url_list:
        return []

    n_workers = _auto_workers(config.rate, config.workers)
    step(
        f"Active scan: {len(url_list)} URL(s) | "
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
    active_procs: list[tuple[multiprocessing.Process, str]] = []  # (proc, url)

    url_iter = iter(url_list)
    completed = 0

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
        for proc, purl in active_procs:
            if not proc.is_alive():
                proc.join(timeout=1)
                completed += 1
                still_running_count = len(active_procs) - 1
                log.debug("Worker done for %s (%d/%d)", purl, completed, len(url_list))
            else:
                still_running.append((proc, purl))
        active_procs = still_running

    try:
        while completed < len(url_list):
            _drain_queue()
            _reap_finished()

            # Fill up to n_workers slots
            while len(active_procs) < n_workers:
                try:
                    next_url = next(url_iter)
                except StopIteration:
                    break

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
                proc.start()
                active_procs.append((proc, next_url))
                info(f"[worker] started → {next_url}")

            time.sleep(0.25)

    except KeyboardInterrupt:
        warn("Scan interrupted — terminating workers...")
        for proc, _ in active_procs:
            proc.terminate()
    finally:
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
        info(f"[active] no query params — {r.url}")
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
