"""Resumable scan session management.

A session file in ~/.axss/sessions/ tracks which active-scan work items have
been completed so that interrupted scans can resume from where they left off.

Lifecycle:
  1. _run_active_scan() in cli.py calls create_session() → writes session file.
  2. After each WorkerResult, the orchestrator calls checkpoint() → atomic write.
  3. First Ctrl-C: orchestrator calls mark_status("paused") → file preserved.
  4. Normal finish: orchestrator calls mark_status("completed") → skipped on resume.
  5. Next invocation: find_existing_session() returns the most recent in_progress
     or paused session whose seed_hash matches.

Atomicity:
  All writes use write-to-temp-then-os.replace() on the same directory, so a
  crash mid-write never leaves a corrupted session file.

Session identity (seed_hash):
  SHA-256 of sorted URL list + sorted POST/upload target keys + scan type flags.
  This is deterministic for --urls FILE mode and deterministic per-crawl for
  -u URL mode (same crawl → same URLs → same hash).  Auth headers and rate
  are deliberately excluded so users can tweak them on resume.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ai_xss_generator.active.worker import ConfirmedFinding, WorkerResult
    from ai_xss_generator.types import PostFormTarget, UploadTarget

from ai_xss_generator.config import CONFIG_DIR

log = logging.getLogger(__name__)

SESSIONS_DIR = CONFIG_DIR / "sessions"


# ---------------------------------------------------------------------------
# Seed hash — stable identity for a scan target + type combination
# ---------------------------------------------------------------------------

def compute_seed_hash(
    urls: list[str],
    post_forms: "list[PostFormTarget]",
    upload_targets: "list[UploadTarget]",
    scan_reflected: bool,
    scan_stored: bool,
    scan_uploads: bool,
    scan_dom: bool,
) -> str:
    """Return a 64-char hex SHA-256 that uniquely identifies this scan profile."""
    canonical = {
        "urls": sorted(urls),
        "post_forms": sorted(
            [
                {"action_url": pf.action_url, "params": sorted(pf.param_names)}
                for pf in post_forms
            ],
            key=lambda d: (d["action_url"], d["params"]),
        ),
        "upload_targets": sorted(
            [
                {
                    "action_url": ut.action_url,
                    "files": sorted(ut.file_field_names),
                    "fields": sorted(ut.companion_field_names),
                }
                for ut in upload_targets
            ],
            key=lambda d: (d["action_url"], d["files"], d["fields"]),
        ),
        "reflected": scan_reflected,
        "stored": scan_stored,
        "uploads": scan_uploads,
        "dom": scan_dom,
    }
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Session file path
# ---------------------------------------------------------------------------

def _session_path(seed_hash: str) -> Path:
    return SESSIONS_DIR / f"{seed_hash[:16]}.json"


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _finding_to_dict(f: "ConfirmedFinding") -> dict:
    return {
        "url": f.url,
        "param_name": f.param_name,
        "context_type": f.context_type,
        "sink_context": f.sink_context,
        "payload": f.payload,
        "transform_name": f.transform_name,
        "execution_method": f.execution_method,
        "execution_detail": f.execution_detail,
        "waf": f.waf,
        "surviving_chars": f.surviving_chars,
        "fired_url": f.fired_url,
        "source": f.source,
        "cloud_escalated": f.cloud_escalated,
        "bypass_family": getattr(f, "bypass_family", ""),
    }


def _dict_to_finding(d: dict) -> "ConfirmedFinding":
    from ai_xss_generator.active.worker import ConfirmedFinding
    return ConfirmedFinding(
        url=d["url"],
        param_name=d["param_name"],
        context_type=d["context_type"],
        sink_context=d["sink_context"],
        payload=d["payload"],
        transform_name=d["transform_name"],
        execution_method=d["execution_method"],
        execution_detail=d["execution_detail"],
        waf=d.get("waf"),
        surviving_chars=d.get("surviving_chars", ""),
        fired_url=d["fired_url"],
        source=d["source"],
        cloud_escalated=d.get("cloud_escalated", False),
        bypass_family=d.get("bypass_family", ""),
    )


def _result_to_dict(r: "WorkerResult") -> dict:
    return {
        "url": r.url,
        "kind": getattr(r, "kind", "get"),
        "status": r.status,
        "transforms_tried": r.transforms_tried,
        "cloud_escalated": r.cloud_escalated,
        "waf": r.waf,
        "error": r.error,
        "duration_seconds": r.duration_seconds,
        "params_tested": r.params_tested,
        "params_reflected": r.params_reflected,
        "dead_target": getattr(r, "dead_target", False),
        "dead_reason": getattr(r, "dead_reason", ""),
        "target_tier": getattr(r, "target_tier", ""),
        "local_model_rounds": getattr(r, "local_model_rounds", 0),
        "cloud_model_rounds": getattr(r, "cloud_model_rounds", 0),
        "fallback_rounds": getattr(r, "fallback_rounds", 0),
        "escalation_reasons": list(getattr(r, "escalation_reasons", []) or []),
        "confirmed_findings": [_finding_to_dict(f) for f in r.confirmed_findings],
    }


def _dict_to_result(d: dict) -> "WorkerResult":
    from ai_xss_generator.active.worker import WorkerResult
    return WorkerResult(
        url=d["url"],
        kind=d.get("kind", "get"),
        status=d["status"],
        confirmed_findings=[_dict_to_finding(f) for f in d.get("confirmed_findings", [])],
        transforms_tried=d.get("transforms_tried", 0),
        cloud_escalated=d.get("cloud_escalated", False),
        waf=d.get("waf"),
        error=d.get("error"),
        duration_seconds=d.get("duration_seconds", 0.0),
        params_tested=d.get("params_tested", 0),
        params_reflected=d.get("params_reflected", 0),
        dead_target=d.get("dead_target", False),
        dead_reason=d.get("dead_reason", ""),
        target_tier=d.get("target_tier", ""),
        local_model_rounds=d.get("local_model_rounds", 0),
        cloud_model_rounds=d.get("cloud_model_rounds", 0),
        fallback_rounds=d.get("fallback_rounds", 0),
        escalation_reasons=list(d.get("escalation_reasons", []) or []),
    )


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------

def _atomic_write(path: Path, data: dict) -> None:
    """Write *data* as JSON to *path* via temp-file + rename (crash-safe)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_existing_session(seed_hash: str) -> dict | None:
    """Return the session dict if an in-progress or paused session exists.

    Guards against hash prefix collisions by verifying the full seed_hash.
    Returns None if no match is found or the file is corrupt.
    """
    path = _session_path(seed_hash)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.debug("Session file unreadable (%s): %s", path, exc)
        return None
    if data.get("seed_hash") != seed_hash:
        log.debug("Session seed_hash mismatch — ignoring %s", path.name)
        return None
    if data.get("status") not in ("in_progress", "paused"):
        return None
    return data


def create_session(
    seed_hash: str,
    config_summary: str,
    total_items: int,
) -> dict:
    """Create and persist a new in-progress session. Returns the session dict."""
    data: dict[str, Any] = {
        "seed_hash": seed_hash,
        "status": "in_progress",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "total_items": total_items,
        "config_summary": config_summary,
        "completed": {},
    }
    path = _session_path(seed_hash)
    _atomic_write(path, data)
    log.debug("Session created: %s (%d items)", path.name, total_items)
    return data


def checkpoint(session: dict, url: str, result: "WorkerResult") -> None:
    """Record a completed work item and atomically rewrite the session file.

    Safe to call from within the orchestrator drain loop — the atomic write
    ensures a crash mid-write never corrupts the session.
    """
    result_key = f"{getattr(result, 'kind', 'get')}:{result.url}"
    session.setdefault("completed", {})[result_key] = _result_to_dict(result)
    session["updated_at"] = _now_iso()
    try:
        _atomic_write(_session_path(session["seed_hash"]), session)
    except Exception as exc:
        log.debug("Session checkpoint failed for %s: %s", result_key, exc)


def mark_status(session: dict, status: str) -> None:
    """Set session status ('paused' | 'completed') and atomically rewrite."""
    session["status"] = status
    session["updated_at"] = _now_iso()
    try:
        _atomic_write(_session_path(session["seed_hash"]), session)
        log.debug("Session marked %s: %s", status, _session_path(session["seed_hash"]).name)
    except Exception as exc:
        log.debug("Session mark_status failed: %s", exc)


def completed_urls(session: dict) -> set[str]:
    """Return the set of completed work-item keys ('kind:url')."""
    completed = set()
    for key, entry in session.get("completed", {}).items():
        if ":" in key:
            completed.add(key)
            continue
        kind = str(entry.get("kind", "get"))
        url = str(entry.get("url", key))
        completed.add(f"{kind}:{url}")
    return completed


def restore_results(session: dict) -> "list[WorkerResult]":
    """Reconstruct WorkerResult objects for all items completed in a prior run.

    These are pre-populated into the orchestrator's results list so that
    _print_summary() and write_report() include prior-run findings.
    """
    results = []
    for entry in session.get("completed", {}).values():
        try:
            results.append(_dict_to_result(entry))
        except Exception as exc:
            log.debug("Failed to restore result entry: %s", exc)
    return results
