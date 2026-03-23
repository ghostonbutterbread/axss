from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ai_xss_generator.crawler import CrawlResult
    from ai_xss_generator.probe import ProbeResult

log = logging.getLogger(__name__)

CACHE_DIR = Path.home() / ".cache" / "axss"

# Scan-artifact cache lives under ~/.axss/cache/<netloc>/
# Separate from the payload cache so they can be managed independently.
SCAN_CACHE_DIR = Path.home() / ".axss" / "cache"

DEFAULT_SCAN_TTL: int = 86_400   # 24 hours

_DEFAULT_TTL = 86_400      # 24 h for static payload lists
_SOCIAL_TTL = 21_600       # 6 h for social/community sources


def _path(key: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    # Sanitize key to a safe filename
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in key)
    return CACHE_DIR / f"{safe}.json"


def cache_get(key: str, ttl: int = _DEFAULT_TTL) -> list[dict[str, Any]] | None:
    """Return cached payload dicts if fresh, else None."""
    path = _path(key)
    if not path.exists():
        return None
    try:
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        if time.time() - float(data["fetched_at"]) > ttl:
            return None
        return data["payloads"]
    except Exception:
        return None


def cache_set(key: str, payloads: list[dict[str, Any]]) -> None:
    """Persist payload dicts with current timestamp."""
    path = _path(key)
    try:
        path.write_text(
            json.dumps({"fetched_at": time.time(), "payloads": payloads}, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        pass  # cache failures are non-fatal


def cache_clear(prefix: str = "") -> int:
    """Delete cache files matching optional prefix. Returns count deleted."""
    if not CACHE_DIR.exists():
        return 0
    count = 0
    for path in CACHE_DIR.glob("*.json"):
        if not prefix or path.stem.startswith(prefix):
            path.unlink(missing_ok=True)
            count += 1
    return count


def cache_info() -> list[dict[str, Any]]:
    """Return metadata about each cached file."""
    if not CACHE_DIR.exists():
        return []
    entries = []
    for path in sorted(CACHE_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            age = int(time.time() - float(data["fetched_at"]))
            entries.append(
                {
                    "key": path.stem,
                    "count": len(data.get("payloads", [])),
                    "age_seconds": age,
                }
            )
        except Exception:
            continue
    return entries


# ---------------------------------------------------------------------------
# Scan-artifact cache — sitemap + probe results
# ---------------------------------------------------------------------------

def _scan_cache_dir(netloc: str) -> Path:
    safe = netloc.replace(":", "_").replace("/", "_") or "unknown"
    d = SCAN_CACHE_DIR / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def _key_hash(parts: list[str]) -> str:
    """24-char hex prefix of SHA-256 over joined parts."""
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:24]


def _is_fresh(cached_at: float, ttl: int) -> bool:
    return (time.time() - cached_at) < ttl


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    """Atomically write *data* as JSON — safe for concurrent worker processes."""
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp_", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.replace(tmp, path)
    except Exception as exc:
        log.debug("scan cache: write failed for %s: %s", path, exc)


def _read_json_safe(path: Path) -> dict[str, Any] | None:
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        log.debug("scan cache: read failed for %s: %s", path, exc)
        return None


def _netloc(url: str) -> str:
    return urllib.parse.urlparse(url).netloc or "unknown"


# ── Sitemap cache ────────────────────────────────────────────────────────────

def _sitemap_path(seed_url: str, scope_spec: str) -> Path:
    h = _key_hash([seed_url, scope_spec or "auto"])
    return _scan_cache_dir(_netloc(seed_url)) / f"sitemap_{h}.json"


def _serialize_sitemap(crawl_result: "CrawlResult") -> dict[str, Any]:
    from dataclasses import asdict as _asdict
    return {
        "cached_at": time.time(),
        "get_urls": list(crawl_result.get_urls),
        "visited_urls": list(crawl_result.visited_urls),
        "detected_waf": crawl_result.detected_waf,
        "post_forms": [_asdict(pf) for pf in crawl_result.post_forms],
        "upload_targets": [_asdict(ut) for ut in crawl_result.upload_targets],
    }


def _deserialize_sitemap(data: dict[str, Any]) -> "CrawlResult":
    from ai_xss_generator.crawler import CrawlResult
    from ai_xss_generator.types import PostFormTarget, UploadTarget
    post_forms = [PostFormTarget(**pf) for pf in data.get("post_forms", [])]
    upload_targets = [UploadTarget(**ut) for ut in data.get("upload_targets", [])]
    return CrawlResult(
        get_urls=data.get("get_urls", []),
        post_forms=post_forms,
        upload_targets=upload_targets,
        visited_urls=data.get("visited_urls", []),
        detected_waf=data.get("detected_waf"),
    )


def get_sitemap(
    seed_url: str,
    scope_spec: str,
    ttl: int = DEFAULT_SCAN_TTL,
) -> "CrawlResult | None":
    """Return a cached CrawlResult if one exists and is within *ttl* seconds."""
    path = _sitemap_path(seed_url, scope_spec)
    data = _read_json_safe(path)
    if data is None:
        return None
    if not _is_fresh(data.get("cached_at", 0.0), ttl):
        log.debug("scan cache: sitemap stale for %s — removing", seed_url)
        path.unlink(missing_ok=True)
        return None
    try:
        result = _deserialize_sitemap(data)
        age_min = int((time.time() - data["cached_at"]) / 60)
        log.info("scan cache: sitemap hit for %s (%d min old)", seed_url, age_min)
        return result
    except Exception as exc:
        log.debug("scan cache: sitemap deserialize failed for %s: %s", seed_url, exc)
        return None


def put_sitemap(
    seed_url: str,
    scope_spec: str,
    crawl_result: "CrawlResult",
) -> None:
    """Persist *crawl_result* to the sitemap cache."""
    path = _sitemap_path(seed_url, scope_spec)
    _write_json_atomic(path, _serialize_sitemap(crawl_result))
    log.debug("scan cache: sitemap written for %s → %s", seed_url, path.name)


def sitemap_age_minutes(seed_url: str, scope_spec: str) -> int | None:
    """Return how old the cached sitemap is in minutes, or None if not cached."""
    path = _sitemap_path(seed_url, scope_spec)
    data = _read_json_safe(path)
    if data is None:
        return None
    cached_at = data.get("cached_at")
    if cached_at is None:
        return None
    return max(0, int((time.time() - float(cached_at)) / 60))


# ── Probe cache ──────────────────────────────────────────────────────────────

def _probe_path(url: str, param_names: list[str]) -> Path:
    h = _key_hash([url, ",".join(sorted(param_names))])
    return _scan_cache_dir(_netloc(url)) / f"probe_{h}.json"


def _serialize_probe(probe_results: "list[ProbeResult]") -> dict[str, Any]:
    results = []
    for pr in probe_results:
        reflections = []
        for rc in pr.reflections:
            reflections.append({
                "context_type": rc.context_type,
                "attr_name": rc.attr_name,
                "tag_name": rc.tag_name,
                "quote_style": rc.quote_style,
                "html_subcontext": rc.html_subcontext,
                "attacker_prefix": rc.attacker_prefix,
                "attacker_suffix": rc.attacker_suffix,
                "payload_shape": rc.payload_shape,
                "subcontext_explanation": rc.subcontext_explanation,
                "evidence_confidence": float(rc.evidence_confidence),
                "surviving_chars": sorted(rc.surviving_chars),
                "snippet": rc.snippet,
                "context_before": rc.context_before,
            })
        results.append({
            "param_name": pr.param_name,
            "original_value": pr.original_value,
            "probe_mode": pr.probe_mode,
            "reflection_transform": pr.reflection_transform,
            "discovery_style": pr.discovery_style,
            "discovered_sink_url": getattr(pr, "discovered_sink_url", ""),
            "reflections": reflections,
        })
    return {"cached_at": time.time(), "results": results}


def _deserialize_probe(data: dict[str, Any]) -> "list[ProbeResult]":
    from ai_xss_generator.probe import ProbeResult, ReflectionContext
    out = []
    for pr_data in data.get("results", []):
        reflections = [
            ReflectionContext(
                context_type=rc.get("context_type", ""),
                attr_name=rc.get("attr_name", ""),
                tag_name=rc.get("tag_name", ""),
                quote_style=rc.get("quote_style", ""),
                html_subcontext=rc.get("html_subcontext", ""),
                attacker_prefix=rc.get("attacker_prefix", ""),
                attacker_suffix=rc.get("attacker_suffix", ""),
                payload_shape=rc.get("payload_shape", ""),
                subcontext_explanation=rc.get("subcontext_explanation", ""),
                evidence_confidence=float(rc.get("evidence_confidence", 0.0)),
                surviving_chars=frozenset(rc.get("surviving_chars", [])),
                snippet=rc.get("snippet", ""),
                context_before=rc.get("context_before", ""),
            )
            for rc in pr_data.get("reflections", [])
        ]
        out.append(ProbeResult(
            param_name=pr_data.get("param_name", ""),
            original_value=pr_data.get("original_value", ""),
            probe_mode=pr_data.get("probe_mode", ""),
            reflection_transform=pr_data.get("reflection_transform", ""),
            discovery_style=pr_data.get("discovery_style", ""),
            discovered_sink_url=pr_data.get("discovered_sink_url", ""),
            reflections=reflections,
        ))
    return out


def get_probe(
    url: str,
    param_names: list[str],
    ttl: int = DEFAULT_SCAN_TTL,
) -> "list[ProbeResult] | None":
    """Return cached probe results if fresh, else None."""
    path = _probe_path(url, param_names)
    data = _read_json_safe(path)
    if data is None:
        return None
    if not _is_fresh(data.get("cached_at", 0.0), ttl):
        log.debug("scan cache: probe stale for %s — removing", url)
        path.unlink(missing_ok=True)
        return None
    try:
        results = _deserialize_probe(data)
        age_min = int((time.time() - data["cached_at"]) / 60)
        log.info(
            "scan cache: probe hit for %s — %d param(s), %d min old",
            url, len(results), age_min,
        )
        return results
    except Exception as exc:
        log.debug("scan cache: probe deserialize failed for %s: %s", url, exc)
        return None


def put_probe(
    url: str,
    param_names: list[str],
    probe_results: "list[ProbeResult]",
) -> None:
    """Persist *probe_results* to the probe cache."""
    if not probe_results:
        return
    path = _probe_path(url, param_names)
    _write_json_atomic(path, _serialize_probe(probe_results))
    log.debug("scan cache: probe written for %s → %s", url, path.name)


# ── Sweep ─────────────────────────────────────────────────────────────────────

def cache_sweep(ttl: int = DEFAULT_SCAN_TTL) -> int:
    """Delete all expired scan-artifact cache files under SCAN_CACHE_DIR.

    Returns the number of files removed.  Safe to call at the start of every
    scan — it only touches files whose ``cached_at`` timestamp is older than
    *ttl* seconds.  Files that cannot be parsed are also removed (they are
    corrupt and would never be used).
    """
    if not SCAN_CACHE_DIR.exists():
        return 0
    removed = 0
    for path in SCAN_CACHE_DIR.rglob("*.json"):
        data = _read_json_safe(path)
        expired = data is None or not _is_fresh(data.get("cached_at", 0.0), ttl)
        if expired:
            try:
                path.unlink(missing_ok=True)
                removed += 1
                log.debug("scan cache: swept expired file %s", path.name)
            except OSError as exc:
                log.debug("scan cache: could not remove %s: %s", path, exc)
    log.info("scan cache: sweep complete — %d expired file(s) removed", removed)
    return removed
