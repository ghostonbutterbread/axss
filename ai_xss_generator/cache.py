from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

CACHE_DIR = Path.home() / ".cache" / "axss"

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
