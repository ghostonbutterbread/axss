"""SQLite storage backend for the curated XSS knowledge base.

Database location: ~/.axss/knowledge.db
Migration: JSONL partitions from ~/.axss/findings/ are imported once on first run
           (curated-tier entries only) then the old directory is left in place
           as a backup.

All public functions are process-safe via SQLite's WAL mode and the
serialised write path guarded by sqlite3's built-in locking.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path.home() / ".axss" / "knowledge.db"
LEGACY_FINDINGS_DIR = Path.home() / ".axss" / "findings"

_SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS curated_findings (
    id               TEXT PRIMARY KEY,
    context_type     TEXT NOT NULL DEFAULT '',
    sink_type        TEXT NOT NULL DEFAULT '',
    bypass_family    TEXT NOT NULL DEFAULT '',
    payload          TEXT NOT NULL,
    explanation      TEXT NOT NULL DEFAULT '',
    surviving_chars  TEXT DEFAULT '',
    waf_name         TEXT DEFAULT '',
    delivery_mode    TEXT DEFAULT '',
    frameworks       TEXT DEFAULT '[]',
    auth_required    INTEGER DEFAULT 0,
    tags             TEXT DEFAULT '[]',
    confidence       REAL DEFAULT 1.0,
    source           TEXT DEFAULT '',
    test_vector      TEXT DEFAULT '',
    curated_by       TEXT DEFAULT '',
    curated_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cf_context_type  ON curated_findings(context_type);
CREATE INDEX IF NOT EXISTS idx_cf_bypass_family ON curated_findings(bypass_family);
CREATE INDEX IF NOT EXISTS idx_cf_waf_name      ON curated_findings(waf_name);
CREATE INDEX IF NOT EXISTS idx_cf_delivery_mode ON curated_findings(delivery_mode);
"""


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create schema and run one-time JSONL migration."""
    with _connect() as conn:
        conn.executescript(_SCHEMA)
    _migrate_jsonl()


def _finding_id(payload: str, sink_type: str, context_type: str, bypass_family: str) -> str:
    material = "|".join([payload, sink_type, context_type, bypass_family])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def save_finding(row: dict[str, Any]) -> bool:
    """Insert or ignore (deduplicate by id). Returns True if inserted."""
    fid = _finding_id(
        row.get("payload", ""),
        row.get("sink_type", ""),
        row.get("context_type", ""),
        row.get("bypass_family", ""),
    )
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        cur = conn.execute(
            """INSERT OR IGNORE INTO curated_findings
               (id, context_type, sink_type, bypass_family, payload, explanation,
                surviving_chars, waf_name, delivery_mode, frameworks, auth_required,
                tags, confidence, source, test_vector, curated_by, curated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                fid,
                row.get("context_type", ""),
                row.get("sink_type", ""),
                row.get("bypass_family", ""),
                row.get("payload", ""),
                row.get("explanation", ""),
                row.get("surviving_chars", ""),
                (row.get("waf_name") or "").lower(),
                (row.get("delivery_mode") or "").lower(),
                json.dumps([str(f).lower() for f in row.get("frameworks", [])]),
                int(bool(row.get("auth_required", False))),
                json.dumps([str(t) for t in row.get("tags", [])]),
                float(row.get("confidence", 1.0)),
                row.get("source", ""),
                row.get("test_vector", ""),
                row.get("curated_by", row.get("model", "")),
                row.get("curated_at", now),
            ),
        )
        return cur.rowcount > 0


def load_findings(context_type: str | None = None) -> list[dict[str, Any]]:
    """Return all curated findings, optionally filtered by context_type."""
    with _connect() as conn:
        if context_type:
            rows = conn.execute(
                "SELECT * FROM curated_findings WHERE context_type = ?", (context_type,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM curated_findings").fetchall()
    return [_row_to_dict(r) for r in rows]


def count_findings(context_type: str | None = None) -> int:
    with _connect() as conn:
        if context_type:
            return conn.execute(
                "SELECT COUNT(*) FROM curated_findings WHERE context_type = ?", (context_type,)
            ).fetchone()[0]
        return conn.execute("SELECT COUNT(*) FROM curated_findings").fetchone()[0]


def delete_finding(finding_id: str) -> bool:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM curated_findings WHERE id = ?", (finding_id,))
        return cur.rowcount > 0


def export_yaml(path: Path) -> int:
    """Dump all curated findings to a JSON file (YAML-compatible subset).

    The file is a JSON array — human-readable, portable, and importable.
    Returns the number of findings written.
    """
    findings = load_findings()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    return len(findings)


def import_yaml(path: Path) -> tuple[int, int]:
    """Import findings from a JSON (or YAML-subset) file.

    Accepts a JSON array of finding dicts.  Returns (inserted, skipped).
    """
    raw = path.read_text(encoding="utf-8")
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        # Try YAML if available, otherwise fail gracefully
        try:
            import yaml  # type: ignore[import]
            entries = yaml.safe_load(raw) or []
        except ImportError:
            return 0, 0
    if not isinstance(entries, list):
        return 0, 0
    inserted = 0
    skipped = 0
    for entry in entries:
        if not isinstance(entry, dict):
            skipped += 1
            continue
        if save_finding(entry):
            inserted += 1
        else:
            skipped += 1
    return inserted, skipped


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    for key in ("frameworks", "tags"):
        try:
            d[key] = json.loads(d.get(key) or "[]")
        except Exception:
            d[key] = []
    d["auth_required"] = bool(d.get("auth_required", 0))
    return d


# ---------------------------------------------------------------------------
# One-time JSONL migration (curated entries only)
# ---------------------------------------------------------------------------

def _migrate_jsonl() -> None:
    """Import curated-tier JSONL entries into SQLite on first run.

    Only runs once — presence of the DB with any row skips migration.
    The JSONL directory is left untouched as a backup.
    """
    if not LEGACY_FINDINGS_DIR.exists():
        return
    sentinel = DB_PATH.parent / ".jsonl_migrated"
    if sentinel.exists():
        return

    imported = 0
    for jsonl_path in sorted(LEGACY_FINDINGS_DIR.glob("*.jsonl")):
        try:
            for line in jsonl_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    # Only migrate curated-tier entries — experimental/verified-runtime stay behind
                    if entry.get("memory_tier", "") != "curated":
                        continue
                    row = {
                        "context_type":    entry.get("context_type", ""),
                        "sink_type":       entry.get("sink_type", ""),
                        "bypass_family":   entry.get("bypass_family", ""),
                        "payload":         entry.get("payload", ""),
                        "explanation":     entry.get("explanation", ""),
                        "surviving_chars": entry.get("surviving_chars", ""),
                        "waf_name":        entry.get("waf_name", ""),
                        "delivery_mode":   entry.get("delivery_mode", ""),
                        "frameworks":      entry.get("frameworks", []),
                        "auth_required":   entry.get("auth_required", False),
                        "tags":            entry.get("tags", []),
                        "confidence":      1.0,
                        "source":          entry.get("provenance", ""),
                        "test_vector":     entry.get("test_vector", ""),
                        "curated_by":      entry.get("model", "migrated"),
                        "curated_at":      entry.get("ts", datetime.now(timezone.utc).isoformat()),
                    }
                    if save_finding(row):
                        imported += 1
                except Exception:
                    continue
        except Exception:
            continue

    sentinel.touch()


# Initialise on import
try:
    init_db()
except Exception:
    pass  # never crash on DB init failure
