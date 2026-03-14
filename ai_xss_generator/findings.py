"""Curated XSS knowledge store — persists trusted bypass patterns and payloads.

Storage: SQLite at ~/.axss/knowledge.db (via store.py)

The store has a single tier: curated.  All entries are globally scoped —
there is no per-host partitioning.  Findings are populated two ways:
  1. Seed scripts  (xssy/seed_*.py) — hand-curated lab knowledge
  2. Curation pipeline (xssy/curate.py) — LLM-extracted from confirmed lab runs

Retrieval scores candidates by:
  context_type / sink_type match, surviving chars overlap, WAF, delivery mode,
  framework hints, and auth context.  See relevant_findings() for weights.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ai_xss_generator import store as _store


# ---------------------------------------------------------------------------
# Bypass family taxonomy
# ---------------------------------------------------------------------------

BYPASS_FAMILIES: list[str] = [
    # ── Encoding / obfuscation ───────────────────────────────────────────────
    "whitespace-in-scheme",
    "case-variant",
    "html-entity-encoding",
    "double-url-encoding",
    "unicode-js-escape",
    "unicode-zero-width",
    "unicode-fullwidth",
    "unicode-whitespace",
    # ── Injection context breakouts ──────────────────────────────────────────
    "js-string-breakout",
    "template-literal-breakout",
    "html-attribute-breakout",
    "comment-breakout",
    "xml-cdata-injection",
    "mutation-xss",
    # ── Sink / feature exploitation ──────────────────────────────────────────
    "event-handler-injection",
    "svg-namespace",
    "srcdoc-injection",
    "data-uri",
    "base-tag-injection",
    "postmessage-injection",
    "template-expression",
    "constructor-chain",
    "prototype-pollution",
    "dom-clobbering",
    # ── Header / request-level ───────────────────────────────────────────────
    "host-header-injection",
    "referer-header-injection",
    "metadata-xss",
    # ── CSP bypasses ─────────────────────────────────────────────────────────
    "csp-nonce-bypass",
    "csp-jsonp-bypass",
    "csp-upload-bypass",
    "csp-injection-bypass",
    "csp-exfiltration",
    # ── Filter / sanitiser evasion ───────────────────────────────────────────
    "regex-filter-bypass",
    "upload-type-bypass",
    "content-sniffing",
    "enctype-spoofing",
]


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A curated XSS bypass pattern.

    Seed scripts and the curation pipeline create these.  All findings in the
    store are globally applicable (no host scope) and trusted by definition.
    """
    sink_type: str
    context_type: str
    surviving_chars: str
    bypass_family: str
    payload: str
    test_vector: str = ""
    model: str = ""          # 'curated', model name, or 'migrated'
    explanation: str = ""
    tags: list[str] = field(default_factory=list)
    verified: bool = True
    waf_name: str = ""
    delivery_mode: str = ""
    frameworks: list[str] = field(default_factory=list)
    auth_required: bool = False
    confidence: float = 1.0
    source: str = ""         # provenance — lab name, URL, etc.
    curated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def finding_id(finding: Finding) -> str:
    material = "|".join([
        finding.payload,
        finding.sink_type,
        finding.context_type,
        finding.bypass_family,
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Storage — delegates to store.py (SQLite)
# ---------------------------------------------------------------------------

def save_finding(finding: Finding) -> bool:
    """Persist a finding to the curated SQLite store.

    Silently deduplicates — returns True if a new row was inserted.
    """
    return _store.save_finding({
        "context_type":    finding.context_type,
        "sink_type":       finding.sink_type,
        "bypass_family":   finding.bypass_family,
        "payload":         finding.payload,
        "explanation":     finding.explanation,
        "surviving_chars": finding.surviving_chars,
        "waf_name":        finding.waf_name,
        "delivery_mode":   finding.delivery_mode,
        "frameworks":      finding.frameworks,
        "auth_required":   finding.auth_required,
        "tags":            finding.tags,
        "confidence":      finding.confidence,
        "source":          finding.source,
        "test_vector":     finding.test_vector,
        "curated_by":      finding.model,
        "curated_at":      finding.curated_at,
    })


def load_findings(context_type: str | None = None) -> list[Finding]:
    return [_row_to_finding(r) for r in _store.load_findings(context_type)]


def count_findings(context_type: str | None = None) -> int:
    return _store.count_findings(context_type)


def export_yaml(path: Path) -> int:
    return _store.export_yaml(path)


def import_yaml(path: Path) -> tuple[int, int]:
    return _store.import_yaml(path)


def memory_stats() -> dict[str, int]:
    total = _store.count_findings()
    return {"total": total, "curated": total}


def _row_to_finding(row: dict[str, Any]) -> Finding:
    return Finding(
        sink_type=str(row.get("sink_type", "")),
        context_type=str(row.get("context_type", "")),
        surviving_chars=str(row.get("surviving_chars", "")),
        bypass_family=str(row.get("bypass_family", "")),
        payload=str(row.get("payload", "")),
        test_vector=str(row.get("test_vector", "")),
        model=str(row.get("curated_by", "")),
        explanation=str(row.get("explanation", "")),
        tags=list(row.get("tags", [])),
        verified=True,
        waf_name=str(row.get("waf_name", "")),
        delivery_mode=str(row.get("delivery_mode", "")),
        frameworks=list(row.get("frameworks", [])),
        auth_required=bool(row.get("auth_required", False)),
        confidence=float(row.get("confidence", 1.0)),
        source=str(row.get("source", "")),
        curated_at=str(row.get("curated_at", "")),
    )


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------

def relevant_findings(
    *,
    sink_type: str,
    context_type: str,
    surviving_chars: str,
    limit: int = 6,
    waf_name: str = "",
    delivery_mode: str = "",
    frameworks: tuple[str, ...] = (),
    auth_required: bool | None = None,
    # Legacy params — accepted but ignored for backward compat
    allowed_tiers: Any = None,
    target_host: str = "",
) -> list[Finding]:
    """Return the most contextually relevant curated findings.

    Scoring weights:
      +4  exact sink_type match
      +2  partial sink_type match
      +3  exact context_type match
      +1-3 surviving chars overlap (capped at 3)
      +2  verified (always True for curated, kept for scoring consistency)
      +3  delivery_mode match
      +3  waf_name exact match
      +1  waf_name partial match
      +0-2 framework overlap (capped at 2)
      +1  auth_required match
    """
    # Narrow load to matching context partition for speed; fall back to all
    if context_type:
        candidates = load_findings(context_type)
        if not candidates:
            candidates = load_findings()
    else:
        candidates = load_findings()

    if not candidates:
        return []

    surviving_set = set(surviving_chars)
    framework_set = {f.lower() for f in frameworks}
    scored: list[tuple[float, Finding]] = []

    for f in candidates:
        score: float = 0.0
        if f.sink_type == sink_type:
            score += 4
        elif sink_type and (sink_type in f.sink_type or f.sink_type in sink_type):
            score += 2
        if f.context_type == context_type:
            score += 3
        score += min(len(surviving_set & set(f.surviving_chars)), 3)
        if f.verified:
            score += 2
        if delivery_mode and f.delivery_mode == delivery_mode.lower():
            score += 3
        if waf_name and f.waf_name == waf_name.lower():
            score += 3
        elif waf_name and f.waf_name and (waf_name.lower() in f.waf_name or f.waf_name in waf_name.lower()):
            score += 1
        if framework_set and f.frameworks:
            score += min(len(framework_set & {fw.lower() for fw in f.frameworks}), 2)
        if auth_required is not None and f.auth_required == auth_required:
            score += 1
        score *= f.confidence  # weight by confidence

        if score > 0:
            scored.append((score, f))

    scored.sort(key=lambda x: -x[0])
    return [f for _, f in scored[:limit]]

# ---------------------------------------------------------------------------
# Bypass family inference
# ---------------------------------------------------------------------------

def infer_bypass_family(payload_str: str, tags: list[str]) -> str:
    tag_set = set(tags)
    text = payload_str.lower()
    if "unicode" in tag_set or "js-escape" in tag_set:
        return "unicode-js-escape"
    if "zero-width" in tag_set or "zwnj" in tag_set:
        return "unicode-zero-width"
    if "full-width" in tag_set:
        return "unicode-fullwidth"
    if "nbsp" in tag_set or "whitespace-bypass" in tag_set or "en-space" in tag_set or "em-space" in tag_set:
        return "unicode-whitespace"
    if "whitespace-in-scheme" in tag_set:
        return "whitespace-in-scheme"
    if "case-variant" in tag_set or ("javascript" in text and "javascript" not in payload_str):
        return "case-variant"
    if "html-entity" in tag_set or "&#" in payload_str:
        return "html-entity-encoding"
    if "double-url" in tag_set or "%25" in payload_str:
        return "double-url-encoding"
    if "js-string-breakout" in tag_set or payload_str.startswith(('";', "';")):
        return "js-string-breakout"
    if "template-literal" in tag_set or "`${" in payload_str:
        return "template-literal-breakout"
    if "attribute-breakout" in tag_set or payload_str.startswith('">'):
        return "html-attribute-breakout"
    if "event-handler" in tag_set or "event-handler-injection" in tag_set:
        return "event-handler-injection"
    if "animate" in text or "onbegin" in text:
        return "svg-namespace"
    if "constructor" in text:
        return "constructor-chain"
    if "data-uri" in tag_set or text.startswith("data:"):
        return "data-uri"
    if "comment-breakout" in tag_set or payload_str.startswith("-->"):
        return "comment-breakout"
    if "srcdoc" in text:
        return "srcdoc-injection"
    if "{{" in payload_str:
        return "template-expression"
    return "unknown"
