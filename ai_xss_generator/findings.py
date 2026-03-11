"""Local findings store — persists discovered filter behaviors and working payloads.

Layout
------
~/.axss/findings/<context_type>.jsonl   — one file per reflection context type
~/.axss/findings/unknown.jsonl          — catch-all for unclassified findings
~/.axss/findings.jsonl                  — legacy flat file (migrated on first access)

Partitioning by context_type means relevant_findings() only reads the slice of
the store that's useful for the current target.  Even with tens of thousands of
total entries the hot-path load is just one or two small files.  Each partition
has its own rolling cap (MAX_PER_PARTITION); the global store is effectively
unbounded as long as context variety keeps growing.

The store serves three purposes:
  1. Inject relevant past findings as few-shot examples into LLM prompts so the
     local model benefits from prior discoveries (including those found by a cloud
     model).
  2. Track which bypass families work against which filter behaviors so the tool
     can short-circuit to the right payload class without asking the LLM.
  3. Gradually accumulate a private knowledge base that grows more useful the more
     the tool is used.
"""
from __future__ import annotations

import json
import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

FINDINGS_DIR  = Path.home() / ".axss" / "findings"
FINDINGS_PATH = Path.home() / ".axss" / "findings.jsonl"   # legacy flat file

# Per-partition rolling cap.  Oldest unverified entries are evicted first when
# a partition exceeds this limit.  With ~20 context types the total store can
# hold ~40 000 entries while keeping any single file manageable.
MAX_PER_PARTITION = 2_000


# ---------------------------------------------------------------------------
# Memory tiers
# ---------------------------------------------------------------------------

MEMORY_TIER_CURATED = "curated"
MEMORY_TIER_VERIFIED_RUNTIME = "verified-runtime"
MEMORY_TIER_EXPERIMENTAL = "experimental"

VALID_MEMORY_TIERS = {
    MEMORY_TIER_CURATED,
    MEMORY_TIER_VERIFIED_RUNTIME,
    MEMORY_TIER_EXPERIMENTAL,
}

TRUSTED_MEMORY_TIERS = (
    MEMORY_TIER_CURATED,
    MEMORY_TIER_VERIFIED_RUNTIME,
)

MEMORY_TIER_PRIORITY = {
    MEMORY_TIER_EXPERIMENTAL: 0,
    MEMORY_TIER_VERIFIED_RUNTIME: 1,
    MEMORY_TIER_CURATED: 2,
}

TARGET_SCOPE_GLOBAL = "global"
TARGET_SCOPE_HOST = "host"

VALID_TARGET_SCOPES = {
    TARGET_SCOPE_GLOBAL,
    TARGET_SCOPE_HOST,
}

REVIEW_STATUS_PENDING = "pending"
REVIEW_STATUS_APPROVED = "approved"
REVIEW_STATUS_REJECTED = "rejected"

VALID_REVIEW_STATUSES = {
    REVIEW_STATUS_PENDING,
    REVIEW_STATUS_APPROVED,
    REVIEW_STATUS_REJECTED,
}

MEMORY_SOURCE_ALL = "all"
MEMORY_SOURCE_LABS = "labs"
MEMORY_SOURCE_TARGETS = "targets"

VALID_MEMORY_SOURCES = {
    MEMORY_SOURCE_ALL,
    MEMORY_SOURCE_LABS,
    MEMORY_SOURCE_TARGETS,
}


# ---------------------------------------------------------------------------
# Bypass family taxonomy — shared between prompts and finding classification
# ---------------------------------------------------------------------------

BYPASS_FAMILIES: list[str] = [
    # ── Encoding / obfuscation ───────────────────────────────────────────────
    "whitespace-in-scheme",      # tab/LF/CR inserted inside javascript: scheme
    "case-variant",              # jAvAsCrIpT:
    "html-entity-encoding",      # &#106;avascript: or &colon;
    "double-url-encoding",       # %2522 → %22 → "
    "unicode-js-escape",         # \u0061lert(1) — JS identifier unicode escape
    "unicode-zero-width",        # ZWS/ZWNJ inserted into keywords or URIs
    "unicode-fullwidth",         # full-width chars in CSS / protocol strings
    "unicode-whitespace",        # NBSP/em/en space as HTML attribute separator
    # ── Injection context breakouts ──────────────────────────────────────────
    "js-string-breakout",        # ";alert(1)// or ';alert(1)//
    "template-literal-breakout", # `${alert(1)}`
    "html-attribute-breakout",   # "><svg/onload=alert(1)>
    "comment-breakout",          # -->payload
    "xml-cdata-injection",       # <![CDATA[<script>alert(1)</script>]]>
    "mutation-xss",              # mXSS — parser mutation after sanitisation
    # ── Sink / feature exploitation ──────────────────────────────────────────
    "event-handler-injection",   # value reflected directly in onX=
    "svg-namespace",             # <svg><animate onbegin=alert(1)>
    "srcdoc-injection",          # srcdoc="<script>alert(1)</script>"
    "data-uri",                  # data:text/html,<script>alert(1)</script>
    "base-tag-injection",        # <base href="//attacker.com/"> hijacks relative URLs
    "postmessage-injection",     # postMessage → eval / innerHTML sink
    "template-expression",       # {{constructor.constructor('alert(1)')()}}
    "constructor-chain",         # [].filter.constructor('alert(1)')()
    "prototype-pollution",       # __proto__[x]=payload
    "dom-clobbering",            # anchor id overrides window property
    # ── Header / request-level ───────────────────────────────────────────────
    "host-header-injection",     # Host: or X-Forwarded-Host reflected unsanitised
    "referer-header-injection",  # Referer header reflected into page
    "metadata-xss",              # XSS payload in file metadata (EXIF, SVG attrs)
    # ── CSP bypasses ─────────────────────────────────────────────────────────
    "csp-nonce-bypass",          # predict or leak nonce, inject matching script tag
    "csp-jsonp-bypass",          # allowlisted JSONP endpoint used as script src
    "csp-upload-bypass",         # upload JS to same origin, bypass script-src self
    "csp-injection-bypass",      # inject into CSP header itself
    "csp-exfiltration",          # data leak via img-src / dns-prefetch despite strict csp
    # ── Filter / sanitiser evasion ───────────────────────────────────────────
    "regex-filter-bypass",       # weak regex strips some but not all variants
    "upload-type-bypass",        # bypass file-type checks to deliver XSS payload
    "content-sniffing",          # browser sniffs MIME and renders as HTML
    "enctype-spoofing",          # multipart/text-plain enctype tricks server parser
]


@dataclass
class Finding:
    sink_type: str        # e.g. "reflected_in_href", "js_string_via_base64"
    context_type: str     # e.g. "html_attr_url", "js_string_dq", "html_body"
    surviving_chars: str  # chars confirmed to survive the filter, e.g. "()/;`"
    bypass_family: str    # one of BYPASS_FAMILIES
    payload: str          # the exact payload string
    test_vector: str      # how to deliver it, e.g. "?param=..."
    model: str            # model that generated/confirmed this finding
    explanation: str = ""
    target_host: str = ""
    tags: list[str] = field(default_factory=list)
    verified: bool = False   # True if manually confirmed to execute in browser
    memory_tier: str = MEMORY_TIER_EXPERIMENTAL
    evidence_type: str = ""
    evidence_detail: str = ""
    provenance: str = ""
    success_count: int = 0
    target_scope: str = TARGET_SCOPE_GLOBAL
    waf_name: str = ""
    delivery_mode: str = ""
    frameworks: list[str] = field(default_factory=list)
    auth_required: bool = False
    review_status: str = REVIEW_STATUS_PENDING
    reviewed_by: str = ""
    reviewed_at: str = ""
    review_note: str = ""
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def normalize_memory_tier(value: str | None, *, verified: bool, model: str, tags: list[str]) -> str:
    tier = (value or "").strip().lower()
    if tier in VALID_MEMORY_TIERS:
        return tier

    tag_set = {tag.strip().lower() for tag in tags}
    model_value = (model or "").strip().lower()
    if verified:
        if model_value == "curated" or model_value.startswith("seed-") or "curated" in tag_set:
            return MEMORY_TIER_CURATED
        return MEMORY_TIER_VERIFIED_RUNTIME
    return MEMORY_TIER_EXPERIMENTAL


def normalize_target_scope(value: str | None, *, verified: bool, target_host: str, model: str, tags: list[str]) -> str:
    scope = (value or "").strip().lower()
    if scope in VALID_TARGET_SCOPES:
        return scope

    tag_set = {tag.strip().lower() for tag in tags}
    model_value = (model or "").strip().lower()
    is_curated = model_value == "curated" or model_value.startswith("seed-") or "curated" in tag_set
    if target_host and verified and not is_curated:
        return TARGET_SCOPE_HOST
    if target_host and not is_curated and "offline-learning" not in tag_set:
        return TARGET_SCOPE_HOST
    return TARGET_SCOPE_GLOBAL


def normalize_review_status(value: str | None, *, tier: str, verified: bool) -> str:
    status = (value or "").strip().lower()
    if status in VALID_REVIEW_STATUSES:
        return status
    if tier == MEMORY_TIER_EXPERIMENTAL and not verified:
        return REVIEW_STATUS_PENDING
    return REVIEW_STATUS_APPROVED


def finding_id(finding: Finding) -> str:
    material = "|".join([
        finding.payload,
        finding.sink_type,
        finding.context_type,
        finding.bypass_family,
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Internal: partition key → file path
# ---------------------------------------------------------------------------

def _partition_key(context_type: str) -> str:
    """Sanitise context_type into a safe filename stem."""
    key = re.sub(r"[^a-z0-9_-]", "_", (context_type or "unknown").lower()).strip("_")
    return key or "unknown"


def _partition_path(context_type: str) -> Path:
    return FINDINGS_DIR / f"{_partition_key(context_type)}.jsonl"


def _finding_from_dict(d: dict[str, object]) -> Finding:
    tags_raw = d.get("tags", [])
    tags = [str(tag) for tag in tags_raw] if isinstance(tags_raw, list) else []
    frameworks_raw = d.get("frameworks", [])
    frameworks = [str(item).lower() for item in frameworks_raw] if isinstance(frameworks_raw, list) else []
    verified = bool(d.get("verified", False))
    model = str(d.get("model", "unknown"))
    target_host = str(d.get("target_host", ""))
    return Finding(
        sink_type=str(d.get("sink_type", "")),
        context_type=str(d.get("context_type", "")),
        surviving_chars=str(d.get("surviving_chars", "")),
        bypass_family=str(d.get("bypass_family", "")),
        payload=str(d.get("payload", "")),
        test_vector=str(d.get("test_vector", "")),
        model=model,
        explanation=str(d.get("explanation", "")),
        target_host=target_host,
        tags=tags,
        verified=verified,
        memory_tier=normalize_memory_tier(
            str(d.get("memory_tier", "")),
            verified=verified,
            model=model,
            tags=tags,
        ),
        evidence_type=str(d.get("evidence_type", "")),
        evidence_detail=str(d.get("evidence_detail", "")),
        provenance=str(d.get("provenance", "")),
        success_count=int(d.get("success_count", 0) or 0),
        target_scope=normalize_target_scope(
            str(d.get("target_scope", "")),
            verified=verified,
            target_host=target_host,
            model=model,
            tags=tags,
        ),
        waf_name=str(d.get("waf_name", "")).lower(),
        delivery_mode=str(d.get("delivery_mode", "")).lower(),
        frameworks=list(dict.fromkeys(frameworks)),
        auth_required=bool(d.get("auth_required", False)),
        review_status=normalize_review_status(
            str(d.get("review_status", "")),
            tier=normalize_memory_tier(
                str(d.get("memory_tier", "")),
                verified=verified,
                model=model,
                tags=tags,
            ),
            verified=verified,
        ),
        reviewed_by=str(d.get("reviewed_by", "")),
        reviewed_at=str(d.get("reviewed_at", "")),
        review_note=str(d.get("review_note", "")),
        ts=str(d.get("ts", "")),
    )


def _load_partition(path: Path) -> list[Finding]:
    """Load all findings from one partition file."""
    if not path.exists():
        return []
    results: list[Finding] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(_finding_from_dict(json.loads(line)))
        except Exception:
            continue
    return results


def _write_partition(path: Path, findings: list[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not findings:
        path.write_text("", encoding="utf-8")
        return
    path.write_text(
        "\n".join(json.dumps(asdict(f)) for f in findings) + "\n",
        encoding="utf-8",
    )


def _trim_partition(path: Path) -> None:
    """Evict oldest unverified entries when partition exceeds MAX_PER_PARTITION."""
    findings = _load_partition(path)
    if len(findings) <= MAX_PER_PARTITION:
        return
    # Separate verified (never evicted) from unverified (evict oldest first)
    verified = [f for f in findings if f.verified]
    unverified = [f for f in findings if not f.verified]
    # How many unverified we can keep
    keep_unverified = max(0, MAX_PER_PARTITION - len(verified))
    # Keep the newest unverified entries (they're appended in order, so tail = newest)
    trimmed = verified + unverified[-keep_unverified:]
    _write_partition(path, trimmed)


def _prefer_text(existing: str, incoming: str) -> str:
    if incoming and (not existing or len(incoming) > len(existing)):
        return incoming
    return existing


def _merge_findings(existing: Finding, incoming: Finding) -> Finding:
    existing_priority = MEMORY_TIER_PRIORITY.get(existing.memory_tier, 0)
    incoming_priority = MEMORY_TIER_PRIORITY.get(incoming.memory_tier, 0)
    tier = incoming.memory_tier if incoming_priority > existing_priority else existing.memory_tier

    if existing.verified and incoming.verified:
        success_count = max(existing.success_count, 1) + max(incoming.success_count, 1)
    else:
        success_count = max(existing.success_count, incoming.success_count)

    preferred_model = incoming.model if incoming_priority > existing_priority and incoming.model else existing.model

    return Finding(
        sink_type=existing.sink_type or incoming.sink_type,
        context_type=existing.context_type or incoming.context_type,
        surviving_chars=existing.surviving_chars or incoming.surviving_chars,
        bypass_family=existing.bypass_family or incoming.bypass_family,
        payload=existing.payload or incoming.payload,
        test_vector=existing.test_vector or incoming.test_vector,
        model=preferred_model or incoming.model or existing.model,
        explanation=_prefer_text(existing.explanation, incoming.explanation),
        target_host=existing.target_host or incoming.target_host,
        tags=list(dict.fromkeys([*existing.tags, *incoming.tags])),
        verified=existing.verified or incoming.verified,
        memory_tier=tier,
        evidence_type=existing.evidence_type or incoming.evidence_type,
        evidence_detail=_prefer_text(existing.evidence_detail, incoming.evidence_detail),
        provenance=_prefer_text(existing.provenance, incoming.provenance),
        success_count=success_count,
        target_scope=existing.target_scope if existing_priority >= incoming_priority else incoming.target_scope,
        waf_name=existing.waf_name or incoming.waf_name,
        delivery_mode=existing.delivery_mode or incoming.delivery_mode,
        frameworks=list(dict.fromkeys([*existing.frameworks, *incoming.frameworks])),
        auth_required=existing.auth_required or incoming.auth_required,
        review_status=(
            incoming.review_status
            if incoming_priority > existing_priority and incoming.review_status in VALID_REVIEW_STATUSES
            else existing.review_status
        ),
        reviewed_by=_prefer_text(existing.reviewed_by, incoming.reviewed_by),
        reviewed_at=max(existing.reviewed_at or "", incoming.reviewed_at or ""),
        review_note=_prefer_text(existing.review_note, incoming.review_note),
        ts=max(existing.ts or "", incoming.ts or ""),
    )


def _same_identity(existing: Finding, incoming: Finding) -> bool:
    if existing.payload != incoming.payload or existing.sink_type != incoming.sink_type:
        return False
    if existing.target_scope != incoming.target_scope:
        return False
    if existing.target_scope == TARGET_SCOPE_HOST:
        return existing.target_host == incoming.target_host
    return True


# ---------------------------------------------------------------------------
# Migration: flat findings.jsonl → partitioned directory
# ---------------------------------------------------------------------------

def _migrate_legacy() -> None:
    """Move entries from the legacy flat file into the new partition layout.

    Called once (the flat file is removed after migration so this is a no-op
    on subsequent runs).
    """
    if not FINDINGS_PATH.exists():
        return
    findings = []
    for line in FINDINGS_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(_finding_from_dict(json.loads(line)))
        except Exception:
            continue

    if not findings:
        FINDINGS_PATH.unlink(missing_ok=True)
        return

    # Group by partition and write
    from collections import defaultdict
    buckets: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[_partition_key(f.context_type)].append(f)

    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    for key, bucket in buckets.items():
        path = FINDINGS_DIR / f"{key}.jsonl"
        existing = _load_partition(path)
        existing_payloads = {(e.payload, e.sink_type) for e in existing}
        new_entries = [f for f in bucket if (f.payload, f.sink_type) not in existing_payloads]
        _write_partition(path, existing + new_entries)
        _trim_partition(path)

    # Rename legacy file so it's preserved but won't be migrated again
    FINDINGS_PATH.rename(FINDINGS_PATH.with_suffix(".jsonl.migrated"))


# Run migration exactly once when this module is imported
try:
    _migrate_legacy()
except Exception:
    pass  # never crash on migration failure


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def save_finding(finding: Finding) -> bool:
    """Append *finding* to the appropriate partition.

    Silently deduplicates (same payload + sink_type) within the partition.
    Trims the partition to MAX_PER_PARTITION after appending.

    Returns True if the finding was actually written, False if it was a duplicate.
    """
    path = _partition_path(finding.context_type)
    existing = _load_partition(path)
    for i, f in enumerate(existing):
        if _same_identity(f, finding):
            merged = _merge_findings(f, finding)
            if merged == f:
                return False
            existing[i] = merged
            _write_partition(path, existing)
            _trim_partition(path)
            return True
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(finding)) + "\n")
    _trim_partition(path)
    return True


def finding_memory_source(finding: Finding) -> str:
    tags = {tag.strip().lower() for tag in finding.tags}
    evidence_type = (finding.evidence_type or "").strip().lower()
    model = (finding.model or "").strip().lower()
    if (
        evidence_type == "xssy_generation"
        or "offline-learning" in tags
        or any(tag.startswith("xssy:") for tag in tags)
        or model.startswith("xssy")
    ):
        return MEMORY_SOURCE_LABS
    return MEMORY_SOURCE_TARGETS


def _matches_memory_source(finding: Finding, memory_source: str) -> bool:
    source = (memory_source or MEMORY_SOURCE_ALL).strip().lower()
    if source not in VALID_MEMORY_SOURCES or source == MEMORY_SOURCE_ALL:
        return True
    return finding_memory_source(finding) == source


def load_findings(context_type: str | None = None) -> list[Finding]:
    """Load findings from disk.

    If *context_type* is given, load only that partition (fast path).
    If None, load all partitions (for CLI export or migration).
    """
    if not FINDINGS_DIR.exists():
        return []
    if context_type is not None:
        return _load_partition(_partition_path(context_type))
    # Load all partitions
    all_findings: list[Finding] = []
    for path in sorted(FINDINGS_DIR.glob("*.jsonl")):
        all_findings.extend(_load_partition(path))
    return all_findings


def partition_stats() -> dict[str, int]:
    """Return {context_type: entry_count} for every partition on disk."""
    if not FINDINGS_DIR.exists():
        return {}
    stats: dict[str, int] = {}
    for path in sorted(FINDINGS_DIR.glob("*.jsonl")):
        count = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
        stats[path.stem] = count
    return stats


def review_queue(limit: int = 25, memory_source: str = MEMORY_SOURCE_ALL) -> list[Finding]:
    candidates = [
        f for f in load_findings()
        if f.memory_tier == MEMORY_TIER_EXPERIMENTAL and f.review_status == REVIEW_STATUS_PENDING
        and _matches_memory_source(f, memory_source)
    ]

    def _priority(f: Finding) -> tuple[int, int, int, str]:
        score = 0
        if f.evidence_type == "xssy_generation":
            score += 2
        if "offline-learning" in f.tags:
            score += 1
        score += min(f.success_count, 3)
        return (-score, -len(f.tags), -len(f.explanation), f.ts)

    candidates.sort(key=_priority)
    return candidates[:limit]


def memory_stats(memory_source: str = MEMORY_SOURCE_ALL) -> dict[str, int]:
    findings = [f for f in load_findings() if _matches_memory_source(f, memory_source)]
    return {
        "total": len(findings),
        "curated": sum(1 for f in findings if f.memory_tier == MEMORY_TIER_CURATED),
        "verified_runtime": sum(1 for f in findings if f.memory_tier == MEMORY_TIER_VERIFIED_RUNTIME),
        "experimental": sum(1 for f in findings if f.memory_tier == MEMORY_TIER_EXPERIMENTAL),
        "pending_review": sum(1 for f in findings if f.review_status == REVIEW_STATUS_PENDING),
        "approved": sum(1 for f in findings if f.review_status == REVIEW_STATUS_APPROVED),
        "rejected": sum(1 for f in findings if f.review_status == REVIEW_STATUS_REJECTED),
    }


def find_finding_by_id(finding_id_value: str) -> Finding | None:
    needle = finding_id_value.strip().lower()
    for finding in load_findings():
        if finding_id(finding) == needle:
            return finding
    return None


def _replace_finding(target: Finding, replacement: Finding) -> bool:
    path = _partition_path(target.context_type)
    existing = _load_partition(path)
    changed = False
    for i, item in enumerate(existing):
        if finding_id(item) == finding_id(target):
            existing[i] = replacement
            changed = True
            break
    if changed:
        _write_partition(path, existing)
    return changed


def review_finding(
    finding_id_value: str,
    *,
    reviewer: str = "manual-review",
    note: str = "",
    promote_to: str | None = None,
    target_scope: str | None = None,
    reject: bool = False,
) -> Finding:
    finding = find_finding_by_id(finding_id_value)
    if finding is None:
        raise KeyError(f"finding {finding_id_value!r} not found")

    if reject:
        updated = Finding(
            **{
                **asdict(finding),
                "review_status": REVIEW_STATUS_REJECTED,
                "reviewed_by": reviewer,
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
                "review_note": note,
            }
        )
    else:
        next_tier = promote_to or finding.memory_tier
        if next_tier not in VALID_MEMORY_TIERS:
            raise ValueError(f"invalid memory tier: {next_tier}")
        next_scope = target_scope or finding.target_scope
        if next_scope not in VALID_TARGET_SCOPES:
            raise ValueError(f"invalid target scope: {next_scope}")
        updated = Finding(
            **{
                **asdict(finding),
                "memory_tier": next_tier,
                "target_scope": next_scope,
                "review_status": REVIEW_STATUS_APPROVED,
                "reviewed_by": reviewer,
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
                "review_note": note,
            }
        )

    if not _replace_finding(finding, updated):
        raise RuntimeError(f"failed to update finding {finding_id_value}")
    return updated


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------

def relevant_findings(
    *,
    sink_type: str,
    context_type: str,
    surviving_chars: str,
    limit: int = 6,
    allowed_tiers: tuple[str, ...] = TRUSTED_MEMORY_TIERS,
    target_host: str = "",
    waf_name: str = "",
    delivery_mode: str = "",
    frameworks: tuple[str, ...] = (),
    auth_required: bool | None = None,
) -> list[Finding]:
    """Return the most contextually relevant past findings.

    Loads only the matching context_type partition (primary) plus the
    unknown/catch-all partition (secondary).  If context_type is empty,
    loads all partitions (same behaviour as before).

    Scoring:
      +4  exact sink_type match
      +2  partial sink_type match
      +3  exact context_type match
      +1-3 surviving chars overlap (capped at 3)
      +2  verified finding
    """
    if context_type:
        primary   = _load_partition(_partition_path(context_type))
        catchall  = _load_partition(_partition_path("unknown"))
        # Also pull from any partition whose name partially matches the sink_type,
        # so related contexts (e.g. html_attr_url + html_attr_href) cross-pollinate.
        candidates: list[Finding] = []
        seen_partitions = {_partition_key(context_type), "unknown"}
        if sink_type and FINDINGS_DIR.exists():
            for path in FINDINGS_DIR.glob("*.jsonl"):
                if path.stem not in seen_partitions and sink_type.split("_")[0] in path.stem:
                    candidates.extend(_load_partition(path))
                    seen_partitions.add(path.stem)
        all_f = primary + catchall + candidates
    else:
        all_f = load_findings()

    if not all_f:
        return []

    surviving_set = set(surviving_chars)
    framework_set = {item.lower() for item in frameworks}
    scored: list[tuple[int, Finding]] = []
    for f in all_f:
        if f.memory_tier not in allowed_tiers:
            continue
        if f.target_scope == TARGET_SCOPE_HOST and (not target_host or f.target_host != target_host):
            continue
        score = 0
        if f.sink_type == sink_type:
            score += 4
        elif sink_type and (sink_type in f.sink_type or f.sink_type in sink_type):
            score += 2
        if f.context_type == context_type:
            score += 3
        score += min(len(surviving_set & set(f.surviving_chars)), 3)
        if f.verified:
            score += 2
        if target_host and f.target_scope == TARGET_SCOPE_HOST and f.target_host == target_host:
            score += 4
        if delivery_mode and f.delivery_mode == delivery_mode.lower():
            score += 3
        if waf_name and f.waf_name == waf_name.lower():
            score += 3
        elif waf_name and f.waf_name and (waf_name.lower() in f.waf_name or f.waf_name in waf_name.lower()):
            score += 1
        if framework_set and f.frameworks:
            score += min(len(framework_set & {item.lower() for item in f.frameworks}), 2)
        if auth_required is not None and f.auth_required == auth_required:
            score += 1
        score += MEMORY_TIER_PRIORITY.get(f.memory_tier, 0)
        if score > 0:
            scored.append((score, f))
    scored.sort(key=lambda x: -x[0])
    return [f for _, f in scored[:limit]]


# ---------------------------------------------------------------------------
# Helpers for models.py
# ---------------------------------------------------------------------------

def findings_prompt_section(findings: list[Finding]) -> str:
    """Format findings as a few-shot prompt block."""
    if not findings:
        return ""
    lines = [
        "Past findings for similar filter/sink contexts "
        "(study the bypass TECHNIQUE — do NOT copy verbatim, adapt to this target):"
    ]
    for f in findings:
        lines.append(
            f"  sink={f.sink_type}  context={f.context_type}  "
            f"surviving_chars={f.surviving_chars!r}  bypass_family={f.bypass_family}  "
            f"tier={f.memory_tier}  scope={f.target_scope}"
        )
        if f.waf_name or f.delivery_mode or f.frameworks:
            lines.append(
                f"  delivery={f.delivery_mode or '-'}  waf={f.waf_name or '-'}  "
                f"frameworks={','.join(f.frameworks) or '-'}"
            )
        lines.append(f"  payload: {f.payload}")
        if f.explanation:
            lines.append(f"  why_it_works: {f.explanation}")
        if f.evidence_detail:
            lines.append(f"  evidence: {f.evidence_detail}")
        lines.append("")
    return "\n".join(lines)


def infer_bypass_family(payload_str: str, tags: list[str]) -> str:
    """Best-effort bypass family classification from payload text and tags."""
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
