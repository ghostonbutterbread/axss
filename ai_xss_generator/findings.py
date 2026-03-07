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
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Internal: partition key → file path
# ---------------------------------------------------------------------------

def _partition_key(context_type: str) -> str:
    """Sanitise context_type into a safe filename stem."""
    key = re.sub(r"[^a-z0-9_-]", "_", (context_type or "unknown").lower()).strip("_")
    return key or "unknown"


def _partition_path(context_type: str) -> Path:
    return FINDINGS_DIR / f"{_partition_key(context_type)}.jsonl"


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
            d = json.loads(line)
            results.append(Finding(
                sink_type=d.get("sink_type", ""),
                context_type=d.get("context_type", ""),
                surviving_chars=d.get("surviving_chars", ""),
                bypass_family=d.get("bypass_family", ""),
                payload=d.get("payload", ""),
                test_vector=d.get("test_vector", ""),
                model=d.get("model", "unknown"),
                explanation=d.get("explanation", ""),
                target_host=d.get("target_host", ""),
                tags=d.get("tags", []),
                verified=d.get("verified", False),
                ts=d.get("ts", ""),
            ))
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
            d = json.loads(line)
            findings.append(Finding(
                sink_type=d.get("sink_type", ""),
                context_type=d.get("context_type", ""),
                surviving_chars=d.get("surviving_chars", ""),
                bypass_family=d.get("bypass_family", ""),
                payload=d.get("payload", ""),
                test_vector=d.get("test_vector", ""),
                model=d.get("model", "unknown"),
                explanation=d.get("explanation", ""),
                target_host=d.get("target_host", ""),
                tags=d.get("tags", []),
                verified=d.get("verified", False),
                ts=d.get("ts", ""),
            ))
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
    for f in existing:
        if f.payload == finding.payload and f.sink_type == finding.sink_type:
            return False  # already stored
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(finding)) + "\n")
    _trim_partition(path)
    return True


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


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------

def relevant_findings(
    *,
    sink_type: str,
    context_type: str,
    surviving_chars: str,
    limit: int = 6,
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
    scored: list[tuple[int, Finding]] = []
    for f in all_f:
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
            f"surviving_chars={f.surviving_chars!r}  bypass_family={f.bypass_family}"
        )
        lines.append(f"  payload: {f.payload}")
        if f.explanation:
            lines.append(f"  why_it_works: {f.explanation}")
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
