"""Local findings store — persists discovered filter behaviors and working payloads.

Stored at ~/.axss/findings.jsonl (one JSON object per line).

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
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


FINDINGS_PATH = Path.home() / ".axss" / "findings.jsonl"
MAX_FINDINGS = 500  # rolling window — oldest entries are dropped when exceeded


# ---------------------------------------------------------------------------
# Bypass family taxonomy — shared between prompts and finding classification
# ---------------------------------------------------------------------------
BYPASS_FAMILIES: list[str] = [
    "whitespace-in-scheme",    # tab/LF/CR inserted inside javascript: scheme
    "case-variant",            # jAvAsCrIpT:
    "html-entity-encoding",    # &#106;avascript: or &colon;
    "double-url-encoding",     # %2522 → %22 → "
    "js-string-breakout",      # ";alert(1)// or ';alert(1)//
    "template-literal-breakout", # `${alert(1)}`
    "html-attribute-breakout", # "><svg/onload=alert(1)>
    "event-handler-injection", # value reflected directly in onX=
    "svg-namespace",           # <svg><animate onbegin=alert(1)>
    "constructor-chain",       # [].filter.constructor('alert(1)')()
    "template-expression",     # {{constructor.constructor('alert(1)')()}}
    "data-uri",                # data:text/html,<script>alert(1)</script>
    "dom-clobbering",          # anchor id overrides window property
    "prototype-pollution",     # __proto__[x]=payload
    "comment-breakout",        # -->payload
    "srcdoc-injection",        # srcdoc="<script>alert(1)</script>"
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
# Storage
# ---------------------------------------------------------------------------

def save_finding(finding: Finding) -> None:
    """Append *finding* to the store. Silently deduplicates and trims to MAX_FINDINGS."""
    FINDINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing = load_findings()
    for f in existing:
        if f.payload == finding.payload and f.sink_type == finding.sink_type:
            return  # already stored
    with FINDINGS_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(finding)) + "\n")
    _trim()


def _trim() -> None:
    if not FINDINGS_PATH.exists():
        return
    lines = [l for l in FINDINGS_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
    if len(lines) > MAX_FINDINGS:
        FINDINGS_PATH.write_text("\n".join(lines[-MAX_FINDINGS:]) + "\n", encoding="utf-8")


def load_findings() -> list[Finding]:
    """Load all findings from disk. Returns empty list on any error."""
    if not FINDINGS_PATH.exists():
        return []
    results: list[Finding] = []
    for line in FINDINGS_PATH.read_text(encoding="utf-8").splitlines():
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

    Scoring:
      +4  exact sink_type match
      +2  partial sink_type match
      +3  exact context_type match
      +1-3 surviving chars overlap (capped at 3)
      +2  verified finding
    """
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
    if "whitespace-bypass" in tag_set or "whitespace-in-scheme" in tag_set:
        return "whitespace-in-scheme"
    if "case-variant" in tag_set or "jaVasCript" in payload_str:
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
