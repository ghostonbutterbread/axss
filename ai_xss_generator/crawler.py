"""Site crawler for XSS surface discovery.

BFS-crawls from a seed URL, extracts links, and returns all discovered URLs
that carry non-tracking query parameters — the actual XSS attack surface.

Design constraints:
  - Same-origin only: never follows links to external domains.
  - Deduplicates by path + sorted testable param NAMES so the same endpoint
    with different param values (e.g. ?q=shoes vs ?q=boots) is only tested once.
  - Tracking/analytics params are filtered before dedup and before returning
    results (reuses the same blocklist as probe.py).
  - Uses the WAF-aware crawl_urls() fetch path from spiders.py so JS-challenge
    WAFs (akamai, cloudflare, etc.) are handled transparently.
  - Hard cap of MAX_PAGES visited pages to prevent runaway crawls.
"""
from __future__ import annotations

import logging
import urllib.parse
from collections import deque
from html.parser import HTMLParser
from typing import Callable

from ai_xss_generator.probe import _TRACKING_PARAM_BLOCKLIST

log = logging.getLogger(__name__)

MAX_PAGES = 300  # hard cap on pages visited per crawl session


# ---------------------------------------------------------------------------
# HTML link extraction
# ---------------------------------------------------------------------------

class _LinkExtractor(HTMLParser):
    """Minimal HTMLParser that collects href and GET form action values."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a":
            href = attr.get("href", "").strip()
            if href:
                self.links.append(href)
        elif tag == "form":
            action = attr.get("action", "").strip()
            method = attr.get("method", "get").strip().upper()
            # Only GET forms: params end up in the URL, which we can probe
            if action and method in ("", "GET"):
                self.links.append(action)


def _extract_links(html: str, base_url: str) -> list[str]:
    """Return resolved, deduplicated same-scheme-or-relative links from *html*."""
    extractor = _LinkExtractor()
    try:
        extractor.feed(html)
    except Exception:
        pass
    return extractor.links


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def _origin(url: str) -> str:
    """Return scheme://netloc for *url*."""
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _resolve(href: str, base_url: str) -> str | None:
    """Resolve *href* against *base_url*. Returns None if not HTTP/S or empty."""
    if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
        return None
    try:
        resolved = urllib.parse.urljoin(base_url, href)
        parsed = urllib.parse.urlparse(resolved)
        if parsed.scheme not in ("http", "https"):
            return None
        # Strip fragment — we care about the page, not the anchor
        return urllib.parse.urlunparse(parsed._replace(fragment=""))
    except Exception:
        return None


def _same_origin(url: str, origin: str) -> bool:
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}" == origin


def _page_key(url: str) -> str:
    """Stable key for page-level dedup: scheme+netloc+path only (ignores params)."""
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/")


def _testable_params(url: str) -> dict[str, str]:
    """Return {name: value} for params that survive the tracking blocklist."""
    p = urllib.parse.urlparse(url)
    if not p.query:
        return {}
    raw = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    return {k: v[0] for k, v in raw.items() if k.lower() not in _TRACKING_PARAM_BLOCKLIST}


def _dedup_key(url: str) -> str:
    """Stable key for target dedup: path + sorted testable param NAMES.

    Values are intentionally excluded — ?q=shoes and ?q=boots test the same
    injection surface so should only be scanned once.
    """
    p = urllib.parse.urlparse(url)
    params = _testable_params(url)
    param_sig = ",".join(sorted(params))
    return f"{p.scheme}://{p.netloc}{p.path}[{param_sig}]"


# ---------------------------------------------------------------------------
# Public crawl() entry point
# ---------------------------------------------------------------------------

def crawl(
    start_url: str,
    *,
    depth: int = 2,
    rate: float = 25.0,
    waf: str | None = None,
    auth_headers: dict[str, str] | None = None,
    on_progress: Callable[[int, int, int], None] | None = None,
) -> list[str]:
    """BFS-crawl from *start_url* and return discovered URLs with testable params.

    Args:
        start_url:   Seed URL. The origin (scheme://netloc) is the crawl boundary.
        depth:       BFS depth limit (default 2). depth=0 only tests start_url.
        rate:        Max requests/sec — passed through to crawl_urls().
        waf:         Detected WAF name — controls fetch strategy in crawl_urls().
        auth_headers: Extra headers for authenticated crawling.
        on_progress: Optional callback(visited, targets_found, current_depth) for
                     live progress updates.

    Returns:
        Deduplicated list of URLs that have at least one non-tracking query
        parameter. Ordered by discovery order (BFS).
    """
    from ai_xss_generator.spiders import crawl_urls

    origin = _origin(start_url)
    visited_pages: set[str] = set()       # page-level dedup (path, no params)
    seen_targets: dict[str, str] = {}     # dedup_key -> canonical URL
    ordered_targets: list[str] = []       # insertion-order for stable output

    # BFS queue: list of (url, depth) pairs for the current and next levels
    current_level: list[str] = [start_url]

    for current_depth in range(depth + 1):
        if not current_level:
            break

        # Deduplicate within this level before fetching
        to_fetch: list[str] = []
        for url in current_level:
            pk = _page_key(url)
            if pk not in visited_pages and len(visited_pages) < MAX_PAGES:
                visited_pages.add(pk)
                to_fetch.append(url)

        if not to_fetch:
            break

        log.debug(
            "Crawl depth=%d: fetching %d page(s) | %d visited | %d targets so far",
            current_depth, len(to_fetch), len(visited_pages), len(seen_targets),
        )

        # Batch-fetch this level using the WAF-aware spider
        crawled = crawl_urls(to_fetch, rate=rate, waf=waf, auth_headers=auth_headers)

        next_level: list[str] = []

        for url in to_fetch:
            result = crawled.get(url)

            # Collect this URL as a scan target if it has testable params
            if _testable_params(url):
                key = _dedup_key(url)
                if key not in seen_targets:
                    seen_targets[key] = url
                    ordered_targets.append(url)

            if on_progress:
                on_progress(len(visited_pages), len(ordered_targets), current_depth)

            if not result or result.get("error"):
                log.debug("Crawl: fetch failed for %s — skipping link extraction", url)
                continue

            # Only extract links if we haven't hit the depth limit yet
            if current_depth < depth:
                html = str(result.get("html", ""))
                # Use the final URL (after redirects) as the base for resolving links
                final_url = url
                for note in result.get("notes", []):
                    if note.startswith("Final URL:"):
                        final_url = note.split("Final URL:", 1)[1].strip()
                        break

                raw_links = _extract_links(html, final_url)
                for href in raw_links:
                    resolved = _resolve(href, final_url)
                    if resolved and _same_origin(resolved, origin):
                        next_level.append(resolved)

        current_level = next_level

    log.info(
        "Crawl complete: %d page(s) visited | %d target(s) with testable params",
        len(visited_pages), len(ordered_targets),
    )
    return ordered_targets
