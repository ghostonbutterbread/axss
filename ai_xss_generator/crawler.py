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
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Callable

from ai_xss_generator.probe import _TRACKING_PARAM_BLOCKLIST
from ai_xss_generator.types import PostFormTarget

log = logging.getLogger(__name__)

# Hidden input names that are almost certainly CSRF tokens — not injectable.
_CSRF_FIELD_NAMES: frozenset[str] = frozenset({
    "csrf", "_csrf", "csrftoken", "csrf_token", "csrf-token",
    "__requestverificationtoken", "authenticity_token", "_token",
    "xsrf", "xsrf_token", "x_csrf_token", "__vt", "nonce",
})


def _is_csrf_field(name: str, input_type: str) -> bool:
    """Return True if this field is likely a CSRF token (hidden + name pattern)."""
    if input_type != "hidden":
        return False
    lower = name.lower()
    return (
        lower in _CSRF_FIELD_NAMES
        or "csrf" in lower
        or "xsrf" in lower
        or "token" in lower
        or "nonce" in lower
    )


@dataclass
class CrawlResult:
    """Return type of crawl() — GET testable URLs and discovered POST form targets."""
    get_urls: list[str]
    post_forms: list[PostFormTarget]
    visited_urls: list[str]  # All pages actually fetched — used for post-injection sweep
    detected_waf: str | None = None  # WAF auto-detected from crawl seed response


MAX_PAGES = 300  # hard cap on pages visited per crawl session


# ---------------------------------------------------------------------------
# HTML link extraction
# ---------------------------------------------------------------------------

class _LinkExtractor(HTMLParser):
    """HTMLParser that collects hrefs, synthesizes GET form submission URLs,
    and records raw POST form data for later conversion to PostFormTarget.

    GET forms: uses actual ``value`` attribute for hidden inputs (preserves
    real CSRF token values so synthesized URLs survive server-side validation),
    and ``"test"`` for user-editable fields.

    POST forms: records all field triples (name, type, value) and the action
    URL so the caller can construct PostFormTarget objects with absolute URLs.
    """

    _SKIP_TYPES: frozenset[str] = frozenset(
        {"submit", "button", "image", "reset", "file"}
    )

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.post_form_raws: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}

        if tag == "a":
            href = attr.get("href", "").strip()
            if href:
                self.links.append(href)

        elif tag == "form":
            method = attr.get("method", "get").strip().upper()
            self._form = {
                "action": attr.get("action", "").strip(),
                "method": method if method else "GET",
                "fields": [],  # list of (name, input_type, value)
            }

        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = attr.get("name", "").strip()
            input_type = attr.get("type", "text").strip().lower()
            value = attr.get("value", "").strip()
            existing_names = [f[0] for f in self._form["fields"]]
            if name and input_type not in self._SKIP_TYPES and name not in existing_names:
                self._form["fields"].append((name, input_type, value))

    def handle_endtag(self, tag: str) -> None:
        if tag != "form" or self._form is None:
            return

        form = self._form
        self._form = None
        method: str = form["method"]
        action: str = form["action"]
        fields: list[tuple[str, str, str]] = form["fields"]

        if method == "GET":
            if fields:
                # Use actual value for hidden inputs (preserves CSRF tokens),
                # "test" placeholder for all other field types.
                params = {
                    name: (value if ftype == "hidden" else "test")
                    for name, ftype, value in fields
                }
                qs = urllib.parse.urlencode(params)
                self.links.append(f"{action}?{qs}" if action else f"?{qs}")
            elif action:
                self.links.append(action)
        else:
            # POST/PUT/DELETE — record for PostFormTarget construction
            if fields:
                self.post_form_raws.append({
                    "action": action,
                    "fields": fields,
                })


def _extract_links(html: str, base_url: str) -> tuple[list[str], list[dict]]:
    """Return (hrefs/synthetic-GET-URLs, raw-POST-form-dicts) extracted from *html*.

    Does not resolve or filter — callers handle _resolve() and _same_origin().
    """
    extractor = _LinkExtractor()
    try:
        extractor.feed(html)
    except Exception:
        pass
    return extractor.links, extractor.post_form_raws


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
) -> CrawlResult:
    """BFS-crawl from *start_url* and return a CrawlResult with:
      - get_urls:   deduplicated URLs that have at least one non-tracking GET param.
      - post_forms: PostFormTarget objects for POST forms discovered during crawl.

    Args:
        start_url:   Seed URL. The origin (scheme://netloc) is the crawl boundary.
        depth:       BFS depth limit (default 2). depth=0 only tests start_url.
        rate:        Max requests/sec — passed through to crawl_urls().
        waf:         Detected WAF name — controls fetch strategy in crawl_urls().
        auth_headers: Extra headers for authenticated crawling.
        on_progress: Optional callback(visited, targets_found, current_depth) for
                     live progress updates.
    """
    from ai_xss_generator.spiders import crawl_urls

    origin = _origin(start_url)
    visited_pages: set[str] = set()
    all_fetched_urls: list[str] = []   # ordered list of every URL actually fetched
    seen_targets: dict[str, str] = {}
    ordered_targets: list[str] = []
    seen_post_keys: set[str] = set()   # dedup POST forms by action+param signature
    post_forms: list[PostFormTarget] = []

    current_level: list[str] = [start_url]
    _crawl_detected_waf: str | None = None

    for current_depth in range(depth + 1):
        if not current_level:
            break

        to_fetch: list[str] = []
        for url in current_level:
            pk = _page_key(url)
            if pk not in visited_pages and len(visited_pages) < MAX_PAGES:
                visited_pages.add(pk)
                to_fetch.append(url)

        if not to_fetch:
            break

        all_fetched_urls.extend(to_fetch)
        log.debug(
            "Crawl depth=%d: fetching %d page(s) | %d visited | %d targets so far",
            current_depth, len(to_fetch), len(visited_pages), len(seen_targets),
        )

        crawled = crawl_urls(
            to_fetch, rate=rate, waf=waf, auth_headers=auth_headers,
            detect_waf_on_seed=(current_depth == 0 and waf is None),
        )

        # Extract WAF detected from seed response (first BFS level only)
        _seed_waf_entry = crawled.pop("__detected_waf__", None)
        if _seed_waf_entry and waf is None:
            waf = _seed_waf_entry.get("waf")
            if waf:
                _crawl_detected_waf = waf
                log.info("WAF auto-detected from crawl seed: %s", waf)

        next_level: list[str] = []

        for url in to_fetch:
            result = crawled.get(url)

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

            html = str(result.get("html", ""))
            final_url = url
            for note in result.get("notes", []):
                if note.startswith("Final URL:"):
                    extracted = note.split("Final URL:", 1)[1].strip()
                    if extracted:
                        final_url = extracted
                    break

            raw_links, raw_post_forms = _extract_links(html, final_url)

            # Follow links to the next BFS level only if depth limit not reached.
            # POST form extraction always happens regardless of depth so forms on
            # pages at the maximum depth are still discovered.
            if current_depth < depth:
                for href in raw_links:
                    resolved = _resolve(href, final_url)
                    if resolved and _same_origin(resolved, origin):
                        next_level.append(resolved)

            # Convert raw POST form dicts to PostFormTarget objects (all depths)
            for raw_form in raw_post_forms:
                    action = raw_form["action"]
                    fields: list[tuple[str, str, str]] = raw_form["fields"]

                    # Resolve the action URL to absolute
                    abs_action = _resolve(action, final_url) if action else final_url
                    if not abs_action:
                        continue

                    # Detect CSRF field and build defaults dict
                    csrf_field: str | None = None
                    hidden_defaults: dict[str, str] = {}
                    param_names: list[str] = []

                    for name, ftype, value in fields:
                        if ftype == "hidden":
                            hidden_defaults[name] = value
                        if csrf_field is None and _is_csrf_field(name, ftype):
                            csrf_field = name
                        else:
                            param_names.append(name)

                    if not param_names:
                        continue

                    # Dedup by action URL + sorted param names
                    post_key = f"{abs_action}[{','.join(sorted(param_names))}]"
                    if post_key in seen_post_keys:
                        continue
                    seen_post_keys.add(post_key)

                    post_forms.append(PostFormTarget(
                        action_url=abs_action,
                        source_page_url=final_url,
                        param_names=param_names,
                        csrf_field=csrf_field,
                        hidden_defaults=hidden_defaults,
                    ))
                    log.debug(
                        "POST form found: action=%s params=%s csrf=%s",
                        abs_action, param_names, csrf_field,
                    )

        next_level = sorted(next_level, key=lambda u: 0 if _testable_params(u) else 1)
        current_level = next_level

    log.info(
        "Crawl complete: %d page(s) visited | %d GET target(s) | %d POST form(s)",
        len(visited_pages), len(ordered_targets), len(post_forms),
    )
    return CrawlResult(get_urls=ordered_targets, post_forms=post_forms, visited_urls=all_fetched_urls, detected_waf=_crawl_detected_waf)
