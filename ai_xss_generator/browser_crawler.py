"""Playwright-based browser crawler for SPA/Angular site discovery.

Unlike the HTTP crawler (crawler.py), this module renders JavaScript before
extracting links, making Angular/React/Vue client-side routes visible.

Key capabilities:
  - Navigates pages in a real Chromium browser (headless).
  - Waits for Angular testabilities to settle before extracting DOM content.
  - Intercepts XHR/fetch requests to discover API endpoints with query params.
  - Extracts links and forms from the live rendered DOM, not raw HTML.
  - Returns the same CrawlResult type as crawl() — drop-in for -u mode.

Designed for use with --browser-crawl; falls back gracefully on timeouts.
"""
from __future__ import annotations

import logging
import urllib.parse
from typing import Callable

from ai_xss_generator.crawler import (
    CrawlResult,
    MAX_PAGES,
    _CSRF_FIELD_NAMES,
    _dedup_key,
    _is_csrf_field,
    _page_key,
    _resolve,
    _same_origin,
    _testable_params,
)
from ai_xss_generator.types import PostFormTarget

log = logging.getLogger(__name__)

# Wait up to this long for networkidle after each navigation (ms)
_NAV_TIMEOUT_MS = 15_000

# How long to wait for Angular testabilities to settle (ms)
_ANGULAR_SETTLE_MS = 5_000

# Resource types that carry no navigable links — skip routing them through the
# browser to avoid wasting time/bandwidth.
_SKIP_RESOURCE_TYPES = frozenset({
    "image", "media", "font", "stylesheet", "other",
})

# File extensions we never want to navigate to in the browser.
_SKIP_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".map", ".pdf", ".zip", ".gz", ".tar", ".mp4", ".mp3",
})


def _should_skip_url(url: str) -> bool:
    """True if this URL should not be navigated to by the browser."""
    path = urllib.parse.urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _SKIP_EXTENSIONS)


def _wait_for_angular(page: object) -> None:  # type: ignore[type-arg]
    """Best-effort wait for Angular to finish rendering.

    Calls getAllAngularTestabilities() if it exists and waits until all
    testabilities report stable. Safe on non-Angular pages — the JS check
    returns true immediately when the global is absent.
    """
    try:
        page.wait_for_function(  # type: ignore[attr-defined]
            """() => {
                if (typeof window.getAllAngularTestabilities !== 'function') return true;
                const ts = window.getAllAngularTestabilities();
                if (!ts || !ts.length) return true;
                return ts.every(t => t.isStable());
            }""",
            timeout=_ANGULAR_SETTLE_MS,
        )
    except Exception:
        pass  # Timeout or non-Angular page — proceed with whatever is rendered


def _extract_links_from_dom(page: object, base_url: str) -> list[str]:  # type: ignore[type-arg]
    """Return resolved same-origin hrefs visible in the live DOM."""
    try:
        hrefs: list[str] = page.evaluate(  # type: ignore[attr-defined]
            """() => Array.from(document.querySelectorAll('[href]'))
                         .map(el => el.getAttribute('href'))
                         .filter(h => h && h.trim() !== '' &&
                                      !h.startsWith('javascript:') &&
                                      !h.startsWith('mailto:') &&
                                      !h.startsWith('tel:') &&
                                      !h.startsWith('#'))"""
        )
    except Exception as exc:
        log.debug("DOM link extraction failed for %s: %s", base_url, exc)
        return []

    resolved: list[str] = []
    for href in hrefs or []:
        url = _resolve(href, base_url)
        if url:
            resolved.append(url)
    return resolved


def _extract_forms_from_dom(page: object, base_url: str) -> list[dict]:  # type: ignore[type-arg]
    """Return raw form descriptors extracted from the live DOM.

    Each descriptor is a dict with keys: action, method, fields.
    fields is a list of [name, type, value] triples.
    """
    try:
        raw: list[dict] = page.evaluate(  # type: ignore[attr-defined]
            """() => Array.from(document.querySelectorAll('form')).map(form => ({
                action: form.getAttribute('action') || '',
                method: (form.method || 'get').toUpperCase(),
                fields: Array.from(
                    form.querySelectorAll('input, textarea, select')
                ).filter(el => el.name && el.name.trim() !== '')
                 .map(el => [
                     el.name,
                     (el.type || 'text').toLowerCase(),
                     el.value || ''
                 ])
            }))"""
        )
        return raw or []
    except Exception as exc:
        log.debug("DOM form extraction failed for %s: %s", base_url, exc)
        return []


_FORM_SKIP_TYPES = frozenset({"submit", "button", "image", "reset", "file"})


def _process_raw_forms(
    raw_forms: list[dict],
    final_url: str,
    seen_post_keys: set[str],
    post_forms: list[PostFormTarget],
) -> None:
    """Convert raw form dicts into PostFormTarget objects (in-place)."""
    for raw_form in raw_forms:
        method = raw_form.get("method", "GET")
        if method != "POST":
            continue

        action = raw_form.get("action", "")
        fields: list[list[str]] = raw_form.get("fields", [])

        abs_action = _resolve(action, final_url) if action else final_url
        if not abs_action:
            continue

        csrf_field: str | None = None
        hidden_defaults: dict[str, str] = {}
        param_names: list[str] = []

        for field in fields:
            name, ftype, value = field[0], field[1], field[2] if len(field) > 2 else ""
            if ftype in _FORM_SKIP_TYPES:
                continue
            if ftype == "hidden":
                hidden_defaults[name] = value
            if csrf_field is None and _is_csrf_field(name, ftype):
                csrf_field = name
            else:
                param_names.append(name)

        if not param_names:
            continue

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
            "Browser crawl — POST form: action=%s params=%s csrf=%s",
            abs_action, param_names, csrf_field,
        )


def browser_crawl(
    start_url: str,
    *,
    depth: int = 2,
    auth_headers: dict[str, str] | None = None,
    on_progress: Callable[[int, int, int], None] | None = None,
) -> CrawlResult:
    """BFS-crawl *start_url* using a real Playwright browser.

    Renders JavaScript before extracting links and forms, making Angular/React/
    Vue client-side routes discoverable. Also intercepts XHR/fetch requests to
    surface API endpoints with injectable query parameters.

    Returns a CrawlResult with the same fields as crawl() so it is a drop-in
    replacement for -u mode in cli.py.

    Args:
        start_url:    Seed URL. Origin (scheme://netloc) is the crawl boundary.
        depth:        BFS depth limit (default 2).
        auth_headers: Extra request headers (e.g. Authorization) injected into
                      every browser request and the network context.
        on_progress:  Optional callback(visited, targets_found, current_depth).
    """
    from playwright.sync_api import sync_playwright

    parsed_origin = urllib.parse.urlparse(start_url)
    origin = f"{parsed_origin.scheme}://{parsed_origin.netloc}"

    visited_pages: set[str] = set()
    all_fetched_urls: list[str] = []
    seen_targets: dict[str, str] = {}
    ordered_targets: list[str] = []
    seen_post_keys: set[str] = set()
    post_forms: list[PostFormTarget] = []

    # Mutable container for network-intercepted URLs (populated from event handler)
    intercepted: list[str] = []

    current_level: list[str] = [start_url]

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        try:
            context = browser.new_context(
                ignore_https_errors=True,
                extra_http_headers=auth_headers or {},
            )

            # Block heavy resource types to speed up crawl
            def _route_handler(route: object) -> None:  # type: ignore[type-arg]
                req = route.request  # type: ignore[attr-defined]
                if req.resource_type in _SKIP_RESOURCE_TYPES:
                    route.abort()  # type: ignore[attr-defined]
                else:
                    route.continue_()  # type: ignore[attr-defined]

            context.route("**/*", _route_handler)

            # Capture XHR/fetch requests with testable query params
            def _on_request(request: object) -> None:  # type: ignore[type-arg]
                req_url: str = request.url  # type: ignore[attr-defined]
                rtype: str = request.resource_type  # type: ignore[attr-defined]
                if rtype in ("xhr", "fetch") and _same_origin(req_url, origin):
                    if _testable_params(req_url):
                        intercepted.append(req_url)

            context.on("request", _on_request)

            page = context.new_page()

            for current_depth in range(depth + 1):
                if not current_level:
                    break

                to_visit: list[str] = []
                for url in current_level:
                    pk = _page_key(url)
                    if pk not in visited_pages and len(visited_pages) < MAX_PAGES:
                        visited_pages.add(pk)
                        to_visit.append(url)

                if not to_visit:
                    break

                all_fetched_urls.extend(to_visit)
                log.debug(
                    "Browser crawl depth=%d: visiting %d page(s) | %d visited | %d targets",
                    current_depth, len(to_visit), len(visited_pages), len(seen_targets),
                )

                next_level: list[str] = []

                for url in to_visit:
                    if _should_skip_url(url):
                        log.debug("Browser crawl: skipping asset URL %s", url)
                        continue

                    # Navigate — try networkidle first, fall back to domcontentloaded
                    navigated = False
                    for wait_until in ("networkidle", "domcontentloaded"):
                        try:
                            page.goto(url, wait_until=wait_until, timeout=_NAV_TIMEOUT_MS)
                            navigated = True
                            break
                        except Exception as exc:
                            log.debug(
                                "Browser nav (%s) failed for %s: %s",
                                wait_until, url, exc,
                            )

                    if not navigated:
                        log.debug("Browser crawl: giving up on %s", url)
                        continue

                    # Angular / SPA settle
                    _wait_for_angular(page)

                    final_url = page.url or url

                    # Register as a testable GET target if it has injectable params
                    if _testable_params(url):
                        key = _dedup_key(url)
                        if key not in seen_targets:
                            seen_targets[key] = url
                            ordered_targets.append(url)

                    if on_progress:
                        on_progress(len(visited_pages), len(ordered_targets), current_depth)

                    # Extract links from live DOM for next BFS level
                    if current_depth < depth:
                        for link in _extract_links_from_dom(page, final_url):
                            if _same_origin(link, origin) and not _should_skip_url(link):
                                next_level.append(link)

                    # Extract forms from live DOM (always — even at max depth)
                    raw_forms = _extract_forms_from_dom(page, final_url)
                    _process_raw_forms(raw_forms, final_url, seen_post_keys, post_forms)

                # Absorb any intercepted XHR/fetch targets discovered on this level
                for iurl in intercepted:
                    ikey = _dedup_key(iurl)
                    if ikey not in seen_targets:
                        seen_targets[ikey] = iurl
                        ordered_targets.append(iurl)
                        log.debug("Browser crawl — XHR/fetch target: %s", iurl)
                intercepted.clear()

                next_level = sorted(
                    next_level,
                    key=lambda u: 0 if _testable_params(u) else 1,
                )
                current_level = next_level

        finally:
            try:
                browser.close()
            except Exception:
                pass

    log.info(
        "Browser crawl complete: %d page(s) visited | %d GET target(s) | %d POST form(s)",
        len(visited_pages), len(ordered_targets), len(post_forms),
    )
    return CrawlResult(
        get_urls=ordered_targets,
        post_forms=post_forms,
        visited_urls=all_fetched_urls,
    )
