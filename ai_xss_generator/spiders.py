from __future__ import annotations

import logging
import os
import time
from itertools import cycle
from pathlib import Path
from typing import Any, Iterable

from scrapling.fetchers import FetcherSession

from ai_xss_generator.parser import extract_markup_from_response

log = logging.getLogger(__name__)

# curl error codes that indicate the server/WAF is actively blocking us
_CURL_HTTP2_STREAM_ERROR = 92   # CURLE_HTTP2_STREAM  — HTTP/2 RST_STREAM
_CURL_TIMEOUT_ERROR = 28        # CURLE_OPERATION_TIMEDOUT — WAF silent-drop

# WAFs that reliably require a real browser (JS challenge / TLS fingerprinting)
_BROWSER_REQUIRED_WAFS = {"akamai", "cloudflare", "datadome", "kasada", "perimeterx"}


def _load_rotation_values(raw_value: str | None) -> list[str]:
    if not raw_value:
        return []
    path = Path(raw_value)
    if path.exists():
        values = path.read_text(encoding="utf-8").splitlines()
    else:
        values = raw_value.split(",")
    return [value.strip() for value in values if value.strip()]


def _is_blocking_curl_error(exc: Exception) -> bool:
    msg = str(exc)
    return f"({_CURL_HTTP2_STREAM_ERROR})" in msg or f"({_CURL_TIMEOUT_ERROR})" in msg


def _fetch_with_playwright(
    url: str,
    proxy: str | None = None,
    auth_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Fetch a single URL using a real Playwright browser (slow but WAF-resistant)."""
    from scrapling.fetchers import DynamicSession

    kwargs: dict[str, Any] = {
        "disable_resources": True,   # skip fonts/images for speed
        "network_idle": False,
        "google_search": True,       # sets a realistic Google referer
    }
    if proxy:
        kwargs["proxy"] = proxy
    if auth_headers:
        kwargs["extra_headers"] = auth_headers

    with DynamicSession(headless=True, timeout=45_000) as session:
        response = session.fetch(url, **kwargs)

    return response


def crawl_urls(
    urls: Iterable[str],
    rate: float = 25.0,
    waf: str | None = None,
    auth_headers: dict[str, str] | None = None,
    detect_waf_on_seed: bool = False,
) -> dict[str, dict[str, Any]]:
    """Fetch a list of URLs and return parsed results keyed by URL.

    Parameters
    ----------
    urls:               URLs to fetch.
    rate:               Max requests per second. 0 disables throttling entirely.
    waf:                Detected/known WAF name. Used to decide fetch strategy.
    auth_headers:       Extra headers (e.g. Authorization, Cookie) merged into every
                        request so authenticated pages are fetched correctly.
    detect_waf_on_seed: When True and waf is None, detect the WAF from the first
                        successful response and store it as __detected_waf__ in results.
    """
    url_list = [u.strip() for u in urls if u and u.strip()]
    results: dict[str, dict[str, Any]] = {}
    _waf_detected: bool = False
    delay = (1.0 / rate) if rate > 0 else 0

    user_agents = (
        _load_rotation_values(os.environ.get("AXSS_USER_AGENTS"))
        or ["axss/0.1 (+authorized security testing; scrapling)"]
    )
    proxies_list = _load_rotation_values(os.environ.get("AXSS_PROXIES")) or []
    ua_cycle = cycle(user_agents)
    proxy_cycle = cycle(proxies_list) if proxies_list else None

    # For WAFs that are known to require a real browser, skip straight to Playwright.
    needs_browser = waf is not None and waf.lower() in _BROWSER_REQUIRED_WAFS

    with FetcherSession(
        impersonate="chrome",
        stealthy_headers=True,
        timeout=20,
        follow_redirects=True,
        retries=2,
    ) as session:
        for index, url in enumerate(url_list):
            if index > 0 and delay > 0:
                time.sleep(delay)

            proxy = next(proxy_cycle) if proxy_cycle else None
            # Auth headers first; User-Agent from rotation always wins
            merged_headers: dict[str, str] = {**(auth_headers or {}), "User-Agent": next(ua_cycle)}
            fetch_kwargs: dict[str, Any] = {"headers": merged_headers}
            if proxy:
                fetch_kwargs["proxy"] = proxy

            curl_error: Exception | None = None

            if not needs_browser:
                # --- Fast path: curl_cffi ---
                try:
                    response = session.get(url, **fetch_kwargs)
                    # 429 / 503 rate-limit backoff: wait and retry up to 3 times
                    _backoff_attempt = 0
                    while getattr(response, "status_code", 0) in (429, 503) and _backoff_attempt < 3:
                        retry_after = int(response.headers.get("retry-after", 0) if hasattr(response, "headers") else 0)
                        wait = retry_after if retry_after > 0 else (2 ** _backoff_attempt * 2)
                        log.warning("Rate-limited (%s) on %s — backing off %ds", response.status_code, url, wait)
                        time.sleep(wait)
                        response = session.get(url, **fetch_kwargs)
                        _backoff_attempt += 1
                    results[url] = _build_result(url, response)
                    if detect_waf_on_seed and not _waf_detected and waf is None:
                        try:
                            from ai_xss_generator.waf_detect import detect_waf as _detect_waf
                            _waf_name = _detect_waf(response)
                            if _waf_name:
                                results["__detected_waf__"] = {"waf": _waf_name}
                        except Exception:
                            pass
                        _waf_detected = True
                    continue
                except Exception as exc:
                    curl_error = exc
                    # On HTTP/2 rejection, retry once with HTTP/1.1 before giving up
                    if f"({_CURL_HTTP2_STREAM_ERROR})" in str(exc):
                        try:
                            from scrapling.engines.static import CurlHttpVersion
                            h1_kwargs = {**fetch_kwargs, "http_version": CurlHttpVersion.V1_1}
                            response = session.get(url, **h1_kwargs)
                            results[url] = _build_result(url, response)
                            if detect_waf_on_seed and not _waf_detected and waf is None:
                                try:
                                    from ai_xss_generator.waf_detect import detect_waf as _detect_waf
                                    _waf_name = _detect_waf(response)
                                    if _waf_name:
                                        results["__detected_waf__"] = {"waf": _waf_name}
                                except Exception:
                                    pass
                                _waf_detected = True
                            continue
                        except Exception as exc2:
                            curl_error = exc2

            if needs_browser or (curl_error is not None and _is_blocking_curl_error(curl_error)):
                # --- Slow path: Playwright real browser ---
                log.info("Falling back to browser fetch for %s (WAF=%s)", url, waf or "unknown")
                try:
                    response = _fetch_with_playwright(url, proxy=proxy, auth_headers=auth_headers or {})
                    results[url] = _build_result(url, response, note="Fetched with Playwright (WAF bypass).")
                    if detect_waf_on_seed and not _waf_detected and waf is None:
                        try:
                            from ai_xss_generator.waf_detect import detect_waf as _detect_waf
                            _waf_name = _detect_waf(response)
                            if _waf_name:
                                results["__detected_waf__"] = {"waf": _waf_name}
                        except Exception:
                            pass
                        _waf_detected = True
                    continue
                except Exception as exc:
                    results[url] = {"source": url, "source_type": "url", "error": str(exc)}
                    continue

            # curl failed with a non-blocking error (DNS failure, etc.)
            if curl_error is not None:
                results[url] = {"source": url, "source_type": "url", "error": str(curl_error)}

    return results


def _build_result(url: str, response: Any, note: str = "Fetched with Scrapling.") -> dict[str, Any]:
    markup = extract_markup_from_response(response)
    if response.url != url:
        markup.notes.append(f"Final URL: {response.url}")
    status_code = getattr(response, "status", None)
    if status_code is None:
        status_code = getattr(response, "status_code", None)
    html_text = response.text or response.body.decode("utf-8", errors="replace")

    # CSP detection — parse headers and attach analysis if a policy is present
    csp_analysis = None
    try:
        from ai_xss_generator.csp import csp_from_headers
        raw_headers = dict(getattr(response, "headers", {}) or {})
        csp_analysis = csp_from_headers(raw_headers)
        if csp_analysis and csp_analysis.would_block:
            markup.notes.append(f"[csp:blocking] {csp_analysis.raw[:120]}")
        elif csp_analysis and csp_analysis.raw:
            markup.notes.append(f"[csp:present] {csp_analysis.raw[:120]}")
    except Exception:
        pass

    return {
        "source": url,
        "source_type": "url",
        "html": html_text,
        "status_code": status_code,
        "final_url": str(getattr(response, "url", "") or url),
        "title": markup.title,
        "forms": markup.forms,
        "inputs": markup.inputs,
        "handlers": markup.handlers,
        "inline_scripts": markup.inline_scripts,
        "notes": [note, *markup.notes],
        "csp": csp_analysis,
    }
