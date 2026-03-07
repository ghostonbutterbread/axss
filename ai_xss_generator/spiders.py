from __future__ import annotations

import os
import time
from itertools import cycle
from pathlib import Path
from typing import Any, Iterable

from scrapling.fetchers import FetcherSession

from ai_xss_generator.parser import extract_markup_from_response


def _load_rotation_values(raw_value: str | None) -> list[str]:
    if not raw_value:
        return []
    path = Path(raw_value)
    if path.exists():
        values = path.read_text(encoding="utf-8").splitlines()
    else:
        values = raw_value.split(",")
    return [value.strip() for value in values if value.strip()]


def crawl_urls(urls: Iterable[str], rate: float = 25.0) -> dict[str, dict[str, Any]]:
    """Fetch a list of URLs with Scrapling and return parsed results keyed by URL.

    Parameters
    ----------
    urls:  URLs to fetch.
    rate:  Max requests per second. 0 disables throttling entirely.
    """
    url_list = [u.strip() for u in urls if u and u.strip()]
    results: dict[str, dict[str, Any]] = {}
    delay = (1.0 / rate) if rate > 0 else 0

    user_agents = (
        _load_rotation_values(os.environ.get("AXSS_USER_AGENTS"))
        or ["axss/0.1 (+authorized security testing; scrapling)"]
    )
    proxies_list = _load_rotation_values(os.environ.get("AXSS_PROXIES")) or []
    ua_cycle = cycle(user_agents)
    proxy_cycle = cycle(proxies_list) if proxies_list else None

    with FetcherSession(
        impersonate="chrome",
        stealthy_headers=True,
        timeout=20,
        follow_redirects=True,
        retries=1,
    ) as session:
        for index, url in enumerate(url_list):
            if index > 0 and delay > 0:
                time.sleep(delay)
            try:
                kwargs: dict[str, Any] = {
                    "headers": {"User-Agent": next(ua_cycle)},
                }
                if proxy_cycle:
                    kwargs["proxy"] = next(proxy_cycle)

                response = session.get(url, **kwargs)
                markup = extract_markup_from_response(response)

                if response.url != url:
                    markup.notes.append(f"Final URL: {response.url}")

                html_text = response.text or response.body.decode("utf-8", errors="replace")
                results[url] = {
                    "source": url,
                    "source_type": "url",
                    "html": html_text,
                    "title": markup.title,
                    "forms": markup.forms,
                    "inputs": markup.inputs,
                    "handlers": markup.handlers,
                    "inline_scripts": markup.inline_scripts,
                    "notes": ["Fetched with Scrapling.", *markup.notes],
                }
            except Exception as exc:
                results[url] = {
                    "source": url,
                    "source_type": "url",
                    "error": str(exc),
                }

    return results
