from __future__ import annotations

from collections.abc import Iterable
from itertools import cycle
import os
from pathlib import Path
from typing import Any

import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.http import Response

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


class AxssSpider(scrapy.Spider):
    name = "axss"
    custom_settings = {
        "LOG_ENABLED": False,
        "LOG_LEVEL": "CRITICAL",
        "TELNETCONSOLE_ENABLED": False,
        "DUPEFILTER_DEBUG": False,
        "ROBOTSTXT_OBEY": False,
        "RETRY_ENABLED": False,
        "COOKIES_ENABLED": False,
        "DOWNLOAD_TIMEOUT": 20,
        "REDIRECT_ENABLED": True,
        "USER_AGENT": "",
        "DEFAULT_REQUEST_HEADERS": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.7",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "DNT": "1",
        },
        "WARN_ON_GENERATOR_RETURN_VALUE": False,
    }

    def __init__(self, *, urls: Iterable[str], results: dict[str, dict[str, Any]], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.start_urls = [url.strip() for url in urls if url.strip()]
        self.results = results
        self._user_agents = cycle(
            _load_rotation_values(os.environ.get("AXSS_USER_AGENTS"))
            or ["axss/0.1 (+authorized security testing; scrapy)"]
        )
        self._proxies = cycle(_load_rotation_values(os.environ.get("AXSS_PROXIES")) or [""])

    def start_requests(self) -> Iterable[scrapy.Request]:
        for url in self.start_urls:
            meta = {"axss_requested_url": url}
            proxy = next(self._proxies)
            if proxy:
                meta["proxy"] = proxy
            yield scrapy.Request(
                url=url,
                callback=self.parse,
                errback=self.handle_error,
                dont_filter=True,
                headers={"User-Agent": next(self._user_agents)},
                meta=meta,
            )

    def parse(self, response: Response, **kwargs: Any) -> None:
        requested_url = response.meta.get("axss_requested_url", response.url)
        markup = extract_markup_from_response(response)
        if response.url != requested_url:
            markup.notes.append(f"Final URL: {response.url}")
        self.results[requested_url] = {
            "source": requested_url,
            "source_type": "url",
            "html": response.text,
            "title": markup.title,
            "forms": markup.forms,
            "inputs": markup.inputs,
            "handlers": markup.handlers,
            "inline_scripts": markup.inline_scripts,
            "notes": ["Fetched with Scrapy spider.", *markup.notes],
        }

    def handle_error(self, failure: Any) -> None:
        request = getattr(failure, "request", None)
        requested_url = request.meta.get("axss_requested_url", request.url) if request is not None else "unknown"
        self.results[requested_url] = {
            "source": requested_url,
            "source_type": "url",
            "error": str(getattr(failure, "value", failure)),
        }


def _rate_settings(rate: float) -> dict[str, Any]:
    """Convert req/sec rate to Scrapy throttle settings. 0 = uncapped."""
    if rate > 0:
        return {
            "DOWNLOAD_DELAY": 1.0 / rate,
            "CONCURRENT_REQUESTS": 1,
            "CONCURRENT_REQUESTS_PER_DOMAIN": 1,
            "AUTOTHROTTLE_ENABLED": False,
        }
    return {
        "DOWNLOAD_DELAY": 0,
        "AUTOTHROTTLE_ENABLED": False,
    }


def crawl_urls(urls: Iterable[str], rate: float = 25.0) -> dict[str, dict[str, Any]]:
    """Crawl a list of URLs and return parsed results keyed by URL.

    Parameters
    ----------
    urls:  URLs to fetch.
    rate:  Max requests per second. 0 disables throttling entirely.
    """
    results: dict[str, dict[str, Any]] = {}
    settings = {"LOG_ENABLED": False, **_rate_settings(rate)}
    process = CrawlerProcess(settings=settings)
    process.crawl(AxssSpider, urls=list(urls), results=results)
    process.start(stop_after_crawl=True, install_signal_handlers=False)
    return results
