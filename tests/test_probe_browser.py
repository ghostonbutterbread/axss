from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

from ai_xss_generator.active.worker import _run
from ai_xss_generator.probe import ProbeResult, ReflectionContext, _browser_context_auth, probe_url


def test_browser_context_auth_moves_cookie_header_into_browser_cookies() -> None:
    extra_headers, cookies, user_agent = _browser_context_auth(
        "https://example.test/search?q=x",
        {
            "Cookie": "sid=abc123; theme=light",
            "Authorization": "Bearer token",
            "X-Test": "1",
        },
        "agent-test",
    )

    assert extra_headers == {
        "Authorization": "Bearer token",
        "X-Test": "1",
    }
    assert cookies == [
        {
            "name": "sid",
            "value": "abc123",
            "domain": "example.test",
            "path": "/",
            "secure": True,
            "httpOnly": False,
        },
        {
            "name": "theme",
            "value": "light",
            "domain": "example.test",
            "path": "/",
            "secure": True,
            "httpOnly": False,
        },
    ]
    assert user_agent == "agent-test"


def test_probe_url_uses_browser_path_for_strong_waf_and_loads_auth_cookies() -> None:
    captured: dict[str, object] = {}

    class FakePage:
        pass

    class FakeContext:
        def __init__(self, *, ignore_https_errors, extra_http_headers, user_agent):
            captured["ignore_https_errors"] = ignore_https_errors
            captured["extra_http_headers"] = dict(extra_http_headers)
            captured["user_agent"] = user_agent
            self.cookies_added: list[dict[str, object]] = []

        def add_cookies(self, cookies):
            self.cookies_added.extend(cookies)
            captured["cookies"] = list(cookies)

        def route(self, pattern, handler):
            captured["route_pattern"] = pattern

        def new_page(self):
            return FakePage()

        def close(self):
            captured["context_closed"] = True

    class FakeBrowser:
        def __init__(self):
            self.context = None

        def new_context(self, **kwargs):
            self.context = FakeContext(**kwargs)
            return self.context

        def close(self):
            captured["browser_closed"] = True

    class FakePlaywright:
        def __init__(self):
            self.browser = FakeBrowser()
            self.chromium = SimpleNamespace(launch=self._launch)

        def _launch(self, **kwargs):
            captured["launch_kwargs"] = dict(kwargs)
            return self.browser

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    with (
        patch("playwright.sync_api.sync_playwright", return_value=FakePlaywright()),
        patch(
            "ai_xss_generator.probe._probe_param_playwright",
            return_value=ProbeResult(
                param_name="q",
                original_value="x",
                reflections=[ReflectionContext(context_type="html_body", surviving_chars=frozenset({"<", ">"}))],
            ),
        ) as browser_probe,
        patch("ai_xss_generator.probe._probe_param") as curl_probe,
    ):
        results = probe_url(
            "https://example.test/search?q=x",
            rate=5,
            waf="akamai",
            auth_headers={
                "Cookie": "sid=abc123; theme=light",
                "Authorization": "Bearer token",
            },
        )

    assert len(results) == 1
    assert results[0].is_reflected
    assert browser_probe.called
    assert not curl_probe.called
    assert captured["extra_http_headers"] == {
        "Authorization": "Bearer token",
        "Accept": "text/html,application/xhtml+xml",
    }
    assert captured["cookies"] == [
        {
            "name": "sid",
            "value": "abc123",
            "domain": "example.test",
            "path": "/",
            "secure": True,
            "httpOnly": False,
        },
        {
            "name": "theme",
            "value": "light",
            "domain": "example.test",
            "path": "/",
            "secure": True,
            "httpOnly": False,
        },
    ]


def test_get_worker_prefetch_uses_browser_fetch_for_strong_waf() -> None:
    url = "https://example.test/search?q=x"
    results = []

    class _FakeFetcherSession:
        def __init__(self, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def get(self, *args, **kwargs):
            raise AssertionError("curl-style prefetch should not be used for akamai")

    with (
        patch("scrapling.fetchers.FetcherSession", _FakeFetcherSession),
        patch("ai_xss_generator.probe.fetch_html_with_browser", return_value="<html></html>") as browser_fetch,
        patch("ai_xss_generator.probe.probe_url", return_value=[]),
    ):
        _run(
            url=url,
            rate=5.0,
            waf_hint="akamai",
            model="qwen3.5",
            cloud_model="anthropic/claude-3-5-sonnet",
            use_cloud=True,
            timeout_seconds=30,
            result_queue=None,
            dedup_registry={},
            dedup_lock=threading.Lock(),
            findings_lock=threading.Lock(),
            start_time=time.monotonic(),
            put_result=results.append,
            auth_headers={"Cookie": "sid=abc123"},
            sink_url=None,
            ai_backend="api",
            cli_tool="claude",
            cli_model=None,
            mode="deep",
        )

    assert browser_fetch.called
    assert results and results[0].status == "no_reflection"
