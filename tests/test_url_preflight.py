"""Tests for pre-flight URL deduplication and liveness filtering."""
from __future__ import annotations

import pytest

from ai_xss_generator.active.orchestrator import (
    _dedup_urls_by_path_shape,
    _filter_live_urls,
)


# ---------------------------------------------------------------------------
# Path-shape deduplication
# ---------------------------------------------------------------------------

class TestDedup:
    def test_collapses_tag_siblings(self):
        urls = [
            "http://blog.example.com/tag/nyc",
            "http://blog.example.com/tag/pampering-products",
            "http://blog.example.com/tag/peluxe",
            "http://blog.example.com/tag/perfume-2",
            "http://blog.example.com/tag/review",
        ]
        result = _dedup_urls_by_path_shape(urls)
        assert len(result) == 1
        assert result[0] == urls[0]  # first URL is the representative

    def test_preserves_distinct_routes(self):
        urls = [
            "http://example.com/account/settings",
            "http://example.com/account/profile",
        ]
        result = _dedup_urls_by_path_shape(urls)
        # Only 2 siblings — below threshold, not collapsed
        assert len(result) == 2

    def test_collapses_pure_numeric_segments(self):
        urls = [
            "http://example.com/users/123/posts",
            "http://example.com/users/456/posts",
        ]
        result = _dedup_urls_by_path_shape(urls)
        assert len(result) == 1

    def test_collapses_uuid_segments(self):
        urls = [
            "http://example.com/items/550e8400-e29b-41d4-a716-446655440000",
            "http://example.com/items/6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        ]
        result = _dedup_urls_by_path_shape(urls)
        assert len(result) == 1

    def test_collapses_slug_with_trailing_digit(self):
        urls = [
            "http://example.com/products/perfume-2",
            "http://example.com/products/review-5",
        ]
        result = _dedup_urls_by_path_shape(urls)
        assert len(result) == 1

    def test_collapses_multi_word_slugs(self):
        urls = [
            "http://example.com/articles/foo-bar-baz",
            "http://example.com/articles/one-two-three",
        ]
        result = _dedup_urls_by_path_shape(urls)
        assert len(result) == 1

    def test_distinct_domains_not_merged(self):
        urls = [
            "http://a.example.com/tag/x",
            "http://b.example.com/tag/x",
            "http://c.example.com/tag/x",
            "http://a.example.com/tag/y",
            "http://a.example.com/tag/z",
        ]
        result = _dedup_urls_by_path_shape(urls)
        # a.example.com/tag/* collapses to 1; b and c are singletons
        assert len(result) == 3

    def test_empty_list(self):
        assert _dedup_urls_by_path_shape([]) == []

    def test_single_url_unchanged(self):
        urls = ["http://example.com/account/settings"]
        assert _dedup_urls_by_path_shape(urls) == urls

    def test_preserves_query_params_on_representative(self):
        urls = [
            "http://example.com/tag/nyc?page=1",
            "http://example.com/tag/london?page=2",
            "http://example.com/tag/paris?page=3",
        ]
        result = _dedup_urls_by_path_shape(urls)
        assert len(result) == 1
        assert "nyc" in result[0]  # first URL kept

    def test_multi_level_numeric_path(self):
        urls = [
            "http://example.com/users/1/posts/100",
            "http://example.com/users/2/posts/200",
        ]
        result = _dedup_urls_by_path_shape(urls)
        assert len(result) == 1

    def test_three_sibling_threshold(self):
        # Exactly 2 non-parametric siblings → NOT collapsed
        two = [
            "http://example.com/section/alpha",
            "http://example.com/section/beta",
        ]
        assert len(_dedup_urls_by_path_shape(two)) == 2

        # 3 siblings → collapsed
        three = two + ["http://example.com/section/gamma"]
        assert len(_dedup_urls_by_path_shape(three)) == 1


# ---------------------------------------------------------------------------
# Liveness filter
# ---------------------------------------------------------------------------

class TestLiveness:
    def test_passes_live_urls(self, monkeypatch):
        def _fake_check(url):
            return (url, True, "200")

        # Patch at the requests level
        import requests

        class FakeResponse:
            status_code = 200
            def close(self): pass

        monkeypatch.setattr(requests, "head",
                            lambda url, **kw: FakeResponse())

        urls = ["http://example.com/a", "http://example.com/b"]
        result = _filter_live_urls(urls)
        assert result == urls

    def test_removes_404_urls(self, monkeypatch):
        import requests

        def fake_head(url, **kw):
            code = 404 if "gone" in url else 200
            return type("R", (), {"status_code": code, "close": lambda self: None})()

        monkeypatch.setattr(requests, "head", fake_head)

        urls = [
            "http://example.com/live-a",
            "http://example.com/gone-b",
            "http://example.com/live-c",
            "http://example.com/gone-d",
            "http://example.com/live-e",
        ]
        result = _filter_live_urls(urls)
        assert len(result) == 3
        assert all("live" in u for u in result)

    def test_keeps_403_waf_challenge(self, monkeypatch):
        """403 from a WAF JS challenge must NOT be dropped — Playwright can handle it."""
        import requests

        def fake_head(url, **kw):
            return type("R", (), {"status_code": 403, "close": lambda self: None})()

        monkeypatch.setattr(requests, "head", fake_head)

        urls = ["http://akamai-protected.example.com/page",
                "http://akamai-protected.example.com/other"]
        result = _filter_live_urls(urls)
        assert result == urls

    def test_keeps_401_auth_gated(self, monkeypatch):
        import requests

        def fake_head(url, **kw):
            return type("R", (), {"status_code": 401, "close": lambda self: None})()

        monkeypatch.setattr(requests, "head", fake_head)

        urls = ["http://example.com/api/protected", "http://example.com/api/other"]
        result = _filter_live_urls(urls)
        assert result == urls

    def test_keeps_429_rate_limited(self, monkeypatch):
        import requests

        def fake_head(url, **kw):
            return type("R", (), {"status_code": 429, "close": lambda self: None})()

        monkeypatch.setattr(requests, "head", fake_head)

        urls = ["http://example.com/a", "http://example.com/b"]
        result = _filter_live_urls(urls)
        assert result == urls

    def test_keeps_500_server_error(self, monkeypatch):
        import requests

        def fake_head(url, **kw):
            return type("R", (), {"status_code": 500, "close": lambda self: None})()

        monkeypatch.setattr(requests, "head", fake_head)

        urls = ["http://example.com/a", "http://example.com/b"]
        result = _filter_live_urls(urls)
        assert result == urls

    def test_removes_410_gone(self, monkeypatch):
        import requests

        def fake_head(url, **kw):
            code = 410 if "old" in url else 200
            return type("R", (), {"status_code": code, "close": lambda self: None})()

        monkeypatch.setattr(requests, "head", fake_head)

        urls = ["http://example.com/new-page", "http://example.com/old-page",
                "http://example.com/new-other"]
        result = _filter_live_urls(urls)
        assert len(result) == 2
        assert all("new" in u for u in result)

    def test_preserves_order(self, monkeypatch):
        import requests

        class FakeResponse:
            status_code = 200
            def close(self): pass

        monkeypatch.setattr(requests, "head", lambda url, **kw: FakeResponse())

        urls = [f"http://example.com/page/{i}" for i in range(10)]
        result = _filter_live_urls(urls)
        assert result == urls

    def test_falls_back_to_get_on_405(self, monkeypatch):
        import requests

        class Fake405:
            status_code = 405
            def close(self): pass

        class Fake200:
            status_code = 200
            def close(self): pass

        monkeypatch.setattr(requests, "head", lambda url, **kw: Fake405())
        monkeypatch.setattr(requests, "get", lambda url, **kw: Fake200())

        urls = ["http://example.com/api/endpoint"]
        result = _filter_live_urls(urls)
        assert result == urls

    def test_removes_connection_error_urls(self, monkeypatch):
        import requests
        from requests.exceptions import ConnectionError as ReqConnError

        def fake_head(url, **kw):
            if "unreachable" in url:
                raise ReqConnError("no route to host")
            r = type("R", (), {"status_code": 200, "close": lambda self: None})()
            return r

        monkeypatch.setattr(requests, "head", fake_head)

        urls = [
            "http://example.com/reachable",
            "http://unreachable.example.com/page",
        ]
        result = _filter_live_urls(urls)
        assert result == ["http://example.com/reachable"]

    def test_skips_check_for_single_url(self, monkeypatch):
        # Below the minimum threshold — no HTTP calls should be made
        called = []
        import requests
        monkeypatch.setattr(requests, "head",
                            lambda url, **kw: called.append(url))

        result = _filter_live_urls(["http://example.com/only"])
        assert called == []
        assert result == ["http://example.com/only"]
