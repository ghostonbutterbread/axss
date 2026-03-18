"""Tests for discover_dom_taint_paths() sources parameter."""
from __future__ import annotations
import urllib.parse
from unittest.mock import MagicMock, patch
import pytest

from ai_xss_generator.active.dom_xss import discover_dom_taint_paths


class TestDiscoverDomTaintPathsSources:
    def test_none_sources_uses_all_sources(self):
        """sources=None → all 6 sources are tested (existing Deep behavior)."""
        browser = MagicMock()
        context = MagicMock()
        page = MagicMock()
        browser.new_context.return_value = context
        context.new_page.return_value = page
        page.evaluate.return_value = []
        page.goto.return_value = None

        discover_dom_taint_paths(
            "http://example.com/?q=1",
            browser,
            sources=None,
        )

        # Should have navigated for query_param, fragment, window_name,
        # local_storage, session_storage, referrer — at least 6 times
        assert browser.new_context.call_count >= 6

    def test_explicit_sources_restricts_navigation(self):
        """Explicit URL-param-only sources list → navigates only for those sources."""
        browser = MagicMock()
        context = MagicMock()
        page = MagicMock()
        browser.new_context.return_value = context
        context.new_page.return_value = page
        page.evaluate.return_value = []
        page.goto.return_value = None

        discover_dom_taint_paths(
            "http://example.com/?q=1&id=2",
            browser,
            sources=[("query_param", "q"), ("query_param", "id")],
        )

        # Should only navigate for the two query params, no more
        assert browser.new_context.call_count == 2

    def test_empty_sources_list_performs_no_navigation(self):
        """Empty sources list → no navigations, empty result."""
        browser = MagicMock()

        result = discover_dom_taint_paths(
            "http://example.com/",
            browser,
            sources=[],
        )

        assert result == []
        browser.new_context.assert_not_called()
