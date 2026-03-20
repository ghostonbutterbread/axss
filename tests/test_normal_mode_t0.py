"""Tests for probe_param_context() — the T0 lightweight context detector."""
from __future__ import annotations
from unittest.mock import MagicMock, patch
import pytest

from ai_xss_generator.probe import probe_param_context


def _mock_session(html: str):
    """Return a context-manager mock whose .get() returns a response with html."""
    resp = MagicMock()
    resp.text = html
    session = MagicMock()
    session.__enter__ = MagicMock(return_value=session)
    session.__exit__ = MagicMock(return_value=False)
    session.get = MagicMock(return_value=resp)
    return session


def _patch_session(html: str):
    session = _mock_session(html)
    return patch("ai_xss_generator.probe.FetcherSession", return_value=session)


def test_html_body_reflection():
    """Canary in plain HTML content → html_body context, is_injectable=True."""
    with _patch_session("<html><body><p>Hello CANARY</p></body></html>") as mock:
        # Intercept the canary value by capturing what get() is called with
        canary_holder: list[str] = []
        original_get = mock.return_value.__enter__.return_value.get

        def capture_get(url, **kwargs):
            import urllib.parse as _up
            params = dict(_up.parse_qsl(_up.urlparse(url).query))
            canary_holder.append(params.get("q", ""))
            resp = MagicMock()
            resp.text = f"<html><body><p>Hello {params.get('q', '')}</p></body></html>"
            return resp

        mock.return_value.__enter__.return_value.get = capture_get

        result = probe_param_context("http://example.test/search?q=test", "q", "test")

    assert result is not None
    assert result.param_name == "q"
    assert result.probe_mode == "normal_t0"
    assert len(result.reflections) == 1
    assert result.reflections[0].context_type == "html_body"
    assert result.is_injectable  # html_body + assumed surviving chars includes <


def test_js_string_reflection():
    """Canary inside a double-quoted JS string → js_string_dq context."""
    def capture_get(url, **kwargs):
        import urllib.parse as _up
        params = dict(_up.parse_qsl(_up.urlparse(url).query))
        canary = params.get("q", "")
        resp = MagicMock()
        resp.text = f'<script>var x = "{canary}";</script>'
        return resp

    session = _mock_session("")
    session.__enter__.return_value.get = capture_get

    with patch("ai_xss_generator.probe.FetcherSession", return_value=session):
        result = probe_param_context("http://example.test/search?q=test", "q", "test")

    assert result is not None
    assert result.reflections[0].context_type == "js_string_dq"
    assert result.is_injectable


def test_no_reflection_returns_none():
    """Canary not found in response → returns None."""
    with _patch_session("<html><body><p>Nothing here</p></body></html>"):
        result = probe_param_context("http://example.test/search?q=test", "q", "test")
    assert result is None


def test_network_error_returns_none():
    """scrapling exception → returns None gracefully."""
    session = MagicMock()
    session.__enter__ = MagicMock(return_value=session)
    session.__exit__ = MagicMock(return_value=False)
    session.get = MagicMock(side_effect=Exception("connection refused"))

    with patch("ai_xss_generator.probe.FetcherSession", return_value=session):
        result = probe_param_context("http://example.test/search?q=test", "q", "test")
    assert result is None


def test_inert_context_returns_none():
    """Canary inside <textarea> (inert context) → returns None."""
    def capture_get(url, **kwargs):
        import urllib.parse as _up
        params = dict(_up.parse_qsl(_up.urlparse(url).query))
        canary = params.get("q", "")
        resp = MagicMock()
        resp.text = f"<html><body><textarea>{canary}</textarea></body></html>"
        return resp

    session = _mock_session("")
    session.__enter__.return_value.get = capture_get

    with patch("ai_xss_generator.probe.FetcherSession", return_value=session):
        result = probe_param_context("http://example.test/search?q=test", "q", "test")
    assert result is None


def test_assumed_surviving_chars_set():
    """T0 result carries the optimistic surviving_chars so is_injectable works
    for all exploitable context types regardless of actual char filtering."""
    def capture_get(url, **kwargs):
        import urllib.parse as _up
        params = dict(_up.parse_qsl(_up.urlparse(url).query))
        canary = params.get("q", "")
        resp = MagicMock()
        resp.text = f"<html><body><p>{canary}</p></body></html>"
        return resp

    session = _mock_session("")
    session.__enter__.return_value.get = capture_get

    with patch("ai_xss_generator.probe.FetcherSession", return_value=session):
        result = probe_param_context("http://example.test/search?q=test", "q", "test")

    assert result is not None
    assert "<" in result.reflections[0].surviving_chars
    assert ">" in result.reflections[0].surviving_chars
    assert '"' in result.reflections[0].surviving_chars
