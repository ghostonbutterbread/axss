from __future__ import annotations

from types import SimpleNamespace

from ai_xss_generator.active.worker import _waf_reference_payloads
from ai_xss_generator.browser_nav import goto_with_edge_recovery


class _FakePage:
    def __init__(self, target_url: str, root_url: str, *, edge_fail: bool = True) -> None:
        self.target_url = target_url
        self.root_url = root_url
        self.edge_fail = edge_fail
        self.preflight_done = False
        self.calls: list[tuple[str, str]] = []

    def goto(self, url: str, *, timeout: int, wait_until: str) -> None:
        self.calls.append((url, wait_until))
        if url == self.root_url:
            self.preflight_done = True
            return
        if url == self.target_url and not self.preflight_done:
            if self.edge_fail:
                raise Exception(f"Page.goto: net::ERR_HTTP2_PROTOCOL_ERROR at {url}")
            raise Exception(f"Page.goto: bad target at {url}")
        return

    def wait_for_load_state(self, state: str, *, timeout: int) -> None:
        return


def test_goto_with_edge_recovery_uses_same_origin_preflight() -> None:
    target = "https://www.example.com/search?q=test"
    root = "https://www.example.com/"
    page = _FakePage(target, root, edge_fail=True)

    ok, phases, exc = goto_with_edge_recovery(page, target, timeout_ms=5000)

    assert ok is True
    assert exc is not None
    assert any(phase.startswith("preflight:") for phase in phases)
    assert any(phase.startswith("retry:") for phase in phases)
    assert root in [url for url, _wait in page.calls]


def test_goto_with_edge_recovery_does_not_preflight_non_edge_errors() -> None:
    target = "https://www.example.com/search?q=test"
    root = "https://www.example.com/"
    page = _FakePage(target, root, edge_fail=False)

    ok, phases, _exc = goto_with_edge_recovery(page, target, timeout_ms=5000)

    assert ok is False
    assert not any(phase.startswith("preflight:") for phase in phases)
    assert root not in [url for url, _wait in page.calls]


def test_waf_reference_payloads_filter_to_url_context_candidates() -> None:
    probe_result = SimpleNamespace(
        reflections=[
            SimpleNamespace(context_type="html_attr_url", attr_name="href"),
        ]
    )

    payloads = _waf_reference_payloads("akamai", probe_result, limit=8)
    payload_texts = [getattr(item, "payload", "") for item in payloads]

    assert payload_texts
    assert all("<" not in payload for payload in payload_texts)
    assert all(
        any(token in payload.lower() for token in ("javascript:", "data:", "java\t", "java\r", "java&#9;", "jav&#x0a;"))
        for payload in payload_texts
    )


def test_waf_reference_payloads_filter_to_markup_for_html_body() -> None:
    probe_result = SimpleNamespace(
        reflections=[
            SimpleNamespace(context_type="html_body", attr_name=""),
        ]
    )

    payloads = _waf_reference_payloads("akamai", probe_result, limit=4)
    payload_texts = [getattr(item, "payload", "") for item in payloads]

    assert payload_texts
    assert all("<" in payload or "&#60;" in payload or "%3C" in payload for payload in payload_texts)
