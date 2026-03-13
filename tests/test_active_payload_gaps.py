from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

from ai_xss_generator.active.generator import (
    html_attr_url_payloads,
    html_body_payloads,
)
from ai_xss_generator.active.reporter import _build_report, write_report
from ai_xss_generator.active.worker import (
    ConfirmedFinding,
    WorkerResult,
    _run,
)
from ai_xss_generator.probe import (
    ProbeResult,
    ReflectionContext,
    _analyze_char_survival,
    _find_reflections,
)


def _fake_context(source: str) -> SimpleNamespace:
    return SimpleNamespace(
        source=source,
        frameworks=[],
        forms=[],
        dom_sinks=[],
        auth_notes=[],
    )


class _FakeFetcherSession:
    def __init__(self, **kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def get(self, url, headers=None):
        return SimpleNamespace(text="<html></html>", body=None)


def test_report_moves_dom_taint_out_of_confirmed_section() -> None:
    dom_xss = ConfirmedFinding(
        url="https://example.test/target",
        param_name="hash",
        context_type="dom_xss",
        sink_context="document.write",
        payload="'onload='alert(1)",
        transform_name="dom_static_fallback",
        execution_method="dom_xss",
        execution_detail="DOM XSS confirmed.",
        waf=None,
        surviving_chars="",
        fired_url="https://example.test/target#'onload='alert(1)",
        source="phase1_transform",
        cloud_escalated=False,
    )
    dom_taint = ConfirmedFinding(
        url="https://example.test/target",
        param_name="name",
        context_type="dom_xss",
        sink_context="document.write",
        payload="",
        transform_name="dom_xss_runtime",
        execution_method="dom_taint",
        execution_detail="DOM taint only.",
        waf=None,
        surviving_chars="",
        fired_url="https://example.test/target?name=axss",
        source="dom_xss_runtime",
        cloud_escalated=False,
    )
    report = _build_report(
        [WorkerResult(url="https://example.test/target", status="confirmed", confirmed_findings=[dom_xss, dom_taint])],
        config_summary="",
        auth_summary="demo/admin",
    )

    assert "## ✅ Confirmed Findings (1 area(s), 1 variant(s))" in report
    assert "## ℹ️ DOM Taint Only (1)" in report
    assert "DOM taint only." in report


def test_report_groups_multiple_confirmed_variants_for_same_area() -> None:
    finding_one = ConfirmedFinding(
        url="https://example.test/search?q=test",
        param_name="q",
        context_type="html_body",
        sink_context="html_body",
        payload="<svg/onload=alert(1)>",
        transform_name="svg_tag",
        execution_method="dialog",
        execution_detail="Dialog fired.",
        waf="akamai",
        surviving_chars="<>/",
        fired_url="https://example.test/search?q=%3Csvg%2Fonload%3Dalert(1)%3E",
        source="cloud_model",
        cloud_escalated=True,
        bypass_family="tag_injection",
    )
    finding_two = ConfirmedFinding(
        url="https://example.test/search?q=test",
        param_name="q",
        context_type="html_body",
        sink_context="html_body",
        payload="<img src=x onerror=alert(1)>",
        transform_name="img_onerror",
        execution_method="dialog",
        execution_detail="Dialog fired.",
        waf="akamai",
        surviving_chars="<>/=",
        fired_url="https://example.test/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
        source="phase1_transform",
        cloud_escalated=True,
        bypass_family="event_handler_injection",
    )

    report = _build_report(
        [WorkerResult(url="https://example.test/search?q=test", status="confirmed", confirmed_findings=[finding_one, finding_two])],
        config_summary="",
        auth_summary="demo/admin",
    )

    assert "## ✅ Confirmed Findings (1 area(s), 2 variant(s))" in report
    assert "**Confirmed variants:** `2` distinct payload/result combinations for this same area." in report
    assert "**Additional confirmed variants:**" in report
    assert report.count("### Finding 1") == 1
    assert "<svg/onload=alert(1)>" in report
    assert "<img src=x onerror=alert(1)>" in report
    assert "event_handler_injection" in report


def test_write_report_emits_html_companion(tmp_path) -> None:
    report_path = tmp_path / "scan.md"
    finding = ConfirmedFinding(
        url="https://example.test/search?q=test",
        param_name="q",
        context_type="html_body",
        sink_context="html_body",
        payload="<svg/onload=alert(1)>",
        transform_name="svg_tag",
        execution_method="dialog",
        execution_detail="Dialog fired.",
        waf="akamai",
        surviving_chars="<>/",
        fired_url="https://example.test/search?q=%3Csvg%2Fonload%3Dalert(1)%3E",
        source="cloud_model",
        cloud_escalated=True,
        bypass_family="tag_injection",
    )

    written = write_report(
        [WorkerResult(url="https://example.test/search?q=test", status="confirmed", confirmed_findings=[finding])],
        config_summary="rate=5",
        auth_summary="demo/admin",
        output_path=str(report_path),
    )

    html_path = report_path.with_suffix(".html")
    assert written == str(report_path)
    assert html_path.exists()
    html_report = html_path.read_text(encoding="utf-8")
    assert "axss Active Scan Report" in html_report
    assert "Confirmed Findings" in html_report
    assert "badge-confirmed" in html_report
    assert "tag_injection" in html_report


def test_report_includes_pilot_summary_and_budget_table() -> None:
    report = _build_report(
        [
            WorkerResult(
                url="https://example.test/live",
                kind="get",
                status="no_execution",
                target_tier="live",
                local_model_rounds=1,
                cloud_model_rounds=2,
                fallback_rounds=1,
                params_tested=1,
                params_reflected=1,
                escalation_reasons=["Reduced local model budget because the target is operating in a stealth/high-friction probe mode."],
            ),
            WorkerResult(
                url="https://example.test/dead",
                kind="dom",
                status="no_execution",
                dead_target=True,
                dead_reason="No DOM taint path was confirmed during runtime discovery.",
                target_tier="hard_dead",
            ),
        ],
        config_summary="rate=5",
        auth_summary="demo/admin",
    )

    assert "## Pilot Summary" in report
    assert "**Auth:** demo/admin" in report
    assert "hard-dead `1`" in report
    assert "live `1`" in report
    assert "Model rounds: local `1`, cloud `2`" in report
    assert "## Pilot Budget By Target (2)" in report
    assert "Reduced local model budget because the target is operating in a stealth/high-friction probe mode." in report
    assert "No DOM taint path was confirmed during runtime discovery." in report


def test_html_body_payloads_include_uppercase_safe_variants() -> None:
    payloads = html_body_payloads(
        frozenset(set('ABCDEFGHIJKLMNOPQRSTUVWXYZ<>"=&#0123456789();/')),
        "name",
    )
    rendered = {payload.payload for payload in payloads}

    assert "<IMG SRC=x ONERROR=&#97;&#108;&#101;&#114;&#116;(1)>" in rendered
    assert any(payload.startswith("<SVG ONLOAD=&#97;&#108;&#101;&#114;&#116;") for payload in rendered)


def test_html_attr_url_payloads_include_entity_and_whitespace_scheme_variants() -> None:
    payloads = html_attr_url_payloads(
        frozenset(set("abcdefghijklmnopqrstuvwxyz&#0123456789;:/=()\t\n\r")),
        "url",
        "href",
    )
    rendered = {payload.payload for payload in payloads}

    assert "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)" in rendered
    assert "java\tscript:alert(1)" in rendered
    assert "java\r\nscript:alert(1)" in rendered


def test_probe_detects_uppercased_reflection_and_survival_markers() -> None:
    canary = "axssdead"
    html = (
        "<p>HELLO AXSSDEAD</p>"
        "<p>AXSSDEADAXSSOP<>AXSSCL</p>"
    )

    reflections = _find_reflections(html, canary)
    surviving = _analyze_char_survival(html, canary)

    assert reflections
    assert reflections[0].context_type == "html_body"
    assert "<" in surviving
    assert ">" in surviving


def test_get_worker_runs_coordinated_split_payload_fallback_for_reflected_only_params() -> None:
    url = "https://example.test/search?firstName=test&lastName=user"
    probe_results = [
        ProbeResult(
            param_name="firstName",
            original_value="test",
            reflections=[ReflectionContext(context_type="html_body", surviving_chars=frozenset())],
        ),
        ProbeResult(
            param_name="lastName",
            original_value="user",
            reflections=[ReflectionContext(context_type="html_body", surviving_chars=frozenset())],
        ),
    ]
    fire_overrides: list[dict[str, str] | None] = []
    results: list[WorkerResult] = []

    class FakeExecutor:
        def __init__(self, auth_headers=None) -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

        def fire(self, **kwargs):
            fire_overrides.append(kwargs.get("payload_overrides"))
            overrides = kwargs.get("payload_overrides") or {}
            confirmed = overrides == {
                "firstName": "<img/src=x",
                "lastName": "onerror=alert(1)>",
            }
            return SimpleNamespace(
                confirmed=confirmed,
                method="dialog" if confirmed else "",
                detail="alert fired" if confirmed else "",
                transform_name=kwargs["transform_name"],
                payload=kwargs["payload"],
                fired_url=kwargs["url"] + "?firstName=%3Cimg%2Fsrc%3Dx&lastName=onerror%3Dalert%281%29%3E",
                error=None,
            )

    with (
        patch("ai_xss_generator.probe.probe_url", return_value=probe_results),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_context(url)),
        patch("scrapling.fetchers.FetcherSession", _FakeFetcherSession),
        patch("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor),
        patch("ai_xss_generator.active.transforms.all_variants_for_probe", return_value=[]),
        patch("ai_xss_generator.active.worker._get_local_payloads", return_value=[]),
        patch("ai_xss_generator.active.worker._get_cloud_payloads", return_value=[]),
    ):
        _run(
            url=url,
            rate=25.0,
            waf_hint=None,
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
            auth_headers=None,
            sink_url=None,
            ai_backend="api",
            cli_tool="claude",
            cli_model=None,
        )

    assert fire_overrides
    assert fire_overrides[0] == {
        "firstName": "<img/src=x",
        "lastName": "onerror=alert(1)>",
    }
    assert results and results[0].status == "confirmed"
    assert results[0].confirmed_findings[0].param_name == "firstName+lastName"
    assert results[0].confirmed_findings[0].transform_name == "split_img_onerror"
