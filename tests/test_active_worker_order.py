from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

from ai_xss_generator.active.transforms import TransformVariant
from ai_xss_generator.active.dom_xss import DomTaintHit
from ai_xss_generator.behavior import attach_behavior_profile, build_target_behavior_profile
from ai_xss_generator.active.worker import (
    LocalTriageResult,
    WorkerResult,
    _discover_sink_from_crawled_pages,
    _dom_hit_priority,
    _probe_result_for_context,
    _run,
    _run_dom,
    _run_post,
    active_worker_timeout_budget,
)
from ai_xss_generator.probe import ProbeResult, ReflectionContext
from ai_xss_generator.types import ParsedContext, PayloadCandidate, PostFormTarget, StrategyProfile


def _fake_context(source: str) -> SimpleNamespace:
    return SimpleNamespace(
        source=source,
        frameworks=[],
        forms=[],
        dom_sinks=[],
        auth_notes=[],
    )


def _fake_parsed_context(source: str) -> ParsedContext:
    return ParsedContext(source=source, source_type="url")


def _context_with_behavior(source: str, *, delivery_mode: str, waf_name: str, auth: bool = False) -> ParsedContext:
    context = ParsedContext(
        source=source,
        source_type="url",
        auth_notes=["Session cookies provided (1 cookie(s))"] if auth else [],
    )
    profile = build_target_behavior_profile(
        url=source,
        delivery_mode=delivery_mode,
        waf_name=waf_name,
        auth_required=auth,
        context=context,
    )
    attached = attach_behavior_profile(context, profile)
    assert attached is not None
    return attached


class _FakeFetcherSession:
    def __init__(self, **kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def get(self, url, headers=None):
        return SimpleNamespace(text="<html></html>", body=None)


def test_probe_result_for_context_preserves_reflection_flags():
    probe_result = SimpleNamespace(
        param_name="q",
        original_value="test",
        reflections=[
            SimpleNamespace(context_type="html_body", surviving_chars=frozenset({"<", ">"})),
            SimpleNamespace(context_type="html_attr_url", surviving_chars=frozenset({"j", "a"})),
        ],
        discovery_style="semantic_search",
        reflection_transform="upper",
        probe_mode="stealth",
        tested_chars="<>ja",
        error=None,
    )

    reduced = _probe_result_for_context(probe_result, "html_body")

    assert reduced.is_reflected is True
    assert reduced.is_injectable is True
    assert reduced.discovery_style == "semantic_search"
    assert reduced.reflection_transform == "upper"
    assert reduced.probe_mode == "stealth"
    assert reduced.tested_chars == "<>ja"
    assert len(reduced.reflections) == 1
    assert reduced.reflections[0].context_type == "html_body"
    assert reduced.to_sinks()[0].sink == "probe:html_body"


def test_get_worker_runs_local_model_per_context_before_any_fallback():
    url = "https://example.test/search?q=x"
    probe_result = ProbeResult(
        param_name="q",
        original_value="x",
        reflections=[
            ReflectionContext(context_type="html_body", surviving_chars=frozenset({"<", ">"})),
            ReflectionContext(context_type="js_string_dq", surviving_chars=frozenset({'"', ";"})),
        ],
    )

    local_calls: list[str] = []
    fire_calls: list[tuple[str, str]] = []
    results: list[WorkerResult] = []

    class FakeExecutor:
        def __init__(self, auth_headers=None, mode="normal") -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

        def fire(self, **kwargs):
            fire_calls.append((kwargs["transform_name"], kwargs["payload"]))
            return SimpleNamespace(
                confirmed=kwargs["payload"] in {"ai-html", "ai-js"},
                method="dialog",
                detail="alert fired",
                transform_name=kwargs["transform_name"],
                payload=kwargs["payload"],
                fired_url=kwargs["url"],
            )

    def _local_payloads(**kwargs):
        ctx = kwargs["probe_result"].reflections[0].context_type
        local_calls.append(ctx)
        if ctx == "html_body":
            return ["ai-html"]
        if ctx == "js_string_dq":
            return ["ai-js"]
        return []

    with (
        patch("ai_xss_generator.probe.probe_url", return_value=[probe_result]),
        patch("ai_xss_generator.cache.get_probe", return_value=[probe_result]),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_context(url)),
        patch("scrapling.fetchers.FetcherSession", _FakeFetcherSession),
        patch("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor),
        patch(
            "ai_xss_generator.active.transforms.all_variants_for_probe",
            return_value=[
                ("q", "html_body", [TransformVariant("raw", "fallback-html")]),
                ("q", "js_string_dq", [TransformVariant("raw", "fallback-js")]),
            ],
        ),
        patch("ai_xss_generator.active.generator.payloads_for_context", return_value=[]),
        patch("ai_xss_generator.active.generator.mutate_seeds", return_value=[]),
        patch("ai_xss_generator.active.worker._get_local_payloads", side_effect=_local_payloads),
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

    assert local_calls == ["html_body", "js_string_dq"]
    assert fire_calls == [("local_model", "ai-html"), ("local_model", "ai-js")]
    assert results and results[0].status == "confirmed"
    assert [f.source for f in results[0].confirmed_findings] == ["local_model", "local_model"]


def test_get_worker_retries_cloud_with_feedback_before_fallback():
    url = "https://example.test/search?q=x"
    probe_result = ProbeResult(
        param_name="q",
        original_value="x",
        reflections=[
            ReflectionContext(context_type="html_body", surviving_chars=frozenset({"<", ">"})),
        ],
    )

    cloud_feedback_counts: list[int] = []
    fire_calls: list[str] = []
    results: list[WorkerResult] = []

    class FakeExecutor:
        def __init__(self, auth_headers=None, mode="normal") -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

        def fire(self, **kwargs):
            fire_calls.append(kwargs["payload"])
            return SimpleNamespace(
                confirmed=kwargs["payload"] == "cloud-pass-2",
                method="dialog",
                detail="alert fired" if kwargs["payload"] == "cloud-pass-2" else "",
                transform_name=kwargs["transform_name"],
                payload=kwargs["payload"],
                fired_url=kwargs["url"],
                error=None,
            )

    def _cloud_payloads(**kwargs):
        feedback = kwargs.get("feedback_lessons")
        cloud_feedback_counts.append(0 if not feedback else len(feedback))
        if feedback:
            return ["cloud-pass-2"]
        return ["cloud-pass-1"]

    with (
        patch("ai_xss_generator.probe.probe_url", return_value=[probe_result]),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_context(url)),
        patch("scrapling.fetchers.FetcherSession", _FakeFetcherSession),
        patch("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor),
        patch(
            "ai_xss_generator.active.transforms.all_variants_for_probe",
            return_value=[("q", "html_body", [TransformVariant("raw", "fallback-html")])],
        ),
        patch("ai_xss_generator.active.generator.payloads_for_context", return_value=[]),
        patch("ai_xss_generator.active.generator.mutate_seeds", return_value=[]),
        patch("ai_xss_generator.active.worker._get_local_payloads", return_value=[]),
        patch("ai_xss_generator.active.worker._get_cloud_payloads", side_effect=_cloud_payloads),
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
            cloud_attempts=2,
            mode="deep",
        )

    assert cloud_feedback_counts == [0, 1]
    assert fire_calls == ["cloud-pass-1", "cloud-pass-2"]
    assert results and results[0].status == "confirmed"
    assert results[0].confirmed_findings[0].source == "cloud_model"
    assert "Cloud attempt 2/2." in results[0].confirmed_findings[0].ai_note


def test_get_worker_keep_searching_collects_multiple_distinct_local_variants():
    url = "https://example.test/search?q=x"
    probe_result = ProbeResult(
        param_name="q",
        original_value="x",
        reflections=[
            ReflectionContext(context_type="html_body", surviving_chars=frozenset({"<", ">"})),
        ],
    )

    results: list[WorkerResult] = []
    fire_calls: list[str] = []

    class FakeExecutor:
        def __init__(self, auth_headers=None, mode="normal") -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

        def fire(self, **kwargs):
            fire_calls.append(kwargs["payload"])
            return SimpleNamespace(
                confirmed=kwargs["payload"] in {"<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"},
                method="dialog",
                detail="alert fired",
                transform_name=kwargs["transform_name"],
                payload=kwargs["payload"],
                fired_url=kwargs["url"],
                error=None,
            )

    with (
        patch("ai_xss_generator.probe.probe_url", return_value=[probe_result]),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_context(url)),
        patch("scrapling.fetchers.FetcherSession", _FakeFetcherSession),
        patch("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor),
        patch(
            "ai_xss_generator.active.transforms.all_variants_for_probe",
            return_value=[("q", "html_body", [TransformVariant("raw", "fallback-html")])],
        ),
        patch("ai_xss_generator.active.generator.payloads_for_context", return_value=[]),
        patch("ai_xss_generator.active.generator.mutate_seeds", return_value=[]),
        patch(
            "ai_xss_generator.active.worker._get_local_payloads",
            return_value=["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
        ),
        patch("ai_xss_generator.active.worker._get_cloud_payloads", return_value=[]),
    ):
        _run(
            url=url,
            rate=25.0,
            waf_hint=None,
            model="qwen3.5",
            cloud_model="anthropic/claude-3-5-sonnet",
            use_cloud=False,
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
            keep_searching=True,
        )

    assert fire_calls == ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "fallback-html"]
    assert results and results[0].status == "confirmed"
    assert len(results[0].confirmed_findings) == 2
    assert {f.payload for f in results[0].confirmed_findings} == {
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    }


def test_get_worker_uses_deterministic_fallback_only_after_local_and_cloud_fail():
    url = "https://example.test/search?q=x"
    probe_result = ProbeResult(
        param_name="q",
        original_value="x",
        reflections=[
            ReflectionContext(context_type="html_body", surviving_chars=frozenset({"<", ">"})),
        ],
    )

    actions: list[str] = []
    results: list[WorkerResult] = []

    class FakeExecutor:
        def __init__(self, auth_headers=None, mode="normal") -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

        def fire(self, **kwargs):
            actions.append(f"fire:{kwargs['transform_name']}")
            return SimpleNamespace(
                confirmed=kwargs["payload"] == "fallback-html",
                method="dialog",
                detail="alert fired",
                transform_name=kwargs["transform_name"],
                payload=kwargs["payload"],
                fired_url=kwargs["url"],
            )

    def _local_payloads(**kwargs):
        ctx = kwargs["probe_result"].reflections[0].context_type
        actions.append(f"local:{ctx}")
        return []

    def _cloud_payloads(**kwargs):
        ctx = kwargs["probe_result"].reflections[0].context_type
        actions.append(f"cloud:{ctx}")
        return []

    with (
        patch("ai_xss_generator.probe.probe_url", return_value=[probe_result]),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_context(url)),
        patch("scrapling.fetchers.FetcherSession", _FakeFetcherSession),
        patch("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor),
        patch(
            "ai_xss_generator.active.transforms.all_variants_for_probe",
            return_value=[
                ("q", "html_body", [TransformVariant("raw", "fallback-html")]),
            ],
        ),
        patch("ai_xss_generator.active.generator.payloads_for_context", return_value=[]),
        patch("ai_xss_generator.active.generator.mutate_seeds", return_value=[]),
        patch("ai_xss_generator.active.worker._get_local_payloads", side_effect=_local_payloads),
        patch("ai_xss_generator.active.worker._get_cloud_payloads", side_effect=_cloud_payloads),
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
            mode="deep",
        )

    assert actions == ["local:html_body", "cloud:html_body", "fire:raw"]
    assert results and results[0].status == "confirmed"
    assert results[0].confirmed_findings[0].source == "phase1_transform"


def test_get_worker_skips_local_on_high_friction_hard_context_and_uses_cloud() -> None:
    url = "https://example.test/login?redirect=/account"
    probe_result = ProbeResult(
        param_name="redirect",
        original_value="/account",
        reflections=[
            ReflectionContext(context_type="html_attr_url", attr_name="href", surviving_chars=frozenset({"'", "\"", "(", ")"})),
        ],
    )
    actions: list[str] = []
    results: list[WorkerResult] = []

    class FakeExecutor:
        def __init__(self, auth_headers=None, mode="normal") -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

        def fire(self, **kwargs):
            actions.append(f"fire:{kwargs['transform_name']}:{kwargs['payload']}")
            return SimpleNamespace(
                confirmed=kwargs["payload"] == "cloud-url",
                method="dialog",
                detail="alert fired",
                transform_name=kwargs["transform_name"],
                payload=kwargs["payload"],
                fired_url=kwargs["url"],
            )

    with (
        patch("ai_xss_generator.probe.probe_url", return_value=[probe_result]),
        patch(
            "ai_xss_generator.parser.parse_target",
            return_value=_context_with_behavior(url, delivery_mode="get", waf_name="akamai", auth=True),
        ),
        patch("scrapling.fetchers.FetcherSession", _FakeFetcherSession),
        patch("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor),
        patch(
            "ai_xss_generator.active.transforms.all_variants_for_probe",
            return_value=[("redirect", "html_attr_url", [TransformVariant("raw", "fallback-url")])],
        ),
        patch("ai_xss_generator.active.generator.payloads_for_context", return_value=[]),
        patch("ai_xss_generator.active.generator.mutate_seeds", return_value=[]),
        patch("ai_xss_generator.active.worker._get_local_payloads", side_effect=AssertionError("local should be skipped")),
        patch("ai_xss_generator.active.worker._get_cloud_payloads", return_value=["cloud-url"]),
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
            auth_headers={"Cookie": "sid=abc"},
            sink_url=None,
            ai_backend="api",
            cli_tool="claude",
            cli_model=None,
            mode="deep",
        )

    assert actions == ["fire:cloud_model:cloud-url"]
    assert results and results[0].status == "confirmed"
    assert results[0].confirmed_findings[0].source == "cloud_model"
    assert "Skipped local model" in results[0].confirmed_findings[0].ai_note
    assert results[0].target_tier == "live"
    assert results[0].local_model_rounds == 0
    assert results[0].cloud_model_rounds == 1
    assert results[0].fallback_rounds == 0
    assert any("Skipped local model" in note for note in results[0].escalation_reasons)


def test_get_worker_marks_dead_target_when_no_reflection() -> None:
    url = "https://example.test/search?q=x"
    results: list[WorkerResult] = []

    with (
        patch("ai_xss_generator.probe.probe_url", return_value=[]),
        patch(
            "ai_xss_generator.parser.parse_target",
            return_value=_context_with_behavior(url, delivery_mode="get", waf_name="akamai"),
        ),
        patch("ai_xss_generator.probe.fetch_html_with_browser", return_value="<html></html>"),
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
            auth_headers=None,
            sink_url=None,
            ai_backend="api",
            cli_tool="claude",
            cli_model=None,
            mode="deep",
        )

    assert results and results[0].status == "no_reflection"
    assert results[0].dead_target is True
    assert results[0].target_tier == "hard_dead"
    assert "No reflection was confirmed" in results[0].dead_reason


def test_get_worker_forwards_payload_candidate_strategy_to_executor() -> None:
    url = "https://example.test/search?q=x"
    probe_result = ProbeResult(
        param_name="q",
        original_value="x",
        reflections=[
            ReflectionContext(context_type="html_body", surviving_chars=frozenset({"<", ">"})),
        ],
    )
    strategies: list[str] = []
    results: list[WorkerResult] = []

    class FakeExecutor:
        def __init__(self, auth_headers=None, mode="normal") -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

        def fire(self, **kwargs):
            candidate = kwargs.get("payload_candidate")
            strategies.append(getattr(getattr(candidate, "strategy", None), "delivery_mode_hint", ""))
            return SimpleNamespace(
                confirmed=True,
                method="dialog",
                detail="alert fired",
                transform_name=kwargs["transform_name"],
                payload=kwargs["payload"],
                fired_url=kwargs["url"] + "#frag",
            )

    with (
        patch("ai_xss_generator.probe.probe_url", return_value=[probe_result]),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_context(url)),
        patch("scrapling.fetchers.FetcherSession", _FakeFetcherSession),
        patch("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor),
        patch(
            "ai_xss_generator.active.transforms.all_variants_for_probe",
            return_value=[("q", "html_body", [TransformVariant("raw", "fallback-html")])],
        ),
        patch("ai_xss_generator.active.generator.payloads_for_context", return_value=[]),
        patch("ai_xss_generator.active.generator.mutate_seeds", return_value=[]),
        patch(
            "ai_xss_generator.active.worker._get_local_payloads",
            return_value=[
                PayloadCandidate(
                    payload="<svg/onload=alert(1)>",
                    title="fragment",
                    explanation="",
                    test_vector="",
                    source="ollama",
                    strategy=StrategyProfile(delivery_mode_hint="fragment"),
                )
            ],
        ),
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

    assert strategies == ["fragment"]
    assert results and results[0].status == "confirmed"


class _FakeBrowser:
    def close(self) -> None:
        pass


class _FakeChromium:
    def launch(self, **kwargs):
        return _FakeBrowser()


class _FakePlaywright:
    chromium = _FakeChromium()

    def start(self):
        return self

    def stop(self) -> None:
        pass


def test_dom_worker_runs_local_model_per_taint_path_before_any_fallback():
    url = "https://example.test/#start"
    dom_hits = [
        DomTaintHit(
            url=url,
            source_type="query_param",
            source_name="q",
            sink="innerHTML",
            canary="axss1",
            canary_url="https://example.test/?q=axss1",
            code_location="innerHTML stack",
        ),
        DomTaintHit(
            url=url,
            source_type="fragment",
            source_name="hash",
            sink="eval",
            canary="axss2",
            canary_url="https://example.test/#axss2",
            code_location="eval stack",
        ),
    ]

    local_calls: list[tuple[str, str, str]] = []
    fire_calls: list[tuple[str, str]] = []
    results: list[WorkerResult] = []

    def _local_payloads(**kwargs):
        note = kwargs["context"].notes[0]
        if '"sink": "innerHTML"' in note:
            local_calls.append(("query_param", "q", "innerHTML"))
            return ["ai-inner"]
        if '"sink": "eval"' in note:
            local_calls.append(("fragment", "hash", "eval"))
            return ["ai-eval"]
        return []

    def _attempt_payloads(**kwargs):
        payload = kwargs["payloads"][0]
        fire_calls.append((kwargs["sink"], payload))
        return True, payload, f"executed:{kwargs['sink']}"

    with (
        patch("playwright.sync_api.sync_playwright", return_value=_FakePlaywright()),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_parsed_context(url)),
        patch("ai_xss_generator.learning.build_memory_profile", return_value={}),
        patch("ai_xss_generator.lessons.build_mapping_lessons", return_value=[]),
        patch("ai_xss_generator.active.dom_xss.discover_dom_taint_paths", return_value=dom_hits),
        patch("ai_xss_generator.active.dom_xss.attempt_dom_payloads", side_effect=_attempt_payloads),
        patch("ai_xss_generator.active.dom_xss.fallback_payloads_for_sink", side_effect=AssertionError("fallback should not run")),
        patch("ai_xss_generator.active.worker._get_dom_local_payloads", side_effect=_local_payloads),
        patch("ai_xss_generator.active.worker._get_dom_cloud_payloads", side_effect=AssertionError("cloud should not run")),
    ):
        _run_dom(
            url=url,
            waf_hint=None,
            model="qwen3.5",
            cloud_model="anthropic/claude-3-5-sonnet",
            use_cloud=True,
            timeout_seconds=30,
            put_result=results.append,
            dedup_registry={},
            dedup_lock=threading.Lock(),
            auth_headers=None,
            ai_backend="api",
            cli_tool="claude",
            cli_model=None,
            mode="deep",
        )

    assert local_calls == [("fragment", "hash", "eval"), ("query_param", "q", "innerHTML")]
    assert fire_calls == [("eval", "ai-eval"), ("innerHTML", "ai-inner")]
    assert results and results[0].status == "confirmed"
    assert [f.source for f in results[0].confirmed_findings] == ["local_model", "local_model"]


def test_dom_worker_uses_static_fallback_only_after_local_and_cloud_fail():
    url = "https://example.test/#start"
    dom_hits = [
        DomTaintHit(
            url=url,
            source_type="query_param",
            source_name="q",
            sink="innerHTML",
            canary="axss1",
            canary_url="https://example.test/?q=axss1",
            code_location="innerHTML stack",
        ),
    ]

    actions: list[str] = []
    results: list[WorkerResult] = []

    def _local_payloads(**kwargs):
        actions.append("local:innerHTML")
        return []

    def _cloud_payloads(**kwargs):
        actions.append("cloud:innerHTML")
        return []

    def _fallback_payloads(sink: str):
        actions.append(f"fallback:{sink}")
        return ["fallback-inner"]

    def _attempt_payloads(**kwargs):
        actions.append(f"fire:{kwargs['payloads'][0]}")
        return True, kwargs["payloads"][0], "executed:fallback"

    with (
        patch("playwright.sync_api.sync_playwright", return_value=_FakePlaywright()),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_parsed_context(url)),
        patch("ai_xss_generator.learning.build_memory_profile", return_value={}),
        patch("ai_xss_generator.lessons.build_mapping_lessons", return_value=[]),
        patch("ai_xss_generator.active.dom_xss.discover_dom_taint_paths", return_value=dom_hits),
        patch("ai_xss_generator.active.dom_xss.attempt_dom_payloads", side_effect=_attempt_payloads),
        patch("ai_xss_generator.active.dom_xss.fallback_payloads_for_sink", side_effect=_fallback_payloads),
        patch("ai_xss_generator.active.worker._get_dom_local_payloads", side_effect=_local_payloads),
        patch("ai_xss_generator.active.worker._get_dom_cloud_payloads", side_effect=_cloud_payloads),
    ):
        _run_dom(
            url=url,
            waf_hint=None,
            model="qwen3.5",
            cloud_model="anthropic/claude-3-5-sonnet",
            use_cloud=True,
            timeout_seconds=30,
            put_result=results.append,
            dedup_registry={},
            dedup_lock=threading.Lock(),
            auth_headers=None,
            ai_backend="api",
            cli_tool="claude",
            cli_model=None,
        )

    assert actions == ["local:innerHTML", "cloud:innerHTML", "fallback:innerHTML", "fire:fallback-inner"]
    assert results and results[0].status == "confirmed"
    assert results[0].confirmed_findings[0].source == "phase1_transform"
    assert results[0].confirmed_findings[0].transform_name == "dom_static_fallback"


def test_dom_worker_starts_cloud_after_local_delay_and_accepts_cloud_result():
    url = "https://example.test/#start"
    dom_hits = [
        DomTaintHit(
            url=url,
            source_type="query_param",
            source_name="q",
            sink="innerHTML",
            canary="axss1",
            canary_url="https://example.test/?q=axss1",
            code_location="innerHTML stack",
        ),
    ]

    actions: list[str] = []
    results: list[WorkerResult] = []

    def _local_payloads(**kwargs):
        time.sleep(0.08)
        actions.append("local:return")
        return ["ai-local"]

    def _cloud_payloads(**kwargs):
        actions.append("cloud:return")
        return ["ai-cloud"]

    def _attempt_payloads(**kwargs):
        payload = kwargs["payloads"][0]
        actions.append(f"fire:{payload}")
        return payload == "ai-cloud", payload, f"executed:{payload}"

    with (
        patch("playwright.sync_api.sync_playwright", return_value=_FakePlaywright()),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_parsed_context(url)),
        patch("ai_xss_generator.learning.build_memory_profile", return_value={}),
        patch("ai_xss_generator.lessons.build_mapping_lessons", return_value=[]),
        patch("ai_xss_generator.active.dom_xss.discover_dom_taint_paths", return_value=dom_hits),
        patch("ai_xss_generator.active.dom_xss.attempt_dom_payloads", side_effect=_attempt_payloads),
        patch("ai_xss_generator.active.dom_xss.fallback_payloads_for_sink", side_effect=AssertionError("fallback should not run")),
        patch("ai_xss_generator.active.worker._get_dom_local_payloads", side_effect=_local_payloads),
        patch("ai_xss_generator.active.worker._get_dom_cloud_payloads", side_effect=_cloud_payloads),
        patch("ai_xss_generator.active.worker._DOM_CLOUD_START_AFTER_SECONDS", 0.01),
    ):
        _run_dom(
            url=url,
            waf_hint=None,
            model="qwen3.5",
            cloud_model="anthropic/claude-3-5-sonnet",
            use_cloud=True,
            timeout_seconds=30,
            put_result=results.append,
            dedup_registry={},
            dedup_lock=threading.Lock(),
            auth_headers=None,
            ai_backend="api",
            cli_tool="claude",
            cli_model=None,
        )

    assert "cloud:return" in actions
    assert "fire:ai-cloud" in actions
    assert results and results[0].status == "confirmed"
    assert results[0].confirmed_findings[0].source == "cloud_model"


def test_dom_worker_retries_cloud_with_feedback_before_fallback():
    url = "https://example.test/#start"
    dom_hits = [
        DomTaintHit(
            url=url,
            source_type="fragment",
            source_name="hash",
            sink="document.write",
            canary="axss1",
            canary_url="https://example.test/#axss1",
            code_location="document.write stack",
        ),
    ]

    cloud_feedback_counts: list[int] = []
    attempt_calls: list[str] = []
    results: list[WorkerResult] = []

    def _cloud_payloads(**kwargs):
        feedback = kwargs.get("feedback_lessons")
        cloud_feedback_counts.append(0 if not feedback else len(feedback))
        if feedback:
            return ["dom-cloud-2"]
        return ["dom-cloud-1"]

    def _attempt_payloads(**kwargs):
        payload = kwargs["payloads"][0]
        attempt_calls.append(payload)
        return payload == "dom-cloud-2", payload, f"executed:{payload}"

    with (
        patch("playwright.sync_api.sync_playwright", return_value=_FakePlaywright()),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_parsed_context(url)),
        patch("ai_xss_generator.learning.build_memory_profile", return_value={}),
        patch("ai_xss_generator.lessons.build_mapping_lessons", return_value=[]),
        patch("ai_xss_generator.active.dom_xss.discover_dom_taint_paths", return_value=dom_hits),
        patch("ai_xss_generator.active.dom_xss.attempt_dom_payloads", side_effect=_attempt_payloads),
        patch("ai_xss_generator.active.dom_xss.fallback_payloads_for_sink", side_effect=AssertionError("fallback should not run")),
        patch("ai_xss_generator.active.worker._get_dom_local_payloads", return_value=[]),
        patch("ai_xss_generator.active.worker._get_dom_cloud_payloads", side_effect=_cloud_payloads),
        patch("ai_xss_generator.active.worker._DOM_CLOUD_START_AFTER_SECONDS", 0.0),
    ):
        _run_dom(
            url=url,
            waf_hint=None,
            model="qwen3.5",
            cloud_model="anthropic/claude-3-5-sonnet",
            use_cloud=True,
            timeout_seconds=30,
            put_result=results.append,
            dedup_registry={},
            dedup_lock=threading.Lock(),
            auth_headers=None,
            ai_backend="api",
            cli_tool="claude",
            cli_model=None,
            cloud_attempts=2,
        )

    assert cloud_feedback_counts == [0, 1]
    assert attempt_calls == ["dom-cloud-1", "dom-cloud-2"]
    assert results and results[0].status == "confirmed"
    assert results[0].confirmed_findings[0].source == "cloud_model"
    assert "Cloud attempt 2/2." in results[0].confirmed_findings[0].ai_note


def test_dom_worker_runs_deep_escalation_before_fallback_after_fast_attempts_fail():
    url = "https://example.test/#start"
    dom_hits = [
        DomTaintHit(
            url=url,
            source_type="fragment",
            source_name="hash",
            sink="document.write",
            canary="axss1",
            canary_url="https://example.test/#axss1",
            code_location="document.write stack",
        ),
    ]

    actions: list[str] = []
    results: list[WorkerResult] = []

    def _cloud_payloads(**kwargs):
        feedback = kwargs.get("feedback_lessons")
        phases = kwargs.get("phases")
        if phases:
            actions.append(f"deep:{','.join(phases)}:{kwargs.get('strategy_hint')}")
            return ["dom-deep"]
        actions.append(f"cloud:{0 if not feedback else len(feedback)}")
        if feedback:
            return ["dom-cloud-2"]
        return ["dom-cloud-1"]

    def _attempt_payloads(**kwargs):
        payload = kwargs["payloads"][0]
        actions.append(f"fire:{payload}")
        if payload == "dom-fallback":
            return True, payload, "executed:fallback"
        return False, payload, ""

    with (
        patch("playwright.sync_api.sync_playwright", return_value=_FakePlaywright()),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_parsed_context(url)),
        patch("ai_xss_generator.learning.build_memory_profile", return_value={}),
        patch("ai_xss_generator.lessons.build_mapping_lessons", return_value=[]),
        patch("ai_xss_generator.active.dom_xss.discover_dom_taint_paths", return_value=dom_hits),
        patch("ai_xss_generator.active.dom_xss.attempt_dom_payloads", side_effect=_attempt_payloads),
        patch("ai_xss_generator.active.dom_xss.fallback_payloads_for_sink", return_value=["dom-fallback"]),
        patch("ai_xss_generator.active.worker._get_dom_local_payloads", return_value=[]),
        patch("ai_xss_generator.active.worker._get_dom_cloud_payloads", side_effect=_cloud_payloads),
        patch("ai_xss_generator.active.worker._analyze_fast_failure_strategy", return_value="Try same-tag pivots before full markup."),
        patch("ai_xss_generator.active.worker._DOM_CLOUD_START_AFTER_SECONDS", 0.0),
    ):
        _run_dom(
            url=url,
            waf_hint=None,
            model="qwen3.5",
            cloud_model="anthropic/claude-3-5-sonnet",
            use_cloud=True,
            timeout_seconds=30,
            put_result=results.append,
            dedup_registry={},
            dedup_lock=threading.Lock(),
            auth_headers=None,
            ai_backend="api",
            cli_tool="claude",
            cli_model=None,
            cloud_attempts=2,
        )

    assert actions == [
        "cloud:0",
        "fire:dom-cloud-1",
        "cloud:1",
        "fire:dom-cloud-2",
        "deep:contextual,research:Try same-tag pivots before full markup.",
        "fire:dom-deep",
        "fire:dom-fallback",
    ]
    assert results and results[0].status == "confirmed"
    assert results[0].confirmed_findings[0].source == "phase1_transform"


def test_post_worker_runs_local_model_per_context_before_any_fallback():
    post_form = PostFormTarget(
        action_url="https://example.test/submit",
        source_page_url="https://example.test/form",
        param_names=["q"],
        csrf_field=None,
        hidden_defaults={},
    )
    probe_result = ProbeResult(
        param_name="q",
        original_value="x",
        reflections=[
            ReflectionContext(context_type="html_body", surviving_chars=frozenset({"<", ">"})),
            ReflectionContext(context_type="js_string_dq", surviving_chars=frozenset({'"', ";"})),
        ],
    )

    local_calls: list[str] = []
    fire_calls: list[tuple[str, str]] = []
    results: list[WorkerResult] = []

    class FakeExecutor:
        def __init__(self, auth_headers=None, mode="normal") -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

        def fire_post(self, **kwargs):
            fire_calls.append((kwargs["transform_name"], kwargs["payload"]))
            return SimpleNamespace(
                confirmed=kwargs["payload"] in {"ai-html", "ai-js"},
                method="dialog",
                detail="alert fired",
                transform_name=kwargs["transform_name"],
                payload=kwargs["payload"],
                fired_url=kwargs["action_url"],
            )

    def _local_payloads(**kwargs):
        ctx = kwargs["probe_result"].reflections[0].context_type
        local_calls.append(ctx)
        if ctx == "html_body":
            return ["ai-html"]
        if ctx == "js_string_dq":
            return ["ai-js"]
        return []

    with (
        patch("ai_xss_generator.probe.probe_post_form", return_value=[probe_result]),
        patch("ai_xss_generator.cache.get_probe", return_value=[probe_result]),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_context(post_form.source_page_url)),
        patch("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor),
        patch("ai_xss_generator.active.worker._autodiscover_post_sink_context", return_value=("", None, None)),
        patch(
            "ai_xss_generator.active.transforms.all_variants_for_probe",
            return_value=[
                ("q", "html_body", [TransformVariant("raw", "fallback-html")]),
                ("q", "js_string_dq", [TransformVariant("raw", "fallback-js")]),
            ],
        ),
        patch("ai_xss_generator.active.generator.payloads_for_context", return_value=[]),
        patch("ai_xss_generator.active.generator.mutate_seeds", return_value=[]),
        patch("ai_xss_generator.active.worker._get_local_payloads", side_effect=_local_payloads),
        patch("ai_xss_generator.active.worker._get_cloud_payloads", return_value=[]),
    ):
        _run_post(
            post_form=post_form,
            rate=25.0,
            waf_hint=None,
            model="qwen3.5",
            cloud_model="anthropic/claude-3-5-sonnet",
            use_cloud=True,
            timeout_seconds=30,
            dedup_registry={},
            dedup_lock=threading.Lock(),
            findings_lock=threading.Lock(),
            start_time=time.monotonic(),
            put_result=results.append,
            auth_headers=None,
            crawled_pages=None,
            sink_url=None,
            ai_backend="api",
            cli_tool="claude",
            cli_model=None,
        )

    assert local_calls == ["html_body", "js_string_dq"]
    assert fire_calls == [("local_model", "ai-html"), ("local_model", "ai-js")]
    assert results and results[0].status == "confirmed"
    assert [f.source for f in results[0].confirmed_findings] == ["local_model", "local_model"]


def test_post_worker_retries_cloud_with_feedback_before_fallback():
    post_form = PostFormTarget(
        action_url="https://example.test/submit",
        source_page_url="https://example.test/form",
        param_names=["q"],
        csrf_field=None,
        hidden_defaults={},
    )
    probe_result = ProbeResult(
        param_name="q",
        original_value="x",
        reflections=[
            ReflectionContext(context_type="html_body", surviving_chars=frozenset({"<", ">"})),
        ],
    )

    cloud_feedback_counts: list[int] = []
    fire_calls: list[str] = []
    results: list[WorkerResult] = []

    class FakeExecutor:
        def __init__(self, auth_headers=None, mode="normal") -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

        def fire_post(self, **kwargs):
            fire_calls.append(kwargs["payload"])
            return SimpleNamespace(
                confirmed=kwargs["payload"] == "post-cloud-2",
                method="dialog",
                detail="alert fired" if kwargs["payload"] == "post-cloud-2" else "",
                transform_name=kwargs["transform_name"],
                payload=kwargs["payload"],
                fired_url=kwargs["action_url"],
                error=None,
            )

    def _cloud_payloads(**kwargs):
        feedback = kwargs.get("feedback_lessons")
        cloud_feedback_counts.append(0 if not feedback else len(feedback))
        if feedback:
            return ["post-cloud-2"]
        return ["post-cloud-1"]

    with (
        patch("ai_xss_generator.probe.probe_post_form", return_value=[probe_result]),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_context(post_form.source_page_url)),
        patch("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor),
        patch("ai_xss_generator.active.worker._autodiscover_post_sink_context", return_value=("", None, None)),
        patch(
            "ai_xss_generator.active.transforms.all_variants_for_probe",
            return_value=[("q", "html_body", [TransformVariant("raw", "fallback-html")])],
        ),
        patch("ai_xss_generator.active.generator.payloads_for_context", return_value=[]),
        patch("ai_xss_generator.active.generator.mutate_seeds", return_value=[]),
        patch("ai_xss_generator.active.worker._get_local_payloads", return_value=[]),
        patch("ai_xss_generator.active.worker._get_cloud_payloads", side_effect=_cloud_payloads),
    ):
        _run_post(
            post_form=post_form,
            rate=25.0,
            waf_hint=None,
            model="qwen3.5",
            cloud_model="anthropic/claude-3-5-sonnet",
            use_cloud=True,
            timeout_seconds=30,
            dedup_registry={},
            dedup_lock=threading.Lock(),
            findings_lock=threading.Lock(),
            start_time=time.monotonic(),
            put_result=results.append,
            auth_headers=None,
            crawled_pages=[],
            sink_url=None,
            ai_backend="api",
            cli_tool="claude",
            cli_model=None,
            cloud_attempts=2,
            mode="deep",
        )

    assert cloud_feedback_counts == [0, 1]
    assert fire_calls == ["post-cloud-1", "post-cloud-2"]
    assert results and results[0].status == "confirmed"
    assert results[0].confirmed_findings[0].source == "cloud_model"
    assert "Cloud attempt 2/2." in results[0].confirmed_findings[0].ai_note


def test_post_worker_uses_deterministic_fallback_only_after_local_and_cloud_fail():
    post_form = PostFormTarget(
        action_url="https://example.test/submit",
        source_page_url="https://example.test/form",
        param_names=["q"],
        csrf_field=None,
        hidden_defaults={},
    )
    probe_result = ProbeResult(
        param_name="q",
        original_value="x",
        reflections=[
            ReflectionContext(context_type="html_body", surviving_chars=frozenset({"<", ">"})),
        ],
    )

    actions: list[str] = []
    results: list[WorkerResult] = []

    class FakeExecutor:
        def __init__(self, auth_headers=None, mode="normal") -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

        def fire_post(self, **kwargs):
            actions.append(f"fire:{kwargs['transform_name']}")
            return SimpleNamespace(
                confirmed=kwargs["payload"] == "fallback-html",
                method="dialog",
                detail="alert fired",
                transform_name=kwargs["transform_name"],
                payload=kwargs["payload"],
                fired_url=kwargs["action_url"],
            )

    def _local_payloads(**kwargs):
        ctx = kwargs["probe_result"].reflections[0].context_type
        actions.append(f"local:{ctx}")
        return []

    def _cloud_payloads(**kwargs):
        ctx = kwargs["probe_result"].reflections[0].context_type
        actions.append(f"cloud:{ctx}")
        return []

    with (
        patch("ai_xss_generator.probe.probe_post_form", return_value=[probe_result]),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_context(post_form.source_page_url)),
        patch("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor),
        patch("ai_xss_generator.active.worker._autodiscover_post_sink_context", return_value=("", None, None)),
        patch(
            "ai_xss_generator.active.transforms.all_variants_for_probe",
            return_value=[
                ("q", "html_body", [TransformVariant("raw", "fallback-html")]),
            ],
        ),
        patch("ai_xss_generator.active.generator.payloads_for_context", return_value=[]),
        patch("ai_xss_generator.active.generator.mutate_seeds", return_value=[]),
        patch("ai_xss_generator.active.worker._get_local_payloads", side_effect=_local_payloads),
        patch("ai_xss_generator.active.worker._get_cloud_payloads", side_effect=_cloud_payloads),
    ):
        _run_post(
            post_form=post_form,
            rate=25.0,
            waf_hint=None,
            model="qwen3.5",
            cloud_model="anthropic/claude-3-5-sonnet",
            use_cloud=True,
            timeout_seconds=30,
            dedup_registry={},
            dedup_lock=threading.Lock(),
            findings_lock=threading.Lock(),
            start_time=time.monotonic(),
            put_result=results.append,
            auth_headers=None,
            crawled_pages=None,
            sink_url=None,
            ai_backend="api",
            cli_tool="claude",
            cli_model=None,
            mode="deep",
        )

    assert actions == ["local:html_body", "cloud:html_body", "fire:raw"]
    assert results and results[0].status == "confirmed"
    assert results[0].confirmed_findings[0].source == "phase1_transform"


def test_discover_sink_from_crawled_pages_extracts_context_and_surviving_chars() -> None:
    canary = "axssbeef"
    html = f"<div>{canary}AXSSOP<>AXSSCL</div>"

    class FakeSession:
        def get(self, url, **kwargs):
            return SimpleNamespace(text=html, body=None)

    discovered = _discover_sink_from_crawled_pages(
        FakeSession(),
        canary,
        ["https://example.test/profile"],
        None,
    )

    assert discovered == ("https://example.test/profile", "html_body", "<>")


def test_post_worker_uses_discovered_sink_context_for_generation_and_follow_up() -> None:
    post_form = PostFormTarget(
        action_url="https://example.test/submit",
        source_page_url="https://example.test/form",
        param_names=["q"],
        csrf_field=None,
        hidden_defaults={},
    )
    probe_result = ProbeResult(
        param_name="q",
        original_value="x",
        reflections=[
            ReflectionContext(context_type="html_body", surviving_chars=frozenset({"<", ">"})),
        ],
    )
    sink_reflection = ReflectionContext(
        context_type="js_string_dq",
        surviving_chars=frozenset({'"', ";"}),
    )

    local_calls: list[str] = []
    sink_urls: list[str | None] = []
    results: list[WorkerResult] = []

    class FakeExecutor:
        def __init__(self, auth_headers=None, mode="normal") -> None:
            pass

        def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

        def fire_post(self, **kwargs):
            sink_urls.append(kwargs.get("sink_url"))
            return SimpleNamespace(
                confirmed=kwargs["payload"] == "ai-js",
                method="dialog",
                detail="alert fired",
                transform_name=kwargs["transform_name"],
                payload=kwargs["payload"],
                fired_url=kwargs["action_url"],
                discovered_sink_url="",
            )

    def _local_payloads(**kwargs):
        local_calls.append(kwargs["probe_result"].reflections[0].context_type)
        return ["ai-js"]

    _triage_approve = LocalTriageResult(score=8, should_escalate=True, reason="test approve", context_notes="")

    with (
        patch("ai_xss_generator.probe.probe_post_form", return_value=[probe_result]),
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_context(post_form.source_page_url)),
        patch("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor),
        patch("ai_xss_generator.active.worker._triage_with_local_model", return_value=_triage_approve),
        patch(
            "ai_xss_generator.active.worker._autodiscover_post_sink_context",
            return_value=("https://example.test/profile", sink_reflection, _fake_context("https://example.test/profile")),
        ),
        patch(
            "ai_xss_generator.active.transforms.all_variants_for_probe",
            return_value=[("q", "js_string_dq", [TransformVariant("raw", "fallback-js")])],
        ),
        patch("ai_xss_generator.active.generator.payloads_for_context", return_value=[]),
        patch("ai_xss_generator.active.generator.mutate_seeds", return_value=[]),
        patch("ai_xss_generator.active.worker._get_local_payloads", side_effect=_local_payloads),
        patch("ai_xss_generator.active.worker._get_cloud_payloads", return_value=[]),
    ):
        _run_post(
            post_form=post_form,
            rate=25.0,
            waf_hint=None,
            model="qwen3.5",
            cloud_model="anthropic/claude-3-5-sonnet",
            use_cloud=True,
            timeout_seconds=30,
            dedup_registry={},
            dedup_lock=threading.Lock(),
            findings_lock=threading.Lock(),
            start_time=time.monotonic(),
            put_result=results.append,
            auth_headers=None,
            crawled_pages=["https://example.test/profile"],
            sink_url=None,
            ai_backend="api",
            cli_tool="claude",
            cli_model=None,
            mode="deep",
        )

    assert local_calls == ["js_string_dq"]
    assert sink_urls == ["https://example.test/profile"]
    assert results and results[0].status == "confirmed"
    assert results[0].confirmed_findings[0].source == "local_model"


def test_cli_backend_gets_extended_worker_budget() -> None:
    assert active_worker_timeout_budget(45, True, "api") == 120
    assert active_worker_timeout_budget(45, True, "cli") == 180
    assert active_worker_timeout_budget(45, True, "cli", cloud_attempts=2) == 300


def test_dom_hit_priority_prefers_fragment_before_query_param() -> None:
    hash_hit = DomTaintHit(
        url="https://example.test/#x",
        source_type="fragment",
        source_name="hash",
        sink="document.write",
        canary="axss1",
        canary_url="https://example.test/#axss1",
        code_location="stack",
    )
    query_hit = DomTaintHit(
        url="https://example.test/?q=x",
        source_type="query_param",
        source_name="q",
        sink="document.write",
        canary="axss2",
        canary_url="https://example.test/?q=axss2",
        code_location="stack",
    )

    ordered = sorted([query_hit, hash_hit], key=_dom_hit_priority)

    assert ordered == [hash_hit, query_hit]
