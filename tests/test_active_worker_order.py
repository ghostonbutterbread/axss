from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

from ai_xss_generator.active.transforms import TransformVariant
from ai_xss_generator.active.worker import WorkerResult, _run, _run_post
from ai_xss_generator.probe import ProbeResult, ReflectionContext
from ai_xss_generator.types import PostFormTarget


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
        def __init__(self, auth_headers=None) -> None:
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
        def __init__(self, auth_headers=None) -> None:
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
        )

    assert actions == ["local:html_body", "cloud:html_body", "fire:raw"]
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
        def __init__(self, auth_headers=None) -> None:
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
        patch("ai_xss_generator.parser.parse_target", return_value=_fake_context(post_form.source_page_url)),
        patch("ai_xss_generator.active.executor.ActiveExecutor", FakeExecutor),
        patch(
            "ai_xss_generator.active.transforms.all_variants_for_probe",
            return_value=[
                ("q", "html_body", [TransformVariant("raw", "fallback-html")]),
                ("q", "js_string_dq", [TransformVariant("raw", "fallback-js")]),
            ],
        ),
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
        def __init__(self, auth_headers=None) -> None:
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
        patch(
            "ai_xss_generator.active.transforms.all_variants_for_probe",
            return_value=[
                ("q", "html_body", [TransformVariant("raw", "fallback-html")]),
            ],
        ),
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
        )

    assert actions == ["local:html_body", "cloud:html_body", "fire:raw"]
    assert results and results[0].status == "confirmed"
    assert results[0].confirmed_findings[0].source == "phase1_transform"
