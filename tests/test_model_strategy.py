from __future__ import annotations

import json

from ai_xss_generator.active.worker import _build_cloud_feedback_lessons
from ai_xss_generator.active.executor import ExecutionResult
from ai_xss_generator.behavior import attach_behavior_profile, build_target_behavior_profile
from ai_xss_generator.models import (
    _cloud_prompt_for_context,
    _generate_with_cli,
    _generation_output_schema,
    _normalize_payloads,
    _prompt_for_generation_phase,
)
from ai_xss_generator.types import ParsedContext
from ai_xss_generator.types import PayloadCandidate


def test_normalize_payloads_keeps_strategy_and_bypass_family() -> None:
    payloads = _normalize_payloads(
        [
            {
                "payload": "<img src=x onerror=alert(1)>",
                "title": "img onerror",
                "explanation": "Fits direct HTML injection.",
                "test_vector": "?q=<img src=x onerror=alert(1)>",
                "tags": ["html", "autofire"],
                "target_sink": "innerHTML",
                "bypass_family": "event-handler-injection",
                "risk_score": 91,
                "strategy": {
                    "attack_family": "html_autofire",
                    "delivery_mode_hint": "query",
                    "encoding_hint": "raw",
                    "session_hint": "same_page",
                    "follow_up_hint": "If raw tags fail, try quote closure or srcdoc pivots.",
                    "coordination_hint": "single_param",
                },
            }
        ],
        source="cli:codex",
    )

    assert len(payloads) == 1
    assert payloads[0].bypass_family == "event-handler-injection"
    assert payloads[0].strategy is not None
    assert payloads[0].strategy.attack_family == "html_autofire"
    assert payloads[0].strategy.follow_up_hint.startswith("If raw tags fail")


def test_normalize_payloads_infers_bypass_family_when_missing() -> None:
    payloads = _normalize_payloads(
        [
            {
                "payload": "javascript:alert(1)",
                "title": "uri",
                "explanation": "URI handler payload.",
                "test_vector": "?redirect=javascript:alert(1)",
                "tags": ["uri"],
                "target_sink": "href",
                "risk_score": 80,
            }
        ],
        source="openrouter",
    )

    assert len(payloads) == 1
    assert payloads[0].bypass_family


def test_cloud_feedback_lessons_include_strategy_shift_constraints() -> None:
    context = ParsedContext(source="https://example.test/login?redirect=x", source_type="url")
    profile = build_target_behavior_profile(
        url=context.source,
        delivery_mode="get",
        waf_name="akamai",
        auth_required=True,
        context=context,
    )
    enriched = attach_behavior_profile(context, profile)
    assert enriched is not None

    lessons = _build_cloud_feedback_lessons(
        attempt_number=1,
        total_attempts=2,
        prompt_context=enriched,
        delivery_mode="get",
        context_type="html_attr_url",
        sink_context="html_attr_url",
        payloads_tried=[
            "javascript:alert(1)",
            "javascript:confirm(1)",
        ],
        duplicate_payloads=["javascript:alert(1)"],
        observation="No dialog, console, or network execution signal fired.",
    )

    assert len(lessons) == 1
    summary = lessons[0].summary
    assert "Do not repeat plain javascript: URIs" in summary
    assert "Do not repeat prior payloads" in summary
    assert "switch attack families" in summary.lower()
    metadata = lessons[0].metadata
    assert "plain_javascript_uri" in metadata["failed_families"]
    assert any("Do not repeat plain javascript: URIs" in item for item in metadata["strategy_constraints"])
    assert any("fragment-only delivery" in item for item in metadata["delivery_constraints"])
    assert "query" in metadata["attempted_delivery_modes"]


def test_cloud_prompt_includes_structured_execution_feedback_profile() -> None:
    context = ParsedContext(source="https://example.test/login?redirect=x", source_type="url")
    profile = build_target_behavior_profile(
        url=context.source,
        delivery_mode="get",
        waf_name="akamai",
        auth_required=True,
        context=context,
    )
    enriched = attach_behavior_profile(context, profile)
    assert enriched is not None
    lessons = _build_cloud_feedback_lessons(
        attempt_number=1,
        total_attempts=2,
        prompt_context=enriched,
        delivery_mode="get",
        context_type="html_attr_url",
        sink_context="html_attr_url",
        payloads_tried=["javascript:alert(1)", "javascript:confirm(1)"],
        duplicate_payloads=["javascript:alert(1)"],
        observation="No dialog, console, or network execution signal fired.",
    )

    prompt = _cloud_prompt_for_context(enriched, past_lessons=lessons, waf="akamai")

    assert "EXECUTION FEEDBACK PROFILE" in prompt
    assert '"failed_families": [' in prompt
    assert '"plain_javascript_uri"' in prompt
    assert '"attempted_delivery_modes": [' in prompt
    assert '"required_strategy_shifts": [' in prompt
    assert '"required_delivery_shifts": [' in prompt
    assert '"creative_techniques": [' in prompt
    assert "Unicode-width variants" in prompt


def test_cloud_feedback_prefers_executed_delivery_history_over_planned_only_modes() -> None:
    context = ParsedContext(source="https://example.test/login?redirect=x", source_type="url")
    profile = build_target_behavior_profile(
        url=context.source,
        delivery_mode="get",
        waf_name="akamai",
        auth_required=True,
        context=context,
    )
    enriched = attach_behavior_profile(context, profile)
    assert enriched is not None
    failed_result = ExecutionResult(
        confirmed=False,
        method="",
        detail="",
        transform_name="cloud_model",
        payload="javascript:alert(1)",
        param_name="redirect",
        fired_url="https://example.test/login?redirect=javascript:alert(1)#frag",
        planned_delivery_modes=["get", "query", "fragment"],
        executed_delivery_modes=["fragment"],
    )

    lessons = _build_cloud_feedback_lessons(
        attempt_number=1,
        total_attempts=2,
        prompt_context=enriched,
        delivery_mode="get",
        context_type="html_attr_url",
        sink_context="html_attr_url",
        payloads_tried=["javascript:alert(1)"],
        execution_results=[failed_result],
        duplicate_payloads=[],
        observation="No dialog, console, or network execution signal fired.",
    )

    assert lessons[0].metadata["attempted_delivery_modes"] == ["fragment"]


def test_cloud_feedback_lessons_capture_edge_blockers_and_delivery_outcomes() -> None:
    context = ParsedContext(source="https://example.test/login?redirect=x", source_type="url")
    profile = build_target_behavior_profile(
        url=context.source,
        delivery_mode="get",
        waf_name="akamai",
        auth_required=True,
        context=context,
    )
    enriched = attach_behavior_profile(context, profile)
    assert enriched is not None

    failed_result = ExecutionResult(
        confirmed=False,
        method="",
        detail="",
        transform_name="cloud_model",
        payload="javascript:alert(1)",
        param_name="redirect",
        fired_url="https://example.test/login?redirect=javascript:alert(1)#frag",
        planned_delivery_modes=["get", "query", "fragment"],
        executed_delivery_modes=["query", "preflight"],
        preflight_attempted=True,
        preflight_succeeded=True,
        follow_up_attempted=True,
        follow_up_succeeded=False,
        edge_signals=["preflight_required", "fragment_dropped", "edge_http2_protocol_error"],
        actual_url="https://example.test/login?redirect=javascript:alert(1)",
        query_preserved=True,
        fragment_preserved=False,
    )

    lessons = _build_cloud_feedback_lessons(
        attempt_number=1,
        total_attempts=2,
        prompt_context=enriched,
        delivery_mode="get",
        context_type="html_attr_url",
        sink_context="html_attr_url",
        payloads_tried=["javascript:alert(1)"],
        execution_results=[failed_result],
        duplicate_payloads=[],
        observation="No dialog, console, or network execution signal fired.",
    )

    metadata = lessons[0].metadata
    assert "fragment_dropped" in metadata["edge_blockers"]
    assert "edge_http2_protocol_error" in metadata["edge_blockers"]
    assert "query_preserved" in metadata["delivery_outcomes"]
    assert "follow_up_blocked" in metadata["delivery_outcomes"]
    assert any("Fragment delivery was not preserved" in item for item in metadata["delivery_constraints"])


def test_cloud_prompt_includes_edge_execution_feedback_details() -> None:
    context = ParsedContext(source="https://example.test/login?redirect=x", source_type="url")
    profile = build_target_behavior_profile(
        url=context.source,
        delivery_mode="get",
        waf_name="akamai",
        auth_required=True,
        context=context,
    )
    enriched = attach_behavior_profile(context, profile)
    assert enriched is not None
    failed_result = ExecutionResult(
        confirmed=False,
        method="",
        detail="",
        transform_name="cloud_model",
        payload="javascript:alert(1)",
        param_name="redirect",
        fired_url="https://example.test/login?redirect=javascript:alert(1)#frag",
        planned_delivery_modes=["get", "query", "fragment"],
        executed_delivery_modes=["query"],
        edge_signals=["fragment_dropped", "edge_http2_protocol_error"],
        actual_url="https://example.test/login?redirect=javascript:alert(1)",
        query_preserved=True,
        fragment_preserved=False,
    )
    lessons = _build_cloud_feedback_lessons(
        attempt_number=1,
        total_attempts=2,
        prompt_context=enriched,
        delivery_mode="get",
        context_type="html_attr_url",
        sink_context="html_attr_url",
        payloads_tried=["javascript:alert(1)"],
        execution_results=[failed_result],
        duplicate_payloads=[],
        observation="No dialog, console, or network execution signal fired.",
    )

    prompt = _cloud_prompt_for_context(enriched, past_lessons=lessons, waf="akamai")
    assert '"edge_blockers": [' in prompt
    assert '"fragment_dropped"' in prompt
    assert '"delivery_outcomes": [' in prompt
    assert '"query_preserved"' in prompt


def test_cloud_feedback_accepts_payload_candidates_for_dom_paths() -> None:
    context = ParsedContext(source="https://example.test/dom#x", source_type="url")
    profile = build_target_behavior_profile(
        url=context.source,
        delivery_mode="dom",
        waf_name="",
        auth_required=False,
        context=context,
    )
    enriched = attach_behavior_profile(context, profile)
    assert enriched is not None

    lessons = _build_cloud_feedback_lessons(
        attempt_number=1,
        total_attempts=2,
        prompt_context=enriched,
        delivery_mode="dom",
        context_type="dom_xss",
        sink_context="document.write",
        payloads_tried=[
            PayloadCandidate(
                payload="'onload='alert(1)",
                title="same-tag",
                explanation="",
                test_vector="#'onload='alert(1)",
                bypass_family="quote_closure",
            ),
            PayloadCandidate(
                payload="'srcdoc='&#x3C;svg/onload=alert(1)&#x3E;'",
                title="srcdoc",
                explanation="",
                test_vector="#'srcdoc='&#x3C;svg/onload=alert(1)&#x3E;'",
                bypass_family="srcdoc_pivot",
            ),
        ],
        duplicate_payloads=[],
        observation="DOM sink stayed taint-only; no execution signal fired.",
    )

    metadata = lessons[0].metadata
    assert "document_write_markup_escape" in metadata["failed_families"]
    assert any("same-tag attribute pivots" in item for item in metadata["strategy_constraints"])


def test_generation_output_schema_scout_is_minimal() -> None:
    schema = _generation_output_schema("scout")
    payload_item = schema["properties"]["payloads"]["items"]

    assert payload_item["required"] == ["payload", "title", "test_vector", "bypass_family"]
    assert "strategy" not in payload_item["properties"]


def test_prompt_for_generation_phase_scout_is_smaller_than_research() -> None:
    context = ParsedContext(source="https://example.test/search?q=x", source_type="url")

    scout = _prompt_for_generation_phase(context, "scout")
    research = _prompt_for_generation_phase(context, "research")

    assert len(scout) < len(research)
    assert "15-25 payloads" not in scout
    assert "Return ONLY strict JSON" in scout


def test_generate_with_cli_escalates_from_scout_to_contextual(monkeypatch) -> None:
    context = ParsedContext(source="https://example.test/search?q=x", source_type="url")
    calls: list[tuple[str, int | None, dict[str, object] | None]] = []

    def fake_generate(tool: str, prompt: str, model: str | None = None, *, timeout_seconds: int | None = None, schema=None):
        calls.append((prompt, timeout_seconds, schema))
        if len(calls) == 1:
            return json.dumps({"payloads": [{"payload": "javascript:1", "title": "weak", "test_vector": "?q=javascript:1", "bypass_family": "weak"}]}), tool
        return json.dumps(
            {
                "payloads": [
                    {
                        "payload": "javascript:alert(1)",
                        "title": "uri",
                        "explanation": "fits href",
                        "test_vector": "?q=javascript:alert(1)",
                        "tags": ["uri"],
                        "target_sink": "href",
                        "bypass_family": "javascript-uri",
                        "risk_score": 80,
                    },
                    {
                        "payload": "java\tscript:alert(1)",
                        "title": "tab uri",
                        "explanation": "fits href",
                        "test_vector": "?q=java%09script:alert(1)",
                        "tags": ["uri"],
                        "target_sink": "href",
                        "bypass_family": "whitespace-in-scheme",
                        "risk_score": 81,
                    },
                    {
                        "payload": "javascript://%0Aalert(1)",
                        "title": "comment",
                        "explanation": "fits href",
                        "test_vector": "?q=javascript://%250Aalert(1)",
                        "tags": ["uri"],
                        "target_sink": "href",
                        "bypass_family": "comment-injection",
                        "risk_score": 79,
                    },
                ]
            }
        ), tool

    monkeypatch.setattr("ai_xss_generator.cli_runner.generate_via_cli_with_tool", fake_generate)
    monkeypatch.setattr(
        "ai_xss_generator.ai_capabilities.recommended_timeout_seconds_for_phase",
        lambda tool, role, phase, fallback, profile="normal": {"scout": 20, "contextual": 45, "research": 90}[phase],
    )

    payloads, actual_tool = _generate_with_cli(context, "claude", None)

    assert actual_tool == "claude"
    assert len(payloads) == 3
    assert len(calls) == 2
    assert calls[0][1] == 20
    assert calls[1][1] == 45
    assert calls[0][2]["properties"]["payloads"]["items"]["required"] == [
        "payload",
        "title",
        "test_vector",
        "bypass_family",
    ]


def test_recommended_timeout_seconds_for_phase_respects_research_profile() -> None:
    from ai_xss_generator.ai_capabilities import recommended_timeout_seconds_for_phase

    normal = recommended_timeout_seconds_for_phase("claude", "xss_payload_generation", "research", 60)
    research = recommended_timeout_seconds_for_phase(
        "claude",
        "xss_payload_generation",
        "research",
        60,
        profile="research",
    )

    assert research > normal
