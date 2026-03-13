from __future__ import annotations

from ai_xss_generator.active.worker import _build_cloud_feedback_lessons
from ai_xss_generator.behavior import attach_behavior_profile, build_target_behavior_profile
from ai_xss_generator.models import _cloud_prompt_for_context, _normalize_payloads
from ai_xss_generator.types import ParsedContext


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
