from __future__ import annotations

from ai_xss_generator.behavior import (
    classify_target_disposition,
    derive_ai_escalation_policy,
    attach_behavior_profile,
    build_target_behavior_profile,
    extract_behavior_profile,
)
from ai_xss_generator.lessons import LESSON_TYPE_BEHAVIOR, build_behavior_lessons
from ai_xss_generator.models import _cloud_prompt_for_context
from ai_xss_generator.probe import (
    ProbeResult,
    ReflectionContext,
    _adaptive_probe_plan,
    _probe_seed_for_param,
)
from ai_xss_generator.types import ParsedContext


def test_build_target_behavior_profile_captures_probe_signals() -> None:
    context = ParsedContext(
        source="https://example.test/search?q=x",
        source_type="url",
        frameworks=["react"],
        auth_notes=["Session cookies provided (1 cookie(s))"],
    )
    probe_result = ProbeResult(
        param_name="q",
        original_value="x",
        reflection_transform="upper",
        discovery_style="search_text",
        probe_mode="stealth",
        tested_chars="\"'()",
        reflections=[
            ReflectionContext(
                context_type="html_body",
                surviving_chars=frozenset({"<", ">", "(", ")"}),
            )
        ],
    )

    profile = build_target_behavior_profile(
        url=context.source,
        delivery_mode="get",
        waf_name="akamai",
        auth_required=True,
        context=context,
        probe_results=[probe_result],
    )

    assert profile.browser_required is True
    assert profile.reflected_params == 1
    assert profile.injectable_params == 1
    assert profile.reflection_transforms == ["upper"]
    assert profile.discovery_styles == ["search_text"]
    assert profile.probe_modes == ["stealth"]
    assert profile.tested_charsets == ["\"'()"]
    assert profile.reflection_contexts == ["html_body"]


def test_attach_behavior_profile_makes_prompt_include_behavior_section() -> None:
    context = ParsedContext(
        source="https://example.test/search?q=x",
        source_type="url",
    )
    profile = build_target_behavior_profile(
        url=context.source,
        delivery_mode="get",
        waf_name="cloudflare",
        probe_results=[],
    )
    enriched = attach_behavior_profile(context, profile)

    assert enriched is not None
    extracted = extract_behavior_profile(enriched)
    assert extracted["waf_name"] == "cloudflare"

    prompt = _cloud_prompt_for_context(enriched)
    assert "CONTEXT ENVELOPE" in prompt
    assert "PLANNING ENVELOPE" in prompt
    assert '"browser_required": true' in prompt
    assert '"waf_hint": "cloudflare"' in prompt


def test_dom_cloud_prompt_includes_behavior_profile_section() -> None:
    base = ParsedContext(
        source="https://example.test/target?name=x",
        source_type="url",
        notes=[
            '[dom:TAINT] {"code_location": "line 10", "sink": "innerHTML", "source_name": "name", "source_type": "query_param"}'
        ],
    )
    profile = build_target_behavior_profile(
        url=base.source,
        delivery_mode="dom",
        waf_name="akamai",
        context=base,
    )
    context = attach_behavior_profile(base, profile)

    assert context is not None
    prompt = _cloud_prompt_for_context(context)
    assert "TARGET BEHAVIOR PROFILE" in prompt
    assert '"delivery_mode": "dom"' in prompt


def test_build_behavior_lessons_returns_behavior_lesson() -> None:
    profile = build_target_behavior_profile(
        url="https://example.test/search?q=x",
        delivery_mode="get",
        waf_name="akamai",
        probe_results=[],
    )

    lessons = build_behavior_lessons(profile)

    assert len(lessons) == 1
    assert lessons[0].lesson_type == LESSON_TYPE_BEHAVIOR
    assert "browser-native" in lessons[0].summary


def test_probe_seed_for_param_uses_low_noise_url_like_seed() -> None:
    seed = _probe_seed_for_param("redirect", "axss1234", "")

    assert seed.style == "url_like"
    assert seed.reflection_value == "https://axss.invalid/axss1234"
    assert "axss1234AXSSOP" in seed.char_probe_value


def test_probe_seed_for_param_inserts_markers_before_email_suffix() -> None:
    seed = _probe_seed_for_param("email", "axss1234", "")

    assert seed.style == "email_like"
    assert seed.reflection_value == "axss1234@example.test"
    assert seed.char_probe_value.startswith("axss1234AXSSOP")
    assert seed.char_probe_value.endswith("@example.test")


def test_adaptive_probe_plan_uses_stealth_on_strong_edge_login_paths() -> None:
    plan = _adaptive_probe_plan(
        url="https://example.test/login?redirect=/account",
        waf="akamai",
        auth_headers={"Cookie": "sid=1"},
        param_name="redirect",
        param_count=2,
    )

    assert plan.mode == "stealth"
    assert plan.chars == '"\'()'
    assert plan.follow_up_limit <= 12


def test_escalation_policy_skips_local_for_high_friction_hard_reflection() -> None:
    context = ParsedContext(source="https://example.test/search?q=x", source_type="url")
    profile = build_target_behavior_profile(
        url=context.source,
        delivery_mode="get",
        waf_name="akamai",
        auth_required=True,
        context=context,
        probe_results=[],
    )
    enriched = attach_behavior_profile(context, profile)

    policy = derive_ai_escalation_policy(
        enriched,
        delivery_mode="get",
        context_type="html_attr_url",
    )

    assert policy.use_local is False
    assert "Skipped local model" in policy.note


def test_escalation_policy_skips_local_for_document_write_dom() -> None:
    context = ParsedContext(source="https://example.test/#x", source_type="url")
    profile = build_target_behavior_profile(
        url=context.source,
        delivery_mode="dom",
        waf_name="cloudflare",
        context=context,
    )
    enriched = attach_behavior_profile(context, profile)

    policy = derive_ai_escalation_policy(
        enriched,
        delivery_mode="dom",
        sink_context="document.write",
    )

    assert policy.use_local is False
    assert policy.cloud_start_after_seconds == 0.0


def test_classify_target_disposition_marks_hard_dead_without_reflection() -> None:
    context = ParsedContext(source="https://example.test/search?q=x", source_type="url")
    profile = build_target_behavior_profile(
        url=context.source,
        delivery_mode="get",
        waf_name="akamai",
        context=context,
    )
    enriched = attach_behavior_profile(context, profile)

    disposition = classify_target_disposition(
        enriched,
        delivery_mode="get",
        reflected_params=0,
        injectable_params=0,
    )

    assert disposition.is_dead is True
    assert disposition.tier == "hard_dead"


def test_classify_target_disposition_marks_soft_dead_for_filtered_reflection() -> None:
    context = ParsedContext(source="https://example.test/search?q=x", source_type="url")
    profile = build_target_behavior_profile(
        url=context.source,
        delivery_mode="get",
        waf_name=None,
        context=context,
    )
    enriched = attach_behavior_profile(context, profile)

    disposition = classify_target_disposition(
        enriched,
        delivery_mode="get",
        reflected_params=1,
        injectable_params=0,
    )

    assert disposition.is_dead is True
    assert disposition.tier == "soft_dead"
