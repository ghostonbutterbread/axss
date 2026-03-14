from __future__ import annotations

import json
from types import SimpleNamespace

from ai_xss_generator.active.worker import _build_cloud_feedback_lessons
from ai_xss_generator.active.executor import ExecutionResult
from ai_xss_generator.behavior import attach_behavior_profile, build_target_behavior_profile
from ai_xss_generator.findings import Finding
from ai_xss_generator.models import (
    _cloud_prompt_for_context,
    _generate_with_cli,
    _generation_output_schema,
    _normalize_payloads,
    _prompt_for_generation_phase,
)
from ai_xss_generator.payloads import BASE_PAYLOADS, _match_payloads_to_context
from ai_xss_generator.probe import ProbeResult
from ai_xss_generator.probe import ReflectionContext
from ai_xss_generator.probe import enrich_context
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

    assert "CONTEXT ENVELOPE" in prompt
    assert "PLANNING ENVELOPE" in prompt
    assert "FAILURE ENVELOPE" in prompt
    assert '"failed_families": [' in prompt
    assert '"plain_javascript_uri"' in prompt
    assert '"attempted_delivery_modes": [' in prompt
    assert '"required_strategy_shifts": [' in prompt
    assert '"required_delivery_shifts": [' in prompt
    assert '"observed_blockers": [' in prompt
    assert "Unicode-width variants" in prompt
    assert "Full parsed context" not in prompt


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


def test_generation_phase_prompts_use_envelopes_instead_of_full_context_blob() -> None:
    context = ParsedContext(source="https://example.test/search?q=x", source_type="url")

    scout = _prompt_for_generation_phase(context, "scout")
    research = _prompt_for_generation_phase(context, "research")

    assert "CONTEXT ENVELOPE" in scout
    assert "PLANNING ENVELOPE" in scout
    assert "CONTEXT ENVELOPE" in research
    assert "PLANNING ENVELOPE" in research
    assert "SUPPLEMENTAL CONTEXT" not in research


def test_match_payloads_to_context_prefers_url_shaped_payloads() -> None:
    matched = _match_payloads_to_context(BASE_PAYLOADS, "html_attr_url", ":()/")

    assert matched
    assert all(any(tag in {"uri", "protocol", "href", "case-variant"} for tag in payload.tags) for payload in matched[:3])


def test_contextual_prompt_prioritizes_success_and_similar_findings() -> None:
    context = ParsedContext(
        source="https://example.test/login?redirect=x",
        source_type="url",
        notes=["[probe:CONFIRMED] 'redirect' -> html_attr_url surviving=':()/;'"],
    )
    past_findings = [
        Finding(
            sink_type="href",
            context_type="html_attr_url",
            surviving_chars=":()/;",
            bypass_family="whitespace-in-scheme",
            payload="java\tscript:alert(1)",
            explanation="Browsers normalize embedded ASCII tab before resolving the scheme.",
        ),
        Finding(
            sink_type="html",
            context_type="html_body",
            surviving_chars="<>",
            bypass_family="event-handler-injection",
            payload="<img src=x onerror=alert(1)>",
            explanation="Raw HTML executes when inserted into the document body.",
        ),
    ]
    past_lessons = [
        SimpleNamespace(
            lesson_type="execution_feedback",
            metadata={
                "execution_confirmed": True,
                "payload": "javascript:alert(1)",
                "bypass_family": "case-variant",
            }
        ),
        SimpleNamespace(
            lesson_type="execution_feedback",
            metadata={
                "failed_families": ["plain_javascript_uri"],
                "attempted_delivery_modes": ["query"],
                "observation": "No dialog, console, or network execution signal fired.",
            }
        ),
    ]

    prompt = _prompt_for_generation_phase(
        context,
        "contextual",
        past_findings=past_findings,
        past_lessons=past_lessons,
    )

    assert "PAYLOADS THAT EXECUTED - generate similar techniques but NOT identical:" in prompt
    assert "PAYLOADS THAT EXECUTED IN SIMILAR CONTEXTS (use as inspiration, mutate don't copy):" in prompt
    assert '"context_type": "html_attr_url"' in prompt
    assert '"why_it_works": "Browsers normalize embedded ASCII tab before resolving the scheme."' in prompt
    assert prompt.index("PAYLOADS THAT EXECUTED - generate similar techniques but NOT identical:") < prompt.index("FAILURE ENVELOPE")


def test_scout_prompt_uses_reference_payloads_as_seed_examples() -> None:
    context = ParsedContext(
        source="https://example.test/login?redirect=x",
        source_type="url",
        notes=["[probe:CONFIRMED] 'redirect' -> html_attr_url surviving=':()/;'"],
    )
    reference_payloads = [
        PayloadCandidate(
            payload="javascript:confirm(1)",
            title="confirmed uri",
            explanation="",
            test_vector="?redirect=javascript:confirm(1)",
            tags=["uri"],
            bypass_family="case-variant",
        )
    ]

    prompt = _prompt_for_generation_phase(
        context,
        "scout",
        reference_payloads=reference_payloads,
    )

    assert "SEED PAYLOADS (mutate, do not copy):" in prompt
    assert '"payload": "javascript:confirm(1)"' in prompt


def test_enrich_context_writes_reflected_subcontext_note() -> None:
    context = ParsedContext(source="https://example.test/page?next=x", source_type="url")

    enriched = enrich_context(
        context,
        [
            ProbeResult(
                param_name="next",
                original_value="x",
                probe_mode="standard",
                tested_chars="<>'\"",
                reflections=[
                    ReflectionContext(
                        context_type="html_attr_url",
                        attr_name="href",
                        tag_name="a",
                        quote_style="double",
                        html_subcontext="double_quoted_url_attr",
                        attacker_prefix='<a href="',
                        attacker_suffix='">Continue</a>',
                        payload_shape="scheme_or_quote_closure",
                        subcontext_explanation="Reflection is inside a double-quoted href attribute on <a>.",
                        evidence_confidence=0.96,
                        surviving_chars=frozenset({":", "/", '"'}),
                        snippet='<a href="axss123">Continue</a>',
                    )
                ],
            )
        ],
    )

    assert any(note.startswith("[probe:SUBCONTEXT] ") for note in enriched.notes)


def test_reflected_prompt_envelope_includes_reflected_subcontext() -> None:
    base = ParsedContext(source="https://example.test/page?next=x", source_type="url")
    enriched = enrich_context(
        base,
        [
            ProbeResult(
                param_name="next",
                original_value="x",
                probe_mode="standard",
                tested_chars="<>'\"",
                reflections=[
                    ReflectionContext(
                        context_type="html_attr_url",
                        attr_name="href",
                        tag_name="a",
                        quote_style="double",
                        html_subcontext="double_quoted_url_attr",
                        attacker_prefix='<a class="cta" href="',
                        attacker_suffix='">Continue</a>',
                        payload_shape="scheme_or_quote_closure",
                        subcontext_explanation="Reflection is inside a double-quoted href attribute on <a>.",
                        evidence_confidence=0.96,
                        surviving_chars=frozenset({":", "/", '"'}),
                        snippet='<a class="cta" href="axss123">Continue</a>',
                    )
                ],
            )
        ],
    )

    prompt = _prompt_for_generation_phase(enriched, "contextual")

    assert '"reflected_subcontext": {' in prompt
    assert '"tag_name": "a"' in prompt
    assert '"attr_name": "href"' in prompt
    assert '"quote_style": "double"' in prompt
    assert '"html_subcontext": "double_quoted_url_attr"' in prompt
    assert '"payload_shape": "scheme_or_quote_closure"' in prompt


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
