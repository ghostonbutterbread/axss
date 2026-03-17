from __future__ import annotations

from unittest.mock import patch

from ai_xss_generator.ai_capabilities import (
    GENERATION_ROLE,
    REASONING_ROLE,
    choose_api_generation_model,
    choose_generation_tool,
    reasoning_role_warning,
    recommended_api_timeout_seconds,
    recommended_timeout_seconds,
    run_api_capability_check,
    run_cli_capability_check,
)


def test_choose_generation_tool_falls_back_when_preferred_fails() -> None:
    with (
        patch(
            "ai_xss_generator.ai_capabilities.get_tool_capability",
            side_effect=[
                {
                    "roles": {
                        GENERATION_ROLE: {"status": "fail", "note": "empty payload list"},
                        REASONING_ROLE: {"status": "pass"},
                    }
                },
                {
                    "roles": {
                        GENERATION_ROLE: {"status": "pass"},
                        REASONING_ROLE: {"status": "pass"},
                    }
                },
            ],
        ),
    ):
        tool, note = choose_generation_tool("codex", auto_check=False)

    assert tool == "claude"
    assert "falling back" in note


def test_choose_api_generation_model_uses_fallback_model() -> None:
    with (
        patch(
            "ai_xss_generator.ai_capabilities.get_api_model_capability",
            side_effect=[
                {"roles": {GENERATION_ROLE: {"status": "fail", "note": "empty payload list"}}},
                {"roles": {GENERATION_ROLE: {"status": "pass"}}},
            ],
        ),
    ):
        model, note = choose_api_generation_model(
            "anthropic/claude-3-5-sonnet",
            fallback_models=("openai/gpt-4.1-mini",),
            auto_check=False,
        )

    assert model == "openai/gpt-4.1-mini"
    assert "falling back" in note


def test_recommended_timeout_helpers_use_cached_suggestion() -> None:
    with (
        patch(
            "ai_xss_generator.ai_capabilities.get_tool_capability",
            return_value=type(
                "Cap",
                (),
                {"roles": {GENERATION_ROLE: {"suggested_timeout_seconds": 75}}},
            )(),
        ),
        patch(
            "ai_xss_generator.ai_capabilities.get_api_model_capability",
            return_value={"roles": {GENERATION_ROLE: {"suggested_timeout_seconds": 95}}},
        ),
    ):
        cli_timeout = recommended_timeout_seconds("claude", GENERATION_ROLE, 60)
        api_timeout = recommended_api_timeout_seconds("anthropic/claude-3-5-sonnet", GENERATION_ROLE, 120)

    assert cli_timeout == 75
    assert api_timeout == 95


def test_run_cli_capability_check_records_pass_states() -> None:
    with (
        patch("ai_xss_generator.ai_capabilities.cli_tool_version", return_value="claude 1.0"),
        patch(
            "ai_xss_generator.ai_capabilities.generate_via_cli_no_fallback",
            return_value=(
                '{"payloads":[{"payload":"<svg/onload=alert(1)>","title":"x","explanation":"x",'
                '"test_vector":"?q=","tags":["x"],"target_sink":"html_body","strategy":'
                '{"attack_family":"event","delivery_mode_hint":"query","encoding_hint":"raw",'
                '"session_hint":"same_page","follow_up_hint":"none","coordination_hint":"single_param"},'
                '"bypass_family":"event-handler-injection","risk_score":90}]}'
            ),
        ),
        patch("ai_xss_generator.ai_capabilities.call_claude", return_value="- quote closure\n- entities\n- scheme tricks"),
        patch("ai_xss_generator.ai_capabilities.save_capability_store"),
        patch("ai_xss_generator.ai_capabilities.load_capability_store", return_value={"tools": {}, "api_models": {}}),
    ):
        capability = run_cli_capability_check("claude", refresh=True)

    assert capability.roles[GENERATION_ROLE]["status"] == "pass"
    assert capability.roles[REASONING_ROLE]["status"] == "pass"


def test_run_api_capability_check_records_fail_for_empty_payloads() -> None:
    with (
        patch("ai_xss_generator.ai_capabilities._call_api_generation", return_value='{"payloads":[]}'),
        patch(
            "ai_xss_generator.ai_capabilities._call_api_reasoning",
            return_value="reasoning output with enough detail",
        ),
        patch("ai_xss_generator.ai_capabilities.save_capability_store"),
        patch("ai_xss_generator.ai_capabilities.load_capability_store", return_value={"tools": {}, "api_models": {}}),
    ):
        capability = run_api_capability_check("anthropic/claude-3-5-sonnet", refresh=True)

    assert capability["roles"][GENERATION_ROLE]["status"] == "fail"
    assert capability["roles"][REASONING_ROLE]["status"] == "pass"


def test_run_cli_capability_check_marks_reasoning_refusal_as_fail() -> None:
    with (
        patch("ai_xss_generator.ai_capabilities.cli_tool_version", return_value="codex 1.0"),
        patch(
            "ai_xss_generator.ai_capabilities.generate_via_cli_no_fallback",
            return_value=(
                '{"payloads":[{"payload":"<svg/onload=alert(1)>","title":"x","explanation":"x",'
                '"test_vector":"?q=","tags":["x"],"target_sink":"html_body","strategy":'
                '{"attack_family":"event","delivery_mode_hint":"query","encoding_hint":"raw",'
                '"session_hint":"same_page","follow_up_hint":"none","coordination_hint":"single_param"},'
                '"bypass_family":"event-handler-injection","risk_score":90}]}'
            ),
        ),
        patch(
            "ai_xss_generator.ai_capabilities.call_codex",
            return_value="I can’t help with XSS exploitation or payload generation.",
        ),
        patch("ai_xss_generator.ai_capabilities.save_capability_store"),
        patch("ai_xss_generator.ai_capabilities.load_capability_store", return_value={"tools": {}, "api_models": {}}),
    ):
        capability = run_cli_capability_check("codex", refresh=True)

    assert capability.roles[REASONING_ROLE]["status"] == "fail"
    assert "policy-blocked" in capability.roles[REASONING_ROLE]["note"]


def test_reasoning_role_warning_reports_failed_reasoning_tool() -> None:
    with patch(
        "ai_xss_generator.ai_capabilities.get_tool_capability",
        return_value={
            "roles": {
                REASONING_ROLE: {
                    "status": "fail",
                    "note": "response appears to be policy-blocked/refused for XSS reasoning",
                }
            }
        },
    ):
        note = reasoning_role_warning(backend="cli", tool="codex", auto_check=False)

    assert "not validated for XSS reasoning" in note
    assert "policy-blocked" in note
