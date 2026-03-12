from __future__ import annotations

from unittest.mock import patch

import pytest

from ai_xss_generator.cli_runner import CliInvocationError, generate_via_cli_with_tool
from ai_xss_generator.models import _generate_with_cli, _try_cloud
from ai_xss_generator.types import ParsedContext


def test_generate_via_cli_falls_back_from_claude_to_codex() -> None:
    with (
        patch(
            "ai_xss_generator.cli_runner.call_claude",
            side_effect=CliInvocationError(
                "claude",
                "claude CLI exited 1: usage limit reached",
                fallback_recommended=True,
            ),
        ),
        patch("ai_xss_generator.cli_runner.call_codex", return_value='{"payloads": []}') as codex,
    ):
        raw, tool = generate_via_cli_with_tool("claude", "prompt")

    assert tool == "codex"
    assert raw == '{"payloads": []}'
    codex.assert_called_once_with("prompt", None)


def test_generate_via_cli_falls_back_from_codex_to_claude() -> None:
    with (
        patch(
            "ai_xss_generator.cli_runner.call_codex",
            side_effect=CliInvocationError(
                "codex",
                "codex CLI timed out after 60s",
                fallback_recommended=True,
            ),
        ),
        patch("ai_xss_generator.cli_runner.call_claude", return_value='{"payloads": []}') as claude,
    ):
        raw, tool = generate_via_cli_with_tool("codex", "prompt", "claude-opus-4-6")

    assert tool == "claude"
    assert raw == '{"payloads": []}'
    claude.assert_called_once_with("prompt", "claude-opus-4-6")


def test_generate_via_cli_does_not_fallback_for_non_retryable_failure() -> None:
    with patch(
        "ai_xss_generator.cli_runner.call_claude",
        side_effect=CliInvocationError(
            "claude",
            "claude CLI exited 1: malformed request",
            fallback_recommended=False,
        ),
    ):
        with pytest.raises(CliInvocationError):
            generate_via_cli_with_tool("claude", "prompt")


def test_generate_with_cli_labels_payloads_with_actual_fallback_tool() -> None:
    context = ParsedContext(source="https://example.test/?q=x", source_type="url")

    with patch(
        "ai_xss_generator.cli_runner.generate_via_cli_with_tool",
        return_value=('{"payloads":[{"payload":"<img src=x onerror=alert(1)>"}]}', "codex"),
    ):
        payloads, actual_tool = _generate_with_cli(
            context=context,
            tool="claude",
            cli_model=None,
        )

    assert actual_tool == "codex"
    assert len(payloads) == 1
    assert payloads[0].source == "cli:codex"


def test_try_cloud_reports_actual_cli_tool_after_fallback() -> None:
    context = ParsedContext(source="https://example.test/?q=x", source_type="url")

    with patch(
        "ai_xss_generator.models._generate_with_cli",
        return_value=([], "codex"),
    ):
        payloads, engine = _try_cloud(
            context=context,
            cloud_model="anthropic/claude-3-5-sonnet",
            reference_payloads=None,
            waf=None,
            past_findings=None,
            past_lessons=None,
            ai_backend="cli",
            cli_tool="claude",
            cli_model=None,
        )

    assert payloads == []
    assert engine == "cli:codex"
