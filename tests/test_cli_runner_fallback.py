from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from ai_xss_generator.cli_runner import (
    CliInvocationError,
    _trace_preview,
    call_codex,
    generate_via_cli_with_tool,
)
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
    codex.assert_called_once_with("prompt", None, timeout_seconds=None, schema=None)


def test_trace_preview_sanitizes_terminal_controls_and_truncates() -> None:
    preview = _trace_preview("abc\x1b[31mred\x00\n" + ("x" * 5000), limit=12)

    assert "\x1b" not in preview
    assert "\x00" not in preview
    assert "?" in preview
    assert "[truncated" in preview


def test_call_codex_reads_final_message_file(tmp_path) -> None:
    captured = {}

    def _fake_run(cmd, tool, timeout_seconds=None):
        captured["cmd"] = cmd
        out_index = cmd.index("--output-last-message") + 1
        schema_index = cmd.index("--output-schema") + 1
        Path(cmd[out_index]).write_text('{"payloads":[{"payload":"<svg/onload=alert(1)>"}]}', encoding="utf-8")
        assert Path(cmd[schema_index]).exists()
        return ""

    with (
        patch("ai_xss_generator.cli_runner.is_available", return_value=True),
        patch("ai_xss_generator.cli_runner._run", side_effect=_fake_run),
        patch("tempfile.TemporaryDirectory") as tempdir,
    ):
        tempdir.return_value.__enter__.return_value = str(tmp_path)
        tempdir.return_value.__exit__.return_value = False
        raw = call_codex("prompt")

    assert raw == '{"payloads":[{"payload":"<svg/onload=alert(1)>"}]}'
    assert "--output-last-message" in captured["cmd"]
    assert "--output-schema" in captured["cmd"]
    assert "--color" in captured["cmd"]


def test_call_codex_falls_back_to_stdout_when_output_file_empty(tmp_path) -> None:
    def _fake_run(cmd, tool, timeout_seconds=None):
        out_index = cmd.index("--output-last-message") + 1
        Path(cmd[out_index]).write_text("", encoding="utf-8")
        return '{"payloads":[{"payload":"stdout-payload"}]}'

    with (
        patch("ai_xss_generator.cli_runner.is_available", return_value=True),
        patch("ai_xss_generator.cli_runner._run", side_effect=_fake_run),
        patch("tempfile.TemporaryDirectory") as tempdir,
    ):
        tempdir.return_value.__enter__.return_value = str(tmp_path)
        tempdir.return_value.__exit__.return_value = False
        raw = call_codex("prompt")

    assert raw == '{"payloads":[{"payload":"stdout-payload"}]}'


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
    claude.assert_called_once_with("prompt", "claude-opus-4-6", timeout_seconds=None)


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


def test_generate_via_cli_tries_each_tool_once_when_both_fail() -> None:
    with (
        patch(
            "ai_xss_generator.cli_runner.call_claude",
            side_effect=CliInvocationError(
                "claude",
                "claude CLI exited 1: usage limit reached",
                fallback_recommended=True,
            ),
        ) as claude,
        patch(
            "ai_xss_generator.cli_runner.call_codex",
            side_effect=CliInvocationError(
                "codex",
                "codex CLI exited 1: usage exhausted",
                fallback_recommended=True,
            ),
        ) as codex,
    ):
        with pytest.raises(RuntimeError):
            generate_via_cli_with_tool("claude", "prompt")

    claude.assert_called_once_with("prompt", None, timeout_seconds=None)
    codex.assert_called_once_with("prompt", None, timeout_seconds=None, schema=None)


def test_generate_with_cli_labels_payloads_with_actual_fallback_tool() -> None:
    context = ParsedContext(source="https://example.test/?q=x", source_type="url")

    with patch(
        "ai_xss_generator.cli_runner.generate_via_cli_with_tool",
        return_value=(
            '{"payloads":['
            '{"payload":"<img src=x onerror=alert(1)>","title":"img","test_vector":"?q=<img src=x onerror=alert(1)>","bypass_family":"event-handler"},'
            '{"payload":"<svg onload=alert(1)>","title":"svg","test_vector":"?q=<svg onload=alert(1)>","bypass_family":"svg"},'
            '{"payload":"<details open ontoggle=alert(1)>","title":"details","test_vector":"?q=<details open ontoggle=alert(1)>","bypass_family":"event-handler"}'
            ']}',
            "codex",
        ),
    ):
        payloads, actual_tool = _generate_with_cli(
            context=context,
            tool="claude",
            cli_model=None,
        )

    assert actual_tool == "codex"
    assert len(payloads) == 3
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
