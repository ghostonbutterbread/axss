from __future__ import annotations

from types import SimpleNamespace

from ai_xss_generator.config import AppConfig, DEFAULT_MODEL, resolve_ai_config


def test_resolve_ai_config_uses_config_defaults() -> None:
    config = AppConfig(
        default_model="qwen3.5:27b",
        use_cloud=True,
        cloud_model="anthropic/claude-3-7-sonnet",
        ai_backend="cli",
        cli_tool="codex",
        cli_model="gpt-5-codex",
    )

    resolved = resolve_ai_config(config)

    assert resolved.model == "qwen3.5:27b"
    assert resolved.use_cloud is True
    assert resolved.cloud_model == "anthropic/claude-3-7-sonnet"
    assert resolved.ai_backend == "cli"
    assert resolved.cli_tool == "codex"
    assert resolved.cli_model == "gpt-5-codex"


def test_resolve_ai_config_applies_args_overrides() -> None:
    config = AppConfig(
        default_model="qwen3.5:9b",
        use_cloud=True,
        cloud_model="anthropic/claude-3-5-sonnet",
        ai_backend="api",
        cli_tool="claude",
        cli_model=None,
    )
    args = SimpleNamespace(
        model="qwen3.5:4b",
        no_cloud=True,
        backend="cli",
        cli_tool="codex",
        cli_model="gpt-5-codex-mini",
    )

    resolved = resolve_ai_config(config, args=args)

    assert resolved.model == "qwen3.5:4b"
    assert resolved.use_cloud is False
    assert resolved.ai_backend == "cli"
    assert resolved.cli_tool == "codex"
    assert resolved.cli_model == "gpt-5-codex-mini"


def test_resolve_ai_config_sanitizes_invalid_values() -> None:
    config = AppConfig(
        default_model="",
        use_cloud=True,
        cloud_model="",
        ai_backend="api",
        cli_tool="claude",
        cli_model=None,
    )
    args = SimpleNamespace(
        model="",
        no_cloud=False,
        backend="bogus",
        cli_tool="wrong",
        cli_model=" ",
    )

    resolved = resolve_ai_config(config, args=args)

    assert resolved.model == DEFAULT_MODEL
    assert resolved.cloud_model == "anthropic/claude-3-5-sonnet"
    assert resolved.ai_backend == "api"
    assert resolved.cli_tool == "claude"
    assert resolved.cli_model is None
