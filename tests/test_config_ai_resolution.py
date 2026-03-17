from __future__ import annotations

from types import SimpleNamespace

from ai_xss_generator import config as config_module
from ai_xss_generator.config import AIRoleConfig, AppConfig, DEFAULT_MODEL, load_config, resolve_ai_config


def test_resolve_ai_config_uses_config_defaults() -> None:
    config = AppConfig(
        default_model="qwen3.5:27b",
        use_cloud=True,
        cloud_model="anthropic/claude-3-7-sonnet",
        api_fallback_models=("openai/gpt-4.1-mini",),
        ai_backend="cli",
        cli_tool="codex",
        cli_model="gpt-5-codex",
        xss_generation_model="codex",
        xss_reasoning_model="claude",
    )

    resolved = resolve_ai_config(config)

    assert resolved.model == "qwen3.5:27b"
    assert resolved.use_cloud is True
    assert resolved.cloud_model == "anthropic/claude-3-7-sonnet"
    assert resolved.api_fallback_models == ("openai/gpt-4.1-mini",)
    assert resolved.ai_backend == "cli"
    assert resolved.cli_tool == "codex"
    assert resolved.cli_model == "gpt-5-codex"
    assert resolved.xss_generation_model == "codex"
    assert resolved.xss_reasoning_model == "claude"
    assert resolved.generation_role.tool == "codex"
    assert resolved.reasoning_role.tool == "claude"


def test_resolve_ai_config_applies_args_overrides() -> None:
    config = AppConfig(
        default_model="qwen3.5:9b",
        use_cloud=True,
        cloud_model="anthropic/claude-3-5-sonnet",
        api_fallback_models=(),
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
    assert resolved.xss_generation_model == "codex"
    assert resolved.xss_reasoning_model == "codex"
    assert resolved.generation_role.tool == "codex"


def test_resolve_ai_config_sanitizes_invalid_values() -> None:
    config = AppConfig(
        default_model="",
        use_cloud=True,
        cloud_model="",
        api_fallback_models=(),
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


def test_resolve_ai_config_prefers_nested_role_config() -> None:
    config = AppConfig(
        default_model="qwen3.5:9b",
        use_cloud=True,
        cloud_model="anthropic/legacy-should-not-win",
        ai_backend="cli",
        cli_tool="codex",
        cli_model="legacy-model",
        generation_role=AIRoleConfig(
            backend="api",
            tool="api",
            model="anthropic/claude-3-5-sonnet",
            fallback_models=("openai/gpt-4.1-mini",),
        ),
        reasoning_role=AIRoleConfig(
            backend="cli",
            tool="codex",
            model="gpt-5-codex",
        ),
    )

    resolved = resolve_ai_config(config)

    assert resolved.ai_backend == "api"
    assert resolved.cloud_model == "anthropic/claude-3-5-sonnet"
    assert resolved.api_fallback_models == ("openai/gpt-4.1-mini",)
    assert resolved.generation_role.backend == "api"
    assert resolved.reasoning_role.tool == "codex"


def test_load_config_accepts_comments_and_new_key_names(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        """
        {
          // Local-only fallback model
          "local_model": "qwen3.5:27b",
          "enable_remote_escalation": false,
          "ai_backend": "cli",
          "cli_tool": "claude",
          "cli_model": null,
          "cloud_model": "anthropic/claude-3-5-sonnet"
        }
        """,
        encoding="utf-8",
    )
    monkeypatch.setattr(config_module, "CONFIG_PATH", config_path)

    loaded = load_config()

    assert loaded.default_model == "qwen3.5:27b"
    assert loaded.use_cloud is False
    assert loaded.ai_backend == "cli"
    assert loaded.cli_tool == "claude"


def test_load_config_accepts_advanced_role_jsonc(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        """
        {
          "local_model": "qwen3.5:9b",
          "enable_remote_escalation": true,
          "ai": {
            "roles": {
              "generation": {
                "backend": "cli",
                "tool": "claude",
                "model": null,
                "fallback_models": []
              },
              "reasoning": {
                "backend": "cli",
                "tool": "codex",
                "model": null,
                "fallback_models": []
              }
            }
          }
        }
        """,
        encoding="utf-8",
    )
    monkeypatch.setattr(config_module, "CONFIG_PATH", config_path)

    loaded = load_config()

    assert loaded.default_model == "qwen3.5:9b"
    assert loaded.use_cloud is True
    assert loaded.generation_role.tool == "claude"
    assert loaded.reasoning_role.tool == "codex"
