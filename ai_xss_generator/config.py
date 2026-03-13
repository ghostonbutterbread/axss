from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


APP_NAME = "axss"
DEFAULT_MODEL = "qwen3.5:9b"
CONFIG_DIR  = Path.home() / ".axss"
CONFIG_PATH = CONFIG_DIR / "config.json"
KEYS_PATH   = CONFIG_DIR / "keys"


def load_api_key(name: str) -> str:
    """Return *name* from ~/.axss/keys, or "" if not present.

    The keys file uses simple KEY=value lines (shell-style, no quotes needed).
    Lines starting with # are comments. Whitespace around = is stripped.

    Example ~/.axss/keys:
        openrouter_api_key = sk-or-v1-...
        openai_api_key     = sk-...
    """
    try:
        text = KEYS_PATH.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return ""
    needle = name.lower().strip()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip().lower() == needle:
            return v.strip()
    return ""


@dataclass(frozen=True)
class AppConfig:
    default_model: str = DEFAULT_MODEL
    # Cloud escalation — set to False to never leave local Ollama.
    # Ignored entirely when no API key (OPENAI_API_KEY / OPENROUTER_API_KEY) is set.
    use_cloud: bool = True
    # Preferred OpenRouter model (only used when ai_backend="api").
    # Example: "anthropic/claude-3-5-sonnet", "google/gemini-2.0-flash-001"
    cloud_model: str = "anthropic/claude-3-5-sonnet"
    # Optional fallback API models to try when the preferred model is not suitable.
    api_fallback_models: tuple[str, ...] = ()
    # Cloud escalation backend: "api" = OpenRouter/OpenAI, "cli" = subprocess CLI.
    ai_backend: str = "api"
    # Which CLI tool to use when ai_backend="cli": "claude" or "codex".
    cli_tool: str = "claude"
    # Model passed to the CLI tool (e.g. "claude-opus-4-6").  None = CLI default.
    cli_model: str | None = None
    # Explicit role split for CLI backends. Values are tool names today.
    xss_generation_model: str | None = None
    xss_reasoning_model: str | None = None


@dataclass(frozen=True)
class ResolvedAIConfig:
    model: str
    use_cloud: bool
    cloud_model: str
    ai_backend: str
    cli_tool: str
    api_fallback_models: tuple[str, ...] = ()
    cli_model: str | None = None
    xss_generation_model: str = "claude"
    xss_reasoning_model: str = "claude"


def load_config() -> AppConfig:
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return AppConfig()

    if not isinstance(raw, dict):
        return AppConfig()

    default_model = raw.get("default_model", DEFAULT_MODEL)
    if not isinstance(default_model, str) or not default_model.strip():
        default_model = DEFAULT_MODEL

    use_cloud = raw.get("use_cloud", True)
    if not isinstance(use_cloud, bool):
        use_cloud = True

    cloud_model = raw.get("cloud_model", "anthropic/claude-3-5-sonnet")
    if not isinstance(cloud_model, str) or not cloud_model.strip():
        cloud_model = "anthropic/claude-3-5-sonnet"

    api_fallback_models_raw = raw.get("api_fallback_models", [])
    api_fallback_models: list[str] = []
    if isinstance(api_fallback_models_raw, list):
        for item in api_fallback_models_raw:
            if isinstance(item, str) and item.strip():
                api_fallback_models.append(item.strip())

    ai_backend = raw.get("ai_backend", "api")
    if ai_backend not in ("api", "cli"):
        ai_backend = "api"

    cli_tool = raw.get("cli_tool", "claude")
    if cli_tool not in ("claude", "codex"):
        cli_tool = "claude"

    cli_model = raw.get("cli_model", None)
    if cli_model is not None and (not isinstance(cli_model, str) or not cli_model.strip()):
        cli_model = None

    xss_generation_model = raw.get("xss_generation_model", None)
    if xss_generation_model is not None and xss_generation_model not in ("claude", "codex"):
        xss_generation_model = None

    xss_reasoning_model = raw.get("xss_reasoning_model", None)
    if xss_reasoning_model is not None and xss_reasoning_model not in ("claude", "codex"):
        xss_reasoning_model = None

    return AppConfig(
        default_model=default_model.strip(),
        use_cloud=use_cloud,
        cloud_model=cloud_model.strip(),
        api_fallback_models=tuple(api_fallback_models),
        ai_backend=ai_backend,
        cli_tool=cli_tool,
        cli_model=cli_model.strip() if cli_model else None,
        xss_generation_model=xss_generation_model,
        xss_reasoning_model=xss_reasoning_model,
    )


def resolve_ai_config(
    config: AppConfig,
    *,
    args: Any | None = None,
    model: str | None = None,
    no_cloud: bool | None = None,
    ai_backend: str | None = None,
    cli_tool: str | None = None,
    cli_model: str | None = None,
    cloud_model: str | None = None,
) -> ResolvedAIConfig:
    """Resolve the effective AI policy once from config plus optional overrides."""
    resolved_model = (
        model
        or getattr(args, "model", None)
        or config.default_model
        or DEFAULT_MODEL
    )
    if not isinstance(resolved_model, str) or not resolved_model.strip():
        resolved_model = DEFAULT_MODEL

    if no_cloud is None:
        no_cloud = bool(getattr(args, "no_cloud", False)) if args is not None else False
    resolved_use_cloud = bool(config.use_cloud) and not bool(no_cloud)

    resolved_cloud_model = cloud_model or config.cloud_model or "anthropic/claude-3-5-sonnet"
    if not isinstance(resolved_cloud_model, str) or not resolved_cloud_model.strip():
        resolved_cloud_model = "anthropic/claude-3-5-sonnet"
    resolved_api_fallback_models = tuple(
        item for item in getattr(config, "api_fallback_models", ()) if isinstance(item, str) and item.strip()
    )

    resolved_backend = ai_backend or getattr(args, "backend", None) or config.ai_backend or "api"
    if resolved_backend not in {"api", "cli"}:
        resolved_backend = "api"

    resolved_cli_tool = (
        cli_tool
        or getattr(args, "cli_tool", None)
        or config.xss_generation_model
        or config.cli_tool
        or "claude"
    )
    if resolved_cli_tool not in {"claude", "codex"}:
        resolved_cli_tool = "claude"

    resolved_reasoning_model = config.xss_reasoning_model or resolved_cli_tool
    if resolved_reasoning_model not in {"claude", "codex"}:
        resolved_reasoning_model = resolved_cli_tool

    resolved_cli_model = cli_model
    if resolved_cli_model is None and args is not None:
        resolved_cli_model = getattr(args, "cli_model", None)
    if resolved_cli_model is None:
        resolved_cli_model = config.cli_model
    if resolved_cli_model is not None:
        if not isinstance(resolved_cli_model, str) or not resolved_cli_model.strip():
            resolved_cli_model = None
        else:
            resolved_cli_model = resolved_cli_model.strip()

    return ResolvedAIConfig(
        model=resolved_model.strip(),
        use_cloud=resolved_use_cloud,
        cloud_model=resolved_cloud_model.strip(),
        api_fallback_models=resolved_api_fallback_models,
        ai_backend=resolved_backend,
        cli_tool=resolved_cli_tool,
        cli_model=resolved_cli_model,
        xss_generation_model=resolved_cli_tool,
        xss_reasoning_model=resolved_reasoning_model,
    )
