from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


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
    # Cloud escalation backend: "api" = OpenRouter/OpenAI, "cli" = subprocess CLI.
    ai_backend: str = "api"
    # Which CLI tool to use when ai_backend="cli": "claude" or "codex".
    cli_tool: str = "claude"
    # Model passed to the CLI tool (e.g. "claude-opus-4-6").  None = CLI default.
    cli_model: str | None = None


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

    ai_backend = raw.get("ai_backend", "api")
    if ai_backend not in ("api", "cli"):
        ai_backend = "api"

    cli_tool = raw.get("cli_tool", "claude")
    if cli_tool not in ("claude", "codex"):
        cli_tool = "claude"

    cli_model = raw.get("cli_model", None)
    if cli_model is not None and (not isinstance(cli_model, str) or not cli_model.strip()):
        cli_model = None

    return AppConfig(
        default_model=default_model.strip(),
        use_cloud=use_cloud,
        cloud_model=cloud_model.strip(),
        ai_backend=ai_backend,
        cli_tool=cli_tool,
        cli_model=cli_model.strip() if cli_model else None,
    )
