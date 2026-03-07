from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


APP_NAME = "axss"
DEFAULT_MODEL = "qwen3.5:9b"
CONFIG_DIR = Path.home() / ".axss"
CONFIG_PATH = CONFIG_DIR / "config.json"


@dataclass(frozen=True)
class AppConfig:
    default_model: str = DEFAULT_MODEL
    # Cloud escalation — set to False to never leave local Ollama.
    # Ignored entirely when no API key (OPENAI_API_KEY / OPENROUTER_API_KEY) is set.
    use_cloud: bool = True
    # Preferred OpenRouter model (only used when OPENROUTER_API_KEY is set).
    # Example: "anthropic/claude-3-5-sonnet", "google/gemini-2.0-flash-001"
    cloud_model: str = "anthropic/claude-3-5-sonnet"


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

    return AppConfig(
        default_model=default_model.strip(),
        use_cloud=use_cloud,
        cloud_model=cloud_model.strip(),
    )
