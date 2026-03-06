from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


APP_NAME = "axss"
DEFAULT_MODEL = "qwen2.5-coder:7b-instruct-q5_K_M"
CONFIG_DIR = Path.home() / ".axss"
CONFIG_PATH = CONFIG_DIR / "config.json"


@dataclass(frozen=True)
class AppConfig:
    default_model: str = DEFAULT_MODEL


def load_config() -> AppConfig:
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return AppConfig()

    default_model = raw.get("default_model", DEFAULT_MODEL) if isinstance(raw, dict) else DEFAULT_MODEL
    if not isinstance(default_model, str) or not default_model.strip():
        default_model = DEFAULT_MODEL
    return AppConfig(default_model=default_model.strip())
