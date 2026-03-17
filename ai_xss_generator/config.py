from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


APP_NAME = "axss"
DEFAULT_MODEL = "qwen3.5:9b"
CONFIG_DIR  = Path.home() / ".axss"
CONFIG_PATH = CONFIG_DIR / "config.json"
KEYS_PATH   = CONFIG_DIR / "keys"


def _strip_json_comments(text: str) -> str:
    out: list[str] = []
    in_string = False
    escape = False
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < length else ""
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            i += 2
            while i < length and text[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i + 1 < length and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i = min(i + 2, length)
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def migrate_config() -> str:
    """Rewrite *CONFIG_PATH* as clean JSON (strips any JSONC comments).

    Returns a human-readable status message describing what was done.
    Safe to call even when the file does not exist yet — in that case a
    minimal default config is written so external tools can parse it.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    if not CONFIG_PATH.exists():
        default: dict[str, Any] = {
            "local_model": DEFAULT_MODEL,
            "enable_remote_escalation": True,
            "ai_backend": "cli",
            "cli_tool": "claude",
            "cli_model": None,
            "cloud_model": "anthropic/claude-3-5-sonnet",
        }
        CONFIG_PATH.write_text(json.dumps(default, indent=2), encoding="utf-8")
        return f"Created default config at {CONFIG_PATH}"

    raw = CONFIG_PATH.read_text(encoding="utf-8")
    stripped = _strip_json_comments(raw)
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError as exc:
        return f"Config parse error after stripping comments: {exc} — file not modified"

    clean = json.dumps(parsed, indent=2, ensure_ascii=False)
    if clean == json.dumps(json.loads(raw), indent=2, ensure_ascii=False) if _is_valid_json(raw) else None:
        return f"{CONFIG_PATH} is already valid JSON — no changes needed"

    CONFIG_PATH.write_text(clean, encoding="utf-8")
    return f"Migrated {CONFIG_PATH} to valid JSON (JSONC comments removed)"


def _is_valid_json(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except json.JSONDecodeError:
        return False


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
class AIRoleConfig:
    backend: str = "cli"
    tool: str = "claude"
    model: str | None = None
    fallback_models: tuple[str, ...] = ()


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
    generation_role: AIRoleConfig = field(default_factory=AIRoleConfig)
    reasoning_role: AIRoleConfig = field(default_factory=AIRoleConfig)
    # Deep mode: reasoning model for strategy analysis before payload generation.
    # Defaults to the same cloud_model. Can be set to a stronger reasoning model
    # (e.g. "openai/o3-mini", "anthropic/claude-opus-4") in advanced config.
    deep_model: str = ""
    # Max injection points to apply deep reasoning to (0 = unlimited).
    # Points are ranked by local triage score; only the top N get --deep treatment.
    deep_limit: int = 0


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
    generation_role: AIRoleConfig = field(default_factory=AIRoleConfig)
    reasoning_role: AIRoleConfig = field(default_factory=AIRoleConfig)
    deep_model: str = ""
    deep_limit: int = 0


def _sanitize_backend(value: Any, default: str = "api") -> str:
    return value if value in ("api", "cli") else default


def _sanitize_tool(value: Any, default: str = "claude") -> str:
    return value if value in ("claude", "codex") else default


def _sanitize_model(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def _sanitize_fallback_models(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    cleaned: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            cleaned.append(item.strip())
    return tuple(cleaned)


def _role_from_config(raw: dict[str, Any], key: str, *, default_backend: str, default_tool: str) -> AIRoleConfig:
    block = raw.get("ai", {})
    role_raw = {}
    if isinstance(block, dict):
        roles_block = block.get("roles", {})
        if isinstance(roles_block, dict):
            maybe_role = roles_block.get(key, {})
            if isinstance(maybe_role, dict):
                role_raw = maybe_role

    if role_raw:
        backend = _sanitize_backend(role_raw.get("backend"), default_backend)
        tool = _sanitize_tool(role_raw.get("tool"), default_tool)
        model = _sanitize_model(role_raw.get("model"))
        fallback_models = _sanitize_fallback_models(role_raw.get("fallback_models", []))
        return AIRoleConfig(
            backend=backend,
            tool=tool,
            model=model,
            fallback_models=fallback_models,
        )

    if key == "generation":
        backend = _sanitize_backend(raw.get("ai_backend", default_backend), default_backend)
        tool = _sanitize_tool(raw.get("xss_generation_model", raw.get("cli_tool", default_tool)), default_tool)
        model = _sanitize_model(raw.get("cli_model")) if backend == "cli" else _sanitize_model(raw.get("cloud_model"))
        fallback_models = _sanitize_fallback_models(raw.get("api_fallback_models", [])) if backend == "api" else ()
        return AIRoleConfig(
            backend=backend,
            tool=tool,
            model=model,
            fallback_models=fallback_models,
        )

    backend = _sanitize_backend(raw.get("ai_backend", default_backend), default_backend)
    tool = _sanitize_tool(raw.get("xss_reasoning_model", raw.get("cli_tool", default_tool)), default_tool)
    model = _sanitize_model(raw.get("cli_model")) if backend == "cli" else _sanitize_model(raw.get("cloud_model"))
    return AIRoleConfig(
        backend=backend,
        tool=tool,
        model=model,
        fallback_models=(),
    )


def _derive_generation_role_from_legacy(config: AppConfig) -> AIRoleConfig:
    backend = _sanitize_backend(config.ai_backend, "api")
    return AIRoleConfig(
        backend=backend,
        tool=_sanitize_tool(config.xss_generation_model or config.cli_tool, "claude"),
        model=config.cli_model if backend == "cli" else config.cloud_model,
        fallback_models=config.api_fallback_models if backend == "api" else (),
    )


def _derive_reasoning_role_from_legacy(config: AppConfig, generation_role: AIRoleConfig) -> AIRoleConfig:
    return AIRoleConfig(
        backend=_sanitize_backend(config.ai_backend, generation_role.backend),
        tool=_sanitize_tool(config.xss_reasoning_model or config.cli_tool, generation_role.tool),
        model=config.cli_model if generation_role.backend == "cli" else config.cloud_model,
        fallback_models=(),
    )


def load_config() -> AppConfig:
    try:
        raw = json.loads(_strip_json_comments(CONFIG_PATH.read_text(encoding="utf-8")))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return AppConfig()

    if not isinstance(raw, dict):
        return AppConfig()

    default_model = raw.get("local_model", raw.get("default_model", DEFAULT_MODEL))
    if not isinstance(default_model, str) or not default_model.strip():
        default_model = DEFAULT_MODEL

    use_cloud = raw.get("enable_remote_escalation", raw.get("use_cloud", True))
    if not isinstance(use_cloud, bool):
        use_cloud = True

    cloud_model = raw.get("cloud_model", "anthropic/claude-3-5-sonnet")
    if not isinstance(cloud_model, str) or not cloud_model.strip():
        cloud_model = "anthropic/claude-3-5-sonnet"

    generation_role = _role_from_config(raw, "generation", default_backend="cli", default_tool="claude")
    reasoning_role = _role_from_config(raw, "reasoning", default_backend="cli", default_tool="claude")

    ai_backend = generation_role.backend
    cli_tool = generation_role.tool
    cli_model = generation_role.model if generation_role.backend == "cli" else _sanitize_model(raw.get("cli_model"))
    api_fallback_models = generation_role.fallback_models or _sanitize_fallback_models(raw.get("api_fallback_models", []))
    xss_generation_model = generation_role.tool
    xss_reasoning_model = reasoning_role.tool

    deep_model = raw.get("deep_model", "")
    if not isinstance(deep_model, str):
        deep_model = ""

    deep_limit_raw = raw.get("deep_limit", 0)
    try:
        deep_limit = max(0, int(deep_limit_raw))
    except (TypeError, ValueError):
        deep_limit = 0

    return AppConfig(
        default_model=default_model.strip(),
        use_cloud=use_cloud,
        cloud_model=cloud_model.strip(),
        api_fallback_models=api_fallback_models,
        ai_backend=ai_backend,
        cli_tool=cli_tool,
        cli_model=cli_model.strip() if cli_model else None,
        xss_generation_model=xss_generation_model,
        xss_reasoning_model=xss_reasoning_model,
        generation_role=generation_role,
        reasoning_role=reasoning_role,
        deep_model=deep_model.strip(),
        deep_limit=deep_limit,
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

    default_role = AIRoleConfig()
    resolved_generation_role = (
        _derive_generation_role_from_legacy(config)
        if config.generation_role == default_role
        else config.generation_role
    )
    resolved_reasoning_role = (
        _derive_reasoning_role_from_legacy(config, resolved_generation_role)
        if config.reasoning_role == default_role
        else config.reasoning_role
    )

    resolved_backend = (
        ai_backend
        or getattr(args, "backend", None)
        or resolved_generation_role.backend
        or config.ai_backend
        or "api"
    )
    resolved_backend = _sanitize_backend(resolved_backend, resolved_generation_role.backend or "api")

    generation_model_candidate = (
        cli_tool
        or getattr(args, "cli_tool", None)
        or resolved_generation_role.tool
        or config.xss_generation_model
        or config.cli_tool
        or "claude"
    )
    resolved_cli_tool = _sanitize_tool(generation_model_candidate, "claude")

    reasoning_model_candidate = (
        resolved_reasoning_role.tool
        if (config.xss_reasoning_model or config.reasoning_role != default_role)
        else resolved_cli_tool
    )
    resolved_reasoning_model = _sanitize_tool(reasoning_model_candidate, resolved_cli_tool)

    resolved_cli_model = cli_model
    if resolved_cli_model is None and args is not None:
        resolved_cli_model = getattr(args, "cli_model", None)
    if resolved_cli_model is None:
        resolved_cli_model = resolved_generation_role.model if resolved_backend == "cli" else config.cli_model
    resolved_cli_model = _sanitize_model(resolved_cli_model)

    resolved_cloud_model = (
        cloud_model
        or (resolved_generation_role.model if resolved_backend == "api" else None)
        or config.cloud_model
        or "anthropic/claude-3-5-sonnet"
    )
    if not isinstance(resolved_cloud_model, str) or not resolved_cloud_model.strip():
        resolved_cloud_model = "anthropic/claude-3-5-sonnet"
    resolved_api_fallback_models = (
        resolved_generation_role.fallback_models
        or tuple(item for item in getattr(config, "api_fallback_models", ()) if isinstance(item, str) and item.strip())
    )

    generation_role = AIRoleConfig(
        backend=resolved_backend,
        tool=resolved_cli_tool if resolved_backend == "cli" else "api",
        model=resolved_cli_model if resolved_backend == "cli" else resolved_cloud_model.strip(),
        fallback_models=resolved_api_fallback_models if resolved_backend == "api" else (),
    )
    reasoning_role = AIRoleConfig(
        backend=resolved_reasoning_role.backend or resolved_backend,
        tool=resolved_reasoning_model if resolved_reasoning_role.backend == "cli" else resolved_reasoning_role.tool,
        model=resolved_reasoning_role.model,
        fallback_models=resolved_reasoning_role.fallback_models,
    )

    # deep_model: CLI arg > config file > fallback to cloud_model
    resolved_deep_model = (
        getattr(args, "deep_model", None)
        or config.deep_model
        or resolved_cloud_model.strip()
    )
    resolved_deep_limit = (
        getattr(args, "deep_limit", None)
        if args is not None and getattr(args, "deep_limit", None) is not None
        else config.deep_limit
    )

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
        generation_role=generation_role,
        reasoning_role=reasoning_role,
        deep_model=resolved_deep_model,
        deep_limit=resolved_deep_limit,
    )
