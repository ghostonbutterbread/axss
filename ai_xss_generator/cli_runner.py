"""CLI-based AI backends for payload generation.

Invokes the claude or codex CLI tools via subprocess, capturing their output
and parsing XSS payload JSON from the response. This lets axss use
subscription-based inference (Claude Max, ChatGPT Plus) instead of per-token
API billing — no API key needed, just a logged-in CLI installation.

Invocation:
  claude:  claude -p "PROMPT" [--model MODEL]
  codex:   codex exec "PROMPT" --skip-git-repo-check

The prompt asks for the same JSON schema used by the Ollama/API backends so
output parsing (_extract_json_blob + _normalize_payloads) is shared.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)

# Per-call timeout in seconds.  Long enough for extended thinking on hard
# contexts but short enough to not block the scan indefinitely.
CLI_TIMEOUT = 60
_TRACE_PREVIEW_CHARS = 4000

_FALLBACK_ERROR_MARKERS = (
    "timed out",
    "timeout",
    "rate limit",
    "too many requests",
    "quota",
    "usage limit",
    "usage exhausted",
    "usage cap",
    "usage is at 100%",
    "limit reached",
    "credit balance",
    "billing",
    "overloaded",
    "capacity",
    "try again later",
)


class CliInvocationError(RuntimeError):
    """CLI invocation failure with enough metadata to decide on failover."""

    def __init__(self, tool: str, message: str, *, fallback_recommended: bool = False) -> None:
        super().__init__(message)
        self.tool = tool
        self.fallback_recommended = fallback_recommended


def _trace_preview(text: str, limit: int = _TRACE_PREVIEW_CHARS) -> str:
    """Return a terminal-safe preview for -vv tracing."""
    cleaned = text.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", cleaned)
    cleaned = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "?", cleaned)
    if len(cleaned) > limit:
        return cleaned[:limit] + f"\n... [truncated {len(cleaned) - limit} chars]"
    return cleaned


def is_available(tool: str) -> bool:
    """Return True if *tool* is on PATH."""
    return shutil.which(tool) is not None


def _alternate_tool(tool: str) -> str:
    if tool == "claude":
        return "codex"
    if tool == "codex":
        return "claude"
    raise ValueError(f"Unknown CLI tool: {tool!r} — expected 'claude' or 'codex'")


def _is_fallback_worthy_error(message: str) -> bool:
    lowered = message.lower()
    return any(marker in lowered for marker in _FALLBACK_ERROR_MARKERS)


def _run(cmd: list[str], tool: str) -> str:
    """Run *cmd*, return stdout.  Raises RuntimeError on non-zero exit or timeout."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CLI_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise CliInvocationError(
            tool,
            f"{tool} CLI timed out after {CLI_TIMEOUT}s — "
            "try increasing CLI_TIMEOUT or simplify the prompt",
            fallback_recommended=True,
        )
    stdout_preview = _trace_preview(result.stdout or "")
    stderr_preview = _trace_preview(result.stderr or "")
    if stdout_preview:
        log.debug("%s CLI stdout preview:\n%s", tool, stdout_preview)
    if stderr_preview:
        log.debug("%s CLI stderr preview:\n%s", tool, stderr_preview)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[:300]
        raise CliInvocationError(
            tool,
            f"{tool} CLI exited {result.returncode}: {detail}",
            fallback_recommended=_is_fallback_worthy_error(detail),
        )
    return result.stdout


def _codex_output_schema() -> dict[str, object]:
    """JSON Schema for the final Codex message used by payload generation."""
    return {
        "type": "object",
        "properties": {
            "payloads": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "payload": {"type": "string"},
                        "title": {"type": "string"},
                        "explanation": {"type": "string"},
                        "test_vector": {"type": "string"},
                        "tags": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "target_sink": {"type": "string"},
                        "bypass_family": {"type": "string"},
                        "risk_score": {"type": "integer"},
                    },
                    "required": [
                        "payload",
                        "title",
                        "explanation",
                        "test_vector",
                        "tags",
                        "target_sink",
                        "bypass_family",
                        "risk_score",
                    ],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["payloads"],
        "additionalProperties": False,
    }


def call_claude(prompt: str, model: str | None = None) -> str:
    """Run 'claude -p PROMPT [--model MODEL]' and return stdout."""
    if not is_available("claude"):
        raise CliInvocationError(
            "claude",
            "claude CLI not found — install Claude Code: https://claude.ai/code",
            fallback_recommended=True,
        )
    cmd = ["claude", "-p", prompt]
    if model:
        cmd += ["--model", model]
    log.debug("CLI invoke: claude -p <prompt> %s", f"--model {model}" if model else "")
    log.debug("claude CLI prompt preview:\n%s", _trace_preview(prompt))
    return _run(cmd, "claude")


def call_codex(prompt: str, model: str | None = None) -> str:
    """Run 'codex exec PROMPT --skip-git-repo-check' and return stdout.

    The --model flag is not currently supported by the codex CLI; the
    *model* argument is accepted but silently ignored.
    """
    if not is_available("codex"):
        raise CliInvocationError(
            "codex",
            "codex CLI not found — install from: https://github.com/openai/codex",
            fallback_recommended=True,
        )
    if model:
        log.warning(
            "codex CLI does not support model selection; --cli-model %r will be ignored", model
        )
    with tempfile.TemporaryDirectory(prefix="axss-codex-") as tmpdir:
        schema_path = Path(tmpdir) / "payload-schema.json"
        output_path = Path(tmpdir) / "codex-last-message.json"
        schema_path.write_text(json.dumps(_codex_output_schema(), indent=2), encoding="utf-8")
        cmd = [
            "codex",
            "exec",
            prompt,
            "--skip-git-repo-check",
            "--color",
            "never",
            "--output-schema",
            str(schema_path),
            "--output-last-message",
            str(output_path),
        ]
        log.debug(
            "CLI invoke: codex exec <prompt> --skip-git-repo-check --color never "
            "--output-schema <schema> --output-last-message <file>"
        )
        log.debug("codex CLI prompt preview:\n%s", _trace_preview(prompt))
        stdout = _run(cmd, "codex")
        final_message = ""
        try:
            final_message = output_path.read_text(encoding="utf-8").strip()
        except OSError:
            final_message = ""
        if final_message:
            log.debug("codex CLI final message preview:\n%s", _trace_preview(final_message))
            return final_message
        if stdout.strip():
            log.debug("codex CLI falling back to stdout as final message")
            return stdout
        raise CliInvocationError(
            "codex",
            "codex CLI completed but did not produce a final structured message",
            fallback_recommended=False,
        )


def generate_via_cli_with_tool(tool: str, prompt: str, model: str | None = None) -> tuple[str, str]:
    """Dispatch to the correct CLI tool with automatic failover to the alternate CLI."""
    try:
        return generate_via_cli_no_fallback(tool, prompt, model), tool
    except CliInvocationError as exc:
        alt = _alternate_tool(tool)
        if not exc.fallback_recommended:
            raise
        log.warning(
            "CLI backend %s failed in a fallback-worthy way; trying %s instead: %s",
            tool,
            alt,
            exc,
        )
        try:
            return generate_via_cli_no_fallback(alt, prompt, model), alt
        except CliInvocationError as alt_exc:
            raise RuntimeError(
                f"{tool} CLI failed ({exc}); fallback {alt} CLI also failed ({alt_exc})"
            ) from alt_exc


def generate_via_cli_no_fallback(tool: str, prompt: str, model: str | None = None) -> str:
    """Dispatch to the requested CLI tool only, without cross-tool failover."""
    if tool == "claude":
        return call_claude(prompt, model)
    if tool == "codex":
        return call_codex(prompt, model)
    raise ValueError(f"Unknown CLI tool: {tool!r} — expected 'claude' or 'codex'")


def generate_via_cli(tool: str, prompt: str, model: str | None = None) -> str:
    """Dispatch to the correct CLI tool and return raw stdout.

    Args:
        tool:   "claude" or "codex"
        prompt: Full prompt string to pass to the CLI.
        model:  Optional model identifier (e.g. "claude-opus-4-6").
                Passed to claude via --model; ignored for codex.

    Returns:
        Raw text response from the CLI (may contain JSON + surrounding text).

    Raises:
        RuntimeError: if the CLI tool is not found, times out, or exits non-zero.
        ValueError:   if *tool* is not a recognised CLI tool name.
    """
    raw, _ = generate_via_cli_with_tool(tool, prompt, model)
    return raw


def check_cli_tool(tool: str) -> dict[str, str]:
    """Probe a CLI tool and return a status dict for check_api_keys().

    Returned dict has keys: service, source, status, detail.
    """
    path = shutil.which(tool)
    service_name = "Claude CLI" if tool == "claude" else "Codex CLI"
    install_hint = (
        "install Claude Code: https://claude.ai/code"
        if tool == "claude"
        else "install from: https://github.com/openai/codex"
    )
    if not path:
        return {
            "service": service_name,
            "source": "not found",
            "status": "missing",
            "detail": install_hint,
        }
    try:
        result = subprocess.run(
            [tool, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        version = (result.stdout or result.stderr or "").strip().splitlines()
        version_str = version[0] if version else "unknown version"
        return {
            "service": service_name,
            "source": path,
            "status": "ok",
            "detail": version_str,
        }
    except Exception as exc:
        return {
            "service": service_name,
            "source": path,
            "status": "error",
            "detail": str(exc),
        }
