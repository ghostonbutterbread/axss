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

import logging
import shutil
import subprocess

log = logging.getLogger(__name__)

# Per-call timeout in seconds.  Long enough for extended thinking on hard
# contexts but short enough to not block the scan indefinitely.
CLI_TIMEOUT = 60


def is_available(tool: str) -> bool:
    """Return True if *tool* is on PATH."""
    return shutil.which(tool) is not None


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
        raise RuntimeError(
            f"{tool} CLI timed out after {CLI_TIMEOUT}s — "
            "try increasing CLI_TIMEOUT or simplify the prompt"
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[:300]
        raise RuntimeError(f"{tool} CLI exited {result.returncode}: {detail}")
    return result.stdout


def call_claude(prompt: str, model: str | None = None) -> str:
    """Run 'claude -p PROMPT [--model MODEL]' and return stdout."""
    if not is_available("claude"):
        raise RuntimeError(
            "claude CLI not found — install Claude Code: https://claude.ai/code"
        )
    cmd = ["claude", "-p", prompt]
    if model:
        cmd += ["--model", model]
    log.debug("CLI invoke: claude -p <prompt> %s", f"--model {model}" if model else "")
    return _run(cmd, "claude")


def call_codex(prompt: str, model: str | None = None) -> str:
    """Run 'codex exec PROMPT --skip-git-repo-check' and return stdout.

    The --model flag is not currently supported by the codex CLI; the
    *model* argument is accepted but silently ignored.
    """
    if not is_available("codex"):
        raise RuntimeError(
            "codex CLI not found — install from: https://github.com/openai/codex"
        )
    cmd = ["codex", "exec", prompt, "--skip-git-repo-check"]
    log.debug("CLI invoke: codex exec <prompt> --skip-git-repo-check")
    return _run(cmd, "codex")


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
    if tool == "claude":
        return call_claude(prompt, model)
    if tool == "codex":
        return call_codex(prompt, model)
    raise ValueError(f"Unknown CLI tool: {tool!r} — expected 'claude' or 'codex'")


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
