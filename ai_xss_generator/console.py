from __future__ import annotations

import io
import sys


def _ensure_utf8() -> None:
    """Re-wrap stdout/stderr with UTF-8 + replace so Unicode payloads never crash."""
    for attr in ("stdout", "stderr"):
        stream = getattr(sys, attr)
        enc = getattr(stream, "encoding", None) or ""
        if hasattr(stream, "buffer") and enc.lower().replace("-", "") != "utf8":
            setattr(sys, attr, io.TextIOWrapper(stream.buffer, encoding="utf-8", errors="replace"))


_ensure_utf8()

# ANSI escape codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"
BRIGHT_RED = "\033[91m"
BRIGHT_GREEN = "\033[92m"
BRIGHT_YELLOW = "\033[93m"
BRIGHT_CYAN = "\033[96m"
WHITE = "\033[37m"


def _tty() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"{code}{text}{RESET}" if _tty() else text


def step(message: str) -> None:
    """[*] Informational progress step — cyan."""
    _before_print()
    prefix = _c(CYAN, "[*]") if _tty() else "[*]"
    print(f"{prefix} {message}", flush=True)
    _after_print()


def success(message: str) -> None:
    """[+] Success — green."""
    _before_print()
    prefix = _c(GREEN, "[+]") if _tty() else "[+]"
    print(f"{prefix} {message}", flush=True)
    _after_print()


def warn(message: str) -> None:
    """[!] Warning — yellow."""
    _before_print()
    prefix = _c(YELLOW, "[!]") if _tty() else "[!]"
    print(f"{prefix} {message}", flush=True)
    _after_print()


def error(message: str) -> None:
    """[-] Error — red."""
    _before_print()
    prefix = _c(RED, "[-]") if _tty() else "[-]"
    print(f"{prefix} {message}", flush=True)
    _after_print()


def info(message: str) -> None:
    """[~] Secondary info — magenta."""
    _before_print()
    prefix = _c(MAGENTA, "[~]") if _tty() else "[~]"
    print(f"{prefix} {message}", flush=True)
    _after_print()


def header(message: str) -> None:
    """Bold cyan header line."""
    _before_print()
    print(_c(BOLD + BRIGHT_CYAN, message), flush=True)
    _after_print()


def dim_line(message: str) -> None:
    """Dimmed supporting text."""
    _before_print()
    print(_c(DIM, message), flush=True)
    _after_print()


def risk_color(score: int) -> str:
    """Return ANSI color code based on risk score (only when TTY)."""
    if not _tty():
        return ""
    if score >= 75:
        return BRIGHT_RED
    if score >= 50:
        return BRIGHT_YELLOW
    return BRIGHT_GREEN


def colorize_score(score: int) -> str:
    """Return score string with risk-appropriate color."""
    color = risk_color(score)
    if color:
        return f"{color}{score}{RESET}"
    return str(score)


def waf_label(name: str) -> str:
    """Magenta WAF name."""
    return _c(MAGENTA + BOLD, name)


# ---------------------------------------------------------------------------
# Persistent status bar — a single line pinned to the current cursor position
# that is erased before any log output and redrawn after.
# ---------------------------------------------------------------------------

_status_text: str = ""
_status_active: bool = False

_SPIN_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _before_print() -> None:
    """Erase the status bar line so the upcoming print lands cleanly."""
    if _status_active and _tty():
        sys.stdout.write("\r\033[2K")
        # No explicit flush — the print() call flushes immediately after.


def _after_print() -> None:
    """Redraw the status bar after a log line has been emitted."""
    if _status_active and _status_text and _tty():
        sys.stdout.write(_status_text)
        sys.stdout.flush()


def set_status_bar(text: str) -> None:
    """Activate the status bar and render *text* on the current line."""
    global _status_text, _status_active
    _status_active = True
    _status_text = text
    if _tty():
        sys.stdout.write("\r\033[2K" + text)
        sys.stdout.flush()


def update_status_bar(text: str) -> None:
    """Overwrite the status bar text in-place."""
    global _status_text
    _status_text = text
    if _status_active and _tty():
        sys.stdout.write("\r\033[2K" + text)
        sys.stdout.flush()


def clear_status_bar() -> None:
    """Erase the status bar line and deactivate it."""
    global _status_active, _status_text
    if _tty() and _status_active:
        sys.stdout.write("\r\033[2K")
        sys.stdout.flush()
    _status_active = False
    _status_text = ""


def fmt_duration(seconds: float) -> str:
    """Return MM:SS string for *seconds*."""
    m = int(seconds) // 60
    s = int(seconds) % 60
    return f"{m:02d}:{s:02d}"


def spin_char(tick: int) -> str:
    """Return the spinner character for *tick*."""
    return _SPIN_FRAMES[tick % len(_SPIN_FRAMES)]
