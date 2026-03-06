from __future__ import annotations

import sys

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
    prefix = _c(CYAN, "[*]") if _tty() else "[*]"
    print(f"{prefix} {message}", flush=True)


def success(message: str) -> None:
    """[+] Success — green."""
    prefix = _c(GREEN, "[+]") if _tty() else "[+]"
    print(f"{prefix} {message}", flush=True)


def warn(message: str) -> None:
    """[!] Warning — yellow."""
    prefix = _c(YELLOW, "[!]") if _tty() else "[!]"
    print(f"{prefix} {message}", flush=True)


def error(message: str) -> None:
    """[-] Error — red."""
    prefix = _c(RED, "[-]") if _tty() else "[-]"
    print(f"{prefix} {message}", flush=True)


def info(message: str) -> None:
    """[~] Secondary info — magenta."""
    prefix = _c(MAGENTA, "[~]") if _tty() else "[~]"
    print(f"{prefix} {message}", flush=True)


def header(message: str) -> None:
    """Bold cyan header line."""
    print(_c(BOLD + BRIGHT_CYAN, message), flush=True)


def dim_line(message: str) -> None:
    """Dimmed supporting text."""
    print(_c(DIM, message), flush=True)


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
