from __future__ import annotations

import io
import shutil
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


# Global verbosity level — 0=normal, 1=-v, 2=-vv
# Set once in main() before spawning workers (inherited via fork on Linux).
VERBOSE_LEVEL: int = 0


def set_verbose_level(level: int) -> None:
    global VERBOSE_LEVEL
    VERBOSE_LEVEL = level


def _tty() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def dynamic_ui_enabled() -> bool:
    """True when status bars and pinned panels are safe to render."""
    return _tty() and VERBOSE_LEVEL < 2


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


def debug(message: str) -> None:
    """[.] Trace output — only printed at -vv (VERBOSE_LEVEL >= 2)."""
    if VERBOSE_LEVEL < 2:
        return
    _before_print()
    prefix = _c(DIM, "[.]") if _tty() else "[.]"
    print(f"{prefix} {message}", flush=True)
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
# Used during the crawl phase.
# ---------------------------------------------------------------------------

_status_text: str = ""
_status_active: bool = False

_SPIN_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _before_print() -> None:
    """Erase the status bar line so the upcoming print lands cleanly."""
    if _panel_active:
        return  # scroll region keeps panel pinned — nothing to erase
    if _status_active and dynamic_ui_enabled():
        sys.stdout.write("\r\033[2K")
        # No explicit flush — the print() call flushes immediately after.


def _after_print() -> None:
    """Redraw the status bar / panel after a log line has been emitted."""
    if _panel_active:
        _redraw_panel()
        return
    if _status_active and _status_text and dynamic_ui_enabled():
        sys.stdout.write(_status_text)
        sys.stdout.flush()


def set_status_bar(text: str) -> None:
    """Activate the status bar and render *text* on the current line."""
    global _status_text, _status_active
    _status_active = True
    _status_text = text
    if dynamic_ui_enabled():
        sys.stdout.write("\r\033[2K" + text)
        sys.stdout.flush()


def update_status_bar(text: str) -> None:
    """Overwrite the status bar text in-place."""
    global _status_text
    _status_text = text
    if _status_active and dynamic_ui_enabled():
        sys.stdout.write("\r\033[2K" + text)
        sys.stdout.flush()


def clear_status_bar() -> None:
    """Erase the status bar line and deactivate it."""
    global _status_active, _status_text
    if dynamic_ui_enabled() and _status_active:
        sys.stdout.write("\r\033[2K")
        sys.stdout.flush()
    _status_active = False
    _status_text = ""


# ---------------------------------------------------------------------------
# Multi-line progress panel — scroll-region–based, used during active scan.
#
# Reserves _PANEL_LINES rows at the bottom of the terminal using an ANSI
# scroll region so all log output scrolls naturally above the panel without
# ever pushing into it.  The three panel rows are:
#
#   row -2  ──── separator ────
#   row -1  [████░░░░] 48%  24/50  02:14 elapsed  ETA 02:23
#   row  0  GET● POST● idle○  │  ✓ 3 confirmed  │  /api/users?role=admin
# ---------------------------------------------------------------------------

_PANEL_LINES: int = 3  # separator + progress bar + workers row

_panel_active: bool = False
_panel_content: list[str] = ["", "", ""]  # current rendered strings for each row


def _term_rows_cols() -> tuple[int, int]:
    sz = shutil.get_terminal_size(fallback=(80, 24))
    return sz.lines, sz.columns


def _redraw_panel() -> None:
    """Internal: repaint panel rows from _panel_content without updating content."""
    if not _panel_active or not dynamic_ui_enabled():
        return
    rows, _ = _term_rows_cols()
    out = ["\033[s"]  # save cursor
    for i, line in enumerate(_panel_content):
        row = rows - _PANEL_LINES + 1 + i
        out.append(f"\033[{row};1H\033[2K{line}")
    out.append("\033[u")  # restore cursor
    sys.stdout.write("".join(out))
    sys.stdout.flush()


def setup_panel() -> None:
    """Lock the scroll region and reserve _PANEL_LINES rows at the bottom.

    Call once before the active scan loop begins.  All subsequent print()
    calls stay within the scroll region and never touch the panel rows.
    """
    global _panel_active, _panel_content
    if not dynamic_ui_enabled():
        return
    rows, _ = _term_rows_cols()
    scroll_bottom = rows - _PANEL_LINES
    _panel_active = True
    _panel_content = ["", "", ""]
    out = [
        f"\033[1;{scroll_bottom}r",   # set scroll region rows 1..scroll_bottom
        "\033[?7l",                   # disable auto-wrap on the panel rows
    ]
    # Clear the reserved panel rows
    for r in range(rows - _PANEL_LINES + 1, rows + 1):
        out.append(f"\033[{r};1H\033[2K")
    out.append("\033[1;1H")           # cursor to top of scroll region
    sys.stdout.write("".join(out))
    sys.stdout.flush()


def update_panel(sep: str, bar: str, workers: str) -> None:
    """Update panel content and repaint.  Call from the orchestrator loop."""
    global _panel_content
    if not dynamic_ui_enabled():
        return
    _panel_content = [sep, bar, workers]
    _redraw_panel()


def teardown_panel() -> None:
    """Clear the panel and restore the full scroll region.

    Call in the finally block after the active scan loop exits.
    """
    global _panel_active, _panel_content
    if not dynamic_ui_enabled() or not _panel_active:
        _panel_active = False
        return
    rows, _ = _term_rows_cols()
    out = []
    # Clear each panel row via absolute positioning (no save/restore needed).
    for r in range(rows - _PANEL_LINES + 1, rows + 1):
        out.append(f"\033[{r};1H\033[2K")
    # Restore the full scroll region BEFORE repositioning the cursor.
    # Setting \033[r homes the cursor on many terminals, so we always
    # follow it with an explicit absolute move rather than relying on
    # \033[u to put us somewhere sensible.
    out.append(f"\033[1;{rows}r")    # restore full scroll region
    out.append("\033[?7h")           # re-enable auto-wrap
    # Land the cursor at the bottom of the log area so subsequent prints
    # continue cleanly into the (now blank) former-panel rows.
    out.append(f"\033[{rows - _PANEL_LINES};1H")
    sys.stdout.write("".join(out))
    sys.stdout.flush()
    _panel_active = False
    _panel_content = ["", "", ""]


def fmt_duration(seconds: float) -> str:
    """Return MM:SS string for *seconds*."""
    m = int(seconds) // 60
    s = int(seconds) % 60
    return f"{m:02d}:{s:02d}"


def spin_char(tick: int) -> str:
    """Return the spinner character for *tick*."""
    return _SPIN_FRAMES[tick % len(_SPIN_FRAMES)]
