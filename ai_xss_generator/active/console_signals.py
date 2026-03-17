"""Helpers for trustworthy console-based execution detection."""
from __future__ import annotations


_CONSOLE_MARKER = "__AXSS_EXEC__"


def console_init_script() -> str:
    """Return an init script that tags page-originated console calls."""
    return f"""(() => {{
        const marker = { _CONSOLE_MARKER!r };
        for (const level of ['log', 'info', 'debug', 'warn', 'error']) {{
            const original = console[level];
            if (typeof original !== 'function') continue;
            console[level] = function(...args) {{
                return original.call(console, marker, ...args);
            }};
        }}
    }})();"""


def is_execution_console_text(text: str) -> bool:
    """True when Playwright console text includes our injected marker."""
    return text.startswith(_CONSOLE_MARKER)


def strip_execution_console_text(text: str) -> str:
    """Remove the injected marker from a console message for reporting."""
    if not is_execution_console_text(text):
        return text
    stripped = text[len(_CONSOLE_MARKER):].lstrip()
    return stripped or _CONSOLE_MARKER
