from __future__ import annotations

import time
import urllib.parse
from typing import Any


_EDGE_NAV_ERROR_PATTERNS = (
    "ERR_HTTP2_PROTOCOL_ERROR",
    "ERR_HTTP2_STREAM_ERROR",
    "ERR_CONNECTION_RESET",
    "ERR_CONNECTION_CLOSED",
    "ERR_NETWORK_CHANGED",
    "ERR_TIMED_OUT",
    "ERR_ABORTED",
)


def same_origin_root(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}/"


def edge_navigation_signal(exc: Exception | str | None) -> str:
    text = str(exc or "")
    for pattern in _EDGE_NAV_ERROR_PATTERNS:
        if pattern in text:
            return pattern.lower()
    return "navigation_error"


def is_edge_navigation_error(exc: Exception | str | None) -> bool:
    text = str(exc or "")
    return any(pattern in text for pattern in _EDGE_NAV_ERROR_PATTERNS)


def goto_with_edge_recovery(
    page: Any,
    url: str,
    *,
    timeout_ms: int,
    stabilize_timeout_ms: int = 0,
    preflight_urls: list[str] | None = None,
) -> tuple[bool, list[str], Exception | None]:
    """Navigate with a small recovery sequence for edge/WAF transport instability."""
    phases: list[str] = []
    last_exc: Exception | None = None

    attempts: list[tuple[str, int]] = [
        ("domcontentloaded", timeout_ms),
        ("commit", min(timeout_ms, 10_000)),
        ("load", min(timeout_ms, 10_000)),
    ]

    def _try(target_url: str, label: str) -> bool:
        nonlocal last_exc
        for wait_until, current_timeout in attempts:
            try:
                page.goto(target_url, timeout=current_timeout, wait_until=wait_until)
                phases.append(f"{label}:{wait_until}")
                return True
            except Exception as exc:
                last_exc = exc
                phases.append(f"{label}:{edge_navigation_signal(exc)}:{wait_until}")
        return False

    if _try(url, "primary"):
        if stabilize_timeout_ms > 0:
            try:
                page.wait_for_load_state("networkidle", timeout=stabilize_timeout_ms)
                phases.append("stabilized")
            except Exception:
                phases.append("stabilize_timeout")
        return True, phases, last_exc

    if not is_edge_navigation_error(last_exc):
        return False, phases, last_exc

    root_url = same_origin_root(url)
    recovery_urls = list(dict.fromkeys((preflight_urls or []) + [root_url]))
    for recovery_url in recovery_urls:
        if not recovery_url or recovery_url == url:
            continue
        try:
            page.goto(
                recovery_url,
                timeout=min(timeout_ms, 8_000),
                wait_until="domcontentloaded",
            )
            phases.append(f"preflight:{recovery_url}")
            time.sleep(0.25)
            break
        except Exception as exc:
            last_exc = exc
            phases.append(f"preflight_failed:{edge_navigation_signal(exc)}")

    ok = _try(url, "retry")
    if ok and stabilize_timeout_ms > 0:
        try:
            page.wait_for_load_state("networkidle", timeout=stabilize_timeout_ms)
            phases.append("stabilized")
        except Exception:
            phases.append("stabilize_timeout")
    return ok, phases, last_exc
