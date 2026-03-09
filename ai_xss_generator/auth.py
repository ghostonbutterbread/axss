"""Authentication helpers: parse --header / --cookies for authenticated scan sessions.

Supports:
  --header "Name: Value"   (repeatable, merged in order)
  --cookies cookies.txt    (Netscape HTTP Cookie File format)

The resulting dict[str, str] is merged into every HTTP request made by the
spider, probe, and active-scanner layers so that all requests carry the same
authentication context.  Cookie values from cookies.txt are folded into a
single ``Cookie`` header; they do NOT override an existing Cookie header set
via --header, they are appended to it.

The ``describe_auth`` function produces redacted human-readable notes that are
embedded in the LLM prompt so the model is aware that the session is
authenticated and can suggest payloads relevant to privileged endpoints.
"""
from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger(__name__)


def parse_headers(raw_list: list[str]) -> dict[str, str]:
    """Parse a list of ``'Name: Value'`` strings into a header dict.

    Duplicate names keep the *last* supplied value.  Malformed entries (no
    colon) are logged at WARNING level and skipped.
    """
    headers: dict[str, str] = {}
    for item in raw_list:
        if ":" not in item:
            log.warning("Skipping malformed --header (no colon): %r", item)
            continue
        name, _, value = item.partition(":")
        name = name.strip()
        if not name:
            log.warning("Skipping --header with empty name: %r", item)
            continue
        headers[name] = value.strip()
    return headers


def load_netscape_cookies(path: str) -> dict[str, str]:
    """Parse a Netscape-format ``cookies.txt`` file.

    Returns ``{name: value}`` for every valid cookie entry.  Lines with fewer
    than 7 tab-separated fields or starting with ``#`` are skipped silently.

    Netscape cookie file field order (tab-separated):
        domain | include_subdomains | path | secure | expires | name | value

    Raises ``ValueError`` when the file cannot be read.
    """
    cookies: dict[str, str] = {}
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"Cannot read cookies file {path!r}: {exc}") from exc

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            log.debug(
                "cookies.txt line %d: expected ≥7 tab-separated fields, got %d — skipped",
                lineno,
                len(parts),
            )
            continue
        name = parts[5].strip()
        value = parts[6].strip()
        if name:
            cookies[name] = value

    if not cookies:
        log.warning("No cookies loaded from %r — file may be empty or malformed.", path)
    else:
        log.debug("Loaded %d cookie(s) from %r", len(cookies), path)

    return cookies


def build_auth_headers(
    headers: list[str] | None = None,
    cookies_path: str | None = None,
) -> dict[str, str]:
    """Return a merged header dict built from ``--header`` values and/or a cookies.txt file.

    Cookie values from *cookies_path* are combined into a single ``Cookie``
    header.  If ``--header`` already provides a ``Cookie`` value the
    cookies.txt values are *appended* (semicolon-separated) rather than
    replacing it.

    Returns an empty dict when no auth source is provided — callers treat this
    as "no authentication".
    """
    result: dict[str, str] = {}

    if headers:
        result.update(parse_headers(headers))

    if cookies_path:
        cookies = load_netscape_cookies(cookies_path)
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            existing = result.get("Cookie", "")
            result["Cookie"] = f"{existing}; {cookie_str}" if existing else cookie_str

    return result


def describe_auth(auth_headers: dict[str, str]) -> list[str]:
    """Return redacted, human-readable notes about the auth context.

    Values are NEVER included — only the presence and type of credentials.
    These notes are embedded in the LLM prompt so the model understands the
    session is authenticated without leaking secrets.
    """
    notes: list[str] = []
    for name, value in auth_headers.items():
        name_lower = name.lower()
        if name_lower == "authorization":
            scheme = value.split()[0] if value.strip() else "unknown"
            notes.append(f"Authorization header present ({scheme} scheme)")
        elif name_lower == "cookie":
            count = value.count("=")
            notes.append(f"Session cookies provided ({count} cookie value(s))")
        elif name_lower in {"x-api-key", "api-key", "x-auth-token", "x-access-token"}:
            notes.append(f"API key header present ({name})")
        else:
            notes.append(f"Custom authentication header present ({name})")
    return notes
