"""Scan-session context helpers.

build_memory_profile() extracts the target fingerprint from a parsed context
object so callers don't have to duplicate that inference logic.
"""
from __future__ import annotations

import urllib.parse
from typing import Any


def build_memory_profile(
    *,
    context: Any | None = None,
    waf_name: str | None = None,
    delivery_mode: str = "",
    target_host: str = "",
    target_scope: str = "",  # accepted but unused — no host scope in new design
) -> dict[str, Any]:
    """Return a target fingerprint dict for the current scan session.

    Used to pass consistent context to generate_payloads(), build_probe_lessons(),
    and build_mapping_lessons() without each caller duplicating the inference.
    """
    frameworks: list[str] = []
    auth_required = False
    source = ""
    inferred_delivery_mode = delivery_mode.lower()

    if context is not None:
        frameworks = [
            str(item).lower()
            for item in getattr(context, "frameworks", [])
            if str(item).strip()
        ]
        auth_required = bool(getattr(context, "auth_notes", []))
        source = str(getattr(context, "source", "") or "")
        if not inferred_delivery_mode:
            parsed = urllib.parse.urlparse(source)
            if parsed.query:
                inferred_delivery_mode = "get"
            elif getattr(context, "forms", []):
                inferred_delivery_mode = "post"
            elif getattr(context, "dom_sinks", []):
                inferred_delivery_mode = "dom"

    host = target_host or urllib.parse.urlparse(source).netloc

    return {
        "target_host":   host,
        "waf_name":      (waf_name or "").lower(),
        "delivery_mode": inferred_delivery_mode,
        "frameworks":    list(dict.fromkeys(frameworks)),
        "auth_required": auth_required,
    }
