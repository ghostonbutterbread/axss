from __future__ import annotations

import json
import re
from typing import Iterable

from ai_xss_generator.console import RESET, colorize_score, risk_color, _tty
from ai_xss_generator.types import GenerationResult, PayloadCandidate

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _truncate(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    return value[: width - 1] + "…"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    # Strip ANSI codes when measuring column widths so colors don't break alignment
    def _visible(s: str) -> int:
        return len(_ANSI_RE.sub("", s))

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], _visible(cell))

    def _pad(s: str, width: int) -> str:
        return s + " " * (width - _visible(s))

    header_line = " | ".join(_pad(h, widths[i]) for i, h in enumerate(headers))
    divider = "-+-".join("-" * w for w in widths)
    body = [" | ".join(_pad(cell, widths[i]) for i, cell in enumerate(row)) for row in rows]
    return "\n".join([header_line, divider, *body])


def render_summary(result: GenerationResult, limit: int = 10) -> str:
    rows = []
    for index, payload in enumerate(result.payloads[:limit], start=1):
        rows.append(
            [
                str(index),
                colorize_score(payload.risk_score),
                _truncate(payload.payload, 44),
                _truncate(payload.target_sink or payload.framework_hint or ",".join(payload.tags[:2]), 20),
                _truncate(payload.title, 24),
            ]
        )
    return _table(["#", "Risk", "Payload", "Focus", "Title"], rows)


def render_list(payloads: Iterable[PayloadCandidate], limit: int = 20, *, source: str = "") -> str:
    lines = []
    if source:
        lines.append(f"Target: {source}")
        lines.append("")
    for index, payload in enumerate(list(payloads)[:limit], start=1):
        score_str = colorize_score(payload.risk_score)
        tags_str = ", ".join(payload.tags[:3])
        lines.append(f"{index:>2}. [{score_str}] {payload.title}")
        lines.append(f"    payload: {payload.payload}")
        lines.append(f"    inject:  {payload.test_vector}")
        if tags_str:
            lines.append(f"    tags:    {tags_str}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_heat(payloads: Iterable[PayloadCandidate], limit: int = 20) -> str:
    lines = []
    for index, payload in enumerate(list(payloads)[:limit], start=1):
        bar = "#" * max(1, round(payload.risk_score / 4))
        color = risk_color(payload.risk_score)
        score_str = f"{color}{payload.risk_score:>3}{RESET}" if _tty() else f"{payload.risk_score:>3}"
        bar_str = f"{color}{bar:<25}{RESET}" if _tty() else f"{bar:<25}"
        lines.append(f"{index:>2}. {score_str} {bar_str} {_truncate(payload.title, 26)}")
        lines.append(f"    {payload.payload}")
    return "\n".join(lines)


def render_json(result: GenerationResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def render_batch_json(
    results: list[GenerationResult],
    *,
    errors: list[dict[str, str]] | None = None,
    merged_result: GenerationResult | None = None,
) -> str:
    body: dict[str, object] = {
        "results": [result.to_dict() for result in results],
        "errors": errors or [],
    }
    if merged_result is not None:
        body["merged_result"] = merged_result.to_dict()
    return json.dumps(body, indent=2)
