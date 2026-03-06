from __future__ import annotations

import json
from typing import Iterable

from ai_xss_generator.types import GenerationResult, PayloadCandidate


def _truncate(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    return value[: width - 1] + "…"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    header_line = " | ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
    divider = "-+-".join("-" * width for width in widths)
    body = [" | ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)) for row in rows]
    return "\n".join([header_line, divider, *body])


def render_summary(result: GenerationResult, limit: int = 10) -> str:
    rows = []
    for index, payload in enumerate(result.payloads[:limit], start=1):
        rows.append(
            [
                str(index),
                str(payload.risk_score),
                _truncate(payload.payload, 44),
                _truncate(payload.target_sink or payload.framework_hint or ",".join(payload.tags[:2]), 20),
                _truncate(payload.title, 24),
            ]
        )
    return _table(["#", "Risk", "Payload", "Focus", "Title"], rows)


def render_list(payloads: Iterable[PayloadCandidate], limit: int = 20) -> str:
    rows = []
    for index, payload in enumerate(list(payloads)[:limit], start=1):
        rows.append(
            [
                str(index),
                str(payload.risk_score),
                _truncate(payload.payload, 44),
                _truncate(", ".join(payload.tags[:3]), 28),
                _truncate(payload.explanation, 46),
            ]
        )
    return _table(["#", "Risk", "Payload", "Tags", "Why"], rows)


def render_heat(payloads: Iterable[PayloadCandidate], limit: int = 20) -> str:
    lines = []
    for index, payload in enumerate(list(payloads)[:limit], start=1):
        bar = "#" * max(1, round(payload.risk_score / 4))
        lines.append(
            f"{index:>2}. {payload.risk_score:>3} {bar:<25} {_truncate(payload.title, 26)} {_truncate(payload.payload, 36)}"
        )
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
