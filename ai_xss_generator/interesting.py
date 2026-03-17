from __future__ import annotations

import datetime
import json
import logging
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

import requests

from ai_xss_generator.cli_runner import generate_via_cli_with_tool
from ai_xss_generator.config import CONFIG_DIR, ResolvedAIConfig, load_api_key

log = logging.getLogger(__name__)

_REPORTS_DIR = CONFIG_DIR / "reports"
_OPENROUTER_URL = "https://openrouter.ai/api/v1"
_OPENAI_URL = "https://api.openai.com/v1"
_OPENAI_FALLBACK_MODEL = "gpt-4o-mini"
_INTERESTING_CHUNK_SIZE = 40
_INTERESTING_TIMEOUT = 90


@dataclass(slots=True)
class InterestingUrl:
    url: str
    score: int
    verdict: str
    reason: str
    candidate_params: list[str]
    likely_xss_types: list[str]
    recommended_mode: str
    next_step: str
    ai_engine: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _interesting_prompt(urls: list[str]) -> str:
    numbered = "\n".join(f"{idx + 1}. {url}" for idx, url in enumerate(urls))
    return f"""You are triaging URLs for an authorized XSS assessment.
Rank the URLs most worth deep single-target testing for reflected, DOM, or stored XSS.

Prioritize:
- redirect / return / startURL / retURL / refURL / origin / pageUrl style parameters
- search pages with q/query/text/keyword style parameters
- legacy community / survey / router flows
- HTML page endpoints over obvious JSON-only APIs
- login / auth / handoff pages only when the parameters still look plausibly reflected or routed into the page

Be skeptical:
- do not claim a vulnerability exists
- low score for obviously static, API-only, or low-signal URLs
- prefer concrete reasons tied to parameter names, path shape, and likely rendering behavior

Return ONLY a JSON object:
{{
  "results": [
    {{
      "url": "exact URL from the input list",
      "score": 1,
      "verdict": "high|medium|low",
      "reason": "1-2 sentences explaining why this URL is or is not interesting for deeper XSS testing",
      "candidate_params": ["param1", "param2"],
      "likely_xss_types": ["reflected", "dom", "stored"],
      "recommended_mode": "single-target reflected|dom|stored|active",
      "next_step": "short operator advice for the next deeper run"
    }}
  ]
}}

Evaluate every URL in this chunk. Keep the output compact and practical.

URLs:
{numbered}""".strip()


def _extract_json(text: str) -> dict[str, Any]:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("AI response did not contain a JSON object")
    payload = json.loads(text[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("AI response JSON root was not an object")
    return payload


def _normalize_item(item: dict[str, Any], *, ai_engine: str) -> InterestingUrl:
    verdict = str(item.get("verdict", "low")).strip().lower() or "low"
    if verdict not in {"high", "medium", "low"}:
        verdict = "low"
    score = item.get("score", 0)
    try:
        parsed_score = int(score)
    except Exception:
        parsed_score = 0
    parsed_score = max(1, min(100, parsed_score))
    return InterestingUrl(
        url=str(item.get("url", "") or ""),
        score=parsed_score,
        verdict=verdict,
        reason=str(item.get("reason", "") or "").strip(),
        candidate_params=[
            str(value).strip()
            for value in item.get("candidate_params", []) or []
            if str(value).strip()
        ],
        likely_xss_types=[
            str(value).strip().lower()
            for value in item.get("likely_xss_types", []) or []
            if str(value).strip()
        ],
        recommended_mode=str(item.get("recommended_mode", "") or "").strip(),
        next_step=str(item.get("next_step", "") or "").strip(),
        ai_engine=ai_engine,
    )


def _call_api_backend(prompt: str, ai_config: ResolvedAIConfig) -> tuple[str, str]:
    or_key = os.environ.get("OPENROUTER_API_KEY", "") or load_api_key("openrouter_api_key")
    if or_key:
        resp = requests.post(
            f"{_OPENROUTER_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {or_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/axss",
                "X-Title": "axss",
            },
            json={
                "model": ai_config.cloud_model,
                "response_format": {"type": "json_object"},
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert XSS triage analyst. Return strict JSON only.",
                    },
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
            },
            timeout=_INTERESTING_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"], ai_config.cloud_model

    oa_key = os.environ.get("OPENAI_API_KEY", "") or load_api_key("openai_api_key")
    if oa_key:
        resp = requests.post(
            f"{_OPENAI_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {oa_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": _OPENAI_FALLBACK_MODEL,
                "response_format": {"type": "json_object"},
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert XSS triage analyst. Return strict JSON only.",
                    },
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
            },
            timeout=_INTERESTING_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"], _OPENAI_FALLBACK_MODEL

    raise RuntimeError(
        "No API backend available for --interesting — configure openrouter_api_key or openai_api_key, "
        "or switch config/backend to CLI."
    )


def _call_backend(prompt: str, ai_config: ResolvedAIConfig) -> tuple[str, str]:
    if ai_config.ai_backend == "cli":
        raw, actual_tool = generate_via_cli_with_tool(ai_config.cli_tool, prompt, ai_config.cli_model)
        return raw, f"cli:{actual_tool}"
    return _call_api_backend(prompt, ai_config)


def analyze_interesting_urls(
    urls: list[str],
    ai_config: ResolvedAIConfig,
    *,
    progress: Callable[[str], None] | None = None,
) -> list[InterestingUrl]:
    """Rank URLs worth deeper single-target XSS testing using the configured AI backend."""
    normalized_urls = [url.strip() for url in urls if url and url.strip()]
    if not normalized_urls:
        return []

    progress = progress or (lambda _message: None)
    merged: dict[str, InterestingUrl] = {}
    total_chunks = (len(normalized_urls) + _INTERESTING_CHUNK_SIZE - 1) // _INTERESTING_CHUNK_SIZE

    for index in range(total_chunks):
        chunk = normalized_urls[index * _INTERESTING_CHUNK_SIZE : (index + 1) * _INTERESTING_CHUNK_SIZE]
        progress(f"Interesting triage chunk {index + 1}/{total_chunks} ({len(chunk)} URL(s))")
        prompt = _interesting_prompt(chunk)
        raw, ai_engine = _call_backend(prompt, ai_config)
        payload = _extract_json(raw)
        items = payload.get("results", [])
        if not isinstance(items, list):
            raise ValueError("Interesting URL triage response did not contain a results array")
        for item in items:
            if not isinstance(item, dict):
                continue
            normalized = _normalize_item(item, ai_engine=ai_engine)
            if normalized.url not in chunk:
                continue
            prior = merged.get(normalized.url)
            if prior is None or normalized.score > prior.score:
                merged[normalized.url] = normalized

    # Ensure every input URL gets a row, even if the model omitted it.
    for url in normalized_urls:
        merged.setdefault(
            url,
            InterestingUrl(
                url=url,
                score=1,
                verdict="low",
                reason="The triage model did not identify a strong XSS signal for this URL in the current pass.",
                candidate_params=[],
                likely_xss_types=[],
                recommended_mode="manual review",
                next_step="Only test this URL deeply if surrounding workflow context makes it high value.",
            ),
        )

    return sorted(merged.values(), key=lambda item: (-item.score, item.url))


def write_interesting_report(
    results: list[InterestingUrl],
    *,
    source_file: str,
    ai_config: ResolvedAIConfig,
    output_path: str | None = None,
) -> str:
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if output_path is None:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = str(_REPORTS_DIR / f"interesting_urls_{ts}.md")

    lines = [
        "# axss Interesting URL Report",
        "",
        f"**Source file:** `{source_file}`  ",
        f"**Backend:** `{ai_config.ai_backend}`  ",
        f"**Cloud model:** `{ai_config.cloud_model}`  ",
        f"**CLI tool:** `{ai_config.cli_tool}`  ",
        f"**URLs ranked:** {len(results)}  ",
        "",
        "| Score | Verdict | URL | Candidate params | Likely XSS | Recommended mode |",
        "|------:|---------|-----|------------------|------------|------------------|",
    ]
    for item in results:
        params = (", ".join(item.candidate_params) or "-").replace("|", "\\|")
        xss_types = (", ".join(item.likely_xss_types) or "-").replace("|", "\\|")
        reason = (item.reason or "-").replace("|", "\\|")
        next_step = item.next_step.replace("|", "\\|") if item.next_step else ""
        lines.append(
            f"| {item.score} | {item.verdict} | `{item.url}` | {params} | {xss_types} | {item.recommended_mode or '-'} |"
        )
        lines.append(f"|  |  |  |  |  | {reason} |")
        if next_step:
            lines.append(f"|  |  |  |  |  | Next: {next_step} |")
    Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path
