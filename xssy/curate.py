"""LLM-powered curation pipeline for the curated knowledge base.

After generating candidate payloads against an xssy.uk lab (or any confirmed
XSS target), curate_lab_finding() asks the configured AI backend to extract
a structured Finding — context_type, bypass_family, filter behaviour,
explanation — and writes it to the SQLite store at ~/.axss/knowledge.db.

The backend used is whatever ai_backend / cli_tool / cloud_model is set in
~/.axss/config.json — exactly the same dispatch as payload generation.
No separate key or service needed.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

import requests

from ai_xss_generator.cli_runner import generate_via_cli
from ai_xss_generator.config import AppConfig, load_api_key
from ai_xss_generator.findings import BYPASS_FAMILIES, Finding, save_finding

if TYPE_CHECKING:
    from ai_xss_generator.types import ParsedContext, PayloadCandidate

log = logging.getLogger(__name__)

_OPENROUTER_URL = "https://openrouter.ai/api/v1"
_OPENAI_URL = "https://api.openai.com/v1"
_TIMEOUT = 90  # seconds per curation call


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

def _curation_prompt(
    payloads: list[Any],
    lab_name: str,
    lab_objective: str,
    lab_url: str,
    context_json: str,
) -> str:
    family_list = ", ".join(BYPASS_FAMILIES)
    top = sorted(payloads, key=lambda p: -p.risk_score)[:10]
    candidates = json.dumps(
        [
            {
                "payload": p.payload,
                "risk_score": p.risk_score,
                "explanation": p.explanation,
                "tags": p.tags,
            }
            for p in top
        ],
        indent=2,
    )
    return f"""You are an expert XSS security researcher curating a knowledge base of generalizable XSS bypass techniques.

A payload generator has produced candidates for the following lab:
  Lab:       {lab_name}
  Objective: {lab_objective}
  URL:       {lab_url}

Candidate payloads (highest confidence first):
{candidates}

Full parsed page context:
{context_json}

Your task: extract the BEST technique from these candidates as a single structured finding.
Focus on what makes it work (the "why") — not just the payload string.
Choose the candidate that best demonstrates the core bypass technique for this injection context.

Return ONLY a JSON object — no markdown, no text outside the JSON:
{{
  "payload":        "the best candidate payload",
  "test_vector":    "exact delivery, e.g. ?param=PAYLOAD or form field name=value",
  "context_type":   "one of: html_body, html_attr_value, html_attr_url, html_comment, js_string_sq, js_string_dq, js_template_literal, js_block, css_value, url_path, url_query",
  "sink_type":      "short label, e.g. reflected_body, reflected_attr, dom_innerhtml, js_eval",
  "bypass_family":  "one of: {family_list}",
  "surviving_chars":"chars that pass the filter (empty string if unknown)",
  "waf_name":       "waf name if detected, else empty string",
  "delivery_mode":  "get, post, or header",
  "frameworks":     ["detected framework names — empty list if none"],
  "auth_required":  false,
  "explanation":    "2-4 sentences: why the technique works for this specific injection context",
  "tags":           ["relevant technique tags"],
  "confidence":     0.85
}}""".strip()


# ---------------------------------------------------------------------------
# Backend dispatch — mirrors _try_cloud in models.py but takes a raw prompt
# ---------------------------------------------------------------------------

def _call_ai(prompt: str, config: AppConfig) -> str:
    """Send *prompt* to whichever backend config specifies; return raw text."""

    # ── CLI backend ───────────────────────────────────────────────────────────
    if config.ai_backend == "cli":
        return generate_via_cli(config.cli_tool, prompt, config.cli_model)

    # ── API backend: OpenRouter first, then OpenAI ────────────────────────────
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
                "model": config.cloud_model,
                "response_format": {"type": "json_object"},
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert XSS security researcher. Return strict JSON.",
                    },
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    oa_key = os.environ.get("OPENAI_API_KEY", "") or load_api_key("openai_api_key")
    if oa_key:
        resp = requests.post(
            f"{_OPENAI_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {oa_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o-mini",
                "response_format": {"type": "json_object"},
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert XSS security researcher. Return strict JSON.",
                    },
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    raise RuntimeError(
        "No AI backend available — set ai_backend=cli in ~/.axss/config.json "
        "or configure an API key (openrouter_api_key / openai_api_key in ~/.axss/keys)"
    )


def _extract_json(text: str) -> dict[str, Any]:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("AI response did not contain a JSON object")
    return json.loads(text[start : end + 1])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def curate_lab_finding(
    payloads: list[Any],
    lab_name: str,
    lab_objective: str,
    lab_url: str,
    context: Any,
    config: AppConfig,
    source: str = "",
    verbose: bool = False,
) -> int:
    """Extract a curated Finding from lab payloads using the configured AI backend.

    Sends the top candidate payloads + parsed page context to the AI, asks it
    to identify and describe the best bypass technique, then saves the result
    to the curated SQLite store.

    Args:
        payloads:      Candidate payloads from generate_payloads().
        lab_name:      Human-readable lab name (used in logs and tags).
        lab_objective: Lab objective string (gives the AI intent context).
        lab_url:       Lab URL (stored as source).
        context:       ParsedContext from the lab's HTML.
        config:        Loaded AppConfig (determines which AI backend to call).
        source:        Optional override for the finding's source field.
        verbose:       Log progress when True.

    Returns:
        Number of findings saved (0 or 1).
    """
    eligible = [p for p in payloads if p.risk_score >= 50]
    if not eligible:
        if verbose:
            log.info("curate: no payloads with risk_score >= 50 for %r — skipping", lab_name)
        return 0

    try:
        context_json = json.dumps(context.to_dict(), indent=2)
    except Exception:
        context_json = "{}"

    prompt = _curation_prompt(eligible, lab_name, lab_objective, lab_url, context_json)

    try:
        raw = _call_ai(prompt, config)
    except Exception as exc:
        log.warning("curate: AI call failed for %r: %s", lab_name, exc)
        return 0

    try:
        data = _extract_json(raw)
    except Exception as exc:
        log.warning("curate: could not parse AI JSON for %r: %s", lab_name, exc)
        return 0

    payload_str = str(data.get("payload", "")).strip()
    if not payload_str:
        log.warning("curate: AI returned empty payload for %r", lab_name)
        return 0

    now = datetime.now(timezone.utc).isoformat()
    finding = Finding(
        payload=payload_str,
        test_vector=str(data.get("test_vector", "")),
        context_type=str(data.get("context_type", "")).strip(),
        sink_type=str(data.get("sink_type", "")).strip(),
        bypass_family=str(data.get("bypass_family", "")).strip(),
        surviving_chars=str(data.get("surviving_chars", "")),
        waf_name=str(data.get("waf_name", "")),
        delivery_mode=str(data.get("delivery_mode", "get")),
        frameworks=[str(f) for f in data.get("frameworks", []) if str(f).strip()],
        auth_required=bool(data.get("auth_required", False)),
        explanation=str(data.get("explanation", "")),
        tags=[str(t) for t in data.get("tags", []) if str(t).strip()],
        confidence=min(1.0, max(0.0, float(data.get("confidence", 0.85)))),
        source=source or lab_url,
        curated_at=now,
    )

    try:
        if save_finding(finding):
            if verbose:
                log.info(
                    "curate: saved  %s  bypass_family=%s  context=%s",
                    lab_name,
                    finding.bypass_family,
                    finding.context_type,
                )
            return 1
        if verbose:
            log.info("curate: duplicate skipped for %r", lab_name)
        return 0
    except Exception as exc:
        log.warning("curate: save_finding failed for %r: %s", lab_name, exc)
        return 0
