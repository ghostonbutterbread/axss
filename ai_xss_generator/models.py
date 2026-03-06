from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import replace
from typing import Any
from urllib.parse import quote_plus

import requests

from ai_xss_generator.payloads import base_payloads_for_context, rank_payloads
from ai_xss_generator.types import ParsedContext, PayloadCandidate


OLLAMA_BASE_URL = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
OPENAI_MODEL = "gpt-4o-mini"
MODEL_ALIASES = {
    "qwen3.5": [
        "qwen3.5",
        "qwen3.5:9b",
        "qwen3.5:4b",
        "qwen3.5:27b",
        "qwen3.5:35b",
    ],
    "qwen3.5:4b": ["qwen3.5:4b"],
    "qwen3.5:9b": ["qwen3.5:9b", "qwen3.5"],
    "qwen3.5:27b": ["qwen3.5:27b"],
    "qwen3.5:35b": ["qwen3.5:35b"],
    "qwen2.5-coder:7b-instruct-q5_K_M": [
        "qwen2.5-coder:7b-instruct-q5_K_M",
        "qwen2.5-coder:7b-instruct-q5_K_M.gguf",
        "qwen2.5-coder:7b",
    ],
    "qwen2.5-coder:7b-instruct-q5_K_M.gguf": [
        "qwen2.5-coder:7b-instruct-q5_K_M.gguf",
        "qwen2.5-coder:7b-instruct-q5_K_M",
        "qwen2.5-coder:7b",
    ],
}


def _prompt_for_context(context: ParsedContext) -> str:
    context_blob = json.dumps(context.to_dict(), indent=2)
    return f"""
You are generating offensive-security test payloads for an authorized XSS assessment.
Return only JSON with this shape:
{{
  "payloads": [
    {{
      "payload": "string",
      "title": "short name",
      "explanation": "why it fits the context",
      "test_vector": "how to try it",
      "tags": ["tag1", "tag2"],
      "target_sink": "optional sink",
      "framework_hint": "optional framework",
      "risk_score": 1-100
    }}
  ]
}}

Requirements:
- Produce at least 20 payloads.
- Tailor to discovered sinks, handlers, forms, and frameworks.
- Include polyglots, encodings, JS obfuscation, DOM clobbering/property chains, and framework-specific probes.
- Keep payloads compact and executable.
- Avoid markdown and commentary outside the JSON object.

Parsed context:
{context_blob}
""".strip()


def _normalize_payloads(items: list[dict[str, Any]], source: str) -> list[PayloadCandidate]:
    normalized: list[PayloadCandidate] = []
    for item in items:
        payload = str(item.get("payload", "")).strip()
        if not payload:
            continue
        normalized.append(
            PayloadCandidate(
                payload=payload,
                title=str(item.get("title", "AI-generated payload")).strip() or "AI-generated payload",
                explanation=str(item.get("explanation", "Tailored by model output.")).strip(),
                test_vector=str(item.get("test_vector", "Inject into the highest-confidence sink.")).strip(),
                tags=[str(tag) for tag in item.get("tags", []) if str(tag).strip()],
                target_sink=str(item.get("target_sink", "")).strip(),
                framework_hint=str(item.get("framework_hint", "")).strip(),
                risk_score=int(item.get("risk_score", 0) or 0),
                source=source,
            )
        )
    return normalized


def _extract_json_blob(text: str) -> dict[str, Any]:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("Model response did not include JSON")
    return json.loads(text[start : end + 1])


def _candidate_models(model: str) -> list[str]:
    candidates = [model, *MODEL_ALIASES.get(model, [])]
    deduped: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in deduped:
            deduped.append(candidate)
    return deduped


def _parse_ollama_table(text: str) -> list[dict[str, str]]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return []
    headers = re.split(r"\s{2,}", lines[0])
    rows: list[dict[str, str]] = []
    for line in lines[1:]:
        columns = re.split(r"\s{2,}", line, maxsplit=max(0, len(headers) - 1))
        if len(columns) < len(headers):
            columns.extend([""] * (len(headers) - len(columns)))
        rows.append({header: value for header, value in zip(headers, columns)})
    return rows


def _run_ollama_command(*args: str) -> subprocess.CompletedProcess[str]:
    if shutil.which("ollama") is None:
        raise RuntimeError("ollama binary not found")
    result = subprocess.run(
        ["ollama", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or f"ollama {' '.join(args)} failed").strip())
    return result


def list_ollama_models() -> tuple[list[dict[str, str]], str]:
    result = _run_ollama_command("list")
    return _parse_ollama_table(result.stdout), "ollama list"


def _search_ollama_library(query: str) -> list[dict[str, str]]:
    response = requests.get(
        f"https://ollama.com/search?q={quote_plus(query)}",
        timeout=10,
        headers={"User-Agent": "axss/0.1 (+authorized security testing)"},
    )
    response.raise_for_status()
    matches = re.findall(r'href="/library/([^"?#]+)"', response.text)
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in matches:
        name = match.strip("/")
        if not name or name in seen:
            continue
        seen.add(name)
        rows.append({"NAME": name, "SOURCE": "ollama.com"})
    return rows[:20]


def search_ollama_models(query: str) -> tuple[list[dict[str, str]], str]:
    if shutil.which("ollama") is not None:
        result = subprocess.run(
            ["ollama", "search", query],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return _parse_ollama_table(result.stdout), "ollama search"
        stderr = (result.stderr or result.stdout or "").lower()
        unsupported_markers = ("unknown command", "no such command", "usage:")
        if not any(marker in stderr for marker in unsupported_markers):
            raise RuntimeError((result.stderr or result.stdout or "ollama search failed").strip())

    rows = _search_ollama_library(query)
    return rows, "ollama.com search"


def _ensure_ollama_model(model: str) -> tuple[bool, str, str]:
    candidates = _candidate_models(model)
    if shutil.which("ollama") is None:
        return False, model, "ollama binary not found"
    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3)
        response.raise_for_status()
        models = response.json().get("models", [])
        available = {entry.get("name") for entry in models if entry.get("name")}
        for candidate in candidates:
            if candidate in available:
                return True, candidate, "model already available"
    except Exception:
        pass
    errors: list[str] = []
    for candidate in candidates:
        pull = subprocess.run(
            ["ollama", "pull", candidate],
            check=False,
            capture_output=True,
            text=True,
        )
        if pull.returncode == 0:
            return True, candidate, "model pulled"
        errors.append(f"{candidate}: {(pull.stderr or pull.stdout or 'ollama pull failed').strip()}")
    return False, model, "; ".join(errors)


def _generate_with_ollama(context: ParsedContext, model: str) -> tuple[list[PayloadCandidate], str]:
    ready, resolved_model, reason = _ensure_ollama_model(model)
    if not ready:
        raise RuntimeError(f"Ollama unavailable: {reason}")
    response = requests.post(
        f"{OLLAMA_BASE_URL}/api/generate",
        json={"model": resolved_model, "prompt": _prompt_for_context(context), "stream": False},
        timeout=90,
    )
    response.raise_for_status()
    body = response.json()
    data = _extract_json_blob(body.get("response", ""))
    return _normalize_payloads(data.get("payloads", []), source="ollama"), resolved_model


def _generate_with_openai(context: ParsedContext) -> list[PayloadCandidate]:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": OPENAI_MODEL,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": "You return strict JSON for authorized XSS testing payload generation.",
                },
                {"role": "user", "content": _prompt_for_context(context)},
            ],
            "temperature": 0.4,
        },
        timeout=90,
    )
    response.raise_for_status()
    body = response.json()
    content = body["choices"][0]["message"]["content"]
    data = _extract_json_blob(content)
    return _normalize_payloads(data.get("payloads", []), source="openai")


def _apply_mutators(
    payloads: list[PayloadCandidate],
    context: ParsedContext,
    mutator_plugins: list[Any],
) -> list[PayloadCandidate]:
    mutated = list(payloads)
    for plugin in mutator_plugins:
        try:
            produced = plugin.mutate(payloads, context)
        except Exception:
            continue
        for item in produced or []:
            mutated.append(item)
    return mutated


def generate_payloads(
    context: ParsedContext,
    model: str,
    mutator_plugins: list[Any] | None = None,
    progress: Any | None = None,
) -> tuple[list[PayloadCandidate], str, bool, str]:
    mutator_plugins = mutator_plugins or []
    if progress is not None:
        progress("Generating payloads...")
    heuristics = base_payloads_for_context(context)
    engine = "heuristic"
    used_fallback = True
    resolved_model = model
    ai_payloads: list[PayloadCandidate] = []
    try:
        ai_payloads, resolved_model = _generate_with_ollama(context, model)
        engine = "ollama"
        used_fallback = False
    except Exception:
        try:
            ai_payloads = _generate_with_openai(context)
            engine = "openai"
            used_fallback = True
            resolved_model = OPENAI_MODEL
        except Exception:
            ai_payloads = []
            engine = "heuristic"
            used_fallback = True
            resolved_model = model

    combined = heuristics + ai_payloads
    if progress is not None:
        progress("Ranking/mutating...")
    combined = _apply_mutators(combined, context, mutator_plugins)
    ranked = rank_payloads(combined, context)
    if engine != "heuristic":
        ranked = [
            replace(payload, risk_score=max(payload.risk_score, 1))
            if payload.source in {"ollama", "openai"}
            else payload
            for payload in ranked
        ]
        ranked = sorted(ranked, key=lambda item: (-item.risk_score, item.payload))
    return ranked, engine, used_fallback, resolved_model
