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

from ai_xss_generator.findings import (
    BYPASS_FAMILIES,
    Finding,
    findings_prompt_section,
    infer_bypass_family,
    relevant_findings,
    save_finding,
)
from ai_xss_generator.payloads import base_payloads_for_context, rank_payloads
from ai_xss_generator.types import ParsedContext, PayloadCandidate


OLLAMA_BASE_URL = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
OPENAI_BASE_URL = "https://api.openai.com/v1"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENAI_FALLBACK_MODEL = "gpt-4o-mini"

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


# ---------------------------------------------------------------------------
# Context extraction helpers
# ---------------------------------------------------------------------------

def _extract_probe_context(context: ParsedContext) -> tuple[str, str, str]:
    """Return (primary_sink_type, context_type, surviving_chars) from context.

    Reads structured probe notes written by probe.py into context.notes.
    Falls back to the first detected DOM sink when probe data is absent.
    """
    sink_type = context.dom_sinks[0].sink if context.dom_sinks else ""
    context_type = ""
    surviving_chars = ""

    for note in context.notes:
        # e.g. "[probe:CONFIRMED] 'url' → html_attr_url(href) surviving='()/;`{}'"
        m = re.search(r"\[probe:CONFIRMED\].*?→\s*(\w+)", note)
        if m and not context_type:
            context_type = m.group(1)
        m2 = re.search(r"surviving='([^']*)'", note)
        if m2 and not surviving_chars:
            surviving_chars = m2.group(1)

    return sink_type, context_type, surviving_chars


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def _prompt_for_context(
    context: ParsedContext,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
) -> str:
    """Build the LLM prompt.

    Structure (ordered by importance for small-model attention):
      1. Probe results (surviving chars, confirmed sink) — actionable, upfront
      2. Past findings for this context (few-shot bypass examples)
      3. WAF context (if any)
      4. Reference public payloads (if any)
      5. Full parsed context JSON
      6. Output schema + requirements
    """
    sink_type, ctx_type, surviving_chars = _extract_probe_context(context)

    # ── Section 1: Active probe summary ──────────────────────────────────────
    probe_section = ""
    if sink_type or surviving_chars:
        blocked_note = (
            f"Only characters in {surviving_chars!r} survived — ALL others are filtered. "
            "Payloads MUST be constructable from the surviving set."
            if surviving_chars
            else "No char survival data — assume conservative filter."
        )
        surviving_display = repr(surviving_chars) if surviving_chars else "unknown"
        probe_section = (
            "ACTIVE PROBE RESULTS (highest priority — payloads must fit these constraints):\n"
            f"  confirmed_sink: {sink_type or 'unknown'}\n"
            f"  reflection_context: {ctx_type or 'unknown'}\n"
            f"  surviving_chars: {surviving_display}\n"
            f"  {blocked_note}\n"
        )

    # ── Section 2: Past findings (few-shot examples) ─────────────────────────
    findings_section = ""
    if past_findings:
        findings_section = findings_prompt_section(past_findings) + "\n"

    # ── Section 3: WAF ───────────────────────────────────────────────────────
    waf_section = ""
    if waf:
        waf_section = (
            f"WAF: {waf.title()} — prioritise bypass techniques for this WAF "
            f"(encoding variants, alternative event handlers, namespace tricks, "
            f"case mixing, whitespace tricks).\n"
        )

    # ── Section 4: Reference public payloads ─────────────────────────────────
    reference_section = ""
    if reference_payloads:
        ref_items = [
            {
                "payload": p.payload if hasattr(p, "payload") else p.get("payload", ""),
                "tags": p.tags if hasattr(p, "tags") else p.get("tags", []),
            }
            for p in reference_payloads[:15]
        ]
        reference_section = (
            "Community reference payloads (technique inspiration only — adapt, don't copy):\n"
            + json.dumps(ref_items, indent=2)
            + "\n"
        )

    # ── Section 5: Context JSON ───────────────────────────────────────────────
    context_blob = json.dumps(context.to_dict(), indent=2)

    # ── Bypass family hint ────────────────────────────────────────────────────
    family_list = ", ".join(BYPASS_FAMILIES)

    return f"""You are generating offensive-security test payloads for an authorized XSS assessment.
Return ONLY a JSON object — no markdown, no explanation outside the JSON.

Output schema:
{{
  "payloads": [
    {{
      "payload": "string",
      "title": "short name",
      "explanation": "why it fits this specific context",
      "test_vector": "exact delivery (e.g. ?param=...)",
      "tags": ["tag1", "tag2"],
      "target_sink": "sink name or empty",
      "bypass_family": "one of: {family_list}",
      "risk_score": 1-100
    }}
  ]
}}

Requirements:
- Produce 15-25 payloads.
- Payloads MUST be tailored to the detected sinks, surviving chars, and context above.
- Generic payloads that ignore the probe results score low — be specific.
- Include payloads from multiple bypass families that are plausible for this context.
- Prefer compact, self-contained payloads with no external dependencies.

{probe_section}{findings_section}{waf_section}{reference_section}Full parsed context:
{context_blob}""".strip()


# ---------------------------------------------------------------------------
# Output quality gate
# ---------------------------------------------------------------------------

def _is_weak_output(payloads: list[PayloadCandidate]) -> bool:
    """Return True when the LLM output is too generic to be useful.

    Triggers escalation to a stronger model.
    """
    if len(payloads) < 3:
        return True
    # If every payload is a verbatim copy of a well-known base payload it means
    # the model just parroted the examples without reasoning about the context.
    _GENERIC = {
        "<img src=x onerror=alert(1)>",
        "\"><svg/onload=alert(document.domain)>",
        "javascript:alert(document.cookie)",
        "<script>alert(1)</script>",
        "';alert(1)//",
        '";alert(1)//',
    }
    novel = [p for p in payloads if p.payload not in _GENERIC]
    return len(novel) < 2


# ---------------------------------------------------------------------------
# Ollama backend
# ---------------------------------------------------------------------------

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


def _candidate_models(model: str) -> list[str]:
    candidates = [model, *MODEL_ALIASES.get(model, [])]
    deduped: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in deduped:
            deduped.append(candidate)
    return deduped


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


# ---------------------------------------------------------------------------
# JSON extraction / normalization
# ---------------------------------------------------------------------------

def _extract_json_blob(text: str) -> dict[str, Any]:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("Model response did not include JSON")
    return json.loads(text[start: end + 1])


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


# ---------------------------------------------------------------------------
# Ollama generation
# ---------------------------------------------------------------------------

def _generate_with_ollama(
    context: ParsedContext,
    model: str,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
) -> tuple[list[PayloadCandidate], str]:
    ready, resolved_model, reason = _ensure_ollama_model(model)
    if not ready:
        raise RuntimeError(f"Ollama unavailable: {reason}")
    prompt = _prompt_for_context(
        context,
        reference_payloads=reference_payloads,
        waf=waf,
        past_findings=past_findings,
    )
    response = requests.post(
        f"{OLLAMA_BASE_URL}/api/generate",
        json={"model": resolved_model, "prompt": prompt, "stream": False},
        timeout=120,
    )
    response.raise_for_status()
    body = response.json()
    data = _extract_json_blob(body.get("response", ""))
    return _normalize_payloads(data.get("payloads", []), source="ollama"), resolved_model


# ---------------------------------------------------------------------------
# OpenAI-compatible generation (OpenAI + OpenRouter share the same function)
# ---------------------------------------------------------------------------

def _generate_with_openai_compat(
    context: ParsedContext,
    base_url: str,
    api_key: str,
    model: str,
    source_label: str,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
) -> list[PayloadCandidate]:
    prompt = _prompt_for_context(
        context,
        reference_payloads=reference_payloads,
        waf=waf,
        past_findings=past_findings,
    )
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    # OpenRouter requires these for rate-limit attribution
    if "openrouter" in base_url:
        headers["HTTP-Referer"] = "https://github.com/axss"
        headers["X-Title"] = "axss"

    response = requests.post(
        f"{base_url}/chat/completions",
        headers=headers,
        json={
            "model": model,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an expert offensive-security researcher. "
                        "Return strict JSON for authorized XSS testing payload generation."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.35,
        },
        timeout=120,
    )
    response.raise_for_status()
    body = response.json()
    content = body["choices"][0]["message"]["content"]
    data = _extract_json_blob(content)
    return _normalize_payloads(data.get("payloads", []), source=source_label)


def _generate_with_openrouter(
    context: ParsedContext,
    cloud_model: str,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
) -> list[PayloadCandidate]:
    from ai_xss_generator.config import load_api_key
    api_key = os.environ.get("OPENROUTER_API_KEY", "") or load_api_key("openrouter_api_key")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY not set")
    return _generate_with_openai_compat(
        context,
        base_url=OPENROUTER_BASE_URL,
        api_key=api_key,
        model=cloud_model,
        source_label="openrouter",
        reference_payloads=reference_payloads,
        waf=waf,
        past_findings=past_findings,
    )


def _generate_with_openai(
    context: ParsedContext,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    past_findings: list[Finding] | None = None,
) -> list[PayloadCandidate]:
    from ai_xss_generator.config import load_api_key
    api_key = os.environ.get("OPENAI_API_KEY", "") or load_api_key("openai_api_key")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")
    return _generate_with_openai_compat(
        context,
        base_url=OPENAI_BASE_URL,
        api_key=api_key,
        model=OPENAI_FALLBACK_MODEL,
        source_label="openai",
        reference_payloads=reference_payloads,
        waf=waf,
        past_findings=past_findings,
    )


# ---------------------------------------------------------------------------
# Cloud escalation — try OpenRouter then OpenAI
# ---------------------------------------------------------------------------

def _try_cloud(
    context: ParsedContext,
    cloud_model: str,
    reference_payloads: list[Any] | None,
    waf: str | None,
    past_findings: list[Finding] | None,
) -> tuple[list[PayloadCandidate], str]:
    """Attempt cloud generation. Returns (payloads, engine_label).

    Tries OpenRouter first (if OPENROUTER_API_KEY set), then OpenAI
    (if OPENAI_API_KEY set). Returns ([], "") if neither is available or
    both fail.
    """
    kwargs = dict(
        reference_payloads=reference_payloads,
        waf=waf,
        past_findings=past_findings,
    )
    from ai_xss_generator.config import load_api_key
    if os.environ.get("OPENROUTER_API_KEY") or load_api_key("openrouter_api_key"):
        try:
            payloads = _generate_with_openrouter(context, cloud_model, **kwargs)
            return payloads, "openrouter"
        except Exception:
            pass

    if os.environ.get("OPENAI_API_KEY") or load_api_key("openai_api_key"):
        try:
            payloads = _generate_with_openai(context, **kwargs)
            return payloads, "openai"
        except Exception:
            pass

    return [], ""


# ---------------------------------------------------------------------------
# Findings persistence for cloud-generated payloads
# ---------------------------------------------------------------------------

def _persist_cloud_findings(
    payloads: list[PayloadCandidate],
    context: ParsedContext,
    model_label: str,
) -> None:
    """Save novel cloud-generated payloads to the findings store so future
    local-model runs can benefit from them as few-shot examples."""
    sink_type, context_type, surviving_chars = _extract_probe_context(context)
    target_host = ""
    try:
        from urllib.parse import urlparse
        target_host = urlparse(context.source).netloc
    except Exception:
        pass

    for p in payloads:
        if not p.payload:
            continue
        family = infer_bypass_family(p.payload, p.tags)
        finding = Finding(
            sink_type=sink_type or p.target_sink or "",
            context_type=context_type,
            surviving_chars=surviving_chars,
            bypass_family=family,
            payload=p.payload,
            test_vector=p.test_vector,
            model=model_label,
            explanation=p.explanation,
            target_host=target_host,
            tags=p.tags,
        )
        try:
            save_finding(finding)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Public cloud escalation — used by the active scanner worker
# ---------------------------------------------------------------------------

def generate_cloud_payloads(
    context: "ParsedContext",
    cloud_model: str,
    waf: str | None = None,
    past_findings: "list[Finding] | None" = None,
) -> "tuple[list[PayloadCandidate], str]":
    """Call the cloud model directly for active-scanner escalation.

    Skips local Ollama entirely — only used when Phase 1 mechanical transforms
    AND local model payloads have already failed to confirm execution.

    Returns (payloads, engine_label).  Returns ([], "") when no API key is set
    or the cloud call fails.
    """
    sink_type, context_type, surviving_chars = _extract_probe_context(context)
    if past_findings is None:
        past_findings = relevant_findings(
            sink_type=sink_type,
            context_type=context_type,
            surviving_chars=surviving_chars,
        )

    payloads, engine = _try_cloud(
        context=context,
        cloud_model=cloud_model,
        reference_payloads=None,
        waf=waf,
        past_findings=past_findings,
    )

    if payloads and engine:
        _persist_cloud_findings(payloads, context, engine)

    return payloads, engine


# ---------------------------------------------------------------------------
# Mutators
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_payloads(
    context: ParsedContext,
    model: str,
    mutator_plugins: list[Any] | None = None,
    progress: Any | None = None,
    reference_payloads: list[Any] | None = None,
    waf: str | None = None,
    use_cloud: bool = True,
    cloud_model: str = "anthropic/claude-3-5-sonnet",
) -> tuple[list[PayloadCandidate], str, bool, str]:
    """Generate, rank, and return payloads for *context*.

    Escalation chain:
      1. Local Ollama (with findings injected into prompt)
      2. If local output is weak AND use_cloud=True AND an API key exists:
         → OpenRouter (preferred) or OpenAI
         → Cloud payloads are saved to ~/.axss/findings.jsonl so future
           local runs benefit from them
      3. Fall through to heuristic-only if everything above fails

    Returns (payloads, engine, used_fallback, resolved_model).
    """
    mutator_plugins = mutator_plugins or []

    if progress is not None:
        progress("Loading relevant past findings...")

    sink_type, context_type, surviving_chars = _extract_probe_context(context)
    past_findings = relevant_findings(
        sink_type=sink_type,
        context_type=context_type,
        surviving_chars=surviving_chars,
    )

    if progress is not None:
        hint = f"{len(past_findings)} relevant finding(s) found" if past_findings else "no prior findings for this context"
        progress(f"Findings store: {hint}.")
        progress("Generating payloads...")

    heuristics = base_payloads_for_context(context)
    engine = "heuristic"
    used_fallback = True
    resolved_model = model
    ai_payloads: list[PayloadCandidate] = []

    # ── Step 1: Local Ollama ──────────────────────────────────────────────────
    try:
        ai_payloads, resolved_model = _generate_with_ollama(
            context,
            model,
            reference_payloads=reference_payloads,
            waf=waf,
            past_findings=past_findings,
        )
        engine = "ollama"
        used_fallback = False
    except Exception:
        pass

    # ── Step 2: Cloud escalation (only when local is weak and cloud allowed) ──
    cloud_used = False
    if _is_weak_output(ai_payloads) and use_cloud:
        if progress is not None:
            progress("Local model output weak — attempting cloud escalation...")

        cloud_payloads, cloud_engine = _try_cloud(
            context,
            cloud_model=cloud_model,
            reference_payloads=reference_payloads,
            waf=waf,
            past_findings=past_findings,
        )

        if cloud_payloads:
            if progress is not None:
                progress(f"Cloud ({cloud_engine}) returned {len(cloud_payloads)} payloads — saving to findings store.")
            _persist_cloud_findings(cloud_payloads, context, cloud_engine)
            ai_payloads = cloud_payloads
            engine = cloud_engine
            resolved_model = cloud_model
            used_fallback = True
            cloud_used = True
        elif progress is not None:
            progress("No cloud API keys configured — running heuristic-only.")

    # ── Combine + rank ────────────────────────────────────────────────────────
    combined = heuristics + ai_payloads

    if progress is not None:
        progress("Ranking/mutating...")

    combined = _apply_mutators(combined, context, mutator_plugins)
    ranked = rank_payloads(combined, context)

    if engine != "heuristic":
        ranked = [
            replace(payload, risk_score=max(payload.risk_score, 1))
            if payload.source in {"ollama", "openai", "openrouter"}
            else payload
            for payload in ranked
        ]
        ranked = sorted(ranked, key=lambda item: (-item.risk_score, item.payload))

    return ranked, engine, used_fallback, resolved_model
