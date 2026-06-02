from __future__ import annotations

from ai_xss_generator import models
from ai_xss_generator.types import ParsedContext, PayloadCandidate


def _remote_payload() -> PayloadCandidate:
    return PayloadCandidate(
        payload="<img src=x onerror=alert(1)>",
        title="remote img onerror",
        explanation="Remote backend generated autofire HTML payload.",
        test_vector="?q=<img src=x onerror=alert(1)>",
        tags=["html"],
        risk_score=90,
        source="cli:codex",
    )


def test_generate_payloads_remote_only_skips_ollama_and_uses_remote(monkeypatch) -> None:
    context = ParsedContext(source="https://example.test/search?q=x", source_type="url")

    def _ollama_should_not_run(*args, **kwargs):
        raise AssertionError("local Ollama should not run in remote-only mode")

    def _remote_backend(*args, **kwargs):
        assert kwargs["ai_backend"] == "cli"
        assert kwargs["cli_tool"] == "codex"
        return [_remote_payload()], "cli:codex"

    monkeypatch.setattr(models, "_generate_with_ollama", _ollama_should_not_run)
    monkeypatch.setattr(models, "_try_cloud", _remote_backend)
    monkeypatch.setattr(models, "relevant_findings", lambda **kwargs: [])

    payloads, engine, used_fallback, resolved_model = models.generate_payloads(
        context=context,
        model="qwen3.5:9b",
        use_cloud=True,
        remote_only=True,
        ai_backend="cli",
        cli_tool="codex",
        cloud_model="anthropic/claude-3-5-sonnet",
    )

    assert engine == "cli:codex"
    assert used_fallback is True
    assert resolved_model == "anthropic/claude-3-5-sonnet"
    assert any(payload.source == "cli:codex" for payload in payloads)


def test_generate_payloads_remote_only_with_cloud_disabled_uses_heuristics(monkeypatch) -> None:
    context = ParsedContext(source="https://example.test/search?q=x", source_type="url")

    def _should_not_run(*args, **kwargs):
        raise AssertionError("no AI backend should run when remote-only and cloud is disabled")

    monkeypatch.setattr(models, "_generate_with_ollama", _should_not_run)
    monkeypatch.setattr(models, "_try_cloud", _should_not_run)
    monkeypatch.setattr(models, "relevant_findings", lambda **kwargs: [])

    payloads, engine, used_fallback, resolved_model = models.generate_payloads(
        context=context,
        model="qwen3.5:9b",
        use_cloud=False,
        remote_only=True,
    )

    assert payloads
    assert engine == "heuristic"
    assert used_fallback is True
    assert resolved_model == "qwen3.5:9b"
