from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from ai_xss_generator.config import ResolvedAIConfig
from ai_xss_generator.interesting import (
    InterestingUrl,
    analyze_interesting_urls,
    write_interesting_report,
)


def test_analyze_interesting_urls_sorts_and_fills_missing_rows() -> None:
    ai_config = ResolvedAIConfig(
        model="qwen3.5:9b",
        use_cloud=True,
        cloud_model="anthropic/claude-3-5-sonnet",
        ai_backend="cli",
        cli_tool="claude",
        cli_model=None,
    )
    urls = [
        "https://example.test/login?startURL=/account",
        "https://example.test/search?q=test",
        "https://example.test/api?origin=x",
    ]
    payload = {
        "results": [
            {
                "url": urls[1],
                "score": 88,
                "verdict": "high",
                "reason": "Direct search parameter on an HTML page.",
                "candidate_params": ["q"],
                "likely_xss_types": ["reflected", "dom"],
                "recommended_mode": "single-target reflected",
                "next_step": "Run reflected mode first with per-context tracing.",
            },
            {
                "url": urls[0],
                "score": 76,
                "verdict": "medium",
                "reason": "Login handoff parameter may reflect in an auth template.",
                "candidate_params": ["startURL"],
                "likely_xss_types": ["reflected"],
                "recommended_mode": "single-target active",
                "next_step": "Check reflected and DOM handling on the login shell.",
            },
        ]
    }

    with patch(
        "ai_xss_generator.interesting._call_backend",
        return_value=(__import__("json").dumps(payload), "cli:claude"),
    ):
        results = analyze_interesting_urls(urls, ai_config)

    assert [item.url for item in results] == [urls[1], urls[0], urls[2]]
    assert results[0].score == 88
    assert results[2].verdict == "low"
    assert "did not identify a strong XSS signal" in results[2].reason


def test_write_interesting_report_writes_markdown() -> None:
    results = [
        InterestingUrl(
            url="https://example.test/search?q=test",
            score=91,
            verdict="high",
            reason="Search parameter is a strong reflection candidate.",
            candidate_params=["q"],
            likely_xss_types=["reflected", "dom"],
            recommended_mode="single-target reflected",
            next_step="Run reflected mode first.",
            ai_engine="cli:claude",
        )
    ]
    ai_config = ResolvedAIConfig(
        model="qwen3.5:9b",
        use_cloud=True,
        cloud_model="anthropic/claude-3-5-sonnet",
        ai_backend="cli",
        cli_tool="claude",
        cli_model=None,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = Path(tmpdir) / "interesting.md"
        written = write_interesting_report(
            results,
            source_file="/tmp/urls.txt",
            ai_config=ai_config,
            output_path=str(report_path),
        )
        body = report_path.read_text(encoding="utf-8")

    assert written == str(report_path)
    assert "# axss Interesting URL Report" in body
    assert "https://example.test/search?q=test" in body
    assert "single-target reflected" in body
