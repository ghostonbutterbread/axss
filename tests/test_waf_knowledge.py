from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ai_xss_generator.models import _cloud_prompt_for_context
from ai_xss_generator.types import ParsedContext
from ai_xss_generator.waf_knowledge import analyze_waf_source, attach_waf_knowledge


def test_analyze_waf_source_extracts_compact_modsecurity_profile(tmp_path) -> None:
    rules = tmp_path / "REQUEST-941-APPLICATION-ATTACK-XSS.conf"
    rules.write_text(
        """
        SecRuleEngine On
        SecRule ARGS "@rx (?i:javascript:|onerror|<script)" \
            "id:941100,phase:2,deny,t:urlDecodeUni,t:lowercase"
        """,
        encoding="utf-8",
    )

    profile = analyze_waf_source(str(tmp_path))

    assert profile.engine_name in {"modsecurity", "coraza"}
    assert profile.normalization["url_decode_passes"] == 1
    assert profile.normalization["case_fold"] == "lower"
    assert profile.matching["javascript_scheme_focus"] is True
    assert "plain_javascript_uri" in profile.likely_pressure_points
    assert "entity_encoding" in profile.preferred_strategies
    assert "plain_javascript_uri" in profile.avoid_strategies


def test_analyze_waf_source_clones_remote_repo_before_analysis(monkeypatch, tmp_path) -> None:
    remote = "https://github.com/example/waf-rules.git"

    monkeypatch.setattr("ai_xss_generator.waf_knowledge._REMOTE_CACHE_ROOT", tmp_path / "remote-cache")
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/git" if cmd == "git" else None)

    def _fake_run(cmd, check, stdout, stderr, text):
        clone_dir = cmd[-1]
        target = tmp_path / "remote-cache" / clone_dir.split("/")[-1]
        target.mkdir(parents=True, exist_ok=True)
        (target / "rules.conf").write_text(
            'SecRule ARGS "@rx javascript:" "id:1,deny,t:urlDecodeUni,t:lowercase"',
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr("subprocess.run", _fake_run)

    profile = analyze_waf_source(remote)

    assert profile.source_type == "remote_git_clone"
    assert profile.engine_name == "modsecurity"
    assert Path(profile.source_ref).exists()


def test_analyze_waf_source_remote_repo_requires_git(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda cmd: None)
    with pytest.raises(RuntimeError):
        analyze_waf_source("https://github.com/coreruleset/coreruleset.git")


def test_prompt_includes_waf_knowledge_section_when_attached(tmp_path) -> None:
    rules = tmp_path / "filter.py"
    rules.write_text(
        """
        import re
        BLOCK = re.compile(r"javascript:|onload|onerror", re.IGNORECASE)
        def blocked(value):
            return bool(BLOCK.search(value.lower()))
        """,
        encoding="utf-8",
    )
    profile = analyze_waf_source(str(tmp_path))
    context = ParsedContext(
        source="https://example.test/search?q=x",
        source_type="url",
    )

    enriched = attach_waf_knowledge(context, profile)

    assert enriched is not None
    prompt = _cloud_prompt_for_context(enriched)
    assert "PLANNING ENVELOPE" in prompt
    assert profile.engine_name in prompt
    assert "waf_prior" in prompt
    assert "preferred_strategies" in prompt
