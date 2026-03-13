from __future__ import annotations

import pytest

from ai_xss_generator.models import _prompt_for_context
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


def test_analyze_waf_source_rejects_remote_sources_for_manual_first_mode() -> None:
    with pytest.raises(ValueError):
        analyze_waf_source("https://github.com/coreruleset/coreruleset")


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
    prompt = _prompt_for_context(enriched)
    assert "WAF SOURCE KNOWLEDGE" in prompt
    assert profile.engine_name in prompt
    assert "preferred_strategies" in prompt
