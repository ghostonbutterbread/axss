from __future__ import annotations
import pytest
from ai_xss_generator.active.generator import payloads_for_context, mutate_seeds


class TestPayloadsForContext:
    def test_html_body_returns_candidates(self):
        results = payloads_for_context("html_body", None)
        assert len(results) > 0
        assert all(hasattr(c, "payload") for c in results)

    def test_html_attr_url_returns_candidates(self):
        results = payloads_for_context("html_attr_url", None)
        assert len(results) > 0

    def test_html_attr_value_returns_candidates(self):
        results = payloads_for_context("html_attr_value", None)
        assert len(results) > 0

    def test_js_string_dq_returns_candidates(self):
        results = payloads_for_context("js_string_dq", None)
        assert len(results) > 0

    def test_js_string_sq_returns_candidates(self):
        results = payloads_for_context("js_string_sq", None)
        assert len(results) > 0

    def test_js_code_returns_candidates(self):
        results = payloads_for_context("js_code", None)
        assert len(results) > 0

    def test_html_attr_event_returns_candidates(self):
        results = payloads_for_context("html_attr_event", None)
        assert len(results) > 0

    def test_unknown_context_returns_empty(self):
        results = payloads_for_context("unknown_context_type", None)
        assert results == []

    def test_none_surviving_chars_bypasses_filter(self):
        # With None, even payloads requiring < should be returned
        results = payloads_for_context("html_body", None)
        payloads = [c.payload for c in results]
        assert any("<" in p for p in payloads)

    def test_empty_surviving_chars_filters_tag_payloads(self):
        # frozenset with no < should exclude html_body tag-injection payloads
        results = payloads_for_context("html_body", frozenset())
        payloads = [c.payload for c in results]
        assert not any("<" in p for p in payloads)

    def test_sorted_by_risk_score_descending(self):
        results = payloads_for_context("html_attr_url", None)
        scores = [c.risk_score for c in results]
        assert scores == sorted(scores, reverse=True)


class TestMutateSeeds:
    def test_returns_list_of_strings(self):
        results = mutate_seeds(["javascript:alert(1)"], None)
        assert isinstance(results, list)
        assert all(isinstance(s, str) for s in results)

    def test_empty_seeds_returns_empty(self):
        assert mutate_seeds([], None) == []

    def test_produces_case_variants(self):
        results = mutate_seeds(["<img src=x onerror=alert(1)>"], None)
        # At least one result should differ in case from the original
        assert any(r != "<img src=x onerror=alert(1)>" for r in results)

    def test_produces_encoding_variants(self):
        results = mutate_seeds(["javascript:alert(1)"], None)
        # Should include at least one entity-encoded or hex variant
        has_encoded = any("&#" in r or "\\x" in r or "\\u" in r or "%" in r for r in results)
        assert has_encoded

    def test_deduplicates_output(self):
        results = mutate_seeds(["alert(1)", "alert(1)"], None)
        assert len(results) == len(set(results))

    def test_surviving_chars_filters_mutations(self):
        # No < in surviving_chars — mutations requiring < should be excluded
        seeds = ["<img src=x onerror=alert(1)>"]
        results = mutate_seeds(seeds, frozenset("abcdefghijklmnopqrstuvwxyz()1\"' "))
        assert not any("<" in r for r in results)

    def test_max_fifteen_variants(self):
        results = mutate_seeds(["javascript:alert(1)"], None)
        assert len(results) <= 15

    def test_original_seed_not_in_output(self):
        # mutate_seeds returns mutations only, not the original seed itself
        seed = "javascript:alert(1)"
        results = mutate_seeds([seed], None)
        assert seed not in results
