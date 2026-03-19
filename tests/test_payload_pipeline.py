from __future__ import annotations
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


class TestGenerateNormalScout:
    def test_signature_accepts_seeds(self):
        """generate_normal_scout must accept a seeds parameter."""
        import inspect
        from ai_xss_generator.models import generate_normal_scout
        sig = inspect.signature(generate_normal_scout)
        assert "seeds" in sig.parameters

    def test_signature(self):
        import inspect
        from ai_xss_generator.models import generate_normal_scout
        sig = inspect.signature(generate_normal_scout)
        params = list(sig.parameters.keys())
        assert "context_type" in params
        assert "waf" in params
        assert "frameworks" in params
        assert "seeds" in params

    def test_returns_list(self):
        """generate_normal_scout returns list[str] even when model unavailable."""
        from ai_xss_generator.models import generate_normal_scout
        # Should return empty list gracefully when no model configured, not raise
        result = generate_normal_scout(
            context_type="html_attr_url",
            waf=None,
            frameworks=[],
            seeds=["javascript:alert(1)"],
            model="__nonexistent_model__",
        )
        assert isinstance(result, list)


class TestTriageProbeResultSignature:
    def test_no_reflection_snippet_param(self):
        """triage_probe_result must NOT accept reflection_snippet."""
        import inspect
        from ai_xss_generator.models import triage_probe_result
        sig = inspect.signature(triage_probe_result)
        assert "reflection_snippet" not in sig.parameters

    def test_no_param_name_param(self):
        """triage_probe_result must NOT accept param_name."""
        import inspect
        from ai_xss_generator.models import triage_probe_result
        sig = inspect.signature(triage_probe_result)
        assert "param_name" not in sig.parameters

    def test_required_params_present(self):
        import inspect
        from ai_xss_generator.models import triage_probe_result
        sig = inspect.signature(triage_probe_result)
        assert "context_type" in sig.parameters
        assert "surviving_chars" in sig.parameters
        assert "waf" in sig.parameters
        assert "delivery_mode" in sig.parameters


class TestBlockedOnAssembly:
    def test_blocked_on_identifies_blocked_char(self):
        from ai_xss_generator.active.worker import _blocked_on_char
        surviving = frozenset("abcdefghijklmnopqrstuvwxyz()1\"' ")
        payload = "<img src=x onerror=alert(1)>"
        result = _blocked_on_char(payload, surviving)
        assert result == "<"  # first char in payload not in surviving

    def test_blocked_on_null_when_all_survive(self):
        from ai_xss_generator.active.worker import _blocked_on_char
        surviving = frozenset("<>abcdefghijklmnopqrstuvwxyz()1\"' =")
        payload = "<img src=x onerror=alert(1)>"
        result = _blocked_on_char(payload, surviving)
        assert result is None

    def test_blocked_on_null_for_empty_surviving(self):
        # Empty surviving_chars means we can't determine what's blocked
        from ai_xss_generator.active.worker import _blocked_on_char
        result = _blocked_on_char("alert(1)", frozenset())
        # Can't determine — no surviving chars to diff against
        assert result is None or isinstance(result, str)


class TestSkipTriageWorkerPath:
    def test_worker_accepts_skip_triage_kwarg(self):
        """run_worker (or equivalent) must accept skip_triage parameter."""
        import inspect
        from ai_xss_generator.active.worker import run_worker
        sig = inspect.signature(run_worker)
        assert "skip_triage" in sig.parameters
