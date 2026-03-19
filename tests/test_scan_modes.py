"""Tests for three-tier scan mode config and worker routing."""
from __future__ import annotations
import pytest
from ai_xss_generator.active.orchestrator import ActiveScanConfig


class TestActiveScanConfigMode:
    def test_default_mode_is_normal(self):
        cfg = ActiveScanConfig()
        assert cfg.mode == "normal"

    def test_fast_mode(self):
        cfg = ActiveScanConfig(mode="fast")
        assert cfg.mode == "fast"

    def test_deep_mode(self):
        cfg = ActiveScanConfig(mode="deep")
        assert cfg.mode == "deep"

    def test_no_fast_field(self):
        cfg = ActiveScanConfig()
        assert not hasattr(cfg, "fast"), "fast boolean field should be removed"

    def test_no_deep_field(self):
        cfg = ActiveScanConfig()
        assert not hasattr(cfg, "deep"), "deep boolean field should be removed"

    def test_no_obliterate_field(self):
        cfg = ActiveScanConfig()
        assert not hasattr(cfg, "obliterate"), "obliterate boolean field should be removed"


class TestDomWorkerSignature:
    def test_run_dom_worker_accepts_findings_lock(self):
        """run_dom_worker must accept a findings_lock parameter."""
        import inspect
        from ai_xss_generator.active.worker import run_dom_worker
        sig = inspect.signature(run_dom_worker)
        assert "findings_lock" in sig.parameters

    def test_run_dom_worker_accepts_dom_sources(self):
        """run_dom_worker must accept a dom_sources parameter."""
        import inspect
        from ai_xss_generator.active.worker import run_dom_worker
        sig = inspect.signature(run_dom_worker)
        assert "dom_sources" in sig.parameters


class TestNormalModeParallelDispatch:
    def test_normal_mode_uses_at_least_two_worker_slots(self):
        """Normal mode with rate >= 2 must guarantee at least 2 concurrent worker slots."""
        from ai_xss_generator.active.orchestrator import _auto_workers_for_mode

        # rate=5, explicit_workers=10 → Normal mode should return at least 2
        n = _auto_workers_for_mode("normal", rate=5.0, explicit_workers=10)
        assert n >= 2

        # Fast mode: uses _auto_workers normally (no minimum-2 guarantee)
        n_fast = _auto_workers_for_mode("fast", rate=5.0, explicit_workers=10)
        assert n_fast >= 1  # no special guarantee

    def test_normal_mode_rate_less_than_2_uses_one_slot(self):
        """Normal mode with rate < 2 falls back to single-pool (no split)."""
        from ai_xss_generator.active.orchestrator import _auto_workers_for_mode
        n = _auto_workers_for_mode("normal", rate=1.0, explicit_workers=10)
        assert n == 1


class TestSkipTriageConfig:
    def test_skip_triage_default_false(self):
        from ai_xss_generator.active.orchestrator import ActiveScanConfig
        cfg = ActiveScanConfig()
        assert cfg.skip_triage is False

    def test_skip_triage_settable(self):
        from ai_xss_generator.active.orchestrator import ActiveScanConfig
        cfg = ActiveScanConfig(skip_triage=True)
        assert cfg.skip_triage is True


class TestFastBatchNormalModeRemoval:
    def test_normal_mode_does_not_call_generate_fast_batch(self):
        """generate_fast_batch must only be called for fast mode, not normal."""
        import inspect
        from ai_xss_generator.active import orchestrator
        src = inspect.getsource(orchestrator)
        assert 'mode in ("fast", "normal")' not in src, \
            "generate_fast_batch should only run in fast mode"
