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
