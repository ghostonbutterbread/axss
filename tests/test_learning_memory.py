"""Tests for the curated SQLite knowledge store (findings.py + store.py)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai_xss_generator.findings import (
    Finding,
    count_findings,
    export_yaml,
    import_yaml,
    load_findings,
    memory_stats,
    relevant_findings,
    save_finding,
)


def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        sink_type="html_body",
        context_type="html_attr_value",
        surviving_chars="<>\"'",
        bypass_family="event-handler-injection",
        payload="<img src=x onerror=alert(1)>",
        explanation="Classic onerror vector.",
        waf_name="",
        delivery_mode="get",
        frameworks=[],
        confidence=1.0,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class CuratedStoreTest(unittest.TestCase):

    def setUp(self):
        import ai_xss_generator.store as _store
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp_db = Path(self._tmpdir.name) / "knowledge.db"
        self._patcher = patch.object(_store, "DB_PATH", self._tmp_db)
        self._patcher.start()
        _store.init_db()

    def tearDown(self):
        self._patcher.stop()
        self._tmpdir.cleanup()

    def test_save_and_load(self):
        f = _make_finding(payload="<svg onload=alert(1)>", bypass_family="svg-namespace")
        saved = save_finding(f)
        self.assertTrue(saved)
        findings = load_findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].payload, "<svg onload=alert(1)>")

    def test_deduplication(self):
        f = _make_finding()
        save_finding(f)
        saved_again = save_finding(f)
        self.assertFalse(saved_again)
        self.assertEqual(count_findings(), 1)

    def test_count_by_context_type(self):
        save_finding(_make_finding(context_type="html_attr_value", payload="p1"))
        save_finding(_make_finding(context_type="js_string_dq", payload="p2",
                                   bypass_family="js-string-breakout"))
        self.assertEqual(count_findings("html_attr_value"), 1)
        self.assertEqual(count_findings("js_string_dq"), 1)
        self.assertEqual(count_findings(), 2)

    def test_memory_stats(self):
        save_finding(_make_finding())
        stats = memory_stats()
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["curated"], 1)

    def test_relevant_findings_scoring(self):
        save_finding(_make_finding(
            context_type="html_attr_value",
            sink_type="reflected_attr",
            bypass_family="html-attribute-breakout",
            payload='"><svg onload=alert(1)>',
            waf_name="cloudflare",
            delivery_mode="get",
        ))
        save_finding(_make_finding(
            context_type="js_string_dq",
            sink_type="js_string",
            bypass_family="js-string-breakout",
            payload='";alert(1)//',
            delivery_mode="get",
        ))
        results = relevant_findings(
            sink_type="reflected_attr",
            context_type="html_attr_value",
            surviving_chars='<>"',
            waf_name="cloudflare",
            delivery_mode="get",
        )
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0].bypass_family, "html-attribute-breakout")

    def test_export_and_import_yaml(self):
        save_finding(_make_finding(payload="p_export", explanation="export test"))
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as tmp:
            yaml_path = Path(tmp.name)

        try:
            exported = export_yaml(yaml_path)
            self.assertEqual(exported, 1)

            import ai_xss_generator.store as _store
            with _store._connect() as conn:
                conn.execute("DELETE FROM curated_findings")

            self.assertEqual(count_findings(), 0)
            inserted, skipped = import_yaml(yaml_path)
            self.assertEqual(inserted, 1)
            self.assertEqual(skipped, 0)
            self.assertEqual(count_findings(), 1)
        finally:
            yaml_path.unlink(missing_ok=True)

    def test_no_host_scope_contamination(self):
        """All curated findings are global — retrieved regardless of target_host."""
        save_finding(_make_finding(
            context_type="html_body",
            payload="<details ontoggle=alert(1)>",
            bypass_family="event-handler-injection",
        ))
        results_a = relevant_findings(
            sink_type="html_body",
            context_type="html_body",
            surviving_chars="<>",
            target_host="site-a.example.com",
        )
        results_b = relevant_findings(
            sink_type="html_body",
            context_type="html_body",
            surviving_chars="<>",
            target_host="site-b.example.com",
        )
        self.assertEqual(len(results_a), 1)
        self.assertEqual(len(results_b), 1)


if __name__ == "__main__":
    unittest.main()
