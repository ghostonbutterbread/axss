import unittest
from unittest.mock import patch

from ai_xss_generator import cli
from ai_xss_generator.cli import build_parser
from ai_xss_generator.config import DEFAULT_MODEL


class CliHelpTest(unittest.TestCase):
    def test_help_pairs_are_clear(self) -> None:
        help_text = build_parser(DEFAULT_MODEL).format_help()

        self.assertIn("-h, --help", help_text)
        self.assertIn("-u TARGET, --url TARGET", help_text)
        self.assertIn("--urls FILE", help_text)
        self.assertIn("--interesting FILE", help_text)
        self.assertIn("-i FILE_OR_SNIPPET, --input FILE_OR_SNIPPET", help_text)
        self.assertIn("-l, --list-models", help_text)
        self.assertIn("-s QUERY, --search-models QUERY", help_text)
        self.assertIn("-m MODEL, --model MODEL", help_text)
        self.assertIn("-o {json,list,heat,interactive}, --output", help_text)
        self.assertIn("-t N, --top N", help_text)
        self.assertIn("-j PATH, --json-out PATH", help_text)
        self.assertIn("-v, --verbose", help_text)
        self.assertIn("--merge-batch", help_text)
        self.assertIn("--attempts N", help_text)
        self.assertIn("--extreme", help_text)
        self.assertIn("--waf-source PATH", help_text)
        self.assertIn("--memory-list", help_text)
        self.assertIn("--memory-stats", help_text)
        self.assertIn("--memory-export", help_text)
        self.assertIn("--memory-import", help_text)
        self.assertNotIn("--memory-review", help_text)
        self.assertNotIn("--memory-promote", help_text)
        self.assertNotIn("--memory-reject", help_text)
        self.assertIn("-V, --version", help_text)
        # XSS type selectors
        self.assertIn("--generate", help_text)
        self.assertIn("--reflected", help_text)
        self.assertIn("--stored", help_text)
        self.assertIn("--uploads", help_text)
        self.assertIn("--dom", help_text)
        self.assertNotIn("--html", help_text)
        self.assertNotIn("(default: None)", help_text)

    def test_memory_commands_parse_cleanly(self) -> None:
        parser = build_parser(DEFAULT_MODEL)

        args = parser.parse_args(["--memory-list"])
        self.assertTrue(args.memory_list)

        args = parser.parse_args(["--memory-stats"])
        self.assertTrue(args.memory_stats)

        args = parser.parse_args(["--memory-export", "/tmp/out.yaml"])
        self.assertEqual(args.memory_export, "/tmp/out.yaml")

        args = parser.parse_args(["--memory-import", "/tmp/in.yaml"])
        self.assertEqual(args.memory_import, "/tmp/in.yaml")

    def test_main_routes_upload_only_scan_to_active_runner(self) -> None:
        captured: dict[str, object] = {}

        def _fake_run_active_scan(*args, **kwargs):
            captured.update(kwargs)
            return 0

        with patch.object(cli, "_run_active_scan", side_effect=_fake_run_active_scan):
            rc = cli.main(["-u", "https://example.test/profile", "--uploads"])

        self.assertEqual(rc, 0)
        self.assertFalse(captured["scan_reflected"])
        self.assertFalse(captured["scan_stored"])
        self.assertTrue(captured["scan_uploads"])
        self.assertFalse(captured["scan_dom"])

    def test_main_default_active_scan_includes_uploads(self) -> None:
        captured: dict[str, object] = {}

        def _fake_run_active_scan(*args, **kwargs):
            captured.update(kwargs)
            return 0

        with patch.object(cli, "_run_active_scan", side_effect=_fake_run_active_scan):
            rc = cli.main(["-u", "https://example.test/profile"])

        self.assertEqual(rc, 0)
        self.assertTrue(captured["scan_reflected"])
        self.assertTrue(captured["scan_stored"])
        self.assertTrue(captured["scan_uploads"])
        self.assertTrue(captured["scan_dom"])

    def test_main_extreme_profile_raises_default_attempts_and_timeout(self) -> None:
        captured: dict[str, object] = {}

        def _fake_run_active_scan(*args, **kwargs):
            captured.update(kwargs)
            captured["timeout"] = args[0].timeout
            captured["attempts"] = args[0].attempts
            return 0

        with patch.object(cli, "_run_active_scan", side_effect=_fake_run_active_scan):
            rc = cli.main(["-u", "https://example.test/profile", "--extreme"])

        self.assertEqual(rc, 0)
        self.assertEqual(captured["attempts"], 3)
        self.assertEqual(captured["timeout"], 600)


if __name__ == "__main__":
    unittest.main()
