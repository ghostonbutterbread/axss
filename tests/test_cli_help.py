import unittest
from unittest.mock import patch

from ai_xss_generator import cli
from ai_xss_generator.cli import build_parser
from ai_xss_generator.config import DEFAULT_MODEL


def _subparser_help(name: str) -> str:
    parser = build_parser(DEFAULT_MODEL)
    for action in parser._subparsers._group_actions:
        sub = action.choices.get(name)
        if sub:
            return sub.format_help()
    return ""


class CliHelpTest(unittest.TestCase):
    def test_top_level_help(self) -> None:
        help_text = build_parser(DEFAULT_MODEL).format_help()
        self.assertIn("-h, --help", help_text)
        self.assertIn("-V, --version", help_text)
        self.assertIn("--clear-reports", help_text)
        self.assertIn("memory", help_text)
        self.assertIn("generate", help_text)
        self.assertIn("scan", help_text)
        self.assertIn("models", help_text)
        # Old flat flags must not appear at top level
        self.assertNotIn("-u TARGET", help_text)
        self.assertNotIn("--memory-list", help_text)
        self.assertNotIn("-l, --list-models", help_text)

    def test_generate_help(self) -> None:
        help_text = _subparser_help("generate")
        self.assertIn("-u TARGET, --url TARGET", help_text)
        self.assertIn("--urls FILE", help_text)
        self.assertIn("-i FILE_OR_SNIPPET, --input FILE_OR_SNIPPET", help_text)
        self.assertIn("--public", help_text)
        self.assertIn("--merge-batch", help_text)
        self.assertIn("-m MODEL, --model MODEL", help_text)
        self.assertIn("--display {list,heat,interactive}", help_text)
        self.assertIn("--format {json}", help_text)
        self.assertIn("-t N, --top N", help_text)
        self.assertIn("-o PATH, --output PATH", help_text)
        self.assertIn("-v, --verbose", help_text)
        self.assertIn("--waf-source PATH", help_text)
        self.assertIn("--no-probe", help_text)
        # generate has no scan-mode flags
        self.assertNotIn("--deep", help_text)
        self.assertNotIn("--fast", help_text)
        self.assertNotIn("--reflected", help_text)
        self.assertNotIn("--extreme", help_text)
        self.assertNotIn("--research", help_text)
        self.assertNotIn("(default: None)", help_text)

    def test_scan_help(self) -> None:
        help_text = _subparser_help("scan")
        self.assertIn("-u TARGET, --url TARGET", help_text)
        self.assertIn("--urls FILE", help_text)
        self.assertIn("--interesting FILE", help_text)
        self.assertIn("--deep", help_text)
        self.assertIn("--fast", help_text)
        self.assertNotIn("--obliterate", help_text)
        self.assertIn("--reflected", help_text)
        self.assertIn("--stored", help_text)
        self.assertIn("--uploads", help_text)
        self.assertIn("--dom", help_text)
        self.assertIn("--attempts N", help_text)
        self.assertIn("--keep-searching", help_text)
        self.assertIn("--waf-source PATH", help_text)
        self.assertIn("-m MODEL, --model MODEL", help_text)
        self.assertIn("--display {list,heat,interactive}", help_text)
        self.assertIn("-o PATH, --output PATH", help_text)
        self.assertNotIn("--extreme", help_text)
        self.assertNotIn("--research", help_text)
        self.assertNotIn("--html", help_text)
        self.assertNotIn("(default: None)", help_text)

    def test_memory_help(self) -> None:
        help_text = _subparser_help("memory")
        self.assertIn("show", help_text)
        self.assertIn("stats", help_text)
        self.assertIn("import", help_text)
        self.assertIn("export", help_text)

    def test_models_help(self) -> None:
        help_text = _subparser_help("models")
        self.assertIn("list", help_text)
        self.assertIn("search", help_text)
        self.assertIn("check-keys", help_text)

    def test_memory_commands_parse_cleanly(self) -> None:
        parser = build_parser(DEFAULT_MODEL)

        args = parser.parse_args(["memory", "show"])
        self.assertEqual(args.command, "memory")
        self.assertEqual(args.memory_action, "show")

        args = parser.parse_args(["memory", "stats"])
        self.assertEqual(args.memory_action, "stats")

        args = parser.parse_args(["memory", "export", "/tmp/out.yaml"])
        self.assertEqual(args.memory_action, "export")
        self.assertEqual(args.path, "/tmp/out.yaml")

        args = parser.parse_args(["memory", "import", "/tmp/in.yaml"])
        self.assertEqual(args.memory_action, "import")
        self.assertEqual(args.path, "/tmp/in.yaml")

        args = parser.parse_args(["scan", "--deep"])
        self.assertEqual(args.command, "scan")
        self.assertTrue(args.deep)

    def test_main_routes_upload_only_scan_to_active_runner(self) -> None:
        captured: dict[str, object] = {}

        def _fake_run_active_scan(*args, **kwargs):
            captured.update(kwargs)
            return 0

        with (
            patch.object(cli, "_run_active_scan", side_effect=_fake_run_active_scan),
            patch("ai_xss_generator.ai_capabilities.choose_generation_tool", return_value=("claude", "")),
        ):
            rc = cli.main(["scan", "-u", "https://example.test/profile", "--uploads"])

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

        with (
            patch.object(cli, "_run_active_scan", side_effect=_fake_run_active_scan),
            patch("ai_xss_generator.ai_capabilities.choose_generation_tool", return_value=("claude", "")),
        ):
            rc = cli.main(["scan", "-u", "https://example.test/profile"])

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

        with (
            patch.object(cli, "_run_active_scan", side_effect=_fake_run_active_scan),
            patch("ai_xss_generator.ai_capabilities.choose_generation_tool", return_value=("claude", "")),
        ):
            rc = cli.main(["scan", "-u", "https://example.test/profile", "--extreme"])

        self.assertEqual(rc, 0)
        self.assertEqual(captured["attempts"], 3)
        self.assertEqual(captured["timeout"], 600)

    def test_scan_help_mode_flags(self) -> None:
        help_text = _subparser_help("scan")
        # --fast is now an explicit flag
        self.assertIn("--fast", help_text)
        # --deep still present
        self.assertIn("--deep", help_text)
        # --obliterate is hidden (suppress=argparse.SUPPRESS) — must NOT appear in help
        self.assertNotIn("--obliterate", help_text)

    def test_obliterate_still_accepted(self) -> None:
        """--obliterate must still parse without error (deprecated hidden alias)."""
        from ai_xss_generator.cli import build_parser
        from ai_xss_generator.config import DEFAULT_MODEL
        parser = build_parser(DEFAULT_MODEL)
        # Should not raise during parse
        args = parser.parse_args(["scan", "-u", "http://example.com", "--obliterate"])
        # argparse sets the flag — mode derivation happens in the handler, not parse_args
        assert args.obliterate is True
        assert args.fast is False
        assert args.deep is False

    def test_main_research_profile_raises_default_attempts_and_timeout(self) -> None:
        captured: dict[str, object] = {}

        def _fake_run_active_scan(*args, **kwargs):
            captured.update(kwargs)
            captured["timeout"] = args[0].timeout
            captured["attempts"] = args[0].attempts
            return 0

        with (
            patch.object(cli, "_run_active_scan", side_effect=_fake_run_active_scan),
            patch("ai_xss_generator.ai_capabilities.choose_generation_tool", return_value=("claude", "")),
        ):
            rc = cli.main(["scan", "-u", "https://example.test/profile", "--research"])

        self.assertEqual(rc, 0)
        self.assertEqual(captured["attempts"], 5)
        self.assertEqual(captured["timeout"], 1200)


if __name__ == "__main__":
    unittest.main()
