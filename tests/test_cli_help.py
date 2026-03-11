import unittest

from ai_xss_generator.cli import build_parser
from ai_xss_generator.config import DEFAULT_MODEL


class CliHelpTest(unittest.TestCase):
    def test_help_pairs_are_clear(self) -> None:
        help_text = build_parser(DEFAULT_MODEL).format_help()

        self.assertIn("-h, --help", help_text)
        self.assertIn("-u TARGET, --url TARGET", help_text)
        self.assertIn("--urls FILE", help_text)
        self.assertIn("-i FILE_OR_SNIPPET, --input FILE_OR_SNIPPET", help_text)
        self.assertIn("-l, --list-models", help_text)
        self.assertIn("-s QUERY, --search-models QUERY", help_text)
        self.assertIn("-m MODEL, --model MODEL", help_text)
        self.assertIn("-o {json,list,heat,interactive}, --output", help_text)
        self.assertIn("-t N, --top N", help_text)
        self.assertIn("-j PATH, --json-out PATH", help_text)
        self.assertIn("-v, --verbose", help_text)
        self.assertIn("--merge-batch", help_text)
        self.assertIn("--memory-review [SOURCE]", help_text)
        self.assertIn("--memory-list [SOURCE]", help_text)
        self.assertIn("--memory-stats [SOURCE]", help_text)
        self.assertNotIn("--memory-source SOURCE", help_text)
        self.assertIn("-V, --version", help_text)
        # New XSS type selectors
        self.assertIn("--generate", help_text)
        self.assertIn("--reflected", help_text)
        self.assertIn("--stored", help_text)
        self.assertIn("--dom", help_text)
        self.assertNotIn("--html", help_text)
        self.assertNotIn("(default: None)", help_text)

    def test_memory_command_source_arguments_parse_cleanly(self) -> None:
        parser = build_parser(DEFAULT_MODEL)

        args = parser.parse_args(["--memory-review"])
        self.assertEqual(args.memory_review, "all")

        args = parser.parse_args(["--memory-review", "labs"])
        self.assertEqual(args.memory_review, "labs")

        args = parser.parse_args(["--memory-list", "targets"])
        self.assertEqual(args.memory_list, "targets")

        args = parser.parse_args(["--memory-stats"])
        self.assertEqual(args.memory_stats, "all")

    def test_memory_limit_must_be_positive(self) -> None:
        parser = build_parser(DEFAULT_MODEL)

        with self.assertRaises(SystemExit):
            parser.parse_args(["--memory-review", "--memory-limit", "0"])


if __name__ == "__main__":
    unittest.main()
