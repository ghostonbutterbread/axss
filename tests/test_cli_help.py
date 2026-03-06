import unittest

from ai_xss_generator.cli import build_parser
from ai_xss_generator.config import DEFAULT_MODEL


class CliHelpTest(unittest.TestCase):
    def test_help_pairs_are_clear(self) -> None:
        help_text = build_parser(DEFAULT_MODEL).format_help()

        self.assertIn("-h, --help", help_text)
        self.assertIn("-u, --url TARGET", help_text)
        self.assertIn("-i, --html FILE_OR_SNIPPET", help_text)
        self.assertIn("-l, --list-models", help_text)
        self.assertIn("-s, --search-models QUERY", help_text)
        self.assertIn("-m, --model MODEL", help_text)
        self.assertIn("-o, --output {json,list,heat}", help_text)
        self.assertIn("-t, --top N", help_text)
        self.assertIn("-j, --json-out PATH", help_text)
        self.assertIn("-V, --version", help_text)
        self.assertNotIn("-h, --html", help_text)
        self.assertNotIn("(default: None)", help_text)


if __name__ == "__main__":
    unittest.main()
