from __future__ import annotations

import unittest

from ai_xss_generator.parser import parse_target


class ParserFrameworkDetectionTest(unittest.TestCase):
    def test_plain_css_does_not_trigger_angular_detection(self) -> None:
        html = """<!doctype html>
<html>
  <head><title>Basic Reflective XSS</title></head>
  <body>
    <div style="padding-right: 5px">demo</div>
    <form action="target.ftl">
      <input type="text" name="name" />
      <input type="submit" />
    </form>
  </body>
</html>
"""
        context = parse_target(url=None, html_value=html, parser_plugins=[])
        self.assertNotIn("Angular", context.frameworks)


if __name__ == "__main__":
    unittest.main()
