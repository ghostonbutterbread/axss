from __future__ import annotations

import re

from ai_xss_generator.types import DomSink, ParsedContext


class RegexSinkParser:
    name = "regex-sinks"

    EXTRA_PATTERNS = {
        "location": re.compile(r"\blocation\s*=\s*", re.IGNORECASE),
        "document.cookie": re.compile(r"document\.cookie", re.IGNORECASE),
        "srcdoc": re.compile(r"\bsrcdoc\s*=", re.IGNORECASE),
    }

    def parse(self, html: str, context: ParsedContext) -> None:
        for sink_name, pattern in self.EXTRA_PATTERNS.items():
            for match in pattern.finditer(html):
                context.dom_sinks.append(
                    DomSink(
                        sink=sink_name,
                        source=html[max(0, match.start() - 30) : match.end() + 60].strip(),
                        location="html-regex",
                        confidence=0.66,
                    )
                )
        if "DOM clobbering candidates present" not in context.notes:
            if re.search(r"\bid=['\"](?:attributes|forms|images|children|parentNode)['\"]", html, re.IGNORECASE):
                context.notes.append("DOM clobbering candidates present.")


PLUGIN = RegexSinkParser()
