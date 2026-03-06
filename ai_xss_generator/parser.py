from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import re
from pathlib import Path
from typing import Any

from ai_xss_generator.types import DomSink, FormContext, FormField, ParsedContext, ScriptVariable

EVENT_HANDLER_RE = re.compile(r"\bon[a-z0-9_-]+\b", re.IGNORECASE)
FRAMEWORK_PATTERNS = {
    "React": re.compile(r"react|data-reactroot|dangerouslySetInnerHTML|jsx", re.IGNORECASE),
    "Vue": re.compile(r"v-|vue|@click|:class|{{.*?}}", re.IGNORECASE | re.DOTALL),
    "Angular": re.compile(r"ng-|angular|\$scope|\[ng", re.IGNORECASE),
    "AngularJS": re.compile(r"ng-app|ng-controller|\$eval|\$parse", re.IGNORECASE),
}
SINK_PATTERNS = {
    "innerHTML": re.compile(r"\.innerHTML\s*=|innerHTML\s*:", re.IGNORECASE),
    "outerHTML": re.compile(r"\.outerHTML\s*=", re.IGNORECASE),
    "insertAdjacentHTML": re.compile(r"insertAdjacentHTML\s*\(", re.IGNORECASE),
    "eval": re.compile(r"\beval\s*\(", re.IGNORECASE),
    "setTimeout": re.compile(r"\bsetTimeout\s*\(", re.IGNORECASE),
    "setInterval": re.compile(r"\bsetInterval\s*\(", re.IGNORECASE),
    "document.write": re.compile(r"document\.write\s*\(", re.IGNORECASE),
    "Function": re.compile(r"\bFunction\s*\(", re.IGNORECASE),
}
VARIABLE_RE = re.compile(
    r"\b(var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)",
    re.IGNORECASE,
)
OBJECT_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*:\s*{", re.IGNORECASE)

try:
    from scrapy import Selector
    from scrapy.http import Response
except Exception:  # pragma: no cover - exercised only when scrapy is unavailable
    Selector = None
    Response = Any


@dataclass(slots=True)
class MarkupExtraction:
    title: str
    forms: list[FormContext]
    inputs: list[FormField]
    handlers: list[str]
    inline_scripts: list[str]
    notes: list[str]


@dataclass(slots=True)
class BatchParseError:
    url: str
    error: str

    def to_dict(self) -> dict[str, str]:
        return {"url": self.url, "error": self.error}


class _MiniHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title = ""
        self.in_title = False
        self.forms: list[FormContext] = []
        self.inputs: list[FormField] = []
        self.handlers: set[str] = set()
        self.inline_scripts: list[str] = []
        self._current_form: FormContext | None = None
        self._in_script = False
        self._script_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key: (value or "") for key, value in attrs}
        for key in attr_map:
            if EVENT_HANDLER_RE.fullmatch(key):
                self.handlers.add(key)
        if tag == "form":
            self._current_form = FormContext(
                action=attr_map.get("action", ""),
                method=(attr_map.get("method", "get") or "get").upper(),
            )
            self.forms.append(self._current_form)
        elif tag in {"input", "textarea", "select", "button"}:
            field = FormField(
                tag=tag,
                name=attr_map.get("name", ""),
                input_type=attr_map.get("type", tag),
                id_value=attr_map.get("id", ""),
                placeholder=attr_map.get("placeholder", ""),
            )
            self.inputs.append(field)
            if self._current_form is not None:
                self._current_form.fields.append(field)
        elif tag == "script":
            self._in_script = True
            self._script_chunks = []
        elif tag == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None
        elif tag == "script" and self._in_script:
            self.inline_scripts.append("".join(self._script_chunks).strip())
            self._in_script = False
            self._script_chunks = []
        elif tag == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title += data.strip()
        if self._in_script:
            self._script_chunks.append(data)


def _field_from_attrs(tag: str, attr_map: dict[str, str]) -> FormField:
    return FormField(
        tag=tag,
        name=attr_map.get("name", ""),
        input_type=attr_map.get("type", tag),
        id_value=attr_map.get("id", ""),
        placeholder=attr_map.get("placeholder", ""),
    )


def _extract_with_selectors(selector: Any) -> MarkupExtraction:
    title = " ".join(part.strip() for part in selector.css("title::text").getall() if part.strip()).strip()

    forms: list[FormContext] = []
    inputs: list[FormField] = []
    handlers: set[str] = set()
    inline_scripts: list[str] = []

    for element in selector.xpath("//*"):
        for attr_name in element.attrib:
            if EVENT_HANDLER_RE.fullmatch(attr_name):
                handlers.add(attr_name)

    for field in selector.css("input, textarea, select, button"):
        inputs.append(_field_from_attrs(field.root.tag, dict(field.attrib)))

    for form in selector.css("form"):
        form_context = FormContext(
            action=form.attrib.get("action", ""),
            method=(form.attrib.get("method", "get") or "get").upper(),
        )
        for field in form.css("input, textarea, select, button"):
            form_context.fields.append(_field_from_attrs(field.root.tag, dict(field.attrib)))
        forms.append(form_context)

    for script in selector.css("script"):
        if script.attrib.get("src"):
            continue
        inline = "".join(script.xpath("text()").getall()).strip()
        if inline:
            inline_scripts.append(inline)

    return MarkupExtraction(
        title=title,
        forms=forms,
        inputs=inputs,
        handlers=sorted(handlers),
        inline_scripts=inline_scripts,
        notes=["Parsed HTML with Scrapy selectors."],
    )


def _extract_with_stdlib(html: str) -> MarkupExtraction:
    parser = _MiniHTMLParser()
    parser.feed(html)
    return MarkupExtraction(
        title=parser.title,
        forms=parser.forms,
        inputs=parser.inputs,
        handlers=sorted(parser.handlers),
        inline_scripts=parser.inline_scripts,
        notes=["Scrapy unavailable; used stdlib HTMLParser fallback."],
    )


def _extract_html_context(html: str) -> MarkupExtraction:
    if Selector is not None:
        return _extract_with_selectors(Selector(text=html))
    return _extract_with_stdlib(html)


def extract_markup_from_response(response: Response) -> MarkupExtraction:
    return _extract_with_selectors(response.selector)


def _extract_frameworks(html: str, scripts: list[str]) -> list[str]:
    blob = html + "\n" + "\n".join(scripts)
    frameworks = [name for name, pattern in FRAMEWORK_PATTERNS.items() if pattern.search(blob)]
    deduped: list[str] = []
    for framework in frameworks:
        if framework not in deduped:
            deduped.append(framework)
    return deduped


def _walk_esprima_node(node: Any) -> list[Any]:
    stack = [node]
    visited: list[Any] = []
    while stack:
        current = stack.pop()
        if current is None:
            continue
        visited.append(current)
        if isinstance(current, list):
            stack.extend(reversed(current))
            continue
        for value in getattr(current, "__dict__", {}).values():
            if isinstance(value, (list, tuple)):
                stack.extend(reversed(list(value)))
            elif hasattr(value, "__dict__"):
                stack.append(value)
    return visited


def _extract_with_esprima(scripts: list[str]) -> tuple[list[DomSink], list[ScriptVariable], list[str], list[str]]:
    try:
        import esprima  # type: ignore
    except Exception:
        return [], [], [], []

    sinks: list[DomSink] = []
    variables: list[ScriptVariable] = []
    objects: list[str] = []
    notes: list[str] = []
    sink_calls = {"eval", "setTimeout", "setInterval", "Function"}
    sink_properties = {"innerHTML", "outerHTML"}

    for script_index, script in enumerate(scripts, start=1):
        try:
            tree = esprima.parseScript(script, {"tolerant": True, "loc": True})
        except Exception:
            continue
        notes.append("Parsed scripts with esprima AST.")
        for node in _walk_esprima_node(tree):
            node_type = getattr(node, "type", "")
            if node_type == "VariableDeclarator" and getattr(node, "id", None) is not None:
                name = getattr(getattr(node, "id", None), "name", "")
                init = getattr(node, "init", None)
                if name:
                    variables.append(
                        ScriptVariable(
                            name=name,
                            kind="var",
                            expression=str(init)[:120] if init is not None else "",
                        )
                    )
                if getattr(init, "type", "") == "ObjectExpression":
                    objects.append(name)
            elif node_type == "CallExpression":
                callee = getattr(node, "callee", None)
                callee_name = getattr(callee, "name", "")
                if callee_name in sink_calls:
                    loc = getattr(node, "loc", None)
                    line = getattr(getattr(loc, "start", None), "line", "?")
                    sinks.append(
                        DomSink(
                            sink=callee_name,
                            source=str(node)[:180],
                            location=f"script[{script_index}]:{line}",
                            confidence=0.97,
                        )
                    )
                if getattr(callee, "type", "") == "MemberExpression":
                    property_name = getattr(getattr(callee, "property", None), "name", "")
                    if property_name == "insertAdjacentHTML":
                        loc = getattr(node, "loc", None)
                        line = getattr(getattr(loc, "start", None), "line", "?")
                        sinks.append(
                            DomSink(
                                sink=property_name,
                                source=str(node)[:180],
                                location=f"script[{script_index}]:{line}",
                                confidence=0.95,
                            )
                        )
            elif node_type == "AssignmentExpression":
                left = getattr(node, "left", None)
                if getattr(left, "type", "") == "MemberExpression":
                    property_name = getattr(getattr(left, "property", None), "name", "")
                    if property_name in sink_properties:
                        loc = getattr(node, "loc", None)
                        line = getattr(getattr(loc, "start", None), "line", "?")
                        sinks.append(
                            DomSink(
                                sink=property_name,
                                source=str(node)[:180],
                                location=f"script[{script_index}]:{line}",
                                confidence=0.97,
                            )
                        )
    return sinks, variables, sorted(set(objects)), list(dict.fromkeys(notes))


def _extract_sinks(scripts: list[str]) -> list[DomSink]:
    sinks: list[DomSink] = []
    for index, script in enumerate(scripts, start=1):
        location = f"script[{index}]"
        for sink_name, pattern in SINK_PATTERNS.items():
            for match in pattern.finditer(script):
                snippet_start = max(0, match.start() - 40)
                snippet_end = min(len(script), match.end() + 80)
                sinks.append(
                    DomSink(
                        sink=sink_name,
                        source=script[snippet_start:snippet_end].strip(),
                        location=location,
                        confidence=0.93 if sink_name in {"innerHTML", "eval", "Function"} else 0.84,
                    )
                )
    return sinks


def _extract_variables(scripts: list[str]) -> tuple[list[ScriptVariable], list[str]]:
    variables: list[ScriptVariable] = []
    objects: list[str] = []
    for script in scripts:
        for match in VARIABLE_RE.finditer(script):
            variables.append(
                ScriptVariable(
                    name=match.group(2),
                    kind=match.group(1),
                    expression=match.group(3).strip(),
                )
            )
        for match in OBJECT_RE.finditer(script):
            objects.append(match.group(1))
    return variables, sorted(set(objects))


def _run_parser_plugins(html: str, context: ParsedContext, parser_plugins: list[Any]) -> None:
    for plugin in parser_plugins:
        try:
            plugin.parse(html, context)
        except Exception:
            continue
        context.parser_plugins.append(getattr(plugin, "name", plugin.__class__.__name__))


def read_html_input(value: str) -> tuple[str, str]:
    path = Path(value)
    if path.exists():
        return path.read_text(encoding="utf-8"), f"file:{path}"
    return value, "snippet"


def read_url_list(path_value: str) -> list[str]:
    path = Path(path_value)
    if not path.exists():
        raise ValueError(f"URL list file not found: {path_value}")

    urls = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not urls:
        raise ValueError(f"No URLs found in {path_value}")
    return urls


def _build_context(
    *,
    html: str,
    source: str,
    source_type: str,
    parser_plugins: list[Any],
    markup: MarkupExtraction | None = None,
) -> ParsedContext:
    markup = markup or _extract_html_context(html)
    frameworks = _extract_frameworks(html, markup.inline_scripts)
    esprima_sinks, esprima_variables, esprima_objects, esprima_notes = _extract_with_esprima(markup.inline_scripts)
    dom_sinks = esprima_sinks + _extract_sinks(markup.inline_scripts)
    variables, objects = _extract_variables(markup.inline_scripts)
    if esprima_variables:
        variables = esprima_variables + variables
    if esprima_objects:
        objects = sorted(set(objects + esprima_objects))
    notes = [*markup.notes, *esprima_notes]
    context = ParsedContext(
        source=source,
        source_type=source_type,
        title=markup.title,
        frameworks=frameworks,
        forms=markup.forms,
        inputs=markup.inputs,
        event_handlers=markup.handlers,
        dom_sinks=dom_sinks,
        variables=variables,
        objects=objects,
        inline_scripts=markup.inline_scripts,
        notes=notes,
    )
    _run_parser_plugins(html, context, parser_plugins)
    return context


def fetch_targets(urls: list[str], rate: float = 25.0) -> tuple[list[dict[str, Any]], list[BatchParseError]]:
    from ai_xss_generator.spiders import crawl_urls

    crawled = crawl_urls(urls, rate=rate)
    items: list[dict[str, Any]] = []
    errors: list[BatchParseError] = []

    for url in urls:
        item = crawled.get(url)
        if not item:
            errors.append(BatchParseError(url=url, error="No response captured."))
            continue
        if item.get("error"):
            errors.append(BatchParseError(url=url, error=str(item["error"])))
            continue
        items.append(item)
    return items, errors


def parse_target(
    *,
    url: str | None,
    html_value: str | None,
    parser_plugins: list[Any] | None = None,
    rate: float = 25.0,
) -> ParsedContext:
    if bool(url) == bool(html_value):
        raise ValueError("Choose exactly one of --url or --input")

    parser_plugins = parser_plugins or []
    if url:
        contexts, errors = parse_targets(urls=[url], parser_plugins=parser_plugins, rate=rate)
        if errors:
            raise ValueError(errors[0].error)
        return contexts[0]

    html, source = read_html_input(html_value or "")
    return _build_context(
        html=html,
        source=source,
        source_type="html",
        parser_plugins=parser_plugins,
    )


def parse_targets(
    *,
    urls: list[str],
    parser_plugins: list[Any] | None = None,
    rate: float = 25.0,
) -> tuple[list[ParsedContext], list[BatchParseError]]:
    parser_plugins = parser_plugins or []
    items, errors = fetch_targets(urls, rate=rate)
    contexts = [
        _build_context(
            html=str(item.get("html", "")),
            source=str(item.get("source", "")),
            source_type=str(item.get("source_type", "url")),
            parser_plugins=parser_plugins,
            markup=MarkupExtraction(
                title=str(item.get("title", "")),
                forms=item.get("forms", []),
                inputs=item.get("inputs", []),
                handlers=item.get("handlers", []),
                inline_scripts=item.get("inline_scripts", []),
                notes=item.get("notes", []),
            ),
        )
        for item in items
    ]
    return contexts, errors
