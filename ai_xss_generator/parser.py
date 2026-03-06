from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import requests

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


def _extract_with_bs4(html: str) -> tuple[str, list[FormContext], list[FormField], list[str], list[str]]:
    from bs4 import BeautifulSoup  # type: ignore

    soup = BeautifulSoup(html, "html.parser")
    title = (soup.title.get_text(" ", strip=True) if soup.title else "").strip()
    forms: list[FormContext] = []
    inputs: list[FormField] = []
    handlers: set[str] = set()
    inline_scripts: list[str] = []
    for form in soup.find_all("form"):
        form_context = FormContext(
            action=form.get("action", ""),
            method=(form.get("method", "get") or "get").upper(),
        )
        for field in form.find_all(["input", "textarea", "select", "button"]):
            form_field = FormField(
                tag=field.name,
                name=field.get("name", ""),
                input_type=field.get("type", field.name),
                id_value=field.get("id", ""),
                placeholder=field.get("placeholder", ""),
            )
            form_context.fields.append(form_field)
            inputs.append(form_field)
        forms.append(form_context)
    for tag in soup.find_all(True):
        for attr_name in tag.attrs:
            if EVENT_HANDLER_RE.fullmatch(attr_name):
                handlers.add(attr_name)
    for script in soup.find_all("script"):
        inline = script.string or script.get_text(" ", strip=False)
        if inline and inline.strip():
            inline_scripts.append(inline.strip())
    return title, forms, inputs, sorted(handlers), inline_scripts


def _extract_with_stdlib(html: str) -> tuple[str, list[FormContext], list[FormField], list[str], list[str]]:
    parser = _MiniHTMLParser()
    parser.feed(html)
    return parser.title, parser.forms, parser.inputs, sorted(parser.handlers), parser.inline_scripts


def _extract_html_context(html: str) -> tuple[str, list[FormContext], list[FormField], list[str], list[str], list[str]]:
    notes: list[str] = []
    try:
        title, forms, inputs, handlers, inline_scripts = _extract_with_bs4(html)
        notes.append("Parsed HTML with BeautifulSoup.")
    except Exception:
        title, forms, inputs, handlers, inline_scripts = _extract_with_stdlib(html)
        notes.append("BeautifulSoup unavailable; used stdlib HTMLParser fallback.")
    return title, forms, inputs, handlers, inline_scripts, notes


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


def fetch_target(url: str) -> str:
    response = requests.get(
        url,
        headers={
            "User-Agent": "axss/0.1 (+authorized security testing)",
        },
        timeout=20,
    )
    response.raise_for_status()
    return response.text


def read_html_input(value: str) -> tuple[str, str]:
    path = Path(value)
    if path.exists():
        return path.read_text(encoding="utf-8"), f"file:{path}"
    return value, "snippet"


def parse_target(
    *,
    url: str | None,
    html_value: str | None,
    parser_plugins: list[Any] | None = None,
) -> ParsedContext:
    if bool(url) == bool(html_value):
        raise ValueError("Choose exactly one of --url or --input")
    parser_plugins = parser_plugins or []
    if url:
        html = fetch_target(url)
        source = url
        source_type = "url"
    else:
        html, source = read_html_input(html_value or "")
        source_type = "html"

    title, forms, inputs, handlers, inline_scripts, notes = _extract_html_context(html)
    frameworks = _extract_frameworks(html, inline_scripts)
    esprima_sinks, esprima_variables, esprima_objects, esprima_notes = _extract_with_esprima(inline_scripts)
    dom_sinks = esprima_sinks + _extract_sinks(inline_scripts)
    variables, objects = _extract_variables(inline_scripts)
    if esprima_variables:
        variables = esprima_variables + variables
    if esprima_objects:
        objects = sorted(set(objects + esprima_objects))
    notes.extend(esprima_notes)
    context = ParsedContext(
        source=source,
        source_type=source_type,
        title=title,
        frameworks=frameworks,
        forms=forms,
        inputs=inputs,
        event_handlers=handlers,
        dom_sinks=dom_sinks,
        variables=variables,
        objects=objects,
        inline_scripts=inline_scripts,
        notes=notes,
    )
    _run_parser_plugins(html, context, parser_plugins)
    return context
