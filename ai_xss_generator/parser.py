from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

from ai_xss_generator.encodings import decode_candidates, uudecode_line
from ai_xss_generator.types import DomSink, FormContext, FormField, ParsedContext, ScriptVariable

EVENT_HANDLER_RE = re.compile(r"\bon[a-z0-9_-]+\b", re.IGNORECASE)
FRAMEWORK_PATTERNS = {
    "React": re.compile(r"react|data-reactroot|dangerouslySetInnerHTML|jsx", re.IGNORECASE),
    "Vue": re.compile(r"v-|vue|@click|:class|{{.*?}}", re.IGNORECASE | re.DOTALL),
    "Angular": re.compile(
        r"\bng-(?:app|bind|class|click|controller|form|href|if|include|init|model|repeat|src|style|submit|switch|view)\b|"
        r"\bangular\b|\$scope\b|\[ng(?:[A-Z][A-Za-z]+|-[a-z-]+)",
        re.IGNORECASE,
    ),
    "AngularJS": re.compile(r"ng-app|ng-controller|\$eval|\$parse", re.IGNORECASE),
}
SINK_PATTERNS = {
    # HTML injection sinks
    "innerHTML": re.compile(r"\.innerHTML\s*=|innerHTML\s*:", re.IGNORECASE),
    "outerHTML": re.compile(r"\.outerHTML\s*=", re.IGNORECASE),
    "insertAdjacentHTML": re.compile(r"insertAdjacentHTML\s*\(", re.IGNORECASE),
    "createContextualFragment": re.compile(r"createContextualFragment\s*\(", re.IGNORECASE),
    "DOMParser.parseFromString": re.compile(r"parseFromString\s*\(", re.IGNORECASE),
    # Code execution sinks
    "eval": re.compile(r"\beval\s*\(", re.IGNORECASE),
    "setTimeout": re.compile(r"\bsetTimeout\s*\(", re.IGNORECASE),
    "setInterval": re.compile(r"\bsetInterval\s*\(", re.IGNORECASE),
    "Function": re.compile(r"\bFunction\s*\(", re.IGNORECASE),
    "execScript": re.compile(r"\bexecScript\s*\(", re.IGNORECASE),
    # Document write sinks
    "document.write": re.compile(r"document\.write\s*\(", re.IGNORECASE),
    "document.writeln": re.compile(r"document\.writeln\s*\(", re.IGNORECASE),
    # Navigation / JavaScript-URL sinks
    "location.href": re.compile(r"(?:window\.|document\.)?location(?:\.href)?\s*=", re.IGNORECASE),
    "location.assign": re.compile(r"location\.assign\s*\(", re.IGNORECASE),
    "location.replace": re.compile(r"location\.replace\s*\(", re.IGNORECASE),
    # Dynamic attribute sinks
    "setAttribute": re.compile(r"\.setAttribute\s*\(", re.IGNORECASE),
    "setAttributeNS": re.compile(r"\.setAttributeNS\s*\(", re.IGNORECASE),
    # jQuery HTML-injection sinks
    "jQuery.html": re.compile(r"\$\([^)]*\)\s*\.html\s*\(|\bjQuery\s*\([^)]*\)\s*\.html\s*\(", re.IGNORECASE),
    "jQuery.append": re.compile(r"\$\([^)]*\)\s*\.(?:append|prepend|after|before|wrap|wrapAll|replaceWith)\s*\(", re.IGNORECASE),
    # Framework-specific sinks
    "dangerouslySetInnerHTML": re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE),
    "trustAsHtml": re.compile(r"\$sce\.trustAsHtml\s*\(|bypassSecurityTrustHtml\s*\(", re.IGNORECASE),
    "v-html": re.compile(r"v-html\s*=", re.IGNORECASE),
    "Handlebars.triple-stache": re.compile(r"\{\{\{", re.IGNORECASE),
}
# DOM-based XSS source expressions — these read attacker-controlled data without a request
DOM_SOURCES: dict[str, re.Pattern[str]] = {
    "location.hash": re.compile(r"location\.hash\b", re.IGNORECASE),
    "location.search": re.compile(r"location\.search\b", re.IGNORECASE),
    "location.href": re.compile(r"location\.href\b", re.IGNORECASE),
    "window.name": re.compile(r"window\.name\b", re.IGNORECASE),
    "document.referrer": re.compile(r"document\.referrer\b", re.IGNORECASE),
    "postMessage": re.compile(r"addEventListener\s*\(\s*['\"]message['\"]", re.IGNORECASE),
    "document.URL": re.compile(r"document\.URL\b", re.IGNORECASE),
    "document.baseURI": re.compile(r"document\.baseURI\b", re.IGNORECASE),
}
VARIABLE_RE = re.compile(
    r"\b(var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)",
    re.IGNORECASE,
)
OBJECT_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*:\s*{", re.IGNORECASE)
# Matches JS string variable assignments: var/let/const name = "..." or '...'
_JS_VAR_STRING_RE = re.compile(
    r"(?:var|let|const)\s+(\w+)\s*=\s*[\"']([^\"']*)[\"']",
    re.IGNORECASE,
)

try:
    from scrapling.engines.toolbelt.custom import Selector, Response
except Exception:  # pragma: no cover - exercised only when scrapling is unavailable
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
                enctype=(attr_map.get("enctype", "") or "").lower(),
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
            # Accumulate up to 100 KB per script block to avoid OOM on minified pages
            already = sum(len(c) for c in self._script_chunks)
            remaining = max(0, 102_400 - already)
            if remaining > 0:
                self._script_chunks.append(data[:remaining])


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
        inputs.append(_field_from_attrs(field.tag, dict(field.attrib)))

    for form in selector.css("form"):
        form_context = FormContext(
            action=form.attrib.get("action", ""),
            method=(form.attrib.get("method", "get") or "get").upper(),
            enctype=(form.attrib.get("enctype", "") or "").lower(),
        )
        for field in form.css("input, textarea, select, button"):
            form_context.fields.append(_field_from_attrs(field.tag, dict(field.attrib)))
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
        notes=["Parsed HTML with Scrapling selectors."],
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
        notes=["Scrapling unavailable; used stdlib HTMLParser fallback."],
    )


def _extract_html_context(html: str) -> MarkupExtraction:
    if Selector is not None:
        return _extract_with_selectors(
            Selector(content=html.encode("utf-8"), url="", encoding="utf-8")
        )
    return _extract_with_stdlib(html)


def extract_markup_from_response(response: Response) -> MarkupExtraction:
    # Scrapling Response extends Selector — pass it directly
    return _extract_with_selectors(response)


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
    seen_ids: set[int] = set()  # cycle guard: track object identity
    while stack:
        current = stack.pop()
        if current is None:
            continue
        nid = id(current)
        if nid in seen_ids:
            continue
        seen_ids.add(nid)
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


_SINK_CAP = 200  # max sinks to extract — prevents huge LLM payloads on minified pages


def _extract_sinks(scripts: list[str]) -> list[DomSink]:
    sinks: list[DomSink] = []
    for index, script in enumerate(scripts, start=1):
        location = f"script[{index}]"
        for sink_name, pattern in SINK_PATTERNS.items():
            for match in pattern.finditer(script):
                if len(sinks) >= _SINK_CAP:
                    return sinks
                snippet_start = max(0, match.start() - 40)
                snippet_end = min(len(script), match.end() + 80)
                sinks.append(
                    DomSink(
                        sink=sink_name,
                        source=script[snippet_start:snippet_end].strip(),
                        location=location,
                        confidence=0.93 if sink_name in {
                            "innerHTML", "outerHTML", "eval", "Function",
                            "document.write", "document.writeln",
                            "createContextualFragment", "dangerouslySetInnerHTML",
                        } else 0.84,
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


def _detect_dom_sources(scripts: list[str]) -> tuple[list[DomSink], list[str]]:
    """Detect DOM-based XSS sources (attacker-controlled inputs) that flow into sinks.

    These indicate DOM XSS that never touches the server — the source reads data from
    location.hash / window.name / etc. and passes it to a sink without sanitisation.
    """
    sinks: list[DomSink] = []
    notes: list[str] = []
    for script_idx, script in enumerate(scripts, start=1):
        sources_found: list[str] = []
        for source_name, pattern in DOM_SOURCES.items():
            if pattern.search(script):
                sources_found.append(source_name)

        if not sources_found:
            continue

        # Check if any dangerous sink also appears in the same script block
        sinks_found: list[str] = []
        for sink_name, pattern in SINK_PATTERNS.items():
            if pattern.search(script):
                sinks_found.append(sink_name)

        for source_name in sources_found:
            confidence = 0.85 if sinks_found else 0.55
            sinks.append(
                DomSink(
                    sink=f"dom_source:{source_name}",
                    source=f"{source_name} read in script[{script_idx}]"
                    + (f"; co-located with sinks: {', '.join(sinks_found)}" if sinks_found else ""),
                    location=f"script[{script_idx}]",
                    confidence=confidence,
                )
            )
            if sinks_found:
                notes.append(
                    f"DOM source '{source_name}' co-located with sink(s) "
                    f"{sinks_found} in script[{script_idx}] — likely DOM-based XSS."
                )

    return sinks, notes


# Dangerous HTML attribute contexts that accept JavaScript/data URIs or raw JS
_DANGEROUS_ATTR_RE = re.compile(
    r"""(?P<attr>href|src|action|formaction|data|srcdoc|on\w+|style)\s*=\s*["']?(?P<value>[^"'\s>]{4,})["']?""",
    re.IGNORECASE,
)
_JAVASCRIPT_URI_RE = re.compile(r"^javascript\s*:", re.IGNORECASE)
_DATA_URI_RE = re.compile(r"^data\s*:", re.IGNORECASE)


def _detect_html_param_reflections(
    url: str, html: str
) -> tuple[list[DomSink], list[str]]:
    """Detect URL param values reflected directly in dangerous HTML attribute contexts.

    Catches cases like:
    - href="[param_value]" where value starts with javascript: or data:
    - on[event]="[param_value]" — raw event handler injection
    - src="[param_value]" — script/img src injection
    """
    import urllib.parse

    sinks: list[DomSink] = []
    notes: list[str] = []

    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return sinks, notes

    if not params:
        return sinks, notes

    for param_name, param_values in params.items():
        for raw_value in param_values:
            if not raw_value or len(raw_value) < 3:
                continue
            if raw_value not in html:
                continue
            # Value is literally reflected — find the attribute context
            for match in _DANGEROUS_ATTR_RE.finditer(html):
                attr = match.group("attr").lower()
                val = match.group("value")
                if raw_value not in val:
                    continue
                # Determine severity of the reflection context
                if attr.startswith("on"):
                    sinks.append(DomSink(
                        sink=f"reflected_in_event_handler:{attr}",
                        source=f"param={param_name!r} → {attr}=\"{val[:60]}\"",
                        location="html:attribute",
                        confidence=0.97,
                    ))
                    notes.append(
                        f"Parameter '{param_name}' is reflected directly inside event "
                        f"handler attribute '{attr}' — direct XSS without JS context escape."
                    )
                elif attr in {"href", "action", "formaction", "src", "data"}:
                    if _JAVASCRIPT_URI_RE.match(val) or _DATA_URI_RE.match(val):
                        sinks.append(DomSink(
                            sink=f"reflected_in_{attr}_uri",
                            source=f"param={param_name!r} → {attr}=\"{val[:60]}\"",
                            location="html:attribute",
                            confidence=0.95,
                        ))
                        notes.append(
                            f"Parameter '{param_name}' is reflected in '{attr}' attribute "
                            f"with a javascript:/data: URI — direct XSS vector."
                        )
                    else:
                        sinks.append(DomSink(
                            sink=f"reflected_in_{attr}",
                            source=f"param={param_name!r} → {attr}=\"{val[:60]}\"",
                            location="html:attribute",
                            confidence=0.72,
                        ))
                        notes.append(
                            f"Parameter '{param_name}' is reflected in '{attr}' attribute — "
                            f"may allow javascript:/data: URI injection."
                        )
                elif attr == "srcdoc":
                    sinks.append(DomSink(
                        sink="reflected_in_srcdoc",
                        source=f"param={param_name!r} → srcdoc=\"{val[:60]}\"",
                        location="html:attribute",
                        confidence=0.93,
                    ))
                    notes.append(
                        f"Parameter '{param_name}' reflected in 'srcdoc' attribute — "
                        f"HTML parsed in iframe context."
                    )
                elif attr == "style":
                    sinks.append(DomSink(
                        sink="reflected_in_style",
                        source=f"param={param_name!r} → style=\"{val[:60]}\"",
                        location="html:attribute",
                        confidence=0.65,
                    ))
                    notes.append(
                        f"Parameter '{param_name}' reflected in 'style' attribute — "
                        f"potential CSS expression/url() injection."
                    )

    return sinks, notes


def _try_uudecode(data: bytes) -> str | None:
    """Attempt to UU-decode bytes. Thin wrapper around encodings.uudecode_line."""
    return uudecode_line(data)


def _decode_candidates(raw_value: str) -> list[tuple[str, str]]:
    """Return (decoded_text, encoding_chain) pairs. Delegates to encodings module."""
    return decode_candidates(raw_value)


def _detect_encoded_param_reflections(
    url: str, scripts: list[str]
) -> tuple[list[DomSink], list[str]]:
    """Detect URL params decoded through encoding chains and reflected into JS string sinks.

    Handles: base64, base64+uuencode, base32, html_entity, url_percent,
    double_url_percent, gzip+base64, json_string, rot13.
    """
    import urllib.parse

    sinks: list[DomSink] = []
    notes: list[str] = []

    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return sinks, notes

    if not params or not scripts:
        return sinks, notes

    seen: set[tuple[str, str, str]] = set()  # (param, chain, script_idx) dedup

    for param_name, param_values in params.items():
        for raw_value in param_values:
            if not raw_value or len(raw_value) < 4:
                continue

            for decoded_text, chain in _decode_candidates(raw_value):
                probe = decoded_text[:30]
                for script_idx, script in enumerate(scripts, start=1):
                    pos = script.find(probe)
                    if pos == -1:
                        continue
                    key = (param_name, chain, str(script_idx))
                    if key in seen:
                        continue
                    seen.add(key)
                    # Find the nearest JS variable assignment enclosing the reflected value
                    snippet = script[max(0, pos - 60): pos + len(decoded_text) + 4]
                    all_var_matches = list(_JS_VAR_STRING_RE.finditer(snippet))
                    var_name = all_var_matches[-1].group(1) if all_var_matches else "unknown"
                    sinks.append(
                        DomSink(
                            sink=f"js_string_via_{chain}",
                            source=(
                                f"param={param_name!r} decoded via {chain} "
                                f"→ var {var_name} = \"...\""
                            ),
                            location=f"script[{script_idx}]:param:{param_name}",
                            confidence=0.92,
                        )
                    )
                    notes.append(
                        f"Parameter '{param_name}' is {chain}-encoded; decoded value "
                        f"reflected unescaped into JS string (var {var_name}). "
                        f"Quote injection may bypass server-side escaping."
                    )

    return sinks, notes


def _run_parser_plugins(html: str, context: ParsedContext, parser_plugins: list[Any]) -> None:
    for plugin in parser_plugins:
        plugin_name = getattr(plugin, "name", plugin.__class__.__name__)
        try:
            plugin.parse(html, context)
        except Exception as exc:
            log.debug("Parser plugin %r raised an error: %s", plugin_name, exc)
            continue
        context.parser_plugins.append(plugin_name)


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


def resolve_url_input(value: str) -> list[str]:
    """Resolve a URL input value to a list of URLs.

    Accepts:
    - A single URL: "https://example.com"
    - A CSV of URLs: "https://a.com,https://b.com"
    - A file path: "targets.txt" (one URL per line)
    """
    if value.startswith(("http://", "https://")):
        if "," in value:
            return [u.strip() for u in value.split(",") if u.strip()]
        return [value]
    return read_url_list(value)


def _build_context(
    *,
    html: str,
    source: str,
    source_type: str,
    parser_plugins: list[Any],
    markup: MarkupExtraction | None = None,
    auth_notes: list[str] | None = None,
) -> ParsedContext:
    markup = markup or _extract_html_context(html)
    frameworks = _extract_frameworks(html, markup.inline_scripts)
    esprima_sinks, esprima_variables, esprima_objects, esprima_notes = _extract_with_esprima(markup.inline_scripts)
    dom_sinks = esprima_sinks + _extract_sinks(markup.inline_scripts)
    dom_src_sinks, dom_src_notes = _detect_dom_sources(markup.inline_scripts)
    enc_sinks, enc_notes = (
        _detect_encoded_param_reflections(source, markup.inline_scripts)
        if source_type == "url" and "?" in source
        else ([], [])
    )
    attr_sinks, attr_notes = (
        _detect_html_param_reflections(source, html)
        if source_type == "url" and "?" in source
        else ([], [])
    )
    dom_sinks = enc_sinks + attr_sinks + dom_src_sinks + dom_sinks
    variables, objects = _extract_variables(markup.inline_scripts)
    if esprima_variables:
        variables = esprima_variables + variables
    if esprima_objects:
        objects = sorted(set(objects + esprima_objects))
    notes = [*markup.notes, *esprima_notes, *dom_src_notes, *enc_notes, *attr_notes]
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
        auth_notes=auth_notes or [],
    )
    _run_parser_plugins(html, context, parser_plugins)
    return context


def fetch_targets(
    urls: list[str],
    rate: float = 25.0,
    waf: str | None = None,
    auth_headers: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], list[BatchParseError]]:
    from ai_xss_generator.spiders import crawl_urls

    crawled = crawl_urls(urls, rate=rate, waf=waf, auth_headers=auth_headers)
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
    waf: str | None = None,
    auth_headers: dict[str, str] | None = None,
    cached_html: str | None = None,
) -> ParsedContext:
    if bool(url) == bool(html_value):
        raise ValueError("Choose exactly one of --url or --input")

    parser_plugins = parser_plugins or []
    if url:
        # Fast path: caller already fetched the page — skip the network round-trip.
        if cached_html is not None:
            from ai_xss_generator.auth import describe_auth
            _auth_notes = describe_auth(auth_headers) if auth_headers else []
            return _build_context(
                html=cached_html,
                source=url,
                source_type="url",
                parser_plugins=parser_plugins,
                auth_notes=_auth_notes,
            )
        contexts, errors = parse_targets(
            urls=[url],
            parser_plugins=parser_plugins,
            rate=rate,
            waf=waf,
            auth_headers=auth_headers,
        )
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
    waf: str | None = None,
    auth_headers: dict[str, str] | None = None,
) -> tuple[list[ParsedContext], list[BatchParseError]]:
    from ai_xss_generator.auth import describe_auth

    parser_plugins = parser_plugins or []
    _auth_notes = describe_auth(auth_headers) if auth_headers else []
    items, errors = fetch_targets(urls, rate=rate, waf=waf, auth_headers=auth_headers)
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
            auth_notes=_auth_notes,
        )
        for item in items
    ]
    return contexts, errors
