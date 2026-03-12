from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from ai_xss_generator.active.worker import _get_dom_local_payloads, _get_local_payloads
from ai_xss_generator.models import (
    _cloud_prompt_for_context,
    _compact_dom_prompt_for_local,
    _document_write_subcontext,
)
from ai_xss_generator.probe import ProbeResult, ReflectionContext
from ai_xss_generator.types import FormContext, FormField, ParsedContext
from xssy.learn import _runtime_learning_context


def test_get_local_payloads_forwards_local_timeout_to_generator():
    probe_result = ProbeResult(
        param_name="q",
        original_value="x",
        reflections=[ReflectionContext(context_type="html_body", surviving_chars=frozenset({"<", ">"}))],
    )
    context = ParsedContext(source="https://example.test/search?q=x", source_type="url")
    captured: dict[str, int] = {}

    def _fake_generate_payloads(**kwargs):
        captured["timeout"] = kwargs["local_timeout_seconds"]
        return [], "heuristic", True, "qwen3.5:9b"

    with (
        patch("ai_xss_generator.probe.enrich_context", return_value=context),
        patch("ai_xss_generator.learning.build_memory_profile", return_value={}),
        patch("ai_xss_generator.models.generate_payloads", side_effect=_fake_generate_payloads),
    ):
        _get_local_payloads(
            url=context.source,
            probe_result=probe_result,
            model="qwen3.5:9b",
            waf=None,
            base_context=context,
            local_timeout_seconds=17,
        )

    assert captured["timeout"] == 17


def test_dom_local_payloads_forwards_local_timeout_to_generator():
    context = ParsedContext(source="https://example.test/#x", source_type="url")
    captured: dict[str, int] = {}

    def _fake_generate_payloads(**kwargs):
        captured["timeout"] = kwargs["local_timeout_seconds"]
        return [], "ollama"

    with (
        patch("ai_xss_generator.learning.build_memory_profile", return_value={}),
        patch("ai_xss_generator.models.generate_dom_local_payloads", side_effect=_fake_generate_payloads),
    ):
        _get_dom_local_payloads(
            context=context,
            model="qwen3.5:9b",
            waf=None,
            local_timeout_seconds=23,
        )

    assert captured["timeout"] == 23


def test_compact_dom_prompt_uses_sink_specific_profile():
    context = ParsedContext(
        source="https://example.test/#x",
        source_type="url",
        notes=[
            '[dom:TAINT] {"code_location": "bundle.js:42", "sink": "document.write", "source_name": "hash", "source_type": "fragment"}'
        ],
    )

    prompt = _compact_dom_prompt_for_local(context)

    assert "Sink profile: document_write" in prompt
    assert "URL-attribute breakout" in prompt
    assert "Produce 3-6 payloads only." in prompt


def test_cloud_prompt_uses_compact_seeded_shape_for_simple_dom_sinks():
    context = ParsedContext(
        source="https://example.test/?name=x",
        source_type="url",
        notes=[
            '[dom:TAINT] {"code_location": "bundle.js:12", "sink": "innerHTML", "source_name": "name", "source_type": "query_param"}'
        ],
    )

    prompt = _cloud_prompt_for_context(context)

    assert "Produce 4-8 payloads only." in prompt
    assert "Do not return an empty payload list." in prompt
    assert "Seed technique examples:" in prompt
    assert '"payload": "<img src=x onerror=alert(1)>"' in prompt
    assert "Context summary:" in prompt


def test_cloud_prompt_keeps_rich_shape_for_document_write_dom_sinks():
    context = ParsedContext(
        source="https://example.test/#x",
        source_type="url",
        notes=[
            '[dom:TAINT] {"code_location": "bundle.js:42", "sink": "document.write", "source_name": "hash", "source_type": "fragment"}'
        ],
    )

    prompt = _cloud_prompt_for_context(context)

    assert "Produce 6-10 payloads only." in prompt
    assert "Document.write subcontext:" in prompt
    assert "same-tag attribute pivots" in prompt
    assert "Targeted examples:" in prompt


def test_document_write_subcontext_infers_iframe_src_attribute_shape():
    context = ParsedContext(
        source="https://example.test/#x",
        source_type="url",
        notes=[
            '[dom:TAINT] {"code_location": "bundle.js:42", "sink": "document.write", "source_name": "hash", "source_type": "fragment"}'
        ],
        inline_scripts=[
            "document.write(\"<iframe src='https://example.test/logging.html?\"+window.location.hash+\"' width='950'></iframe>\")"
        ],
    )

    subcontext = _document_write_subcontext(context)

    assert subcontext["html_subcontext"] == "single_quoted_html_attr"
    assert subcontext["tag"] == "iframe"
    assert subcontext["attribute"] == "src"
    assert subcontext["payload_shape"] == "same_tag_attribute_breakout"
    assert "Fragment payloads often arrive URL-encoded" in subcontext["source_behavior"]




def test_xssy_learning_prefers_probe_enriched_runtime_context():
    lab_url = "https://demo.xssy.uk/"
    runtime_url = "https://demo.xssy.uk/target.ftl?name=axsslearn"
    base_context = ParsedContext(
        source=lab_url,
        source_type="url",
        title="Basic Reflective XSS",
        forms=[
            FormContext(
                action="/target.ftl",
                method="GET",
                fields=[FormField(tag="input", name="name", input_type="text")],
            )
        ],
        notes=["xssy.uk lab: Basic Reflective XSS"],
    )
    runtime_context = ParsedContext(source=runtime_url, source_type="url", notes=["runtime html"])
    enriched_context = ParsedContext(
        source=runtime_url,
        source_type="url",
        notes=["[probe:CONFIRMED] 'name' -> html_body surviving='<>''"],
    )
    probe_results = [
        ProbeResult(
            param_name="name",
            original_value="axsslearn",
            reflections=[ReflectionContext(context_type="html_body", surviving_chars=frozenset({"<", ">"}))],
        )
    ]

    with (
        patch("xssy.learn.requests.get", return_value=SimpleNamespace(text="<html></html>")),
        patch("xssy.learn.parse_target", return_value=runtime_context),
        patch("xssy.learn.probe_url", return_value=probe_results),
        patch("xssy.learn.enrich_context", return_value=enriched_context),
        patch("xssy.learn.build_mapping_lessons", return_value=["map"]),
        patch("xssy.learn.build_probe_lessons", return_value=["probe"]),
    ):
        context, lessons, source = _runtime_learning_context(
            lab_url=lab_url,
            base_context=base_context,
        )

    assert context is enriched_context
    assert lessons == ["map", "probe"]
    assert source == "get_probe"
