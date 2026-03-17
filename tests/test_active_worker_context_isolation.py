from ai_xss_generator.active.worker import _make_finding, _probe_result_for_context
from ai_xss_generator.probe import ProbeResult, ReflectionContext


def test_probe_result_for_context_keeps_only_requested_reflection():
    probe_result = ProbeResult(
        param_name="q",
        original_value="x",
        reflections=[
            ReflectionContext(
                context_type="html_body",
                surviving_chars=frozenset({"<", ">"}),
            ),
            ReflectionContext(
                context_type="js_string_dq",
                surviving_chars=frozenset({'"', ";"}),
            ),
        ],
    )

    isolated = _probe_result_for_context(probe_result, "js_string_dq")

    assert isolated.param_name == "q"
    assert len(isolated.reflections) == 1
    assert isolated.reflections[0].context_type == "js_string_dq"
    assert isolated.reflections[0].surviving_chars == frozenset({'"', ";"})


def test_make_finding_uses_surviving_chars_from_isolated_context():
    probe_result = ProbeResult(
        param_name="q",
        original_value="x",
        reflections=[
            ReflectionContext(
                context_type="html_body",
                surviving_chars=frozenset({"<", ">"}),
            ),
            ReflectionContext(
                context_type="js_string_dq",
                surviving_chars=frozenset({'"', ";"}),
            ),
        ],
    )
    isolated = _probe_result_for_context(probe_result, "js_string_dq")

    class _ExecResult:
        payload = '";alert(1)//'
        transform_name = "local_model"
        method = "dialog"
        detail = "alert fired"
        fired_url = "https://example.test/?q=%22%3Balert(1)//"

    finding = _make_finding(
        url="https://example.test/?q=x",
        probe_result=isolated,
        context_type="js_string_dq",
        result=_ExecResult(),
        waf=None,
        source="local_model",
        cloud_escalated=False,
    )

    assert finding.context_type == "js_string_dq"
    assert finding.surviving_chars == '";'
