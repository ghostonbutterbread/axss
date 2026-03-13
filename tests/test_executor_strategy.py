from __future__ import annotations

from ai_xss_generator.active.executor import _build_delivery_plan, _build_post_delivery_plan
from ai_xss_generator.types import PayloadCandidate, StrategyProfile


def test_build_delivery_plan_uses_fragment_strategy_hint() -> None:
    candidate = PayloadCandidate(
        payload="<svg/onload=alert(1)>",
        title="fragment dom",
        explanation="",
        test_vector="",
        strategy=StrategyProfile(
            delivery_mode_hint="fragment",
            coordination_hint="fragment_only",
        ),
    )

    plan = _build_delivery_plan(
        url="https://example.test/search?q=x",
        param_name="q",
        payload=candidate.payload,
        all_params={"q": "x"},
        payload_candidate=candidate,
    )

    assert plan.fired_url == "https://example.test/search?q=%3Csvg%2Fonload%3Dalert%281%29%3E#<svg/onload=alert(1)>"
    assert plan.param_overrides["q"] == candidate.payload


def test_build_delivery_plan_applies_multi_param_test_vector() -> None:
    candidate = PayloadCandidate(
        payload="placeholder",
        title="split",
        explanation="",
        test_vector="?first=%3Csvg&second=onload%3Dalert%281%29%3E",
        strategy=StrategyProfile(coordination_hint="multi_param"),
    )

    plan = _build_delivery_plan(
        url="https://example.test/search?first=a&second=b",
        param_name="first",
        payload=candidate.payload,
        all_params={"first": "a", "second": "b"},
        payload_candidate=candidate,
    )

    assert plan.param_overrides == {
        "first": "<svg",
        "second": "onload=alert(1)>",
    }
    assert "first=%3Csvg" in plan.fired_url
    assert "second=onload%3Dalert%281%29%3E" in plan.fired_url


def test_build_post_delivery_plan_applies_multi_param_test_vector() -> None:
    candidate = PayloadCandidate(
        payload="ignored",
        title="split post",
        explanation="",
        test_vector="first=%3Cdetails%2Fopen&second=ontoggle%3Dalert%281%29%3E",
        strategy=StrategyProfile(coordination_hint="multi_param"),
    )

    plan = _build_post_delivery_plan(
        param_name="first",
        payload=candidate.payload,
        payload_candidate=candidate,
    )

    assert plan.param_overrides == {
        "first": "<details/open",
        "second": "ontoggle=alert(1)>",
    }
