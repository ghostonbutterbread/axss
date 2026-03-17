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


def test_build_delivery_plan_adds_preflight_for_navigate_then_fire() -> None:
    candidate = PayloadCandidate(
        payload="alert(1)",
        title="stateful",
        explanation="",
        test_vector="",
        strategy=StrategyProfile(session_hint="navigate_then_fire"),
    )

    plan = _build_delivery_plan(
        url="https://example.test/account/view?id=7",
        param_name="id",
        payload=candidate.payload,
        all_params={"id": "7"},
        payload_candidate=candidate,
    )

    assert plan.preflight_urls == ["https://example.test/"]


def test_build_delivery_plan_honors_test_vector_path_override() -> None:
    candidate = PayloadCandidate(
        payload="payload",
        title="path override",
        explanation="",
        test_vector="/account/profile?view=full#frag",
        strategy=StrategyProfile(delivery_mode_hint="query"),
    )

    plan = _build_delivery_plan(
        url="https://example.test/search?q=x",
        param_name="q",
        payload=candidate.payload,
        all_params={"q": "x"},
        payload_candidate=candidate,
    )

    assert plan.fired_url == "https://example.test/account/profile?q=payload&view=full#frag"


def test_build_post_delivery_plan_supports_multiple_follow_up_hints() -> None:
    candidate = PayloadCandidate(
        payload="ignored",
        title="stored multi follow-up",
        explanation="",
        test_vector="name=test",
        strategy=StrategyProfile(
            session_hint="post_then_sink",
            follow_up_hint="/profile/avatar,/profile/view|/feed",
        ),
    )

    plan = _build_post_delivery_plan(
        source_page_url="https://example.test/settings/avatar",
        param_name="name",
        payload=candidate.payload,
        payload_candidate=candidate,
        sink_url=None,
    )

    assert plan.follow_up_urls == [
        "https://example.test/profile/avatar",
        "https://example.test/profile/view",
        "https://example.test/feed",
    ]


def test_build_post_delivery_plan_applies_multi_param_test_vector() -> None:
    candidate = PayloadCandidate(
        payload="ignored",
        title="split post",
        explanation="",
        test_vector="first=%3Cdetails%2Fopen&second=ontoggle%3Dalert%281%29%3E",
        strategy=StrategyProfile(coordination_hint="multi_param"),
    )

    plan = _build_post_delivery_plan(
        source_page_url="https://example.test/profile",
        param_name="first",
        payload=candidate.payload,
        payload_candidate=candidate,
    )

    assert plan.param_overrides == {
        "first": "<details/open",
        "second": "ontoggle=alert(1)>",
    }


def test_build_post_delivery_plan_adds_sink_follow_up_for_post_then_sink() -> None:
    candidate = PayloadCandidate(
        payload="ignored",
        title="stored",
        explanation="",
        test_vector="name=test",
        strategy=StrategyProfile(
            session_hint="post_then_sink",
            follow_up_hint="/profile/avatar",
        ),
    )

    plan = _build_post_delivery_plan(
        source_page_url="https://example.test/settings/avatar",
        param_name="name",
        payload=candidate.payload,
        payload_candidate=candidate,
        sink_url=None,
    )

    assert plan.follow_up_urls == ["https://example.test/profile/avatar"]
