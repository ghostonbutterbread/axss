import json
from unittest.mock import MagicMock, patch

import pytest

from ai_xss_generator.models import generate_fast_seeded_batch
from ai_xss_generator.types import PayloadCandidate


_SEVEN_CONTEXTS = [
    "html_body", "html_attr_event", "html_attr_url",
    "js_string_dq", "js_string_sq", "js_template", "url_fragment",
]


def _make_mock_response(context_type: str) -> dict:
    return {
        "payloads": [
            {
                "payload": f"<img onerror=alert(1)>",
                "title": f"test-{context_type}",
                "tags": [f"context:{context_type}"],
                "bypass_family": "raw",
                "risk_score": 7,
            }
        ] * 3
    }


def _make_fake_post(prompts_list=None):
    """Returns a fake requests.post that captures prompts and returns mock API responses."""
    def fake_post(url, **kwargs):
        prompt = kwargs.get("json", {}).get("messages", [{}])[-1].get("content", "")
        if prompts_list is not None:
            prompts_list.append(prompt)
        ctx = "html_body"
        for c in _SEVEN_CONTEXTS:
            if f'"{c}"' in prompt:
                ctx = c
                break
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps(_make_mock_response(ctx))}}]
        }
        return mock_resp
    return fake_post


def test_fires_exactly_seven_calls():
    call_count = 0

    def counting_post(url, **kwargs):
        nonlocal call_count
        call_count += 1
        return _make_fake_post()(url, **kwargs)

    with patch("requests.post", side_effect=counting_post):
        with patch("ai_xss_generator.config.load_api_key", return_value="test-key"):
            with patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key", "OPENAI_API_KEY": ""}, clear=False):
                generate_fast_seeded_batch(
                    cloud_model="test-model",
                    count_per_context=3,
                    request_timeout_seconds=5,
                )

    assert call_count == 7, f"Expected 7 calls, got {call_count}"


def test_returns_payload_candidates():
    with patch("requests.post", side_effect=_make_fake_post()):
        with patch("ai_xss_generator.config.load_api_key", return_value="test-key"):
            with patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key", "OPENAI_API_KEY": ""}, clear=False):
                result = generate_fast_seeded_batch(
                    cloud_model="test-model",
                    count_per_context=3,
                    request_timeout_seconds=5,
                )

    assert isinstance(result, list)
    assert all(isinstance(p, PayloadCandidate) for p in result)
    assert len(result) > 0


def test_each_call_receives_context_type_in_prompt():
    prompts: list[str] = []

    with patch("requests.post", side_effect=_make_fake_post(prompts)):
        with patch("ai_xss_generator.config.load_api_key", return_value="test-key"):
            with patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key", "OPENAI_API_KEY": ""}, clear=False):
                generate_fast_seeded_batch(
                    cloud_model="test-model",
                    count_per_context=2,
                    request_timeout_seconds=5,
                )

    assert len(prompts) == 7
    for prompt in prompts:
        assert any(ctx in prompt for ctx in _SEVEN_CONTEXTS), \
            f"Prompt doesn't reference any known context_type: {prompt[:100]}"


def test_waf_hint_appended_to_prompts():
    prompts: list[str] = []

    with patch("requests.post", side_effect=_make_fake_post(prompts)):
        with patch("ai_xss_generator.config.load_api_key", return_value="test-key"):
            with patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key", "OPENAI_API_KEY": ""}, clear=False):
                generate_fast_seeded_batch(
                    cloud_model="test-model",
                    waf_hint="cloudflare",
                    count_per_context=2,
                    request_timeout_seconds=5,
                )

    for prompt in prompts:
        assert "cloudflare" in prompt.lower(), \
            f"WAF hint not found in prompt: {prompt[:100]}"


def test_returns_empty_list_on_all_failures():
    def failing_post(url, **kwargs):
        raise ConnectionError("simulated failure")

    with patch("requests.post", side_effect=failing_post):
        with patch("ai_xss_generator.config.load_api_key", return_value="test-key"):
            with patch.dict("os.environ", {"OPENROUTER_API_KEY": "test-key", "OPENAI_API_KEY": ""}, clear=False):
                result = generate_fast_seeded_batch(
                    cloud_model="test-model",
                    count_per_context=2,
                    request_timeout_seconds=5,
                )
    assert result == []
