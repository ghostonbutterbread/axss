from ai_xss_generator.payloads.golden_seeds import (
    GOLDEN_SEEDS,
    STORED_UNIVERSAL,
    all_seeds_flat,
    seeds_for_context,
    stored_universal_payloads,
)


def test_all_seven_context_keys_present():
    expected = {
        "html_body", "html_attr_event", "html_attr_url",
        "js_string_dq", "js_string_sq", "js_template",
        "url_fragment",
    }
    # polyglot is an extra key used for fallback — verify the 7 required keys are present
    assert expected.issubset(set(GOLDEN_SEEDS.keys()))


def test_seeds_for_known_context_returns_up_to_n():
    result = seeds_for_context("html_body", n=2)
    assert len(result) <= 2
    assert all(isinstance(p, str) and p.strip() for p in result)


def test_seeds_for_unknown_context_falls_back_to_polyglots():
    result = seeds_for_context("unknown_context_xyz", n=3)
    assert len(result) > 0
    assert all(isinstance(p, str) for p in result)


def test_all_seeds_flat_deduplicated():
    flat = all_seeds_flat()
    assert len(flat) == len(set(flat)), "Duplicate seeds found in all_seeds_flat()"


def test_all_seeds_flat_non_empty():
    flat = all_seeds_flat()
    assert len(flat) >= 10


def test_stored_universal_payloads_non_empty():
    payloads = stored_universal_payloads()
    assert len(payloads) >= 5
    assert all(isinstance(p, str) and p.strip() for p in payloads)


def test_no_payload_appears_twice_in_golden_seeds():
    all_payloads = [p for seeds in GOLDEN_SEEDS.values() for p in seeds]
    assert len(all_payloads) == len(set(all_payloads)), "Duplicate in GOLDEN_SEEDS"


def test_seeds_for_context_n_zero_returns_empty():
    assert seeds_for_context("html_body", n=0) == []


def test_polyglot_key_present():
    assert "polyglot" in GOLDEN_SEEDS
    assert len(GOLDEN_SEEDS["polyglot"]) >= 1
