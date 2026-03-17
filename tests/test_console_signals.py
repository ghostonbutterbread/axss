from ai_xss_generator.active.console_signals import (
    console_init_script,
    is_execution_console_text,
    strip_execution_console_text,
)


def test_console_marker_detection_matches_prefixed_messages() -> None:
    assert is_execution_console_text("__AXSS_EXEC__ xss")
    assert not is_execution_console_text("Failed to load resource: net::ERR_FAILED")


def test_console_marker_stripping_preserves_non_marker_text() -> None:
    assert strip_execution_console_text("__AXSS_EXEC__ payload fired") == "payload fired"
    assert strip_execution_console_text("plain message") == "plain message"


def test_console_init_script_embeds_marker() -> None:
    script = console_init_script()
    assert "__AXSS_EXEC__" in script
    assert "console[level]" in script
