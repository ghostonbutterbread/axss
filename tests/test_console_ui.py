from __future__ import annotations

import logging
from unittest.mock import patch

from ai_xss_generator.cli import _TRACE_HANDLER_NAME, _configure_logging
from ai_xss_generator.console import (
    clear_status_bar,
    dynamic_ui_enabled,
    set_status_bar,
    set_verbose_level,
    setup_panel,
    teardown_panel,
    update_panel,
    update_status_bar,
)


def test_dynamic_ui_disabled_at_double_verbose() -> None:
    with patch("ai_xss_generator.console._tty", return_value=True):
        set_verbose_level(2)
        assert not dynamic_ui_enabled()
        set_verbose_level(0)


def test_status_ui_noops_when_double_verbose() -> None:
    with (
        patch("ai_xss_generator.console._tty", return_value=True),
        patch("sys.stdout.write") as write,
        patch("sys.stdout.flush"),
    ):
        set_verbose_level(2)
        set_status_bar("status")
        update_status_bar("status2")
        setup_panel()
        update_panel("sep", "bar", "workers")
        clear_status_bar()
        teardown_panel()
        assert not write.called
        set_verbose_level(0)


def test_configure_logging_limits_full_trace_to_app_loggers() -> None:
    app_logger = logging.getLogger("ai_xss_generator")
    xssy_logger = logging.getLogger("xssy")
    root_logger = logging.getLogger()
    noisy_logger = logging.getLogger("urllib3")

    original_root_handlers = list(root_logger.handlers)

    _configure_logging(2)
    try:
        assert any(h.get_name() == _TRACE_HANDLER_NAME for h in app_logger.handlers)
        assert any(h.get_name() == _TRACE_HANDLER_NAME for h in xssy_logger.handlers)
        assert not any(h.get_name() == _TRACE_HANDLER_NAME for h in root_logger.handlers)
        assert app_logger.level == logging.DEBUG
        assert xssy_logger.level == logging.DEBUG
        assert noisy_logger.level == logging.WARNING
    finally:
        _configure_logging(0)

    assert list(root_logger.handlers) == original_root_handlers
    assert not any(h.get_name() == _TRACE_HANDLER_NAME for h in app_logger.handlers)
    assert not any(h.get_name() == _TRACE_HANDLER_NAME for h in xssy_logger.handlers)
