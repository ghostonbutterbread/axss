"""Tests for ephemeral probe lessons (lessons.py — no file I/O)."""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from ai_xss_generator.lessons import (
    Lesson,
    LESSON_TYPE_FILTER,
    LESSON_TYPE_MAPPING,
    LESSON_TYPE_XSS_LOGIC,
    build_mapping_lessons,
    build_probe_lessons,
)


def _make_reflection(**kwargs):
    r = MagicMock()
    r.context_type = kwargs.get("context_type", "html_attr_value")
    r.attr_name = kwargs.get("attr_name", "")
    r.surviving_chars = frozenset(kwargs.get("surviving_chars", "<>\"'"))
    return r


def _make_probe_result(param_name: str, reflections: list) -> MagicMock:
    r = MagicMock()
    r.param_name = param_name
    r.reflections = reflections
    return r


class EphemeralLessonsTest(unittest.TestCase):

    def test_build_probe_lessons_returns_logic_and_filter(self):
        reflection = _make_reflection(context_type="html_attr_value")
        probe_result = _make_probe_result("q", [reflection])

        lessons = build_probe_lessons([probe_result], delivery_mode="get")

        types = {lesson.lesson_type for lesson in lessons}
        self.assertIn(LESSON_TYPE_XSS_LOGIC, types)
        self.assertIn(LESSON_TYPE_FILTER, types)
        self.assertEqual(len(lessons), 2)

    def test_probe_lessons_capture_surviving_chars(self):
        reflection = _make_reflection(
            context_type="html_body",
            surviving_chars=frozenset("<>()")
        )
        probe_result = _make_probe_result("name", [reflection])
        probe_result.tested_chars = "<>()"
        probe_result.probe_mode = "stealth"
        lessons = build_probe_lessons([probe_result], delivery_mode="get")
        filter_lesson = next(l for l in lessons if l.lesson_type == LESSON_TYPE_FILTER)
        for ch in "<>()":
            self.assertIn(ch, filter_lesson.surviving_chars)
        self.assertIn("Tested charset was ()<>", filter_lesson.summary)

    def test_build_mapping_lessons_capture_forms_dom_auth(self):
        form = MagicMock()
        form.method = "POST"
        dom_sink = MagicMock()
        dom_sink.sink = "dom_source:location.hash"
        context = MagicMock()
        context.forms = [form]
        context.dom_sinks = [dom_sink]
        context.frameworks = ["angular"]
        context.auth_notes = ["Bearer token detected"]

        lessons = build_mapping_lessons(context)

        lesson_titles = [l.title for l in lessons]
        self.assertTrue(any("Form" in t for t in lesson_titles))
        self.assertTrue(any("source" in t.lower() for t in lesson_titles))
        self.assertTrue(any("Framework" in t for t in lesson_titles))
        self.assertTrue(any("Authenticated" in t for t in lesson_titles))

    def test_lessons_are_not_persisted(self):
        """lessons.py exposes no persistence — no save_lesson or LESSONS_DIR."""
        import ai_xss_generator.lessons as lessons_module
        self.assertFalse(hasattr(lessons_module, "save_lesson"))
        self.assertFalse(hasattr(lessons_module, "load_lessons"))
        self.assertFalse(hasattr(lessons_module, "LESSONS_DIR"))

    def test_no_storage_fields_on_lesson_dataclass(self):
        """Lesson dataclass has no persistence-specific fields."""
        lesson = Lesson(lesson_type=LESSON_TYPE_MAPPING, title="t", summary="s")
        self.assertFalse(hasattr(lesson, "target_host"))
        self.assertFalse(hasattr(lesson, "target_scope"))
        self.assertFalse(hasattr(lesson, "memory_tier"))
        self.assertFalse(hasattr(lesson, "review_status"))


if __name__ == "__main__":
    unittest.main()
