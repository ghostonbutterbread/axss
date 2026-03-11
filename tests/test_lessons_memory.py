from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import ai_xss_generator.lessons as lessons
from ai_xss_generator.probe import ProbeResult, ReflectionContext
from ai_xss_generator.types import DomSink, FormContext, ParsedContext


class LessonsMemoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.original_dir = lessons.LESSONS_DIR
        lessons.LESSONS_DIR = Path(self.tmpdir.name) / "lessons"

    def tearDown(self) -> None:
        lessons.LESSONS_DIR = self.original_dir

    def test_relevant_lessons_prefers_matching_landscape(self) -> None:
        generic = lessons.Lesson(
            lesson_type=lessons.LESSON_TYPE_XSS_LOGIC,
            title="html_attr_url reflection logic",
            summary="Generic URL-attribute lesson.",
            sink_type="probe:html_attr_url",
            context_type="html_attr_url",
            surviving_chars=":/()",
            delivery_mode="get",
            memory_tier="curated",
        )
        tailored = lessons.Lesson(
            lesson_type=lessons.LESSON_TYPE_XSS_LOGIC,
            title="html_attr_url reflection logic",
            summary="Host-specific URL-attribute lesson.",
            sink_type="probe:html_attr_url",
            context_type="html_attr_url",
            surviving_chars=":/()",
            target_scope="host",
            target_host="app.example.test",
            waf_name="cloudflare",
            delivery_mode="get",
            frameworks=["react"],
            memory_tier="verified-runtime",
            confidence=0.9,
        )

        lessons.save_lesson(generic)
        lessons.save_lesson(tailored)

        retrieved = lessons.relevant_lessons(
            sink_type="probe:html_attr_url",
            context_type="html_attr_url",
            surviving_chars=":/()",
            target_host="app.example.test",
            waf_name="cloudflare",
            delivery_mode="get",
            frameworks=("react",),
        )
        self.assertEqual(retrieved[0].summary, "Host-specific URL-attribute lesson.")

    def test_build_probe_lessons_capture_logic_and_filter(self) -> None:
        probe_result = ProbeResult(
            param_name="next",
            original_value="",
            reflections=[
                ReflectionContext(
                    context_type="html_attr_url",
                    attr_name="href",
                    surviving_chars=frozenset(":/()"),
                )
            ],
        )
        memory_profile = {
            "target_host": "app.example.test",
            "target_scope": "host",
            "waf_name": "",
            "delivery_mode": "get",
            "frameworks": ["react"],
            "auth_required": False,
        }

        built = lessons.build_probe_lessons(
            [probe_result],
            memory_profile=memory_profile,
            delivery_mode="get",
            provenance="https://app.example.test/",
            memory_tier="verified-runtime",
        )

        self.assertEqual({lesson.lesson_type for lesson in built}, {
            lessons.LESSON_TYPE_XSS_LOGIC,
            lessons.LESSON_TYPE_FILTER,
        })
        logic = next(lesson for lesson in built if lesson.lesson_type == lessons.LESSON_TYPE_XSS_LOGIC)
        filt = next(lesson for lesson in built if lesson.lesson_type == lessons.LESSON_TYPE_FILTER)
        self.assertIn("scheme control", logic.summary)
        self.assertEqual(filt.surviving_chars, "()/:")
        self.assertIn("<", filt.blocked_chars)
        self.assertEqual(logic.review_status, "approved")
        self.assertEqual(filt.review_status, "approved")

    def test_build_mapping_lessons_capture_forms_dom_and_auth(self) -> None:
        context = ParsedContext(
            source="https://app.example.test/profile",
            source_type="url",
            frameworks=["React"],
            forms=[FormContext(action="/profile", method="POST")],
            dom_sinks=[
                DomSink(
                    sink="dom_source:location.hash",
                    source="location.hash read in script[1]; co-located with sinks: innerHTML",
                    location="script[1]",
                    confidence=0.9,
                )
            ],
            auth_notes=["Authorization header present"],
        )
        memory_profile = {
            "target_host": "app.example.test",
            "target_scope": "host",
            "waf_name": "",
            "delivery_mode": "get",
            "frameworks": ["react"],
            "auth_required": True,
        }

        built = lessons.build_mapping_lessons(
            context,
            memory_profile=memory_profile,
            evidence_type="xssy_context",
            memory_tier="experimental",
            provenance="https://app.example.test/profile",
        )
        titles = {lesson.title for lesson in built}
        self.assertIn("Form workflow surface", titles)
        self.assertIn("Client-side source surface", titles)
        self.assertIn("Framework rendering surface", titles)
        self.assertIn("Authenticated workflow surface", titles)

    def test_review_lesson_updates_metadata(self) -> None:
        lesson = lessons.Lesson(
            lesson_type=lessons.LESSON_TYPE_MAPPING,
            title="Form workflow surface",
            summary="Lab workflow lesson.",
            memory_tier="experimental",
            evidence_type="xssy_context",
            provenance="https://demo.xssy.uk/",
        )
        lessons.save_lesson(lesson)

        promoted = lessons.review_lesson(
            lessons.lesson_id(lesson),
            reviewer="tester",
            note="useful across many labs",
            promote_to="curated",
            target_scope="global",
        )
        self.assertEqual(promoted.review_status, "approved")
        self.assertEqual(promoted.memory_tier, "curated")
        self.assertEqual(promoted.reviewed_by, "tester")

        second = lessons.Lesson(
            lesson_type=lessons.LESSON_TYPE_FILTER,
            title="html_body filter profile",
            summary="Target filter lesson.",
            memory_tier="experimental",
            evidence_type="active_probe",
            provenance="https://app.example.test/",
        )
        lessons.save_lesson(second)
        rejected = lessons.review_lesson(
            lessons.lesson_id(second),
            reviewer="tester",
            note="too noisy",
            reject=True,
        )
        self.assertEqual(rejected.review_status, "rejected")
        self.assertEqual(rejected.review_note, "too noisy")

    def test_memory_source_filters_labs_vs_targets(self) -> None:
        lab_lesson = lessons.Lesson(
            lesson_type=lessons.LESSON_TYPE_MAPPING,
            title="Framework rendering surface",
            summary="Lab lesson.",
            memory_tier="experimental",
            evidence_type="xssy_context",
            provenance="https://demo.xssy.uk/",
        )
        target_lesson = lessons.Lesson(
            lesson_type=lessons.LESSON_TYPE_MAPPING,
            title="Authenticated workflow surface",
            summary="Target lesson.",
            memory_tier="experimental",
            evidence_type="parsed_context",
            provenance="https://app.example.test/profile",
        )
        lessons.save_lesson(lab_lesson)
        lessons.save_lesson(target_lesson)

        self.assertEqual(len(lessons.review_queue(memory_source="labs")), 1)
        self.assertEqual(len(lessons.review_queue(memory_source="targets")), 1)
        self.assertEqual(lessons.memory_stats(memory_source="labs")["total"], 1)
        self.assertEqual(lessons.memory_stats(memory_source="targets")["total"], 1)


if __name__ == "__main__":
    unittest.main()
