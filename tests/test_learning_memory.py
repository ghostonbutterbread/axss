from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import ai_xss_generator.findings as findings


class LearningMemoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.original_dir = findings.FINDINGS_DIR
        self.original_path = findings.FINDINGS_PATH
        findings.FINDINGS_DIR = Path(self.tmpdir.name) / "findings"
        findings.FINDINGS_PATH = Path(self.tmpdir.name) / "findings.jsonl"

    def tearDown(self) -> None:
        findings.FINDINGS_DIR = self.original_dir
        findings.FINDINGS_PATH = self.original_path

    def test_default_retrieval_ignores_experimental_findings(self) -> None:
        experimental = findings.Finding(
            sink_type="probe:html_body",
            context_type="html_body",
            surviving_chars="<>/()",
            bypass_family="event-handler-injection",
            payload="<img src=x onerror=alert(1)>",
            test_vector="?q=<img src=x onerror=alert(1)>",
            model="xssy-learn",
            memory_tier=findings.MEMORY_TIER_EXPERIMENTAL,
            evidence_type="xssy_generation",
        )
        verified = findings.Finding(
            sink_type="probe:html_body",
            context_type="html_body",
            surviving_chars="<>/()",
            bypass_family="event-handler-injection",
            payload="<svg/onload=alert(1)>",
            test_vector="?q=<svg/onload=alert(1)>",
            model="local_model",
            verified=True,
            memory_tier=findings.MEMORY_TIER_VERIFIED_RUNTIME,
            evidence_type="active_scan",
            success_count=1,
        )

        findings.save_finding(experimental)
        findings.save_finding(verified)

        trusted = findings.relevant_findings(
            sink_type="probe:html_body",
            context_type="html_body",
            surviving_chars="<>/()",
        )
        all_tiers = findings.relevant_findings(
            sink_type="probe:html_body",
            context_type="html_body",
            surviving_chars="<>/()",
            allowed_tiers=(
                findings.MEMORY_TIER_CURATED,
                findings.MEMORY_TIER_VERIFIED_RUNTIME,
                findings.MEMORY_TIER_EXPERIMENTAL,
            ),
        )

        self.assertEqual([f.payload for f in trusted], ["<svg/onload=alert(1)>"])
        self.assertEqual({f.payload for f in all_tiers}, {
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
        })

    def test_verified_duplicate_upgrades_experimental_entry(self) -> None:
        experimental = findings.Finding(
            sink_type="probe:html_attr_url",
            context_type="html_attr_url",
            surviving_chars=":/()",
            bypass_family="case-variant",
            payload="jaVasCript:alert(1)",
            test_vector="?next=jaVasCript:alert(1)",
            model="xssy-learn",
            memory_tier=findings.MEMORY_TIER_EXPERIMENTAL,
        )
        verified = findings.Finding(
            sink_type="probe:html_attr_url",
            context_type="html_attr_url",
            surviving_chars=":/()",
            bypass_family="case-variant",
            payload="jaVasCript:alert(1)",
            test_vector="?next=jaVasCript:alert(1)",
            model="cloud_model",
            verified=True,
            memory_tier=findings.MEMORY_TIER_VERIFIED_RUNTIME,
            evidence_type="active_scan",
            success_count=1,
        )

        findings.save_finding(experimental)
        findings.save_finding(verified)

        stored = findings.load_findings("html_attr_url")
        self.assertEqual(len(stored), 1)
        self.assertTrue(stored[0].verified)
        self.assertEqual(stored[0].memory_tier, findings.MEMORY_TIER_VERIFIED_RUNTIME)
        self.assertEqual(stored[0].success_count, 1)

    def test_host_scoped_findings_do_not_cross_pollinate(self) -> None:
        same_host = findings.Finding(
            sink_type="probe:html_body",
            context_type="html_body",
            surviving_chars="<>/()",
            bypass_family="event-handler-injection",
            payload="<svg/onload=alert(1)>",
            test_vector="?q=<svg/onload=alert(1)>",
            model="local_model",
            verified=True,
            memory_tier=findings.MEMORY_TIER_VERIFIED_RUNTIME,
            target_scope=findings.TARGET_SCOPE_HOST,
            target_host="app.example.test",
        )
        other_host = findings.Finding(
            sink_type="probe:html_body",
            context_type="html_body",
            surviving_chars="<>/()",
            bypass_family="event-handler-injection",
            payload="<img src=x onerror=alert(1)>",
            test_vector="?q=<img src=x onerror=alert(1)>",
            model="local_model",
            verified=True,
            memory_tier=findings.MEMORY_TIER_VERIFIED_RUNTIME,
            target_scope=findings.TARGET_SCOPE_HOST,
            target_host="other.example.test",
        )

        findings.save_finding(same_host)
        findings.save_finding(other_host)

        retrieved = findings.relevant_findings(
            sink_type="probe:html_body",
            context_type="html_body",
            surviving_chars="<>/()",
            target_host="app.example.test",
        )
        self.assertEqual([f.payload for f in retrieved], ["<svg/onload=alert(1)>"])

    def test_retrieval_prefers_matching_target_landscape(self) -> None:
        generic = findings.Finding(
            sink_type="probe:html_attr_url",
            context_type="html_attr_url",
            surviving_chars=":/()",
            bypass_family="case-variant",
            payload="javascript:alert(1)",
            test_vector="?next=javascript:alert(1)",
            model="seed",
            verified=True,
            memory_tier=findings.MEMORY_TIER_CURATED,
            target_scope=findings.TARGET_SCOPE_GLOBAL,
        )
        tailored = findings.Finding(
            sink_type="probe:html_attr_url",
            context_type="html_attr_url",
            surviving_chars=":/()",
            bypass_family="case-variant",
            payload="jaVasCript:alert(1)",
            test_vector="?next=jaVasCript:alert(1)",
            model="local_model",
            verified=True,
            memory_tier=findings.MEMORY_TIER_VERIFIED_RUNTIME,
            target_scope=findings.TARGET_SCOPE_HOST,
            target_host="app.example.test",
            waf_name="cloudflare",
            delivery_mode="get",
            frameworks=["react"],
        )

        findings.save_finding(generic)
        findings.save_finding(tailored)

        retrieved = findings.relevant_findings(
            sink_type="probe:html_attr_url",
            context_type="html_attr_url",
            surviving_chars=":/()",
            target_host="app.example.test",
            waf_name="cloudflare",
            delivery_mode="get",
            frameworks=("react",),
        )
        self.assertEqual(retrieved[0].payload, "jaVasCript:alert(1)")

    def test_review_promote_and_reject_update_metadata(self) -> None:
        pending = findings.Finding(
            sink_type="probe:html_body",
            context_type="html_body",
            surviving_chars="<>/()",
            bypass_family="event-handler-injection",
            payload="<svg/onload=alert(1)>",
            test_vector="?q=<svg/onload=alert(1)>",
            model="xssy-learn",
            memory_tier=findings.MEMORY_TIER_EXPERIMENTAL,
            target_scope=findings.TARGET_SCOPE_GLOBAL,
        )
        findings.save_finding(pending)
        fid = findings.finding_id(pending)

        promoted = findings.review_finding(
            fid,
            reviewer="tester",
            note="portable enough to trust",
            promote_to=findings.MEMORY_TIER_CURATED,
            target_scope=findings.TARGET_SCOPE_GLOBAL,
        )
        self.assertEqual(promoted.review_status, findings.REVIEW_STATUS_APPROVED)
        self.assertEqual(promoted.memory_tier, findings.MEMORY_TIER_CURATED)
        self.assertEqual(promoted.reviewed_by, "tester")

        rejected_seed = findings.Finding(
            sink_type="probe:html_attr_url",
            context_type="html_attr_url",
            surviving_chars=":/()",
            bypass_family="case-variant",
            payload="jaVasCript:alert(1)",
            test_vector="?next=jaVasCript:alert(1)",
            model="xssy-learn",
            memory_tier=findings.MEMORY_TIER_EXPERIMENTAL,
        )
        findings.save_finding(rejected_seed)
        rejected = findings.review_finding(
            findings.finding_id(rejected_seed),
            reviewer="tester",
            note="too target-specific",
            reject=True,
        )
        self.assertEqual(rejected.review_status, findings.REVIEW_STATUS_REJECTED)
        self.assertEqual(rejected.review_note, "too target-specific")

    def test_memory_source_filters_labs_vs_targets(self) -> None:
        lab = findings.Finding(
            sink_type="probe:html_body",
            context_type="html_body",
            surviving_chars="<>",
            bypass_family="event-handler-injection",
            payload="<svg/onload=alert(1)>",
            test_vector="?q=<svg/onload=alert(1)>",
            model="xssy-learn",
            memory_tier=findings.MEMORY_TIER_EXPERIMENTAL,
            evidence_type="xssy_generation",
            tags=["offline-learning", "xssy:1"],
        )
        target = findings.Finding(
            sink_type="probe:html_body",
            context_type="html_body",
            surviving_chars="<>",
            bypass_family="event-handler-injection",
            payload="<img src=x onerror=alert(1)>",
            test_vector="?q=<img src=x onerror=alert(1)>",
            model="local_model",
            memory_tier=findings.MEMORY_TIER_EXPERIMENTAL,
            evidence_type="cloud_generation",
        )

        findings.save_finding(lab)
        findings.save_finding(target)

        self.assertEqual(len(findings.review_queue(memory_source=findings.MEMORY_SOURCE_LABS)), 1)
        self.assertEqual(len(findings.review_queue(memory_source=findings.MEMORY_SOURCE_TARGETS)), 1)
        self.assertEqual(findings.memory_stats(memory_source=findings.MEMORY_SOURCE_LABS)["total"], 1)
        self.assertEqual(findings.memory_stats(memory_source=findings.MEMORY_SOURCE_TARGETS)["total"], 1)


if __name__ == "__main__":
    unittest.main()
