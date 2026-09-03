"""Tests for the standalone backup job report parser.

Uses apps/log_intake/fixtures/backup_report_60_lines.log as test data.
That fixture is a SYNTHETIC, hand-authored sample -- not a real backup
system export -- used here purely as a format/structure reference.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

Plain unittest.TestCase on purpose: this parser has no Django/DB dependency
(it isn't wired into the upload pipeline yet), so the tests shouldn't need
one either.
"""

from pathlib import Path
from unittest import TestCase

from apps.log_intake.services.backup_report_parser import parse_backup_report_log

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "backup_report_60_lines.log"


class ParseBackupReportLogTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.raw_text = FIXTURE_PATH.read_text(encoding="utf-8")
        cls.events = parse_backup_report_log(cls.raw_text)
        cls.by_type = {}
        for event in cls.events:
            cls.by_type.setdefault(event.event_type, []).append(event)

    def test_fixture_has_8_job_stanzas(self):
        # Sanity check on the fixture itself, not the parser.
        self.assertEqual(self.raw_text.count("Job Name:"), 8)

    def test_produces_one_event_per_vm_result_plus_unexplained_job_events(self):
        # 19 VM-level results (2+3+2+3+2+3+2+2 across the 8 jobs) plus 2
        # "unexplained" job-level events (jobs 1 and 3: job Status=WARNING
        # but every VM in them succeeded).
        self.assertEqual(len(self.events), 21)

    def test_vm_level_severity_counts(self):
        self.assertEqual(len(self.by_type["backup_success"]), 15)
        self.assertEqual(len(self.by_type["backup_warning"]), 2)
        self.assertEqual(len(self.by_type["backup_failed"]), 2)

    def test_vm_severity_driven_by_vm_result_not_job_status(self):
        for event in self.by_type["backup_success"]:
            self.assertEqual(event.severity_hint, "low")
        for event in self.by_type["backup_warning"]:
            self.assertEqual(event.severity_hint, "medium")
        for event in self.by_type["backup_failed"]:
            self.assertEqual(event.severity_hint, "high")

    def test_unexplained_job_events_only_fire_when_no_vm_explains_the_status(self):
        # Jobs 1 and 3: Status=WARNING, all VMs succeeded.
        unexplained = self.by_type["backup_job_warning_unexplained"]
        self.assertEqual(len(unexplained), 2)
        for event in unexplained:
            self.assertEqual(event.severity_hint, "medium")
            self.assertEqual(event.confidence_score, 0.65)
            self.assertIn("no individual VM result explains it", event.normalized_summary)

    def test_job6_failed_status_does_not_produce_an_unexplained_event(self):
        # Job 6: Status=FAILED, and VM APP01 within it is Result=FAILED --
        # that VM-level FAILED event already carries the true worst
        # severity, so no separate "unexplained" event should exist for it.
        self.assertNotIn("backup_job_failed_unexplained", self.by_type)

    def test_job8_under_stated_warning_is_visible_on_the_vm_event_itself(self):
        # Job 8: Status=WARNING, but VM FILE01 is Result=FAILED with a real
        # Error message. No separate event is emitted for this case (the
        # VM-level FAILED event already is the true worst signal) -- but
        # the disagreement must still be visible in that event's summary.
        failed_events = self.by_type["backup_failed"]
        file01_failure = next(e for e in failed_events if e.affected_system == "FILE01")
        self.assertIn("Permission denied writing backup archive", file01_failure.normalized_summary)
        self.assertIn("job reported WARNING overall", file01_failure.normalized_summary)

    def test_no_account_or_ip_fields_for_this_format(self):
        for event in self.events:
            self.assertEqual(event.account, "")
            self.assertIsNone(event.source_ip)
            self.assertIsNone(event.destination_ip)

    def test_timestamp_uses_end_time(self):
        first_success = self.by_type["backup_success"][0]
        self.assertEqual(first_success.timestamp.isoformat(), "2026-08-23T01:02:00")

    def test_source_tool_defaults_to_backup(self):
        for event in self.events:
            self.assertEqual(event.source_tool, "backup")

    def test_unexplained_job_event_scoped_to_server_not_a_vm(self):
        for event in self.by_type["backup_job_warning_unexplained"]:
            self.assertEqual(event.affected_system, "pbs01.example.local")

    def test_confidence_scores_reflect_directly_reported_vs_inferred(self):
        for event in self.by_type["backup_success"]:
            self.assertEqual(event.confidence_score, 0.92)
        for event in self.by_type["backup_job_warning_unexplained"]:
            self.assertEqual(event.confidence_score, 0.65)
