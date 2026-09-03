"""Tests for the standalone SSL certificate inventory parser.

Uses apps/log_intake/fixtures/ssl_certificate_50.csv as test data. That
fixture is a SYNTHETIC, hand-authored sample (per the fixture set's own
README) -- not a real certificate scan -- used here purely as a
format/structure reference.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

Plain unittest.TestCase on purpose: this parser has no Django/DB dependency
(it isn't wired into the upload pipeline yet), so the tests shouldn't need
one either.
"""

from pathlib import Path
from unittest import TestCase

from apps.log_intake.services.ssl_certificate_parser import parse_ssl_certificate_log

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "ssl_certificate_50.csv"


class ParseSslCertificateLogTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.raw_text = FIXTURE_PATH.read_text(encoding="utf-8")
        cls.events = parse_ssl_certificate_log(cls.raw_text)
        cls.by_type = {}
        for event in cls.events:
            cls.by_type.setdefault(event.event_type, []).append(event)

    def test_produces_one_event_per_row(self):
        self.assertEqual(len(self.events), 50)

    def test_status_counts_match_fixture(self):
        self.assertEqual(len(self.by_type["certificate_valid"]), 26)
        self.assertEqual(len(self.by_type["certificate_expiring_soon"]), 8)
        self.assertEqual(len(self.by_type["certificate_expiring_critical"]), 4)
        self.assertEqual(len(self.by_type["certificate_expired"]), 5)
        self.assertEqual(len(self.by_type["certificate_name_mismatch"]), 7)

    def test_all_recognized_statuses_are_near_certain_confidence(self):
        for event in self.events:
            self.assertEqual(event.confidence_score, 0.99)

    def test_valid_is_low_severity(self):
        for event in self.by_type["certificate_valid"]:
            self.assertEqual(event.severity_hint, "low")

    def test_expiring_soon_is_medium_severity(self):
        for event in self.by_type["certificate_expiring_soon"]:
            self.assertEqual(event.severity_hint, "medium")

    def test_expiring_critical_and_expired_are_both_critical_severity(self):
        for event in self.by_type["certificate_expiring_critical"]:
            self.assertEqual(event.severity_hint, "critical")
        for event in self.by_type["certificate_expired"]:
            self.assertEqual(event.severity_hint, "critical")

    def test_name_mismatch_is_high_not_critical_severity(self):
        for event in self.by_type["certificate_name_mismatch"]:
            self.assertEqual(event.severity_hint, "high")

    def test_timestamp_is_deliberately_none(self):
        # No field in this format answers "when did this event happen" --
        # valid_from/valid_to are a validity window, not an event time.
        for event in self.events:
            self.assertIsNone(event.timestamp)

    def test_no_account_or_ip_fields_for_this_format(self):
        for event in self.events:
            self.assertEqual(event.account, "")
            self.assertIsNone(event.source_ip)
            self.assertIsNone(event.destination_ip)

    def test_first_row_matches_known_fixture_values(self):
        # Row 1: service01.example.gov.vc / common_name other01... / NAME_MISMATCH
        event = self.events[0]
        self.assertEqual(event.affected_system, "service01.example.gov.vc")
        self.assertEqual(event.event_type, "certificate_name_mismatch")
        self.assertEqual(event.severity_hint, "high")
        self.assertIn("common_name=other01.example.gov.vc", event.normalized_summary)
        self.assertEqual(event.source_tool, "ssl_certificate")

    def test_name_mismatch_common_name_always_differs_from_hostname(self):
        for event in self.by_type["certificate_name_mismatch"]:
            self.assertIn("common_name=", event.normalized_summary)
