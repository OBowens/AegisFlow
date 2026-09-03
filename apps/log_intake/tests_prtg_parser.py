"""Tests for the standalone PRTG sensor-status parser.

Uses apps/log_intake/fixtures/prtg_50.csv as test data. That fixture is a
SYNTHETIC, hand-authored sample (per the fixture set's own README) -- not a
real PRTG export -- used here purely as a format/structure reference.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

Plain unittest.TestCase on purpose: this parser has no Django/DB dependency
(it isn't wired into the upload pipeline yet), so the tests shouldn't need
one either.
"""

from datetime import datetime
from pathlib import Path
from unittest import TestCase

from apps.log_intake.services.prtg_parser import parse_prtg_log

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "prtg_50.csv"


class ParsePrtgLogTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.raw_text = FIXTURE_PATH.read_text(encoding="utf-8")
        cls.events = parse_prtg_log(cls.raw_text)
        cls.by_type = {}
        for event in cls.events:
            cls.by_type.setdefault(event.event_type, []).append(event)

    def test_produces_one_event_per_row(self):
        self.assertEqual(len(self.events), 50)

    def test_status_counts_match_fixture(self):
        self.assertEqual(len(self.by_type["sensor_up"]), 30)
        self.assertEqual(len(self.by_type["sensor_warning"]), 8)
        self.assertEqual(len(self.by_type["sensor_paused"]), 6)
        self.assertEqual(len(self.by_type["sensor_unknown"]), 2)
        self.assertEqual(len(self.by_type["sensor_down"]), 4)

    def test_all_recognized_statuses_are_high_confidence(self):
        for event in self.events:
            self.assertEqual(event.confidence_score, 0.9)

    def test_down_status_is_high_severity(self):
        for event in self.by_type["sensor_down"]:
            self.assertEqual(event.severity_hint, "high")

    def test_warning_status_is_medium_severity(self):
        for event in self.by_type["sensor_warning"]:
            self.assertEqual(event.severity_hint, "medium")

    def test_up_status_is_low_severity(self):
        for event in self.by_type["sensor_up"]:
            self.assertEqual(event.severity_hint, "low")

    def test_paused_status_is_low_severity_not_an_alert(self):
        for event in self.by_type["sensor_paused"]:
            self.assertEqual(event.severity_hint, "low")

    def test_unknown_status_is_medium_severity(self):
        for event in self.by_type["sensor_unknown"]:
            self.assertEqual(event.severity_hint, "medium")

    def test_no_account_or_ip_fields_for_this_format(self):
        for event in self.events:
            self.assertEqual(event.account, "")
            self.assertIsNone(event.source_ip)
            self.assertIsNone(event.destination_ip)

    def test_first_row_matches_known_fixture_values(self):
        event = self.events[0]
        self.assertEqual(event.affected_system, "CORE-SW01")
        self.assertEqual(event.event_type, "sensor_up")
        self.assertEqual(event.severity_hint, "low")
        self.assertEqual(event.timestamp, datetime(2026, 8, 23, 8, 0, 0))
        self.assertIn("Traffic Port 24", event.normalized_summary)
        self.assertEqual(event.source_tool, "prtg")

    def test_all_events_have_a_timestamp(self):
        for event in self.events:
            self.assertIsNotNone(event.timestamp)
