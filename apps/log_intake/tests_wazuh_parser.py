"""Tests for the standalone Wazuh alert parser.

Uses apps/log_intake/fixtures/wazuh_50.jsonl as test data. That fixture is a
SYNTHETIC, hand-authored sample (per the fixture set's own README) -- not a
real Wazuh export -- used here purely as a format/structure reference.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

Plain unittest.TestCase on purpose: this parser has no Django/DB dependency
(it isn't wired into the upload pipeline yet), so the tests shouldn't need
one either.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import TestCase

from apps.log_intake.services.wazuh_parser import parse_wazuh_log

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "wazuh_50.jsonl"


class ParseWazuhLogTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.raw_text = FIXTURE_PATH.read_text(encoding="utf-8")
        cls.events = parse_wazuh_log(cls.raw_text)
        cls.by_type = {}
        for event in cls.events:
            cls.by_type.setdefault(event.event_type, []).append(event)

    def test_produces_one_event_per_line(self):
        # Unlike the multi-line sshd auth log, Wazuh alerts are already one
        # complete JSON object per event -- no correlation/collapsing needed.
        self.assertEqual(len(self.events), 50)

    def test_all_known_rule_ids_produce_high_confidence(self):
        for event in self.events:
            self.assertGreaterEqual(event.confidence_score, 0.9)

    def test_successful_login_is_low_severity(self):
        matches = self.by_type["successful_login"]
        self.assertEqual(len(matches), 1)
        event = matches[0]
        self.assertEqual(event.severity_hint, "low")
        self.assertEqual(event.account, "jsmith")
        self.assertEqual(event.source_ip, "10.20.15.44")
        self.assertEqual(event.affected_system, "rds01")
        self.assertEqual(
            event.timestamp,
            datetime(2026, 8, 23, 8, 12, 53, tzinfo=timezone(timedelta(hours=-4))),
        )

    def test_malware_detected_is_critical_with_no_account_or_ip(self):
        matches = self.by_type["malware_detected"]
        self.assertEqual(len(matches), 5)
        for event in matches:
            self.assertEqual(event.severity_hint, "critical")
            self.assertEqual(event.account, "")
            self.assertIsNone(event.source_ip)
            self.assertIn("Synthetic.Test.Malware", event.normalized_summary)

    def test_file_integrity_alert_is_high_severity(self):
        matches = self.by_type["file_integrity_alert"]
        self.assertEqual(len(matches), 7)
        for event in matches:
            self.assertEqual(event.severity_hint, "high")
            self.assertEqual(event.account, "")

    def test_invalid_user_login_attempt_is_medium_severity(self):
        matches = self.by_type["invalid_user_login_attempt"]
        self.assertEqual(len(matches), 5)
        for event in matches:
            self.assertEqual(event.severity_hint, "medium")
            self.assertIsNotNone(event.source_ip)
            self.assertNotEqual(event.account, "")

    def test_repeated_ssh_auth_failure_is_high_severity(self):
        matches = self.by_type["repeated_ssh_auth_failure"]
        self.assertEqual(len(matches), 4)
        for event in matches:
            self.assertEqual(event.severity_hint, "high")

    def test_password_changed_is_medium_severity_with_no_account(self):
        # The fixture never populates data.srcuser on rule 5103 rows.
        matches = self.by_type["password_changed"]
        self.assertEqual(len(matches), 5)
        for event in matches:
            self.assertEqual(event.severity_hint, "medium")
            self.assertEqual(event.account, "")

    def test_windows_login_failure_is_medium_severity_with_no_srcip(self):
        # Rule 18107 rows in this fixture carry no `data` block at all.
        matches = self.by_type["windows_login_failure"]
        self.assertEqual(len(matches), 8)
        for event in matches:
            self.assertEqual(event.severity_hint, "medium")
            self.assertIsNone(event.source_ip)
            self.assertEqual(event.account, "")

    def test_web_auth_failure_is_high_severity(self):
        matches = self.by_type["web_auth_failure"]
        self.assertEqual(len(matches), 5)
        for event in matches:
            self.assertEqual(event.severity_hint, "high")
            self.assertIsNotNone(event.source_ip)

    def test_web_server_error_is_medium_severity(self):
        matches = self.by_type["web_server_error"]
        self.assertEqual(len(matches), 6)
        for event in matches:
            self.assertEqual(event.severity_hint, "medium")

    def test_service_stopped_has_no_account_or_ip(self):
        matches = self.by_type["service_stopped"]
        self.assertEqual(len(matches), 4)
        for event in matches:
            self.assertEqual(event.account, "")
            self.assertIsNone(event.source_ip)

    def test_all_events_have_a_timestamp_and_source_tool(self):
        for event in self.events:
            self.assertIsNotNone(event.timestamp)
            self.assertEqual(event.source_tool, "wazuh")

    def test_raw_message_is_the_full_original_json(self):
        # Nothing is discarded -- raw_message round-trips the whole alert.
        event = self.events[1]  # rule 5710, has a data block
        self.assertIn('"srcuser": "klee"', event.raw_message)
        self.assertIn('"srcip": "203.0.113.55"', event.raw_message)
