"""Tests for the standalone Windows Security event parser.

Uses apps/log_intake/fixtures/windows_security_50.jsonl as test data. That
fixture is a SYNTHETIC, hand-authored sample (per the fixture set's own
README) -- not a real Windows Event Log export -- used here purely as a
format/structure reference.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

Plain unittest.TestCase on purpose: this parser has no Django/DB dependency
(it isn't wired into the upload pipeline yet), so the tests shouldn't need
one either.
"""

from pathlib import Path
from unittest import TestCase

from apps.log_intake.services.windows_security_parser import parse_windows_security_log

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "windows_security_50.jsonl"


class ParseWindowsSecurityLogTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.raw_text = FIXTURE_PATH.read_text(encoding="utf-8")
        cls.events = parse_windows_security_log(cls.raw_text)
        cls.by_type = {}
        for event in cls.events:
            cls.by_type.setdefault(event.event_type, []).append(event)

    def test_produces_one_event_per_line(self):
        self.assertEqual(len(self.events), 50)

    def test_event_id_counts_match_fixture(self):
        expected = {
            "successful_logon": 3,
            "logon_failure": 6,
            "logoff": 1,
            "explicit_credential_logon": 6,
            "privileged_logon": 2,
            "process_created": 4,
            "account_created": 1,
            "account_enabled": 2,
            "account_disabled": 3,
            "group_added_global_group": 1,
            "group_added_local_group": 6,
            "account_lockout": 4,
            "kerberos_ticket_requested": 6,
            "kerberos_service_ticket_requested": 3,
            "kerberos_preauth_failed": 2,
        }
        for event_type, count in expected.items():
            self.assertEqual(
                len(self.by_type.get(event_type, [])), count, msg=f"event_type={event_type}"
            )
        self.assertEqual(sum(expected.values()), 50)

    def test_all_known_event_ids_produce_high_confidence(self):
        for event in self.events:
            self.assertGreaterEqual(event.confidence_score, 0.97)

    def test_account_lockout_is_high_severity(self):
        for event in self.by_type["account_lockout"]:
            self.assertEqual(event.severity_hint, "high")

    def test_logon_failure_is_medium_severity_and_carries_failure_reason(self):
        for event in self.by_type["logon_failure"]:
            self.assertEqual(event.severity_hint, "medium")
            self.assertNotEqual(event.account, "")

    def test_successful_logon_is_low_severity(self):
        for event in self.by_type["successful_logon"]:
            self.assertEqual(event.severity_hint, "low")

    def test_privilege_and_identity_events_are_escalated_above_information_level(self):
        # These are all Level=Information in the raw fixture, but our
        # EventID table intentionally scores them medium as commonly
        # watched identity/privilege-change indicators.
        for event_type in (
            "explicit_credential_logon",
            "privileged_logon",
            "account_created",
            "account_enabled",
            "group_added_global_group",
            "group_added_local_group",
        ):
            for event in self.by_type[event_type]:
                self.assertEqual(event.severity_hint, "medium")

    def test_process_created_extracts_account_and_stays_low_severity(self):
        matches = self.by_type["process_created"]
        self.assertEqual(len(matches), 4)
        for event in matches:
            self.assertEqual(event.severity_hint, "low")
            self.assertNotEqual(event.account, "")

    def test_kerberos_ticket_events_extract_ip_and_are_low_severity(self):
        for event in self.by_type["kerberos_ticket_requested"]:
            self.assertEqual(event.severity_hint, "low")
            self.assertIsNotNone(event.source_ip)

    def test_first_event_matches_known_fixture_row(self):
        # Line 1: EventID 4732, Computer APP01.example.local, TargetUserName jsmith
        event = self.events[0]
        self.assertEqual(event.event_type, "group_added_local_group")
        self.assertEqual(event.affected_system, "APP01.example.local")
        self.assertEqual(event.account, "jsmith")
        self.assertEqual(event.severity_hint, "medium")
        self.assertIsNone(event.source_ip)

    def test_all_events_have_affected_system_timestamp_and_source_tool(self):
        for event in self.events:
            self.assertIsNotNone(event.timestamp)
            self.assertNotEqual(event.affected_system, "Unknown system")
            self.assertEqual(event.source_tool, "windows")

    def test_destination_ip_is_never_populated(self):
        # Windows Security events describe the local host, not a connection
        # pair, so destination_ip has no source field to come from.
        for event in self.events:
            self.assertIsNone(event.destination_ip)
