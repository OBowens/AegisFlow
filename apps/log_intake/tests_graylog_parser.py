"""Tests for the standalone Graylog message parser.

Uses apps/log_intake/fixtures/graylog_50.jsonl as test data. That fixture is
a SYNTHETIC, hand-authored sample (per the fixture set's own README) -- not
a real Graylog export -- used here purely as a format/structure reference.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

Plain unittest.TestCase on purpose: this parser has no Django/DB dependency
(it isn't wired into the upload pipeline yet), so the tests shouldn't need
one either.

Row indices below (events[N]) are 0-based and correspond 1:1 to the
fixture's line numbers (line 1 -> events[0]), since this parser emits
exactly one event per JSON line with no correlation/collapsing.
"""

from pathlib import Path
from unittest import TestCase

from apps.log_intake.services.graylog_parser import parse_graylog_log

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "graylog_50.jsonl"


class ParseGraylogLogTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.raw_text = FIXTURE_PATH.read_text(encoding="utf-8")
        cls.events = parse_graylog_log(cls.raw_text)
        cls.by_type = {}
        for event in cls.events:
            cls.by_type.setdefault(event.event_type, []).append(event)

    def test_produces_one_event_per_line(self):
        self.assertEqual(len(self.events), 50)

    def test_sshd_facility_splits_into_successful_and_failed_logins(self):
        self.assertEqual(len(self.by_type["successful_login"]), 6)
        self.assertEqual(len(self.by_type["failed_login"]), 13)
        for event in self.by_type["successful_login"]:
            self.assertEqual(event.severity_hint, "low")  # all level 6 in fixture
            self.assertEqual(event.confidence_score, 0.95)
        for event in self.by_type["failed_login"]:
            self.assertEqual(event.severity_hint, "medium")  # all level 4 in fixture
            self.assertNotEqual(event.account, "")
            self.assertIsNotNone(event.source_ip)

    def test_sshd_extracts_account_and_source_ip(self):
        event = self.events[2]  # line 3: Accepted password for mroberts from 10.20.15.51
        self.assertEqual(event.event_type, "successful_login")
        self.assertEqual(event.account, "mroberts")
        self.assertEqual(event.source_ip, "10.20.15.51")
        self.assertEqual(event.affected_system, "web-server01")

    def test_firewall_severity_comes_from_explicit_field_not_level(self):
        # Every firewall row shares graylog level=2, but severity varies
        # (high/medium/critical) via the firewall's own `severity` field --
        # confirms we're trusting that field, not re-deriving from level.
        matches = self.by_type["ips_blocked"] + self.by_type["ips_allowed"]
        self.assertEqual(len(matches), 8)
        severities = {event.severity_hint for event in matches}
        self.assertEqual(severities, {"high", "medium", "critical"})
        for event in matches:
            self.assertEqual(event.confidence_score, 0.95)
            self.assertIsNotNone(event.source_ip)
            self.assertIsNotNone(event.destination_ip)

    def test_firewall_blocked_vs_allowed_action_split(self):
        self.assertEqual(len(self.by_type["ips_blocked"]), 2)
        self.assertEqual(len(self.by_type["ips_allowed"]), 6)

    def test_application_http_status_drives_event_type_and_severity(self):
        self.assertEqual(len(self.by_type["http_response_200"]), 2)
        self.assertEqual(len(self.by_type["http_response_403"]), 2)
        self.assertEqual(len(self.by_type["http_response_401"]), 1)
        for event in self.by_type["http_response_200"]:
            self.assertEqual(event.severity_hint, "low")
        for event in self.by_type["http_response_403"] + self.by_type["http_response_401"]:
            self.assertEqual(event.severity_hint, "high")

    def test_backup_message_vocabulary_maps_to_distinct_event_types(self):
        self.assertEqual(len(self.by_type["backup_snapshot_cleanup_warning"]), 3)
        self.assertEqual(len(self.by_type["backup_job_failed"]), 2)
        self.assertEqual(len(self.by_type["backup_job_completed"]), 1)

    def test_backup_severity_comes_from_message_not_level(self):
        # The fixture's `level` field disagrees with itself for the same
        # backup message (e.g. "snapshot cleanup warning" appears at both
        # level 3 and level 6), so severity_hint must come from the
        # message-based completed/warning/failed classification instead --
        # every row of a given backup message type gets the same severity,
        # mirroring backup_report_parser.py's _STATUS_SEVERITY.
        for event in self.by_type["backup_snapshot_cleanup_warning"]:
            self.assertEqual(event.severity_hint, "medium")
        for event in self.by_type["backup_job_failed"]:
            self.assertEqual(event.severity_hint, "high")
        for event in self.by_type["backup_job_completed"]:
            self.assertEqual(event.severity_hint, "low")

    def test_postgres_message_vocabulary_maps_to_distinct_event_types(self):
        self.assertEqual(len(self.by_type["db_checkpoint_complete"]), 2)
        self.assertEqual(len(self.by_type["db_connection_limit_reached"]), 3)

    def test_postgres_severity_comes_from_message_not_level(self):
        # "too many connections" appears at three different levels in the
        # fixture (3, 4, 5) despite being the same real capacity concern
        # every time -- severity_hint must come from the message-based
        # classification instead, same fix as backup.
        for event in self.by_type["db_checkpoint_complete"]:
            self.assertEqual(event.severity_hint, "low")
        for event in self.by_type["db_connection_limit_reached"]:
            self.assertEqual(event.severity_hint, "medium")

    def test_windows_severity_comes_from_message_not_level(self):
        # "Account locked out" appears at level 6 (x2) and level 4 in the
        # fixture despite being the same event every time -- severity_hint
        # must come from the message-based classification instead.
        for event in self.by_type["account_lockout"]:
            self.assertEqual(event.severity_hint, "high")
        for event in self.by_type["successful_logon"]:
            self.assertEqual(event.severity_hint, "low")
        for event in self.by_type["logon_failure"]:
            self.assertEqual(event.severity_hint, "medium")
        for event in self.by_type["group_membership_change"]:
            self.assertEqual(event.severity_hint, "medium")

    def test_windows_facility_uses_message_not_unreliable_event_id(self):
        # event_id is inconsistent with message in this fixture (e.g. 4728
        # appears against "Account locked out", "User logon successful",
        # and "User logon failed" alike) -- event_type must come from
        # message text, and confidence must reflect the lower certainty of
        # a free-text-only classification.
        self.assertEqual(len(self.by_type["account_lockout"]), 3)
        self.assertEqual(len(self.by_type["successful_logon"]), 2)
        self.assertEqual(len(self.by_type["group_membership_change"]), 1)
        self.assertEqual(len(self.by_type["logon_failure"]), 1)
        for event_type in (
            "account_lockout",
            "successful_logon",
            "group_membership_change",
            "logon_failure",
        ):
            for event in self.by_type[event_type]:
                self.assertEqual(event.confidence_score, 0.65)
                self.assertEqual(event.account, "")
                self.assertIsNone(event.source_ip)
                self.assertIn('"event_id"', event.raw_message)

    def test_all_events_have_a_timestamp_and_source_tool(self):
        for event in self.events:
            self.assertIsNotNone(event.timestamp)
            self.assertEqual(event.source_tool, "graylog")

    def test_timestamp_parses_z_suffix_as_utc(self):
        event = self.events[0]
        self.assertEqual(event.timestamp.isoformat(), "2026-08-23T12:00:17+00:00")
