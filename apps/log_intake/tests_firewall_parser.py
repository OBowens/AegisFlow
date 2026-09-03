"""Tests for the standalone FortiGate-style firewall parser.

Uses apps/log_intake/fixtures/firewall_fortigate_style_50.log as test data.
That fixture is a SYNTHETIC, hand-authored sample -- not a real FortiGate
export -- used here purely as a format/structure reference.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

Plain unittest.TestCase on purpose: this parser has no Django/DB dependency
(it isn't wired into the upload pipeline yet), so the tests shouldn't need
one either.
"""

from pathlib import Path
from unittest import TestCase

from apps.log_intake.services.firewall_parser import parse_fortigate_firewall_log

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "firewall_fortigate_style_50.log"


class ParseFortigateFirewallLogTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.raw_text = FIXTURE_PATH.read_text(encoding="utf-8")
        cls.events = parse_fortigate_firewall_log(cls.raw_text)
        cls.by_type = {}
        for event in cls.events:
            cls.by_type.setdefault(event.event_type, []).append(event)

    def test_produces_one_event_per_line(self):
        self.assertEqual(len(self.events), 50)

    def test_subtype_counts_match_fixture(self):
        self.assertEqual(len(self.by_type["malware_blocked"]), 6)
        self.assertEqual(
            len(self.by_type["dns_query_blocked"]) + len(self.by_type["dns_query_allowed"]), 9
        )
        self.assertEqual(
            len(self.by_type["web_category_blocked"]) + len(self.by_type["web_category_bypassed"]), 9
        )
        self.assertEqual(len(self.by_type["intrusion_blocked"]), 7)
        self.assertEqual(
            len(self.by_type["traffic_allowed"]) + len(self.by_type["traffic_denied"]), 6
        )
        self.assertEqual(len(self.by_type["vpn_login_failure"]), 5)
        self.assertEqual(len(self.by_type["admin_login_failure"]), 8)

    def test_virus_always_critical_regardless_of_action(self):
        for event in self.by_type["malware_blocked"]:
            self.assertEqual(event.severity_hint, "critical")
            self.assertEqual(event.confidence_score, 0.97)

    def test_dns_pass_scores_higher_than_block(self):
        # action="pass" on an already-flagged query is worse than "block".
        self.assertEqual(len(self.by_type["dns_query_blocked"]), 3)
        self.assertEqual(len(self.by_type["dns_query_allowed"]), 6)
        for event in self.by_type["dns_query_blocked"]:
            self.assertEqual(event.severity_hint, "medium")
        for event in self.by_type["dns_query_allowed"]:
            self.assertEqual(event.severity_hint, "high")

    def test_webfilter_malicious_category_outranks_business_or_unrated(self):
        malicious_blocked = [
            e
            for e in self.by_type["web_category_blocked"]
            if "Malicious Websites" in e.normalized_summary
        ]
        other_blocked = [
            e
            for e in self.by_type["web_category_blocked"]
            if "Malicious Websites" not in e.normalized_summary
        ]
        self.assertTrue(malicious_blocked)
        self.assertTrue(other_blocked)
        for event in malicious_blocked:
            self.assertEqual(event.severity_hint, "high")
        for event in other_blocked:
            self.assertEqual(event.severity_hint, "low")

        malicious_passthrough = [
            e
            for e in self.by_type["web_category_bypassed"]
            if "Malicious Websites" in e.normalized_summary
        ]
        self.assertTrue(malicious_passthrough)
        for event in malicious_passthrough:
            self.assertEqual(event.severity_hint, "critical")

    def test_ips_uses_fortigates_own_severity_field_directly(self):
        severities = {event.severity_hint for event in self.by_type["intrusion_blocked"]}
        self.assertEqual(severities, {"critical", "high", "medium"})
        critical_events = [e for e in self.by_type["intrusion_blocked"] if e.severity_hint == "critical"]
        self.assertEqual(len(critical_events), 1)
        high_events = [e for e in self.by_type["intrusion_blocked"] if e.severity_hint == "high"]
        self.assertEqual(len(high_events), 4)
        medium_events = [e for e in self.by_type["intrusion_blocked"] if e.severity_hint == "medium"]
        self.assertEqual(len(medium_events), 2)

    def test_traffic_forward_is_always_low_severity_bulk_noise(self):
        for event in self.by_type.get("traffic_allowed", []) + self.by_type.get("traffic_denied", []):
            self.assertEqual(event.severity_hint, "low")
            self.assertEqual(event.confidence_score, 0.6)

    def test_vpn_unknown_user_scores_higher_than_bad_password(self):
        unknown_user_events = [
            e for e in self.by_type["vpn_login_failure"] if "sslvpn_login_unknown_user" in e.normalized_summary
        ]
        bad_password_events = [
            e for e in self.by_type["vpn_login_failure"] if "bad_password" in e.normalized_summary
        ]
        self.assertEqual(len(unknown_user_events), 1)
        self.assertEqual(len(bad_password_events), 2)
        for event in unknown_user_events:
            self.assertEqual(event.severity_hint, "high")
        for event in bad_password_events:
            self.assertEqual(event.severity_hint, "medium")

    def test_admin_login_failure_is_high_severity_with_account_and_ip(self):
        for event in self.by_type["admin_login_failure"]:
            self.assertEqual(event.severity_hint, "high")
            self.assertEqual(event.account, "admin")
            self.assertIsNotNone(event.source_ip)
            self.assertEqual(event.affected_system, "FW-EDGE-01")

    def test_traffic_content_subtypes_use_srcip_as_affected_system(self):
        for event in self.by_type["malware_blocked"]:
            self.assertEqual(event.affected_system, event.source_ip)

    def test_control_plane_subtypes_use_devname_as_affected_system(self):
        for event in self.by_type["vpn_login_failure"]:
            self.assertEqual(event.affected_system, "FW-EDGE-01")

    def test_timestamp_parses_from_split_date_and_time_fields(self):
        first_event = self.events[0]
        self.assertEqual(first_event.timestamp.isoformat(), "2026-08-23T08:00:36")

    def test_source_tool_defaults_to_firewall(self):
        for event in self.events:
            self.assertEqual(event.source_tool, "firewall")

    def test_first_line_matches_known_fixture_values(self):
        event = self.events[0]
        self.assertEqual(event.event_type, "malware_blocked")
        self.assertEqual(event.severity_hint, "critical")
        self.assertEqual(event.source_ip, "10.20.15.87")
        self.assertEqual(event.destination_ip, "203.0.113.22")
        self.assertIn("Synthetic-Test-Malware", event.normalized_summary)
        self.assertIn("invoice.exe", event.normalized_summary)
