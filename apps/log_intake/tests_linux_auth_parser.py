"""Tests for the standalone Linux sshd auth-log parser.

Uses the real sample file captured from journalctl on this VM
(apps/log_intake/fixtures/linux_auth_sample.log) as a fixture. That file is
mostly automated internet scanning noise against sshd, not a real incident
on this system -- it's used here purely as a format/structure reference.

Plain unittest.TestCase on purpose: this parser has no Django/DB
dependency yet (it isn't wired into the upload pipeline), so the tests
shouldn't need one either.
"""

from pathlib import Path
from unittest import TestCase

from apps.log_intake.services.linux_auth_parser import parse_linux_auth_log

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "linux_auth_sample.log"


class ParseLinuxAuthLogTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.raw_text = FIXTURE_PATH.read_text(encoding="utf-8")
        cls.events = parse_linux_auth_log(cls.raw_text)
        cls.by_ip = {}
        for event in cls.events:
            cls.by_ip.setdefault(event.source_ip, []).append(event)

    def test_produces_one_event_per_connection_not_per_line(self):
        # The fixture has 500 lines but only a fraction are distinct sshd
        # connections; each connection's probe/disconnect lines must
        # collapse into a single event.
        self.assertGreater(len(self.events), 50)
        self.assertLess(len(self.events), 250)

    def test_invalid_user_probe_merges_disconnect_lines(self):
        # PID 284079: "Invalid user danny from 123.58.213.128 port 59646"
        # + "Received disconnect ..." + "Disconnected from invalid user
        # danny ..." must become exactly one invalid_user_probe event.
        matches = [
            e for e in self.by_ip.get("123.58.213.128", []) if e.account == "danny"
        ]
        self.assertEqual(len(matches), 1)
        event = matches[0]
        self.assertEqual(event.event_type, "invalid_user_probe")
        self.assertEqual(event.severity_hint, "low")
        self.assertIn("Invalid user danny", event.raw_message)
        self.assertIn("Disconnected from invalid user danny", event.raw_message)
        self.assertEqual(event.timestamp.isoformat(), "2026-08-23T18:55:14.241419+00:00")

    def test_authenticating_user_disconnect_only_maps_to_failed_login(self):
        # PID 284063 in the fixture has *only* the disconnect-family lines
        # for this connection (no leading "Invalid user" line, since root
        # is a real account) -- the parser must still originate one event
        # from those lines alone, at the connection's own timestamp/port
        # (202.101.144.44 scans repeatedly, so scope by port to isolate it).
        matches = [
            e
            for e in self.by_ip.get("202.101.144.44", [])
            if e.account == "root" and e.raw_message.endswith("port 37047 [preauth]")
        ]
        self.assertEqual(len(matches), 1)
        event = matches[0]
        self.assertEqual(event.event_type, "failed_login")
        self.assertEqual(event.severity_hint, "medium")
        self.assertLess(event.confidence_score, 0.9)  # inferred, not stated outright

    def test_successful_publickey_login_is_low_severity_high_confidence(self):
        matches = [e for e in self.events if e.event_type == "successful_login"]
        self.assertEqual(len(matches), 2)
        for event in matches:
            self.assertEqual(event.account, "prett")
            self.assertEqual(event.source_ip, "69.79.13.222")
            self.assertEqual(event.severity_hint, "low")
            self.assertGreaterEqual(event.confidence_score, 0.95)

    def test_blank_username_probe_has_no_account_but_still_parses(self):
        matches = [e for e in self.by_ip.get("45.153.34.71", [])]
        self.assertEqual(len(matches), 1)
        event = matches[0]
        self.assertEqual(event.event_type, "invalid_user_probe")
        self.assertEqual(event.account, "")

    def test_bare_connection_teardown_with_no_username_is_low_confidence_disconnect(self):
        # PID 285874/285876/285878: "Connection closed by IP port N
        # [preauth]" with no username at all.
        matches = [e for e in self.by_ip.get("172.104.11.46", [])]
        self.assertEqual(len(matches), 3)
        for event in matches:
            self.assertEqual(event.event_type, "disconnect")
            self.assertEqual(event.account, "")
            self.assertEqual(event.confidence_score, 0.6)

    def test_kex_exchange_failure_still_yields_a_disconnect_event(self):
        # error: kex_exchange_identification (no IP) followed by
        # "Connection reset by 45.33.12.122 port 58593" (same pid, no
        # [preauth], no username) -- one disconnect event for that pid.
        matches = [e for e in self.by_ip.get("45.33.12.122", [])]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].event_type, "disconnect")
        self.assertIn("kex_exchange_identification", matches[0].raw_message)

    def test_banner_exchange_garbage_is_a_disconnect_event(self):
        matches = [e for e in self.by_ip.get("36.255.97.14", [])]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].event_type, "disconnect")

    def test_non_sshd_lines_are_ignored(self):
        # sudo invocations, systemd-logind session lines, and pam_unix
        # bookkeeping carry no source IP and must not appear as events.
        for event in self.events:
            self.assertNotIn("sudo", event.raw_message.lower())
            self.assertNotIn("systemd-logind", event.raw_message.lower())

    def test_all_events_have_a_source_ip_and_confidence_in_range(self):
        for event in self.events:
            self.assertIsNotNone(event.source_ip)
            self.assertGreaterEqual(event.confidence_score, 0.0)
            self.assertLessEqual(event.confidence_score, 1.0)
            self.assertIsNotNone(event.timestamp)

    def test_repeat_scanning_ip_produces_multiple_distinct_events(self):
        # 45.148.10.152 hits this host repeatedly with "authenticating
        # user root" -- confirms grouping is per-connection (per pid), not
        # collapsing everything from the same source IP into one event.
        matches = self.by_ip.get("45.148.10.152", [])
        self.assertGreater(len(matches), 5)
        self.assertTrue(all(e.event_type == "failed_login" for e in matches))
