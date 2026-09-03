"""Tests for the standalone Proxmox VE syslog parser.

Uses apps/log_intake/fixtures/proxmox_syslog_50.log as test data. That
fixture is a SYNTHETIC, hand-authored sample -- not a real Proxmox export
-- used here purely as a format/structure reference.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

Plain unittest.TestCase on purpose: this parser has no Django/DB dependency
(it isn't wired into the upload pipeline yet), so the tests shouldn't need
one either.
"""

from pathlib import Path
from unittest import TestCase

from apps.log_intake.services.proxmox_syslog_parser import parse_proxmox_syslog

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "proxmox_syslog_50.log"


class ParseProxmoxSyslogTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.raw_text = FIXTURE_PATH.read_text(encoding="utf-8")
        cls.events = parse_proxmox_syslog(cls.raw_text)
        cls.by_type = {}
        for event in cls.events:
            cls.by_type.setdefault(event.event_type, []).append(event)

    def test_produces_one_event_per_line(self):
        self.assertEqual(len(self.events), 50)

    def test_process_type_counts_match_fixture(self):
        self.assertEqual(
            len(self.by_type["vm_task_qmstop"]) + len(self.by_type["vm_task_qmstart"]), 12
        )
        self.assertEqual(len(self.by_type["authentication_failure"]), 6)
        self.assertEqual(len(self.by_type["successful_login"]), 3)
        self.assertEqual(len(self.by_type["vm_migration_completed"]), 5)
        self.assertEqual(len(self.by_type["backup_success"]), 5)
        self.assertEqual(len(self.by_type["backup_failed"]), 4)
        self.assertEqual(len(self.by_type["network_bridge_state_change"]), 4)
        self.assertEqual(len(self.by_type["storage_usage_report"]), 9)
        self.assertEqual(len(self.by_type["cluster_membership_change"]), 2)

    def test_end_task_splits_by_task_type(self):
        self.assertEqual(len(self.by_type["vm_task_qmstop"]), 7)
        self.assertEqual(len(self.by_type["vm_task_qmstart"]), 5)

    def test_routine_task_and_migration_events_are_low_severity(self):
        for event_type in ("vm_task_qmstop", "vm_task_qmstart", "vm_migration_completed"):
            for event in self.by_type[event_type]:
                self.assertEqual(event.severity_hint, "low")

    def test_auth_failure_is_medium_with_account_and_ip(self):
        for event in self.by_type["authentication_failure"]:
            self.assertEqual(event.severity_hint, "medium")
            self.assertTrue(event.account)
            self.assertIsNotNone(event.source_ip)

    def test_successful_login_is_low_severity(self):
        for event in self.by_type["successful_login"]:
            self.assertEqual(event.severity_hint, "low")

    def test_backup_failed_is_high_backup_success_is_low(self):
        for event in self.by_type["backup_failed"]:
            self.assertEqual(event.severity_hint, "high")
            self.assertIn("backup-nas", event.normalized_summary)
        for event in self.by_type["backup_success"]:
            self.assertEqual(event.severity_hint, "low")

    def test_kernel_bridge_events_are_treated_as_low_severity_noise(self):
        for event in self.by_type["network_bridge_state_change"]:
            self.assertEqual(event.severity_hint, "low")
            self.assertEqual(event.confidence_score, 0.7)

    def test_storage_usage_crosses_severity_threshold_at_90_percent(self):
        storage_events = self.by_type["storage_usage_report"]
        medium = [e for e in storage_events if e.severity_hint == "medium"]
        low = [e for e in storage_events if e.severity_hint == "low"]
        self.assertEqual(len(medium), 3)  # 94%, 90%, 92% in the fixture
        self.assertEqual(len(low), 6)
        for event in medium:
            self.assertRegex(event.normalized_summary, r"(9[0-9]|100)% usage")
        for event in low:
            self.assertRegex(event.normalized_summary, r"[0-8][0-9]% usage")

    def test_cluster_membership_change_is_medium_severity(self):
        for event in self.by_type["cluster_membership_change"]:
            self.assertEqual(event.severity_hint, "medium")

    def test_vm_scoped_events_use_vm_id_not_node_as_affected_system(self):
        for event in self.by_type["backup_success"] + self.by_type["vm_migration_completed"]:
            self.assertTrue(event.affected_system.startswith("VM "))

    def test_node_scoped_events_use_host_as_affected_system(self):
        auth_event = self.by_type["authentication_failure"][0]
        self.assertIn(auth_event.affected_system, {"pve01", "pve02", "pve03"})

    def test_timestamp_infers_current_year_from_yearless_syslog_format(self):
        first_event = self.events[0]
        self.assertEqual(first_event.timestamp.isoformat(), "2026-08-23T08:00:04")

    def test_source_tool_defaults_to_proxmox(self):
        for event in self.events:
            self.assertEqual(event.source_tool, "proxmox")

    def test_first_line_matches_known_fixture_values(self):
        event = self.events[0]
        self.assertEqual(event.event_type, "vm_task_qmstop")
        self.assertEqual(event.affected_system, "VM 135")
        self.assertEqual(event.account, "ops@pve")
        self.assertEqual(event.severity_hint, "low")
