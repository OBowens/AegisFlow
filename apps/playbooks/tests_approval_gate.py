"""Coverage for the deterministic approval gate
(apps.playbooks.services.approval_gate.requires_human_approval) and its
"Requires human approval" label on the Response Playbook page.

No AI call involved -- this is a pure text scan, so the function-level
tests below don't need any mocking or database access.
"""

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.playbooks.models import PlaybookStep, ResponsePlaybook
from apps.playbooks.services.approval_gate import requires_human_approval


class RequiresHumanApprovalTestCase(AuthedTestCase):
    def test_disable_account_flags(self):
        self.assertTrue(requires_human_approval("Disable the compromised account"))

    def test_document_root_cause_does_not_flag(self):
        self.assertFalse(requires_human_approval("Document the root cause"))

    def test_other_destructive_examples_flag(self):
        destructive_examples = [
            "Block the malicious IP at the perimeter firewall",
            "Restart the affected server",
            "Shut down the compromised host",
            "Restore the database from the last known-good backup",
            "Delete the malicious file from the endpoint",
            "Isolate the compromised device from the network",
            "Update firewall rules to deny access from that range",
            "Revoke the leaked API credentials",
            "Quarantine the infected workstation",
            "Reimage the affected laptop",
        ]
        for text in destructive_examples:
            with self.subTest(text=text):
                self.assertTrue(requires_human_approval(text))

    def test_other_benign_examples_do_not_flag(self):
        benign_examples = [
            "Notify the account owner and relevant stakeholders",
            "Check related logs for repeated patterns and scope",
            "Escalate to the security lead if scope widens",
            "Confirm affected system and preserve evidence",
            "Review authentication logs for anomalies",
            "Verify whether MFA is enabled for the account",
        ]
        for text in benign_examples:
            with self.subTest(text=text):
                self.assertFalse(requires_human_approval(text))

    def test_blank_or_missing_text_does_not_flag(self):
        self.assertFalse(requires_human_approval(""))
        self.assertFalse(requires_human_approval(None))

    def test_case_insensitive(self):
        self.assertTrue(requires_human_approval("DISABLE THE COMPROMISED ACCOUNT"))


class PlaybookApprovalBadgeViewTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible brute-force attempt against admin account",
            incident_type="Authentication Attack",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="Email Server",
            summary="Credential abuse requires immediate containment.",
        )
        self.playbook = ResponsePlaybook.objects.create(
            organization=self.organization,
            incident=self.incident,
            title="Credential abuse response playbook",
            summary="Coordinate containment, evidence handling, and communication steps.",
            priority=ResponsePlaybook.Priority.HIGH,
            status=ResponsePlaybook.Status.ACTIVE,
        )
        PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=1,
            action="Disable the compromised account",
            owner="IT Officer <it.officer@demo.com>",
            urgency=PlaybookStep.Urgency.HIGH,
            status=PlaybookStep.Status.PENDING,
        )
        PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=2,
            action="Document the root cause",
            owner="Recorder <recorder@demo.com>",
            urgency=PlaybookStep.Urgency.MEDIUM,
            status=PlaybookStep.Status.PENDING,
        )

    def test_flagged_step_shows_the_label_and_benign_step_does_not(self):
        response = self.client.get(reverse("playbooks:index"), {"incident": self.incident.id})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Disable the compromised account")
        self.assertContains(response, "Document the root cause")
        # Exactly one step (the destructive one) carries the badge.
        self.assertContains(response, "Requires human approval", count=1)
