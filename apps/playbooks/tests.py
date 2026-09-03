from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.playbooks.models import PlaybookStep, ResponsePlaybook, SOPChecklist
from apps.reports.models import GeneratedReport


class PlaybookViewsTestCase(AuthedTestCase):
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
            summary="Credential abuse requires immediate containment and owner assignment.",
        )
        self.playbook = ResponsePlaybook.objects.create(
            organization=self.organization,
            incident=self.incident,
            title="Credential abuse response playbook",
            summary="Coordinate containment, evidence handling, and communication steps.",
            immediate_steps="Lock the targeted account\nBlock the source IP range",
            next_steps="Reset credentials and confirm MFA\nNotify the system owner",
            escalation_steps="Security Lead <sec.lead@demo.com>\nDepartment Head <dept.head@demo.com>",
            priority=ResponsePlaybook.Priority.HIGH,
            status=ResponsePlaybook.Status.ACTIVE,
        )
        PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=1,
            action="Review failed login attempts",
            owner="IT Officer <it.officer@demo.com>",
            urgency=PlaybookStep.Urgency.HIGH,
            status=PlaybookStep.Status.COMPLETED,
        )
        PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=2,
            action="Confirm successful logins",
            owner="Security Lead <sec.lead@demo.com>",
            urgency=PlaybookStep.Urgency.HIGH,
            status=PlaybookStep.Status.IN_PROGRESS,
        )
        SOPChecklist.objects.create(
            name="Authentication attack checklist",
            incident_type="Authentication Attack",
            checklist_items=(
                "Verify incident details and affected account\n"
                "Collect and preserve relevant logs\n"
                "Lock account and reset credentials"
            ),
            version="1.0",
            is_active=True,
        )
        self.report = GeneratedReport.objects.create(
            organization=self.organization,
            incident=self.incident,
            report_type=GeneratedReport.ReportType.UPLOAD_SUMMARY,
            title="Manager incident summary",
            summary="High-level summary for management.",
            body="Report body",
        )

    def test_playbook_index_uses_dashboard_shell(self):
        response = self.client.get(reverse("playbooks:index"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Response Playbook")
        self.assertContains(response, "app-shell")
        self.assertContains(response, "Playbook Source")
        self.assertContains(response, "Incident Summary")
        self.assertContains(response, "Human Approval Required")
        # The toolbar's AI button posts to the real generation endpoint
        # (it appends steps to an existing playbook), not a GET re-load.
        self.assertContains(response, "Add AI Steps")
        self.assertContains(
            response, reverse("incidents:generate_playbook", args=[self.incident.id])
        )
        self.assertNotContains(response, "Regenerate Playbook")
        self.assertContains(response, "View Upload Summary")
        # The toolbar's in-page section links are labelled as navigation,
        # not as actions the page cannot actually perform.
        self.assertContains(response, "Go to Checklist")
        self.assertContains(response, "Go to Escalation Path")
        self.assertNotContains(response, "Export Checklist")
        self.assertNotContains(response, "Assign Owner")
        self.assertContains(response, "Linked SOP / Checklist")
        self.assertContains(response, "Escalation Path")
        self.assertContains(response, "Immediate Actions (0-2 Hours)")
        self.assertContains(response, "Next 24 Hours")
        self.assertContains(response, "Possible brute-force attempt against admin account")

    def test_escalation_footer_points_at_the_sop_library_not_a_fake_policy_page(self):
        response = self.client.get(reverse("playbooks:index"))

        # No "escalation policy" page exists; the honest destination for
        # approved response procedures is the SOP Library.
        self.assertNotContains(response, "View Escalation Policy")
        self.assertContains(response, "View SOP Library")
        self.assertContains(response, f'href="{reverse("playbooks:sops")}"')

    def test_playbook_index_empty_state_without_playbooks(self):
        ResponsePlaybook.objects.all().delete()

        response = self.client.get(reverse("playbooks:index"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No response playbook generated yet")
        self.assertContains(response, "Playbook Source")
        self.assertContains(response, "Use Existing Incident")
        self.assertContains(response, "Ask for Custom Playbook")
        self.assertContains(response, "Immediate Actions (0-2 Hours)")
        self.assertContains(response, "Next 24 Hours")
