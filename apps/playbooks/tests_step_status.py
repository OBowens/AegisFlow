"""Coverage for the real playbook step status control
(apps.playbooks.views.playbook_update_step_status): confirms the
decorative pill+chevron with no handler is gone, a real <select>
POSTs to a real endpoint, the change persists to PlaybookStep.status,
and it writes an AuditLog entry in the same shape as the existing
incident status-change feature (apps.incidents.views.incident_update_status).
"""

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.audit.models import AuditLog
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.playbooks.models import PlaybookStep, ResponsePlaybook


class PlaybookStepStatusUpdateTestCase(AuthedTestCase):
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
            summary="Credential abuse requires containment.",
        )
        self.playbook = ResponsePlaybook.objects.create(
            organization=self.organization,
            incident=self.incident,
            title="Credential abuse response playbook",
            status=ResponsePlaybook.Status.ACTIVE,
        )
        self.step = PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=1,
            action="Review failed login attempts",
            status=PlaybookStep.Status.PENDING,
        )
        self.status_url = reverse("playbooks:update_step_status", args=[self.step.id])
        self.playbook_page = f"{reverse('playbooks:index')}?playbook={self.playbook.id}"

    def test_step_row_renders_a_real_select_not_a_decorative_chevron(self):
        response = self.client.get(self.playbook_page)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.status_url)
        self.assertContains(response, 'name="status"')
        self.assertNotContains(response, "playbook-reference-row__chevron")

    def test_get_request_does_not_change_status(self):
        response = self.client.get(self.status_url)

        self.assertRedirects(response, reverse("playbooks:index"))
        self.step.refresh_from_db()
        self.assertEqual(self.step.status, PlaybookStep.Status.PENDING)
        self.assertEqual(AuditLog.objects.count(), 0)

    def test_invalid_status_value_is_ignored(self):
        response = self.client.post(
            self.status_url, {"status": "not-a-real-status", "next": self.playbook_page}
        )

        self.assertRedirects(response, self.playbook_page)
        self.step.refresh_from_db()
        self.assertEqual(self.step.status, PlaybookStep.Status.PENDING)
        self.assertEqual(AuditLog.objects.count(), 0)

    def test_updating_status_persists_and_creates_audit_log(self):
        response = self.client.post(
            self.status_url,
            {"status": PlaybookStep.Status.IN_PROGRESS, "next": self.playbook_page},
        )

        self.assertRedirects(response, self.playbook_page)

        self.step.refresh_from_db()
        self.assertEqual(self.step.status, PlaybookStep.Status.IN_PROGRESS)

        self.assertEqual(AuditLog.objects.count(), 1)
        audit_log = AuditLog.objects.get()
        self.assertEqual(audit_log.organization, self.organization)
        self.assertEqual(audit_log.action, "playbook_step_status_changed")
        self.assertEqual(audit_log.target_type, "PlaybookStep")
        self.assertEqual(audit_log.target_id, str(self.step.id))
        self.assertIn("pending", audit_log.details.lower())
        self.assertIn("in_progress", audit_log.details.lower())

        # Shows up on the existing audit dashboard, same as incident status changes.
        audit_response = self.client.get(reverse("audit:index"))
        self.assertEqual(audit_response.status_code, 200)

    def test_setting_the_same_status_again_does_not_write_a_redundant_audit_log(self):
        response = self.client.post(
            self.status_url,
            {"status": PlaybookStep.Status.PENDING, "next": self.playbook_page},
        )

        self.assertRedirects(response, self.playbook_page)
        self.step.refresh_from_db()
        self.assertEqual(self.step.status, PlaybookStep.Status.PENDING)
        self.assertEqual(AuditLog.objects.count(), 0)

    def test_status_change_persists_across_a_fresh_page_load(self):
        self.client.post(
            self.status_url,
            {"status": PlaybookStep.Status.COMPLETED, "next": self.playbook_page},
        )

        response = self.client.get(self.playbook_page)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "playbook-step-status--completed")
        self.step.refresh_from_db()
        self.assertEqual(self.step.status, PlaybookStep.Status.COMPLETED)

    def test_next_param_outside_playbooks_is_ignored_for_safety(self):
        response = self.client.post(
            self.status_url,
            {"status": PlaybookStep.Status.SKIPPED, "next": "https://evil.example.com/"},
        )

        self.assertRedirects(response, reverse("playbooks:index"))

    def test_fallback_steps_without_a_real_playbookstep_row_have_no_control(self):
        # Steps parsed from free-text (no real PlaybookStep rows) have
        # nothing to persist a status change against, so no control renders.
        no_step_row_playbook = ResponsePlaybook.objects.create(
            organization=self.organization,
            incident=None,
            title="Custom Playbook: reset a VM safely",
            summary="Custom scenario",
            immediate_steps="Snapshot the VM\nReset the VM",
            status=ResponsePlaybook.Status.ACTIVE,
        )
        response = self.client.get(f"{reverse('playbooks:index')}?playbook={no_step_row_playbook.id}")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "playbook-reference-row__chevron")
        self.assertNotContains(response, "playbook-step-status-form")
