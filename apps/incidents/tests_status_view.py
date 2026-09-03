"""Coverage for the incident status selector on the Incident Detail page
(apps.incidents.views.incident_update_status): shows the current status
(all 5 real states, not a binary toggle), persists a change to
IncidentGroup.status, and writes an AuditLog entry in the same shape as
the only other real writer of that model (apps/ai_core/orchestrator.py).
"""

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.audit.models import AuditLog
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization


class IncidentUpdateStatusViewTestCase(AuthedTestCase):
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
            title="Possible brute-force attempt against privileged account",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="WEB-01",
            summary="Repeated failed logins detected.",
        )
        self.status_url = reverse("incidents:update_status", args=[self.incident.id])
        self.detail_url = reverse("incidents:detail", args=[self.incident.id])

    def test_detail_page_shows_current_status_and_all_five_options(self):
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "incident-status-pill--open")
        self.assertContains(response, self.status_url)
        for value, label in IncidentGroup.Status.choices:
            self.assertContains(response, f'value="{value}"')
            self.assertContains(response, label)

    def test_get_request_does_not_change_status(self):
        response = self.client.get(self.status_url)

        self.assertRedirects(response, self.detail_url)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, IncidentGroup.Status.OPEN)
        self.assertEqual(AuditLog.objects.count(), 0)

    def test_invalid_status_value_is_ignored(self):
        response = self.client.post(self.status_url, {"status": "not-a-real-status"})

        self.assertRedirects(response, self.detail_url)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, IncidentGroup.Status.OPEN)
        self.assertEqual(AuditLog.objects.count(), 0)

    def test_updating_status_persists_creates_audit_log_and_shows_on_dashboard(self):
        response = self.client.post(self.status_url, {"status": IncidentGroup.Status.INVESTIGATING})

        self.assertRedirects(response, self.detail_url)

        # 1. Persisted.
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, IncidentGroup.Status.INVESTIGATING)

        # 2. AuditLog row created, same shape as apps/ai_core/orchestrator.py's
        # AuditLog.objects.create(...) calls.
        self.assertEqual(AuditLog.objects.count(), 1)
        audit_log = AuditLog.objects.get()
        self.assertEqual(audit_log.organization, self.organization)
        self.assertEqual(audit_log.action, "incident_status_changed")
        self.assertEqual(audit_log.target_type, "IncidentGroup")
        self.assertEqual(audit_log.target_id, str(self.incident.id))
        self.assertIn("open", audit_log.details.lower())
        self.assertIn("investigating", audit_log.details.lower())

        # Detail page reflects the new status immediately.
        detail_response = self.client.get(self.detail_url)
        self.assertContains(detail_response, "incident-status-pill--investigating")

        # 3. Shows up on the existing audit dashboard.
        audit_response = self.client.get(reverse("audit:index"))
        self.assertEqual(audit_response.status_code, 200)
        self.assertContains(audit_response, "Incident status changed")
        self.assertContains(audit_response, self.incident.title)

    def test_setting_the_same_status_again_does_not_write_a_redundant_audit_log(self):
        response = self.client.post(self.status_url, {"status": IncidentGroup.Status.OPEN})

        self.assertRedirects(response, self.detail_url)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, IncidentGroup.Status.OPEN)
        self.assertEqual(AuditLog.objects.count(), 0)

    def test_status_change_persists_across_a_fresh_page_load(self):
        self.client.post(self.status_url, {"status": IncidentGroup.Status.CLOSED})

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "incident-status-pill--closed")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, IncidentGroup.Status.CLOSED)
