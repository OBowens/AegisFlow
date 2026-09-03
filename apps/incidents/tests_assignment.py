from django.contrib.auth import get_user_model
from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.audit.models import AuditLog
from apps.organizations.models import Organization

from .models import IncidentGroup


class IncidentAssignmentTestCase(AuthedTestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="osreah", first_name="Osreah", last_name="Bowens"
        )
        self.organization = Organization.objects.create(
            name="Island Tech", organization_type="Business"
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="High severity log activity on DB01",
            incident_type="log_activity",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            workflow_state={"stage": "understand"},
        )

    def test_assign_button_assigns_without_starting_investigation(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("incidents:assign_to_me", args=[self.incident.id])
        )

        self.assertRedirects(response, f"{reverse('incidents:index')}?tab=queue")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, IncidentGroup.Status.OPEN)
        self.assertEqual(self.incident.workflow_state["stage"], "understand")
        self.assertEqual(self.incident.assigned_to, self.user)
        self.assertTrue(
            AuditLog.objects.filter(
                action="incident_assigned", target_id=str(self.incident.id)
            ).exists()
        )

    def test_queue_renders_assign_control(self):
        response = self.client.get(f"{reverse('incidents:index')}?tab=queue")

        self.assertContains(response, reverse("incidents:assign_to_me", args=[self.incident.id]))
        self.assertContains(response, ">Assign</button>", html=False)
