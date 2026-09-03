from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.audit.models import AIRun
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.playbooks.models import PlaybookStep


class GuidedWorkflowTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Workflow Org")
        self.incident = IncidentGroup.objects.create(organization=self.organization, title="High severity database activity on DB01", incident_type="database", severity=IncidentGroup.Severity.HIGH, affected_systems="DB01")
        self.verify_url = reverse("incidents:workflow", args=[self.incident.id, "verify"])
        self.respond_url = reverse("incidents:workflow", args=[self.incident.id, "respond"])
        self.answers = {"workflow_action": "continue", "verification_reachable": "confirmed", "verification_service_health": "not_confirmed", "verification_expected_change": "not_sure", "verification_scope": "confirmed"}

    @patch("apps.incidents.views.run_workflow_next_step")
    @patch("apps.incidents.views.run_playbook_generation")
    def test_verify_answers_persist_independently_and_generate_plan(self, generate, next_step):
        generate.return_value = {"model": "test-model", "steps": [{"action": "Restart the database service safely."}]}
        next_step.return_value = {"model": "test-model", "next_step": "Check the database service status."}
        response = self.client.post(self.verify_url, self.answers)
        self.assertRedirects(response, self.respond_url)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.workflow_state["verification_results"], {"reachable": "confirmed", "service_health": "not_confirmed", "expected_change": "not_sure", "scope": "confirmed"})
        self.assertEqual(AIRun.objects.get(ai_module="writer").status, AIRun.Status.SUCCESS)
        self.assertTrue(PlaybookStep.objects.filter(source=PlaybookStep.Source.AI_GENERATED).exists())
        persisted = self.client.get(self.verify_url)
        self.assertContains(persisted, "value=\"confirmed\" checked", count=2)
        self.assertContains(persisted, "value=\"not_confirmed\" checked")
        self.assertContains(persisted, "value=\"not_sure\" checked")

    @patch("apps.incidents.views.run_workflow_next_step")
    @patch("apps.incidents.views.run_playbook_generation", side_effect=RuntimeError("provider unavailable"))
    def test_generation_failure_stays_in_respond_with_recovery_actions(self, _generate, next_step):
        next_step.return_value = {"model": "test-model", "next_step": "Check the database service status."}
        response = self.client.post(self.verify_url, self.answers, follow=True)
        self.assertRedirects(response, self.respond_url)
        self.assertContains(response, "Something prevented AegisFlow from preparing the response.")
        self.assertContains(response, "Try Again")
        self.assertContains(response, "Ask AegisFlow for Help")
        self.assertContains(response, "Save &amp; Exit")
        self.assertEqual(AIRun.objects.get(ai_module="writer").status, AIRun.Status.FAILED)

    def test_phishing_incident_gets_contextual_checks(self):
        self.incident.title = "Possible credential access via phishing"
        self.incident.incident_type = "phishing"
        self.incident.save(update_fields=["title", "incident_type"])
        response = self.client.get(self.verify_url)
        self.assertContains(response, "Did the user interact with the suspicious link?")
        self.assertContains(response, "Were credentials entered or exposed?")
        self.assertNotContains(response, "Is DB01 reachable?")