"""Coverage for the "Generate AI Playbook" button on the Incident Detail
page (apps.incidents.views.incident_generate_playbook): on-demand only
(POST-triggered, never automatic), reuses run_playbook_generation, logs
each attempt to AIRun, persists generated steps as PlaybookStep rows
tagged source=AI_GENERATED (never touching the existing generic steps),
displays them with the approval-gate badge, and handles a missing
ANTHROPIC_API_KEY gracefully instead of a 500.

Same mocking pattern as tests_ask_view.py: a mocked run_playbook_generation
stands in for a real Claude call -- no network, no API key, nothing spent.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AIRun
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.playbooks.models import PlaybookStep, ResponsePlaybook


class IncidentGeneratePlaybookViewTestCase(AuthedTestCase):
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
        self.generate_url = reverse("incidents:generate_playbook", args=[self.incident.id])
        self.detail_url = reverse("incidents:detail", args=[self.incident.id])

    def test_detail_page_shows_the_button_and_no_ai_steps_yet(self):
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Generate AI Playbook")
        self.assertContains(response, self.generate_url)
        self.assertEqual(AIRun.objects.count(), 0)
        self.assertEqual(PlaybookStep.objects.count(), 0)

    def test_get_request_does_not_trigger_generation(self):
        response = self.client.get(self.generate_url)

        self.assertRedirects(response, self.detail_url)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_successful_generation_persists_steps_and_logs_ai_run(self):
        fake_result = {
            "incident_id": self.incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant for this test",
            "steps": [
                {"action": "Review authentication logs for the targeted account.", "requires_approval": False},
                {"action": "Disable the compromised account immediately.", "requires_approval": True},
                {"action": "Document the root cause in the incident report.", "requires_approval": False},
            ],
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.incidents.views.run_playbook_generation", return_value=fake_result
        ) as mock_run:
            response = self.client.post(self.generate_url)

        self.assertEqual(response.status_code, 200)
        mock_run.assert_called_once_with(self.incident)

        # Response page shows the generated steps in the merged Recommended
        # Actions panel, clearly labeled, with the destructive one carrying
        # the approval badge.
        self.assertContains(response, "AI-generated")
        self.assertContains(response, "Disable the compromised account immediately.")
        self.assertContains(response, "Requires human approval")
        self.assertContains(response, "Review authentication logs for the targeted account.")

        # A ResponsePlaybook was created (with its baseline 6 generic
        # steps) plus the 3 AI-generated steps on top of it.
        self.assertEqual(ResponsePlaybook.objects.count(), 1)
        playbook = ResponsePlaybook.objects.get()
        self.assertEqual(playbook.incident_id, self.incident.id)

        generic_steps = PlaybookStep.objects.filter(source=PlaybookStep.Source.GENERIC)
        ai_steps = PlaybookStep.objects.filter(source=PlaybookStep.Source.AI_GENERATED)
        self.assertEqual(generic_steps.count(), 6)
        self.assertEqual(ai_steps.count(), 3)

        # AI steps continue the step numbering after the generic ones,
        # rather than colliding with them.
        self.assertEqual(
            sorted(ai_steps.values_list("step_number", flat=True)), [7, 8, 9]
        )

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.ai_module, "writer")
        self.assertEqual(ai_run.input_type, "IncidentGroup")
        self.assertEqual(ai_run.input_id, str(self.incident.id))
        self.assertEqual(ai_run.status, AIRun.Status.SUCCESS)
        self.assertEqual(ai_run.model_used, "claude-sonnet-5")
        self.assertEqual(ai_run.output_type, "ResponsePlaybook")
        self.assertEqual(ai_run.output_id, str(playbook.id))

    def test_generating_twice_does_not_touch_earlier_ai_generated_steps(self):
        first_result = {
            "incident_id": self.incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "steps": [{"action": "Lock the targeted account.", "requires_approval": True}],
            "generated_at": timezone.now(),
        }
        second_result = {
            "incident_id": self.incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "steps": [{"action": "Notify the account owner.", "requires_approval": False}],
            "generated_at": timezone.now(),
        }

        with patch("apps.incidents.views.run_playbook_generation", return_value=first_result):
            self.client.post(self.generate_url)

        with patch("apps.incidents.views.run_playbook_generation", return_value=second_result):
            response = self.client.post(self.generate_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Lock the targeted account.")
        self.assertContains(response, "Notify the account owner.")

        self.assertEqual(ResponsePlaybook.objects.count(), 1)
        self.assertEqual(PlaybookStep.objects.filter(source=PlaybookStep.Source.GENERIC).count(), 6)
        self.assertEqual(
            PlaybookStep.objects.filter(source=PlaybookStep.Source.AI_GENERATED).count(), 2
        )
        self.assertEqual(AIRun.objects.count(), 2)

    def test_reload_after_post_shows_the_persisted_steps_without_a_new_ai_call(self):
        fake_result = {
            "incident_id": self.incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "steps": [{"action": "Notify the account owner.", "requires_approval": False}],
            "generated_at": timezone.now(),
        }

        with patch("apps.incidents.views.run_playbook_generation", return_value=fake_result):
            self.client.post(self.generate_url)

        with patch(
            "apps.incidents.views.run_playbook_generation",
            side_effect=AssertionError("run_playbook_generation must not be called on a plain page load"),
        ) as mock_run_on_get:
            get_response = self.client.get(self.detail_url)

        self.assertEqual(get_response.status_code, 200)
        mock_run_on_get.assert_not_called()
        self.assertContains(get_response, "Notify the account owner.")

    def test_missing_api_key_shows_friendly_message_not_a_500(self):
        with patch(
            "apps.incidents.views.run_playbook_generation",
            side_effect=RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment "
                "before calling AnthropicProvider.send_message()."
            ),
        ) as mock_run:
            response = self.client.post(self.generate_url)

        self.assertEqual(response.status_code, 200)
        mock_run.assert_called_once_with(self.incident)
        self.assertContains(response, "AI analysis isn&#x27;t available yet")
        self.assertNotContains(response, "ANTHROPIC_API_KEY is not set")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.status, AIRun.Status.FAILED)
        self.assertIn("ANTHROPIC_API_KEY is not set", ai_run.error_message)
        self.assertEqual(PlaybookStep.objects.count(), 0)
