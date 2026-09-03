"""Coverage for the "What Should I Fix First?" button on the Dashboard
(apps.core.views.explain_priorities): on-demand only (POST-triggered,
never automatic), reuses run_priority_briefing, logs each attempt to
AIRun, persists the result (latest-wins, same as ReadinessExplanation)
scoped to the organization, and handles a missing ANTHROPIC_API_KEY
gracefully instead of a 500.

Same mocking pattern as apps/resilience/tests_explain_readiness_view.py:
a mocked run_priority_briefing stands in for a real Claude call -- no
network, no API key, nothing spent.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AIRun
from apps.core.models import PriorityBriefing
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization


class ExplainPrioritiesViewTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        IncidentGroup.objects.create(
            organization=self.organization,
            title="Old critical ransomware indicator",
            incident_type="malware",
            severity=IncidentGroup.Severity.CRITICAL,
            status=IncidentGroup.Status.OPEN,
            affected_systems="FILE-SRV-01",
        )
        self.explain_url = reverse("core:explain_priorities")
        self.index_url = reverse("core:index")

    def test_dashboard_shows_the_button_and_no_briefing_yet(self):
        response = self.client.get(self.index_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "What Should I Fix First?")
        self.assertContains(response, self.explain_url)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_get_request_does_not_trigger_generation(self):
        response = self.client.get(self.explain_url)

        self.assertRedirects(response, self.index_url)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_successful_briefing_persists_and_logs_ai_run(self):
        fake_result = {
            "organization_id": self.organization.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant for this test",
            "briefing": (
                "1. Old critical ransomware indicator -- fix first: critical "
                "severity, untriaged for weeks."
            ),
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.core.views.run_priority_briefing", return_value=fake_result
        ) as mock_run:
            response = self.client.post(self.explain_url, follow=True)

        self.assertRedirects(response, self.index_url)
        mock_run.assert_called_once_with(self.organization)

        self.assertContains(response, "fix first: critical")

        self.assertEqual(PriorityBriefing.objects.count(), 1)
        saved = PriorityBriefing.objects.get()
        self.assertEqual(saved.organization_id, self.organization.id)
        self.assertEqual(saved.briefing_text, fake_result["briefing"])
        self.assertEqual(saved.model_used, "claude-sonnet-5")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.ai_module, "prioritizer")
        self.assertEqual(ai_run.input_type, "Organization")
        self.assertEqual(ai_run.input_id, str(self.organization.id))
        self.assertEqual(ai_run.status, AIRun.Status.SUCCESS)
        self.assertEqual(ai_run.output_id, str(saved.id))

    def test_briefing_persists_across_a_fresh_page_load(self):
        fake_result = {
            "organization_id": self.organization.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "briefing": "Fix the ransomware indicator on FILE-SRV-01 first.",
            "generated_at": timezone.now(),
        }

        with patch("apps.core.views.run_priority_briefing", return_value=fake_result):
            self.client.post(self.explain_url)

        with patch(
            "apps.core.views.run_priority_briefing",
            side_effect=AssertionError("must not be called on a plain page load"),
        ) as mock_run_on_get:
            get_response = self.client.get(self.index_url)

        self.assertEqual(get_response.status_code, 200)
        mock_run_on_get.assert_not_called()
        self.assertContains(get_response, "Fix the ransomware indicator on FILE-SRV-01 first.")
        self.assertEqual(PriorityBriefing.objects.count(), 1)
        self.assertEqual(AIRun.objects.count(), 1)

    def test_missing_api_key_shows_friendly_message_not_a_500(self):
        with patch(
            "apps.core.views.run_priority_briefing",
            side_effect=RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment "
                "before calling AnthropicProvider.send_message()."
            ),
        ) as mock_run:
            response = self.client.post(self.explain_url, follow=True)

        mock_run.assert_called_once_with(self.organization)
        self.assertContains(response, "AI prioritization isn&#x27;t available yet")
        self.assertNotContains(response, "ANTHROPIC_API_KEY is not set")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.status, AIRun.Status.FAILED)
        self.assertIn("ANTHROPIC_API_KEY is not set", ai_run.error_message)
        self.assertEqual(PriorityBriefing.objects.count(), 0)
