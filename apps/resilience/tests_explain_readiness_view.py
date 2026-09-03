"""Coverage for the "Explain My Readiness" button on the Disaster
Readiness page (apps.resilience.views.explain_readiness): on-demand only
(POST-triggered, never automatic), reuses run_readiness_explanation,
logs each attempt to AIRun, persists the result (latest-wins, same as
AnalystResult) so it survives a reload, and handles a missing
ANTHROPIC_API_KEY gracefully instead of a 500.

Same mocking pattern as apps/incidents/tests_analyze_view.py: a mocked
run_readiness_explanation stands in for a real Claude call -- no network,
no API key, nothing spent.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AIRun
from apps.organizations.models import Organization
from apps.resilience.models import DisasterReadinessFinding, ReadinessExplanation


class ExplainReadinessViewTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        DisasterReadinessFinding.objects.create(
            organization=self.organization,
            readiness_issue="No recent backup restore test",
            disaster_impact="A backup could fail silently without a tested restore procedure.",
            recovery_concern="Recovery time is unknown without a rehearsed restore.",
            source=DisasterReadinessFinding.Source.LOG_BASED,
            priority=DisasterReadinessFinding.Priority.HIGH,
        )
        self.explain_url = reverse("resilience:explain")
        self.index_url = reverse("resilience:index")

    def test_index_page_shows_the_button_and_no_explanation_yet(self):
        response = self.client.get(self.index_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Explain My Readiness")
        self.assertContains(response, self.explain_url)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_get_request_does_not_trigger_generation(self):
        response = self.client.get(self.explain_url)

        self.assertRedirects(response, self.index_url)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_successful_explanation_persists_and_logs_ai_run(self):
        fake_result = {
            "organization_id": self.organization.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant for this test",
            "explanation": (
                "Your score is low mainly because backups have never been restore-tested. "
                "Prioritize a real restore test this month."
            ),
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.ai_core.modules.readiness_advisor.run_readiness_explanation",
            return_value=fake_result,
        ) as mock_run:
            response = self.client.post(self.explain_url, follow=True)

        self.assertRedirects(response, self.index_url)
        mock_run.assert_called_once_with(self.organization)

        self.assertContains(response, "backups have never been restore-tested")

        self.assertEqual(ReadinessExplanation.objects.count(), 1)
        saved = ReadinessExplanation.objects.get()
        self.assertEqual(saved.organization_id, self.organization.id)
        self.assertEqual(saved.explanation_text, fake_result["explanation"])
        self.assertEqual(saved.model_used, "claude-sonnet-5")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.ai_module, "readiness_advisor")
        self.assertEqual(ai_run.input_type, "Organization")
        self.assertEqual(ai_run.input_id, str(self.organization.id))
        self.assertEqual(ai_run.status, AIRun.Status.SUCCESS)
        self.assertEqual(ai_run.model_used, "claude-sonnet-5")
        self.assertEqual(ai_run.output_id, str(saved.id))

    def test_explanation_persists_across_a_fresh_page_load(self):
        fake_result = {
            "organization_id": self.organization.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "explanation": "Backups are the main drag on your score right now.",
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.ai_core.modules.readiness_advisor.run_readiness_explanation",
            return_value=fake_result,
        ):
            self.client.post(self.explain_url)

        # Reload as a plain GET, with run_readiness_explanation patched to
        # raise if called -- proves no accidental re-billing on reload.
        with patch(
            "apps.ai_core.modules.readiness_advisor.run_readiness_explanation",
            side_effect=AssertionError("must not be called on a plain page load"),
        ) as mock_run_on_get:
            get_response = self.client.get(self.index_url)

        self.assertEqual(get_response.status_code, 200)
        mock_run_on_get.assert_not_called()
        self.assertContains(get_response, "Backups are the main drag on your score right now.")
        self.assertContains(get_response, "claude-sonnet-5")

        self.assertEqual(ReadinessExplanation.objects.count(), 1)
        self.assertEqual(AIRun.objects.count(), 1)

    def test_missing_api_key_shows_friendly_message_not_a_500(self):
        with patch(
            "apps.ai_core.modules.readiness_advisor.run_readiness_explanation",
            side_effect=RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment "
                "before calling AnthropicProvider.send_message()."
            ),
        ) as mock_run:
            response = self.client.post(self.explain_url, follow=True)

        mock_run.assert_called_once_with(self.organization)
        self.assertContains(response, "AI readiness explanation isn&#x27;t available yet")
        self.assertNotContains(response, "ANTHROPIC_API_KEY is not set")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.status, AIRun.Status.FAILED)
        self.assertIn("ANTHROPIC_API_KEY is not set", ai_run.error_message)
        self.assertEqual(ReadinessExplanation.objects.count(), 0)
