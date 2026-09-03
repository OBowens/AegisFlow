"""Coverage for the "Ask AI to Analyze" button on the Incident Detail page
(apps.incidents.views.incident_analyze): on-demand only (POST-triggered,
never automatic), logs each attempt to AIRun, and handles a missing
ANTHROPIC_API_KEY gracefully instead of a 500.

Same pattern as apps/ai_core/tests_analyst.py: a mocked
run_incident_analysis stands in for a real Claude call -- no network, no
API key, nothing spent.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AIRun
from apps.incidents.models import AnalystResult, IncidentGroup
from apps.organizations.models import Organization


class IncidentAnalyzeViewTestCase(AuthedTestCase):
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
        self.analyze_url = reverse("incidents:analyze", args=[self.incident.id])
        self.detail_url = reverse("incidents:detail", args=[self.incident.id])

    def test_detail_page_shows_the_ask_ai_button_and_no_result_yet(self):
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Ask AI to Analyze")
        self.assertContains(response, self.analyze_url)
        self.assertNotContains(response, "AI Analysis")
        self.assertEqual(AIRun.objects.count(), 0)

    def test_get_request_does_not_trigger_analysis(self):
        response = self.client.get(self.analyze_url)

        self.assertRedirects(response, self.detail_url)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_successful_analysis_renders_result_and_logs_ai_run(self):
        fake_result = {
            "incident_id": self.incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant for this test",
            "analysis": (
                "This is a credential-stuffing pattern. Severity: high. "
                "Next steps: reset the password and enable MFA."
            ),
            "generated_at": timezone.now(),
        }

        with patch("apps.incidents.views.run_incident_analysis", return_value=fake_result) as mock_run:
            response = self.client.post(self.analyze_url)

        self.assertEqual(response.status_code, 200)
        mock_run.assert_called_once_with(self.incident)
        self.assertContains(response, "AI Analysis")
        self.assertContains(response, "credential-stuffing pattern")
        self.assertContains(response, "claude-sonnet-5")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.ai_module, "analyst")
        self.assertEqual(ai_run.input_type, "IncidentGroup")
        self.assertEqual(ai_run.input_id, str(self.incident.id))
        self.assertEqual(ai_run.status, AIRun.Status.SUCCESS)
        self.assertEqual(ai_run.model_used, "claude-sonnet-5")
        self.assertEqual(ai_run.error_message, "")

        self.assertEqual(AnalystResult.objects.count(), 1)
        saved = AnalystResult.objects.get()
        self.assertEqual(saved.incident_id, self.incident.id)
        self.assertEqual(saved.analysis_text, fake_result["analysis"])
        self.assertEqual(saved.model_used, "claude-sonnet-5")
        self.assertEqual(ai_run.output_id, str(saved.id))

    def test_reload_after_post_shows_saved_result_without_a_new_ai_call(self):
        fake_result = {
            "incident_id": self.incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant for this test",
            "analysis": "Repeated failed logins from a single external IP -- likely brute force.",
            "generated_at": timezone.now(),
        }

        with patch("apps.incidents.views.run_incident_analysis", return_value=fake_result) as mock_run:
            post_response = self.client.post(self.analyze_url)

        self.assertEqual(post_response.status_code, 200)
        self.assertEqual(mock_run.call_count, 1)
        self.assertEqual(AnalystResult.objects.count(), 1)

        # Reload the page as a plain GET -- run_incident_analysis must NOT
        # be called again. Raising if it is makes this a hard failure
        # rather than a silent extra (billable, once live) AI call.
        with patch(
            "apps.incidents.views.run_incident_analysis",
            side_effect=AssertionError("run_incident_analysis must not be called on a plain page load"),
        ) as mock_run_on_get:
            get_response = self.client.get(self.detail_url)

        self.assertEqual(get_response.status_code, 200)
        mock_run_on_get.assert_not_called()
        self.assertContains(get_response, "AI Analysis")
        self.assertContains(
            get_response, "Repeated failed logins from a single external IP -- likely brute force."
        )
        self.assertContains(get_response, "claude-sonnet-5")

        # Still exactly one saved result and one AIRun -- the reload didn't
        # create a second of either.
        self.assertEqual(AnalystResult.objects.count(), 1)
        self.assertEqual(AIRun.objects.count(), 1)

    def test_plain_page_load_shows_the_most_recently_saved_result(self):
        older = AnalystResult.objects.create(
            incident=self.incident,
            analysis_text="Older analysis text.",
            model_used="claude-sonnet-5",
        )
        AnalystResult.objects.filter(pk=older.pk).update(
            generated_at=timezone.now() - timezone.timedelta(days=1)
        )
        AnalystResult.objects.create(
            incident=self.incident,
            analysis_text="Newer analysis text.",
            model_used="claude-sonnet-5",
        )

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Newer analysis text.")
        self.assertNotContains(response, "Older analysis text.")

    def test_missing_api_key_shows_friendly_message_not_a_500(self):
        with patch(
            "apps.incidents.views.run_incident_analysis",
            side_effect=RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment "
                "before calling AnthropicProvider.send_message()."
            ),
        ) as mock_run:
            response = self.client.post(self.analyze_url)

        self.assertEqual(response.status_code, 200)
        mock_run.assert_called_once_with(self.incident)
        self.assertContains(response, "AI analysis isn&#x27;t available yet")
        self.assertContains(response, "API key not configured")
        self.assertNotContains(response, "ANTHROPIC_API_KEY is not set")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.status, AIRun.Status.FAILED)
        self.assertIn("ANTHROPIC_API_KEY is not set", ai_run.error_message)
        self.assertEqual(ai_run.model_used, "")
        self.assertEqual(AnalystResult.objects.count(), 0)

    def test_unexpected_runtime_error_also_shows_a_friendly_message(self):
        with patch(
            "apps.incidents.views.run_incident_analysis",
            side_effect=RuntimeError("Anthropic API request failed (500): internal error"),
        ):
            response = self.client.post(self.analyze_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "AI analysis failed. Please try again in a moment.")

        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.status, AIRun.Status.FAILED)
        self.assertIn("Anthropic API request failed", ai_run.error_message)
