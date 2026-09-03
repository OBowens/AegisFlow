"""Coverage for the "Explain in Plain Language" / "What Should I Tell
Management?" panels on the Incident Detail page
(apps.incidents.views.incident_explain): on-demand only (POST-triggered,
never automatic), reuses run_incident_explanation, logs each attempt to
AIRun, persists the result (latest-wins per (incident, audience) pair,
same as AnalystResult), and handles a missing ANTHROPIC_API_KEY
gracefully instead of a 500.

Also proves the two audiences are independent slots: generating one
does not touch or clear the other's saved result.

Same mocking pattern as apps/incidents/tests_analyze_view.py.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AIRun
from apps.incidents.models import IncidentExplanation, IncidentGroup
from apps.organizations.models import Organization


class IncidentExplainAudienceViewTestCase(AuthedTestCase):
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
        )
        self.plain_language_url = reverse(
            "incidents:explain_plain_language", args=[self.incident.id]
        )
        self.management_url = reverse("incidents:explain_management", args=[self.incident.id])
        self.detail_url = reverse("incidents:detail", args=[self.incident.id])

    def test_detail_page_shows_both_buttons_and_no_explanations_yet(self):
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Explain in Plain Language")
        self.assertContains(response, "What Should I Tell Management?")
        self.assertContains(response, self.plain_language_url)
        self.assertContains(response, self.management_url)
        self.assertEqual(IncidentExplanation.objects.count(), 0)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_get_request_does_not_trigger_generation(self):
        response = self.client.get(self.plain_language_url)

        self.assertRedirects(response, self.detail_url)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_successful_plain_language_explanation_persists_and_logs_ai_run(self):
        fake_result = {
            "incident_id": self.incident.id,
            "audience": "plain_language",
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "explanation": "Someone tried many passwords on an important account.",
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.incidents.views.run_incident_explanation", return_value=fake_result
        ) as mock_run:
            response = self.client.post(self.plain_language_url)

        self.assertEqual(response.status_code, 200)
        mock_run.assert_called_once_with(self.incident, "plain_language")
        self.assertContains(response, "Someone tried many passwords on an important account.")

        self.assertEqual(IncidentExplanation.objects.count(), 1)
        saved = IncidentExplanation.objects.get()
        self.assertEqual(saved.incident_id, self.incident.id)
        self.assertEqual(saved.audience, "plain_language")
        self.assertEqual(saved.explanation_text, fake_result["explanation"])

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.ai_module, "incident_explainer")
        self.assertEqual(ai_run.input_type, "IncidentGroup")
        self.assertEqual(ai_run.input_id, str(self.incident.id))
        self.assertEqual(ai_run.status, AIRun.Status.SUCCESS)
        self.assertEqual(ai_run.output_id, str(saved.id))

    def test_generating_management_summary_does_not_touch_the_plain_language_result(self):
        plain_result = {
            "incident_id": self.incident.id,
            "audience": "plain_language",
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "explanation": "Plain language text that must survive.",
            "generated_at": timezone.now(),
        }
        management_result = {
            "incident_id": self.incident.id,
            "audience": "management",
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "explanation": "This exposes the business to account-takeover risk.",
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.incidents.views.run_incident_explanation", return_value=plain_result
        ):
            self.client.post(self.plain_language_url)

        with patch(
            "apps.incidents.views.run_incident_explanation", return_value=management_result
        ) as mock_run:
            response = self.client.post(self.management_url)

        mock_run.assert_called_once_with(self.incident, "management")
        # Both must appear together -- generating management didn't wipe
        # the already-saved plain-language slot.
        self.assertContains(response, "Plain language text that must survive.")
        self.assertContains(response, "This exposes the business to account-takeover risk.")

        self.assertEqual(IncidentExplanation.objects.count(), 2)
        self.assertEqual(
            IncidentExplanation.objects.filter(audience="plain_language").count(), 1
        )
        self.assertEqual(IncidentExplanation.objects.filter(audience="management").count(), 1)
        self.assertEqual(AIRun.objects.count(), 2)

    def test_explanation_persists_across_a_fresh_page_load(self):
        fake_result = {
            "incident_id": self.incident.id,
            "audience": "management",
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "explanation": "Frame this as account-takeover risk for leadership.",
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.incidents.views.run_incident_explanation", return_value=fake_result
        ):
            self.client.post(self.management_url)

        with patch(
            "apps.incidents.views.run_incident_explanation",
            side_effect=AssertionError("must not be called on a plain page load"),
        ) as mock_run_on_get:
            get_response = self.client.get(self.detail_url)

        mock_run_on_get.assert_not_called()
        self.assertContains(get_response, "Frame this as account-takeover risk for leadership.")
        self.assertEqual(IncidentExplanation.objects.count(), 1)
        self.assertEqual(AIRun.objects.count(), 1)

    def test_missing_api_key_shows_friendly_message_not_a_500(self):
        with patch(
            "apps.incidents.views.run_incident_explanation",
            side_effect=RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment "
                "before calling AnthropicProvider.send_message()."
            ),
        ) as mock_run:
            response = self.client.post(self.plain_language_url)

        mock_run.assert_called_once_with(self.incident, "plain_language")
        self.assertContains(response, "AI analysis isn&#x27;t available yet")
        self.assertNotContains(response, "ANTHROPIC_API_KEY is not set")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.status, AIRun.Status.FAILED)
        self.assertIn("ANTHROPIC_API_KEY is not set", ai_run.error_message)
        self.assertEqual(IncidentExplanation.objects.count(), 0)
