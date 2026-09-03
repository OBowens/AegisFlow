"""Coverage for the "Explain This Risk" button on the Detected Gaps page
(apps.risk.views.explain_risk): on-demand only (POST-triggered, never
automatic), reuses run_risk_narration, logs each attempt to AIRun,
persists the result (latest-wins, same as AnalystResult) scoped to the
specific GapFinding, and handles a missing ANTHROPIC_API_KEY gracefully
instead of a 500.

Same mocking pattern as apps/incidents/tests_analyze_view.py: a mocked
run_risk_narration stands in for a real Claude call -- no network, no
API key, nothing spent.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AIRun
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.risk.models import GapFinding, RiskNarration


class ExplainRiskViewTestCase(AuthedTestCase):
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
        self.gap = GapFinding.objects.create(
            organization=self.organization,
            incident=self.incident,
            gap_name="Authentication monitoring or MFA evidence needs review",
            description="Repeated authentication activity was not caught by any alerting rule.",
            affected_system="WEB-01",
            source=GapFinding.Source.LOG_BASED,
            priority=GapFinding.Priority.HIGH,
        )
        self.explain_url = reverse("risk:explain", args=[self.gap.id])
        self.index_url = reverse("risk:index")

    def test_index_page_shows_the_button_and_no_narration_yet(self):
        response = self.client.get(self.index_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Explain This Risk")
        self.assertContains(response, self.explain_url)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_get_request_does_not_trigger_generation(self):
        response = self.client.get(self.explain_url)

        self.assertRedirects(response, self.index_url)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_successful_narration_persists_and_logs_ai_run(self):
        fake_result = {
            "gap_id": self.gap.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "narration": "This gap matters because MFA evidence is missing for a privileged account.",
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.risk.views.run_risk_narration", return_value=fake_result
        ) as mock_run:
            response = self.client.post(self.explain_url, follow=True)

        mock_run.assert_called_once_with(self.gap)
        self.assertContains(response, "This gap matters because MFA evidence is missing")

        self.assertEqual(RiskNarration.objects.count(), 1)
        saved = RiskNarration.objects.get()
        self.assertEqual(saved.gap_id, self.gap.id)
        self.assertEqual(saved.narration_text, fake_result["narration"])
        self.assertEqual(saved.model_used, "claude-sonnet-5")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.ai_module, "risk_advisor")
        self.assertEqual(ai_run.input_type, "GapFinding")
        self.assertEqual(ai_run.input_id, str(self.gap.id))
        self.assertEqual(ai_run.status, AIRun.Status.SUCCESS)
        self.assertEqual(ai_run.output_id, str(saved.id))

    def test_narration_persists_across_a_fresh_page_load(self):
        fake_result = {
            "gap_id": self.gap.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "narration": "Enable MFA on this account to close the gap.",
            "generated_at": timezone.now(),
        }

        with patch("apps.risk.views.run_risk_narration", return_value=fake_result):
            self.client.post(self.explain_url)

        with patch(
            "apps.risk.views.run_risk_narration",
            side_effect=AssertionError("must not be called on a plain page load"),
        ) as mock_run_on_get:
            get_response = self.client.get(self.index_url)

        self.assertEqual(get_response.status_code, 200)
        mock_run_on_get.assert_not_called()
        self.assertContains(get_response, "Enable MFA on this account to close the gap.")
        self.assertEqual(RiskNarration.objects.count(), 1)
        self.assertEqual(AIRun.objects.count(), 1)

    def test_missing_api_key_shows_friendly_message_not_a_500(self):
        with patch(
            "apps.risk.views.run_risk_narration",
            side_effect=RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment "
                "before calling AnthropicProvider.send_message()."
            ),
        ) as mock_run:
            response = self.client.post(self.explain_url, follow=True)

        mock_run.assert_called_once_with(self.gap)
        self.assertContains(response, "AI risk narration isn&#x27;t available yet")
        self.assertNotContains(response, "ANTHROPIC_API_KEY is not set")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.status, AIRun.Status.FAILED)
        self.assertIn("ANTHROPIC_API_KEY is not set", ai_run.error_message)
        self.assertEqual(RiskNarration.objects.count(), 0)
