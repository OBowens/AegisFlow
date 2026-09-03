"""Coverage for the "Compare with Another Incident" panel on the
Incident Detail page (apps.incidents.views.incident_compare): on-demand
only (POST-triggered, never automatic), reuses run_incident_comparison,
logs each attempt to AIRun, persists every comparison (a growing thread
per incident, like AnalystQuestion, not a single "latest wins" slot --
a team may compare against several different candidates), validates the
target incident ID before spending anything, and handles a missing
ANTHROPIC_API_KEY gracefully instead of a 500.

Same mocking pattern as apps/incidents/tests_ask_view.py: a mocked
run_incident_comparison stands in for a real Claude call -- no network,
no API key, nothing spent.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AIRun
from apps.incidents.models import IncidentComparison, IncidentGroup
from apps.organizations.models import Organization


class IncidentCompareViewTestCase(AuthedTestCase):
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
        self.other_incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Suspicious database access from external IP",
            incident_type="unauthorized_access",
            severity=IncidentGroup.Severity.MEDIUM,
            status=IncidentGroup.Status.OPEN,
            affected_systems="DB-02",
        )
        self.compare_url = reverse("incidents:compare", args=[self.incident.id])
        self.detail_url = reverse("incidents:detail", args=[self.incident.id])

    def test_detail_page_shows_the_compare_form_and_no_thread_yet(self):
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Compare with Another Incident")
        self.assertContains(response, self.compare_url)
        self.assertEqual(IncidentComparison.objects.count(), 0)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_get_request_does_not_trigger_a_comparison(self):
        response = self.client.get(self.compare_url)

        self.assertRedirects(response, self.detail_url)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_blank_id_does_not_trigger_a_call(self):
        with patch(
            "apps.incidents.views.run_incident_comparison",
            side_effect=AssertionError("must not be called for a blank id"),
        ) as mock_run:
            response = self.client.post(self.compare_url, {"other_incident_id": "   "})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Enter a valid incident ID to compare with.")
        mock_run.assert_not_called()
        self.assertEqual(AIRun.objects.count(), 0)
        self.assertEqual(IncidentComparison.objects.count(), 0)

    def test_comparing_to_self_does_not_trigger_a_call(self):
        with patch(
            "apps.incidents.views.run_incident_comparison",
            side_effect=AssertionError("must not be called when comparing to self"),
        ) as mock_run:
            response = self.client.post(
                self.compare_url, {"other_incident_id": str(self.incident.id)}
            )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Choose a different incident to compare against.")
        mock_run.assert_not_called()
        self.assertEqual(AIRun.objects.count(), 0)

    def test_nonexistent_target_id_does_not_trigger_a_call(self):
        missing_id = self.other_incident.id + 9999
        with patch(
            "apps.incidents.views.run_incident_comparison",
            side_effect=AssertionError("must not be called for a missing incident"),
        ) as mock_run:
            response = self.client.post(
                self.compare_url, {"other_incident_id": str(missing_id)}
            )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f"Incident #{missing_id} was not found.")
        mock_run.assert_not_called()
        self.assertEqual(AIRun.objects.count(), 0)

    def test_successful_comparison_persists_and_logs_ai_run(self):
        fake_result = {
            "incident_id": self.incident.id,
            "other_incident_id": self.other_incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant for this test",
            "comparison": (
                "Shared source IP and account suggest a possible link, but the "
                "different systems and 12-day gap mean this is only moderately "
                "confident."
            ),
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.incidents.views.run_incident_comparison", return_value=fake_result
        ) as mock_run:
            response = self.client.post(
                self.compare_url, {"other_incident_id": str(self.other_incident.id)}
            )

        self.assertEqual(response.status_code, 200)
        mock_run.assert_called_once_with(self.incident, self.other_incident)
        self.assertContains(response, "moderately")
        self.assertContains(response, "Suspicious database access from external IP")

        self.assertEqual(IncidentComparison.objects.count(), 1)
        saved = IncidentComparison.objects.get()
        self.assertEqual(saved.incident_id, self.incident.id)
        self.assertEqual(saved.compared_incident_id, self.other_incident.id)
        self.assertEqual(saved.comparison_text, fake_result["comparison"])
        self.assertEqual(saved.model_used, "claude-sonnet-5")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.ai_module, "comparator")
        self.assertEqual(ai_run.input_type, "IncidentGroup")
        self.assertEqual(ai_run.input_id, f"{self.incident.id},{self.other_incident.id}")
        self.assertEqual(ai_run.status, AIRun.Status.SUCCESS)
        self.assertEqual(ai_run.output_id, str(saved.id))

    def test_two_comparisons_against_different_incidents_both_persist(self):
        third_incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Mail server probing from external IP",
            incident_type="reconnaissance",
            severity=IncidentGroup.Severity.LOW,
            status=IncidentGroup.Status.OPEN,
            affected_systems="MAIL-03",
        )
        first_result = {
            "incident_id": self.incident.id,
            "other_incident_id": self.other_incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "comparison": "First comparison result.",
            "generated_at": timezone.now(),
        }
        second_result = {
            "incident_id": self.incident.id,
            "other_incident_id": third_incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "comparison": "Second comparison result.",
            "generated_at": timezone.now(),
        }

        with patch("apps.incidents.views.run_incident_comparison", return_value=first_result):
            self.client.post(self.compare_url, {"other_incident_id": str(self.other_incident.id)})
        with patch("apps.incidents.views.run_incident_comparison", return_value=second_result):
            self.client.post(self.compare_url, {"other_incident_id": str(third_incident.id)})

        self.assertEqual(IncidentComparison.objects.count(), 2)
        self.assertEqual(AIRun.objects.count(), 2)

        with patch(
            "apps.incidents.views.run_incident_comparison",
            side_effect=AssertionError("must not be called on a plain page load"),
        ) as mock_run_on_get:
            reload_response = self.client.get(self.detail_url)

        mock_run_on_get.assert_not_called()
        self.assertContains(reload_response, "First comparison result.")
        self.assertContains(reload_response, "Second comparison result.")

    def test_missing_api_key_shows_friendly_message_not_a_500(self):
        with patch(
            "apps.incidents.views.run_incident_comparison",
            side_effect=RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment "
                "before calling AnthropicProvider.send_message()."
            ),
        ) as mock_run:
            response = self.client.post(
                self.compare_url, {"other_incident_id": str(self.other_incident.id)}
            )

        self.assertEqual(response.status_code, 200)
        mock_run.assert_called_once_with(self.incident, self.other_incident)
        self.assertContains(response, "AI analysis isn&#x27;t available yet")
        self.assertNotContains(response, "ANTHROPIC_API_KEY is not set")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.status, AIRun.Status.FAILED)
        self.assertIn("ANTHROPIC_API_KEY is not set", ai_run.error_message)
        self.assertEqual(IncidentComparison.objects.count(), 0)
