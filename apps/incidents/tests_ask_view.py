"""Coverage for the "Ask a Question" Q&A thread on the Incident Detail page
(apps.incidents.views.incident_ask): on-demand only (POST-triggered, never
automatic), reuses build_incident_context via run_incident_question, logs
each attempt to AIRun, persists every question+answer pair (a growing
thread, unlike AnalystResult's "latest wins"), and handles a missing
ANTHROPIC_API_KEY gracefully instead of a 500.

Same mocking pattern as tests_analyze_view.py: a mocked run_incident_question
stands in for a real Claude call -- no network, no API key, nothing spent.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AIRun
from apps.incidents.models import AnalystQuestion, IncidentGroup
from apps.organizations.models import Organization


class IncidentAskViewTestCase(AuthedTestCase):
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
        self.ask_url = reverse("incidents:ask", args=[self.incident.id])
        self.detail_url = reverse("incidents:detail", args=[self.incident.id])

    def test_detail_page_shows_the_ask_form_and_no_thread_yet(self):
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Ask a Question")
        self.assertContains(response, self.ask_url)
        self.assertEqual(AnalystQuestion.objects.count(), 0)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_get_request_does_not_trigger_a_question(self):
        response = self.client.get(self.ask_url)

        self.assertRedirects(response, self.detail_url)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_blank_question_does_not_trigger_a_call(self):
        with patch(
            "apps.incidents.views.run_incident_question",
            side_effect=AssertionError("must not be called for a blank question"),
        ) as mock_run:
            response = self.client.post(self.ask_url, {"question": "   "})

        self.assertRedirects(response, self.detail_url)
        mock_run.assert_not_called()
        self.assertEqual(AIRun.objects.count(), 0)
        self.assertEqual(AnalystQuestion.objects.count(), 0)

    def test_two_questions_both_persist_and_show_up_after_reload(self):
        first_answer = {
            "incident_id": self.incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant for this test",
            "question": "Was the source IP seen before on this account?",
            "answer": "Yes -- the same source IP appears in one prior alert on this account.",
            "generated_at": timezone.now(),
        }
        second_answer = {
            "incident_id": self.incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant for this test",
            "question": "Was MFA enabled for the targeted account?",
            "answer": (
                "The evidence in this context does not include MFA configuration "
                "for the account, so a confident answer is not possible."
            ),
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.incidents.views.run_incident_question", return_value=first_answer
        ) as mock_run:
            response_one = self.client.post(
                self.ask_url, {"question": first_answer["question"]}
            )

        self.assertEqual(response_one.status_code, 200)
        mock_run.assert_called_once_with(self.incident, first_answer["question"])
        self.assertContains(response_one, first_answer["question"])
        self.assertContains(response_one, first_answer["answer"])

        with patch(
            "apps.incidents.views.run_incident_question", return_value=second_answer
        ) as mock_run_two:
            response_two = self.client.post(
                self.ask_url, {"question": second_answer["question"]}
            )

        self.assertEqual(response_two.status_code, 200)
        mock_run_two.assert_called_once_with(self.incident, second_answer["question"])
        # Both questions show up together on the second response already.
        self.assertContains(response_two, first_answer["question"])
        self.assertContains(response_two, first_answer["answer"])
        self.assertContains(response_two, second_answer["question"])
        self.assertContains(response_two, second_answer["answer"])

        self.assertEqual(AnalystQuestion.objects.count(), 2)
        self.assertEqual(AIRun.objects.count(), 2)
        for ai_run in AIRun.objects.all():
            self.assertEqual(ai_run.ai_module, "analyst_qa")
            self.assertEqual(ai_run.input_type, "IncidentGroup")
            self.assertEqual(ai_run.input_id, str(self.incident.id))
            self.assertEqual(ai_run.status, AIRun.Status.SUCCESS)
            self.assertEqual(ai_run.model_used, "claude-sonnet-5")

        # Reload as a plain GET -- run_incident_question must NOT be called
        # again, and both Q&A pairs must still be there, oldest first.
        with patch(
            "apps.incidents.views.run_incident_question",
            side_effect=AssertionError("run_incident_question must not be called on a plain page load"),
        ) as mock_run_on_get:
            reload_response = self.client.get(self.detail_url)

        self.assertEqual(reload_response.status_code, 200)
        mock_run_on_get.assert_not_called()
        self.assertContains(reload_response, first_answer["question"])
        self.assertContains(reload_response, first_answer["answer"])
        self.assertContains(reload_response, second_answer["question"])
        self.assertContains(reload_response, second_answer["answer"])

        content = reload_response.content.decode()
        self.assertLess(
            content.index(first_answer["question"]),
            content.index(second_answer["question"]),
            "expected the first question to render before the second (most recent last)",
        )

        self.assertEqual(AnalystQuestion.objects.count(), 2)
        self.assertEqual(AIRun.objects.count(), 2)

    def test_missing_api_key_shows_friendly_message_not_a_500(self):
        with patch(
            "apps.incidents.views.run_incident_question",
            side_effect=RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment "
                "before calling AnthropicProvider.send_message()."
            ),
        ) as mock_run:
            response = self.client.post(self.ask_url, {"question": "What happened here?"})

        self.assertEqual(response.status_code, 200)
        mock_run.assert_called_once_with(self.incident, "What happened here?")
        self.assertContains(response, "AI analysis isn&#x27;t available yet")
        self.assertContains(response, "API key not configured")
        self.assertNotContains(response, "ANTHROPIC_API_KEY is not set")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.status, AIRun.Status.FAILED)
        self.assertIn("ANTHROPIC_API_KEY is not set", ai_run.error_message)
        self.assertEqual(ai_run.model_used, "")
        self.assertEqual(AnalystQuestion.objects.count(), 0)

    def test_unexpected_runtime_error_also_shows_a_friendly_message(self):
        with patch(
            "apps.incidents.views.run_incident_question",
            side_effect=RuntimeError("Anthropic API request failed (500): internal error"),
        ):
            response = self.client.post(self.ask_url, {"question": "What happened here?"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "AI analysis failed. Please try again in a moment.")

        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.status, AIRun.Status.FAILED)
        self.assertIn("Anthropic API request failed", ai_run.error_message)
        self.assertEqual(AnalystQuestion.objects.count(), 0)
