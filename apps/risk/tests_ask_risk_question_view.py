"""Coverage for the "Ask a Question" Q&A thread on each gap card on the
Detected Gaps page (apps.risk.views.ask_risk_question): on-demand only
(POST-triggered, never automatic), reuses run_risk_question, logs each
attempt to AIRun, persists every question+answer pair (a growing thread,
scoped to GapFinding, mirroring apps.incidents.tests_ask_view exactly),
and handles a missing ANTHROPIC_API_KEY gracefully instead of a 500.

Same mocking pattern as apps/incidents/tests_ask_view.py and
apps/risk/tests_explain_risk_view.py: a mocked run_risk_question stands
in for a real Claude call -- no network, no API key, nothing spent.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AIRun
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.risk.models import GapFinding, RiskQuestion


class AskRiskQuestionViewTestCase(AuthedTestCase):
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
        self.gap = GapFinding.objects.create(
            organization=self.organization,
            incident=self.incident,
            gap_name="Authentication monitoring or MFA evidence needs review",
            description="Repeated authentication activity was not caught by any alerting rule.",
            affected_system="WEB-01",
            source=GapFinding.Source.LOG_BASED,
            priority=GapFinding.Priority.HIGH,
        )
        self.ask_url = reverse("risk:ask", args=[self.gap.id])
        self.index_url = reverse("risk:index")

    def test_index_page_shows_the_ask_form_and_no_thread_yet(self):
        response = self.client.get(self.index_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.ask_url)
        self.assertEqual(RiskQuestion.objects.count(), 0)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_get_request_does_not_trigger_a_question(self):
        response = self.client.get(self.ask_url)

        self.assertRedirects(response, self.index_url)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_blank_question_does_not_trigger_a_call(self):
        with patch(
            "apps.risk.views.run_risk_question",
            side_effect=AssertionError("must not be called for a blank question"),
        ) as mock_run:
            response = self.client.post(self.ask_url, {"question": "   "})

        self.assertRedirects(response, f"{self.index_url}#gap-{self.gap.id}")
        mock_run.assert_not_called()
        self.assertEqual(AIRun.objects.count(), 0)
        self.assertEqual(RiskQuestion.objects.count(), 0)

    def test_two_questions_both_persist_and_show_up_after_reload(self):
        first_answer = {
            "gap_id": self.gap.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant for this test",
            "question": "Was MFA enabled for the affected account?",
            "answer": "The evidence does not include MFA configuration for this account.",
            "generated_at": timezone.now(),
        }
        second_answer = {
            "gap_id": self.gap.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant for this test",
            "question": "Has this account been compromised before?",
            "answer": "No prior compromise is recorded in the evidence for this gap.",
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.risk.views.run_risk_question", return_value=first_answer
        ) as mock_run:
            response_one = self.client.post(
                self.ask_url, {"question": first_answer["question"]}, follow=True
            )

        self.assertEqual(response_one.status_code, 200)
        mock_run.assert_called_once_with(self.gap, first_answer["question"])
        self.assertContains(response_one, first_answer["question"])
        self.assertContains(response_one, first_answer["answer"])

        with patch(
            "apps.risk.views.run_risk_question", return_value=second_answer
        ) as mock_run_two:
            response_two = self.client.post(
                self.ask_url, {"question": second_answer["question"]}, follow=True
            )

        mock_run_two.assert_called_once_with(self.gap, second_answer["question"])
        self.assertContains(response_two, first_answer["question"])
        self.assertContains(response_two, second_answer["question"])

        self.assertEqual(RiskQuestion.objects.count(), 2)
        self.assertEqual(AIRun.objects.count(), 2)
        for ai_run in AIRun.objects.all():
            self.assertEqual(ai_run.ai_module, "risk_advisor_qa")
            self.assertEqual(ai_run.input_type, "GapFinding")
            self.assertEqual(ai_run.input_id, str(self.gap.id))
            self.assertEqual(ai_run.status, AIRun.Status.SUCCESS)

        # Reload as a plain GET -- run_risk_question must NOT be called
        # again, and both Q&A pairs must still be there, oldest first.
        with patch(
            "apps.risk.views.run_risk_question",
            side_effect=AssertionError("must not be called on a plain page load"),
        ) as mock_run_on_get:
            reload_response = self.client.get(self.index_url)

        mock_run_on_get.assert_not_called()
        content = reload_response.content.decode()
        self.assertLess(
            content.index(first_answer["question"]),
            content.index(second_answer["question"]),
            "expected the first question to render before the second (most recent last)",
        )
        self.assertEqual(RiskQuestion.objects.count(), 2)
        self.assertEqual(AIRun.objects.count(), 2)

    def test_missing_api_key_shows_friendly_message_not_a_500(self):
        with patch(
            "apps.risk.views.run_risk_question",
            side_effect=RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment "
                "before calling AnthropicProvider.send_message()."
            ),
        ) as mock_run:
            response = self.client.post(
                self.ask_url, {"question": "What happened here?"}, follow=True
            )

        mock_run.assert_called_once_with(self.gap, "What happened here?")
        self.assertContains(response, "AI risk narration isn&#x27;t available yet")
        self.assertNotContains(response, "ANTHROPIC_API_KEY is not set")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.status, AIRun.Status.FAILED)
        self.assertIn("ANTHROPIC_API_KEY is not set", ai_run.error_message)
        self.assertEqual(RiskQuestion.objects.count(), 0)
