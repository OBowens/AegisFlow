"""Coverage for the "Ask a Readiness Question" Q&A thread on the
Disaster Readiness page (apps.resilience.views.ask_readiness_question):
on-demand only (POST-triggered, never automatic), reuses
run_readiness_question, logs each attempt to AIRun, persists every
question+answer pair (a growing thread, scoped to Organization,
mirroring apps.risk.tests_ask_risk_question_view exactly), and handles
a missing ANTHROPIC_API_KEY gracefully instead of a 500.

Also proves the previously-dead "View all example questions" link is
gone and the form is a real POST now, not the disabled
action="#" / onsubmit="return false" placeholder it used to be.

Same mocking pattern as apps/resilience/tests_explain_readiness_view.py
and apps/risk/tests_ask_risk_question_view.py: a mocked
run_readiness_question stands in for a real Claude call -- no network,
no API key, nothing spent.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AIRun
from apps.organizations.models import Organization
from apps.resilience.models import DisasterReadinessFinding, ReadinessQuestion


class AskReadinessQuestionViewTestCase(AuthedTestCase):
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
        self.ask_url = reverse("resilience:ask_question")
        self.index_url = reverse("resilience:index")

    def test_index_page_shows_the_real_form_and_no_dead_link(self):
        response = self.client.get(self.index_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Ask a Readiness Question")
        self.assertContains(response, self.ask_url)
        self.assertNotContains(response, "View all example questions")
        self.assertNotContains(response, 'action="#"')
        self.assertNotContains(response, "onsubmit=")
        self.assertEqual(ReadinessQuestion.objects.count(), 0)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_get_request_does_not_trigger_a_question(self):
        response = self.client.get(self.ask_url)

        self.assertRedirects(response, self.index_url)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_blank_question_does_not_trigger_a_call(self):
        with patch(
            "apps.ai_core.modules.readiness_advisor.run_readiness_question",
            side_effect=AssertionError("must not be called for a blank question"),
        ) as mock_run:
            response = self.client.post(self.ask_url, {"question": "   "})

        self.assertRedirects(response, self.index_url)
        mock_run.assert_not_called()
        self.assertEqual(AIRun.objects.count(), 0)
        self.assertEqual(ReadinessQuestion.objects.count(), 0)

    def test_two_questions_both_persist_and_show_up_after_reload(self):
        first_answer = {
            "organization_id": self.organization.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant for this test",
            "question": "What should we check this hurricane season?",
            "answer": "Start with your backup restore test and generator fuel levels.",
            "generated_at": timezone.now(),
        }
        second_answer = {
            "organization_id": self.organization.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant for this test",
            "question": "Do we have enough generator fuel for a week-long outage?",
            "answer": "Your UPS coverage should bridge to generator failover automatically.",
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.ai_core.modules.readiness_advisor.run_readiness_question",
            return_value=first_answer,
        ) as mock_run:
            response_one = self.client.post(
                self.ask_url, {"question": first_answer["question"]}, follow=True
            )

        self.assertEqual(response_one.status_code, 200)
        mock_run.assert_called_once_with(self.organization, first_answer["question"])
        self.assertContains(response_one, first_answer["question"])
        self.assertContains(response_one, first_answer["answer"])

        with patch(
            "apps.ai_core.modules.readiness_advisor.run_readiness_question",
            return_value=second_answer,
        ) as mock_run_two:
            response_two = self.client.post(
                self.ask_url, {"question": second_answer["question"]}, follow=True
            )

        mock_run_two.assert_called_once_with(self.organization, second_answer["question"])
        self.assertContains(response_two, first_answer["question"])
        self.assertContains(response_two, second_answer["question"])

        self.assertEqual(ReadinessQuestion.objects.count(), 2)
        self.assertEqual(AIRun.objects.count(), 2)
        for ai_run in AIRun.objects.all():
            self.assertEqual(ai_run.ai_module, "readiness_advisor_qa")
            self.assertEqual(ai_run.input_type, "Organization")
            self.assertEqual(ai_run.input_id, str(self.organization.id))
            self.assertEqual(ai_run.status, AIRun.Status.SUCCESS)

        # Reload as a plain GET -- run_readiness_question must NOT be
        # called again, and both Q&A pairs must still be there, oldest first.
        with patch(
            "apps.ai_core.modules.readiness_advisor.run_readiness_question",
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
        self.assertEqual(ReadinessQuestion.objects.count(), 2)
        self.assertEqual(AIRun.objects.count(), 2)

    def test_missing_api_key_shows_friendly_message_not_a_500(self):
        with patch(
            "apps.ai_core.modules.readiness_advisor.run_readiness_question",
            side_effect=RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment "
                "before calling AnthropicProvider.send_message()."
            ),
        ) as mock_run:
            response = self.client.post(
                self.ask_url, {"question": "What should we prioritize?"}, follow=True
            )

        mock_run.assert_called_once_with(self.organization, "What should we prioritize?")
        self.assertContains(response, "AI readiness explanation isn&#x27;t available yet")
        self.assertNotContains(response, "ANTHROPIC_API_KEY is not set")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.status, AIRun.Status.FAILED)
        self.assertIn("ANTHROPIC_API_KEY is not set", ai_run.error_message)
        self.assertEqual(ReadinessQuestion.objects.count(), 0)
