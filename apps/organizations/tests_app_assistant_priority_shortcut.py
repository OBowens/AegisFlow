"""The App Assistant answers "what should I fix first" style questions
directly from the latest PriorityBriefing (a plain DB read -- no AI call,
no AIRun row), instead of the static-corpus assistant deflecting the user
elsewhere. Unrelated how-to questions are untouched and still go to the
corpus assistant.

Both assistant surfaces -- the full-page Aegis Assistant page and the
compact drawer in the app shell -- POST to this one view
(organizations:ask_app_assistant), so covering the view covers both.

Same mocking pattern as tests_app_assistant_view.py: run_app_assistant_question
is patched so the matched path can assert it is never called, and the
unrelated path can assert it still is.
"""

from datetime import timedelta
from unittest.mock import patch

from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AIRun
from apps.core.models import PriorityBriefing
from apps.organizations.models import AppAssistantQuestion, Organization

_RUN_AI = "apps.ai_core.modules.app_assistant.run_app_assistant_question"


class AppAssistantPriorityShortcutTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization", organization_type="Demo"
        )
        self.ask_url = reverse("organizations:ask_app_assistant")
        self.assistant_url = reverse("organizations:app_assistant")

    def _briefing(self, *, text, age_days=0):
        briefing = PriorityBriefing.objects.create(
            organization=self.organization,
            briefing_text=text,
            model_used="claude-sonnet-5",
        )
        PriorityBriefing.objects.filter(pk=briefing.pk).update(
            generated_at=timezone.now() - timedelta(days=age_days)
        )
        return briefing

    def test_matched_question_returns_the_briefing_and_never_calls_the_ai(self):
        self._briefing(
            text="1. WEB01 - contain the intrusion.\n2. Patch DB02.", age_days=1
        )

        with patch(
            _RUN_AI,
            side_effect=AssertionError("AI must not be called for a prioritization question"),
        ) as mock_run:
            response = self.client.post(
                self.ask_url,
                {"question": "What should I fix first?"},
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )

        mock_run.assert_not_called()
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("1. WEB01 - contain the intrusion.", body["answer"])
        self.assertIn("Patch DB02.", body["answer"])
        self.assertIn("Home page", body["answer"])
        self.assertEqual(body["model"], "")

        # No AI call happened -> no AIRun row. The Q&A is still persisted.
        self.assertEqual(AIRun.objects.count(), 0)
        saved = AppAssistantQuestion.objects.get()
        self.assertEqual(saved.question_text, "What should I fix first?")
        self.assertIn("Patch DB02.", saved.answer_text)
        self.assertEqual(saved.model_used, "")

    def test_matched_question_with_no_briefing_answers_honestly_no_ai_call(self):
        with patch(
            _RUN_AI, side_effect=AssertionError("AI must not be called")
        ) as mock_run:
            response = self.client.post(
                self.ask_url,
                {"question": "what should I focus on next?"},
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )

        mock_run.assert_not_called()
        body = response.json()
        self.assertIn("No priority briefing has been generated", body["answer"])
        self.assertIn("Explain priorities", body["answer"])
        self.assertEqual(AIRun.objects.count(), 0)
        self.assertEqual(AppAssistantQuestion.objects.count(), 1)

    def test_stale_briefing_is_not_embedded(self):
        self._briefing(text="THREE WEEK OLD RANKING", age_days=30)

        with patch(_RUN_AI, side_effect=AssertionError("AI must not be called")):
            response = self.client.post(
                self.ask_url,
                {"question": "what's most urgent?"},
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )

        body = response.json()
        self.assertNotIn("THREE WEEK OLD RANKING", body["answer"])
        self.assertIn("out of date", body["answer"])
        self.assertEqual(AIRun.objects.count(), 0)

    def test_unrelated_question_still_uses_the_static_corpus_assistant(self):
        answer = {
            "organization_id": self.organization.id,
            "model": "claude-sonnet-5",
            "question": "how do I upload a log file",
            "answer": "Open Upload Data in the sidebar and choose your export.",
            "corpus_version": "1",
            "generated_at": timezone.now(),
        }

        with patch(_RUN_AI, return_value=answer) as mock_run:
            response = self.client.post(
                self.ask_url,
                {"question": "how do I upload a log file"},
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            )

        mock_run.assert_called_once_with(self.organization, "how do I upload a log file")
        self.assertEqual(response.json()["answer"], answer["answer"])
        self.assertEqual(AIRun.objects.count(), 1)
        self.assertEqual(AIRun.objects.get().status, AIRun.Status.SUCCESS)

    def test_non_xhr_matched_question_persists_and_redirects(self):
        self._briefing(text="Ranked work item one.", age_days=0)

        with patch(_RUN_AI, side_effect=AssertionError("AI must not be called")):
            response = self.client.post(self.ask_url, {"question": "where do I start?"})

        self.assertRedirects(response, self.assistant_url)
        saved = AppAssistantQuestion.objects.get()
        self.assertIn("Ranked work item one.", saved.answer_text)
        self.assertEqual(AIRun.objects.count(), 0)
