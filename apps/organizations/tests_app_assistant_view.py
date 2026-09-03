"""Coverage for the App Assistant page and its Q&A thread
(apps.organizations.views.app_assistant / ask_app_assistant): on-demand
only (POST-triggered, never automatic), reuses run_app_assistant_question,
logs each attempt to AIRun (stamped with the corpus version via
prompt_version), persists every question+answer pair (a growing thread,
scoped to Organization -- app-wide, not tied to one incident/gap), and
handles a missing ANTHROPIC_API_KEY gracefully instead of a 500.

Also proves the two previously-dead "Ask AegisFlow" / "Ask AI
Assistant" links (header Help & Support popover, and the Work Queue
"How to use the queue" modal) now point at this page instead of the
incidents tab-overview dead end, and that the incident-detail
assistant's suggestion chips are real buttons wired to the question
field, not decorative spans.

Same mocking pattern as apps/resilience/tests_ask_readiness_question_view.py
and apps/risk/tests_ask_risk_question_view.py: a mocked
run_app_assistant_question stands in for a real Claude call -- no
network, no API key, nothing spent.
"""

from unittest.mock import patch

from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AIRun
from apps.ai_core.services.app_assistant_context import APP_ASSISTANT_CORPUS_VERSION
from apps.organizations.models import AppAssistantQuestion, Organization


class AppAssistantViewTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.assistant_url = reverse("organizations:app_assistant")
        self.ask_url = reverse("organizations:ask_app_assistant")

    def test_assistant_page_renders_the_real_form(self):
        response = self.client.get(self.assistant_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.ask_url)
        self.assertEqual(AppAssistantQuestion.objects.count(), 0)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_get_request_does_not_trigger_a_question(self):
        response = self.client.get(self.ask_url)

        self.assertRedirects(response, self.assistant_url)
        self.assertEqual(AIRun.objects.count(), 0)

    def test_blank_question_does_not_trigger_a_call(self):
        with patch(
            "apps.ai_core.modules.app_assistant.run_app_assistant_question",
            side_effect=AssertionError("must not be called for a blank question"),
        ) as mock_run:
            response = self.client.post(self.ask_url, {"question": "   "})

        self.assertRedirects(response, self.assistant_url)
        mock_run.assert_not_called()
        self.assertEqual(AIRun.objects.count(), 0)
        self.assertEqual(AppAssistantQuestion.objects.count(), 0)

    def test_question_persists_stamps_corpus_version_and_renders_after_reload(self):
        answer = {
            "organization_id": self.organization.id,
            "model": "claude-sonnet-5",
            "question": "What does the Verify stage do?",
            "answer": "The Verify stage walks you through AI-suggested checks for this incident.",
            "corpus_version": APP_ASSISTANT_CORPUS_VERSION,
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.ai_core.modules.app_assistant.run_app_assistant_question",
            return_value=answer,
        ) as mock_run:
            response = self.client.post(self.ask_url, {"question": answer["question"]}, follow=True)

        self.assertEqual(response.status_code, 200)
        mock_run.assert_called_once_with(self.organization, answer["question"])
        self.assertContains(response, answer["question"])
        self.assertContains(response, answer["answer"])

        self.assertEqual(AppAssistantQuestion.objects.count(), 1)
        saved = AppAssistantQuestion.objects.get()
        self.assertEqual(saved.organization, self.organization)
        self.assertEqual(saved.answer_text, answer["answer"])

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.ai_module, "app_assistant_qa")
        self.assertEqual(ai_run.input_type, "Organization")
        self.assertEqual(ai_run.input_id, str(self.organization.id))
        self.assertEqual(ai_run.status, AIRun.Status.SUCCESS)
        self.assertEqual(ai_run.prompt_version, APP_ASSISTANT_CORPUS_VERSION)

        # Reload as a plain GET -- must not re-trigger a call, and the
        # thread must still be there.
        with patch(
            "apps.ai_core.modules.app_assistant.run_app_assistant_question",
            side_effect=AssertionError("must not be called on a plain page load"),
        ) as mock_run_on_get:
            reload_response = self.client.get(self.assistant_url)

        mock_run_on_get.assert_not_called()
        self.assertContains(reload_response, answer["question"])
        self.assertContains(reload_response, answer["answer"])

    def test_missing_api_key_shows_friendly_message_not_a_500(self):
        with patch(
            "apps.ai_core.modules.app_assistant.run_app_assistant_question",
            side_effect=RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment "
                "before calling AnthropicProvider.send_message()."
            ),
        ) as mock_run:
            response = self.client.post(self.ask_url, {"question": "How do I upload logs?"}, follow=True)

        mock_run.assert_called_once_with(self.organization, "How do I upload logs?")
        self.assertContains(response, "AegisFlow Assistant isn&#x27;t available yet")
        self.assertNotContains(response, "ANTHROPIC_API_KEY is not set")

        self.assertEqual(AIRun.objects.count(), 1)
        ai_run = AIRun.objects.get()
        self.assertEqual(ai_run.status, AIRun.Status.FAILED)
        self.assertIn("ANTHROPIC_API_KEY is not set", ai_run.error_message)
        self.assertEqual(AppAssistantQuestion.objects.count(), 0)


class AppAssistantEntryPointLinksTestCase(AuthedTestCase):
    """The two links that used to dead-end at incidents ?tab=overview
    now point at the real App Assistant page."""

    def setUp(self):
        self.assistant_url = reverse("organizations:app_assistant")

    def test_header_help_popover_ask_aegisflow_link_points_at_the_assistant(self):
        response = self.client.get(reverse("core:index"))
        self.assertContains(response, f'href="{self.assistant_url}">Ask AegisFlow<')

    def test_work_queue_modal_ask_ai_assistant_link_points_at_the_assistant(self):
        response = self.client.get(reverse("incidents:index") + "?tab=queue")
        self.assertContains(
            response, f'<a href="{self.assistant_url}"><svg class="icon"><use href="#icon-sparkles"></use></svg> Ask AI Assistant</a>'
        )


class IncidentAssistantSuggestionChipsTestCase(AuthedTestCase):
    """The incident-detail assistant's suggestion chips are real
    buttons wired to the question field (same data-question-suggestion
    / data-incident-question pattern as the workflow-stage rail), not
    decorative <span> text."""

    def test_suggestion_chips_are_wired_buttons_not_decorative_spans(self):
        from apps.incidents.models import IncidentGroup

        incident = IncidentGroup.objects.create(
            organization=Organization.objects.create(
                name="Demo Organization",
                organization_type="Demo",
                country="St. Vincent and the Grenadines",
                sector="Technology",
                risk_profile="medium",
            ),
            title="Suspicious login activity",
            incident_type="unauthorized_access",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="WEB01",
        )

        response = self.client.get(reverse("incidents:detail", args=[incident.id]))
        html = response.content.decode()

        self.assertIn('<button type="button" data-question-suggestion>What is happening?</button>', html)
        self.assertIn('data-incident-question', html)
        self.assertNotIn("<span>What is happening?</span>", html)
