"""Coverage for the App Assistant agent (apps/ai_core/modules/
app_assistant.py) and its static corpus
(apps/ai_core/services/app_assistant_context.py):

- The corpus is real, versioned reference text about the app itself
  (navigation, the guided workflow, evidence tiers) -- not empty, not
  a placeholder.
- run_app_assistant_question actually sends that corpus plus the
  system preamble plus the typed question to the provider -- the
  "answers from the corpus" half of the App Assistant's job.
- The system preamble instructs the model to say plainly when
  something isn't covered rather than guess, and to redirect
  item-specific questions to that item's own scoped assistant instead
  of answering from live data it doesn't have -- the "says it doesn't
  know when asked something outside scope" half. A fake provider
  cannot prove what a real model would say, but it does prove this
  instruction is genuinely what gets sent, and that whatever the
  provider returns (including a "not covered" answer) passes through
  unmodified rather than being overridden.

Same mocking pattern as apps/ai_core/tests_readiness_advisor.py --
no API key needed, nothing spent.
"""

from django.test import TestCase

from apps.ai_core.modules.app_assistant import (
    APP_ASSISTANT_SYSTEM_PREAMBLE,
    run_app_assistant_question,
)
from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.app_assistant_context import (
    APP_ASSISTANT_CORPUS_VERSION,
    build_app_assistant_context,
)
from apps.organizations.models import Organization


class _FakeProvider:
    """Stands in for a real AI provider -- returns a canned response
    instead of calling out to Claude, so the test spends nothing and
    needs no API key."""

    model = "claude-sonnet-5-fake"

    def __init__(self, response_text):
        self.response_text = response_text
        self.last_prompt = None

    def send_message(self, prompt, **kwargs):
        self.last_prompt = prompt
        return self.response_text


class AppAssistantCorpusTestCase(TestCase):
    def test_corpus_covers_navigation_workflow_and_terminology(self):
        context = build_app_assistant_context()

        # Navigation.
        self.assertIn("Work Queue", context)
        self.assertIn("Upload Data", context)
        self.assertIn("Readiness", context)
        self.assertIn("SOP Library", context)
        self.assertIn("Audit History", context)

        # The guided workflow -- all six stages by name.
        for stage in ("Overview", "Understand", "Verify", "Respond", "Resolve", "Close"):
            self.assertIn(stage, context)

        # Terminology the Verify-stage badges actually use.
        self.assertIn("Evidence Available", context)
        self.assertIn("Manual check required", context)

    def test_corpus_states_its_own_scope_boundary(self):
        context = build_app_assistant_context()
        self.assertIn("does not have access to any organization's live", context)

    def test_corpus_version_is_set(self):
        self.assertTrue(APP_ASSISTANT_CORPUS_VERSION)


class AppAssistantSystemPreambleTestCase(TestCase):
    def test_preamble_instructs_the_model_not_to_guess(self):
        self.assertIn("say plainly that it isn't covered instead of guessing", APP_ASSISTANT_SYSTEM_PREAMBLE)

    def test_preamble_instructs_the_model_to_redirect_item_specific_questions(self):
        self.assertIn("point the user to that item's own page", APP_ASSISTANT_SYSTEM_PREAMBLE)


class RunAppAssistantQuestionTestCase(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )

    def test_prompt_sent_to_provider_includes_corpus_preamble_and_typed_question(self):
        fake_provider = _FakeProvider("The Verify stage walks you through AI-suggested checks.")

        run_app_assistant_question(
            self.organization, "What does the Verify stage do?", provider=fake_provider
        )

        self.assertIn(APP_ASSISTANT_SYSTEM_PREAMBLE, fake_provider.last_prompt)
        self.assertIn("Evidence Available", fake_provider.last_prompt)
        self.assertIn("## Question\nWhat does the Verify stage do?", fake_provider.last_prompt)

    def test_pipeline_returns_display_ready_result_answered_from_the_corpus(self):
        fake_response = (
            'The "Evidence Available" badge means a real, on-hand data source backs '
            "that specific verification question for this incident."
        )
        fake_provider = _FakeProvider(fake_response)

        result = run_app_assistant_question(
            self.organization, 'What does "Evidence Available" mean?', provider=fake_provider
        )

        self.assertEqual(result["organization_id"], self.organization.id)
        self.assertEqual(result["model"], "claude-sonnet-5-fake")
        self.assertEqual(result["answer"], fake_response)
        self.assertEqual(result["corpus_version"], APP_ASSISTANT_CORPUS_VERSION)
        self.assertIn("generated_at", result)

    def test_pipeline_passes_through_an_out_of_scope_answer_unmodified(self):
        # Proves the app never overrides or filters what the model
        # says -- if it correctly declines (per the preamble's
        # instruction) rather than guessing, that answer reaches the
        # caller exactly as returned, not silently replaced.
        decline_response = (
            "That's not covered in what I know about the app -- for live details "
            "about incident INC-4021, please ask on that incident's own page."
        )
        fake_provider = _FakeProvider(decline_response)

        result = run_app_assistant_question(
            self.organization, "What happened on incident INC-4021?", provider=fake_provider
        )

        self.assertEqual(result["answer"], decline_response)

    def test_pipeline_propagates_the_provider_missing_key_error(self):
        unconfigured_provider = AnthropicProvider(api_key=None)
        unconfigured_provider.api_key = None

        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            run_app_assistant_question(self.organization, "How do I upload logs?", provider=unconfigured_provider)
