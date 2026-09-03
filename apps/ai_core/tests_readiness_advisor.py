"""Coverage for the Readiness Advisor agent (apps/ai_core/modules/
readiness_advisor.py):

- build_readiness_context (apps/ai_core/services/readiness_context.py)
  reuses apps.resilience.views's own domain-classification helpers, so
  the real score and each domain's real status flow into the prompt
  exactly as the Disaster Readiness page itself computes them.
- run_readiness_explanation is the full pipeline -- gather context ->
  build prompt -> call provider -> handle response -- proven correct
  with a fake provider standing in for what Claude would actually
  return. No API key needed, nothing spent.

Same mocking pattern as apps/ai_core/tests_analyst.py and tests_writer.py.
"""

from django.test import TestCase

from apps.ai_core.modules.readiness_advisor import run_readiness_explanation, run_readiness_question
from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.readiness_context import build_readiness_context
from apps.organizations.models import Organization
from apps.resilience.models import DisasterReadinessFinding
from apps.resilience.services.scoring import compute_readiness_score


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


class BuildReadinessContextTestCase(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        # Distinctive backup-domain finding, HIGH priority -- this is the
        # one specific domain/status this test proves actually reaches
        # the prompt, not a stub.
        self.finding = DisasterReadinessFinding.objects.create(
            organization=self.organization,
            readiness_issue="No recent backup restore test",
            disaster_impact="A backup could fail silently without a tested restore procedure.",
            recovery_concern="Recovery time is unknown without a rehearsed restore.",
            source=DisasterReadinessFinding.Source.LOG_BASED,
            priority=DisasterReadinessFinding.Priority.HIGH,
        )

    def test_context_includes_real_score_and_the_specific_domain_status(self):
        context = build_readiness_context(self.organization)

        expected_score = compute_readiness_score(critical_count=0, high_count=1, medium_count=0)

        self.assertIn("## Readiness Overview", context)
        self.assertIn(self.organization.name, context)
        self.assertIn(f"Overall score: {expected_score}%", context)

        self.assertIn("## Domain Status", context)
        self.assertIn("Backup & Recovery (HIGH RISK)", context)
        self.assertIn("No recent backup restore test", context)

    def test_context_reports_no_contradictions_when_none_exist(self):
        context = build_readiness_context(self.organization)

        self.assertIn("## Readiness Contradictions\nNone found for this organization.", context)


class RunReadinessExplanationTestCase(TestCase):
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

    def test_prompt_sent_to_provider_includes_real_score_and_domain_status(self):
        # Same context-injection proof pattern as
        # apps/ai_core/tests_analyst.py / tests_writer.py.
        fake_provider = _FakeProvider("Your score reflects an untested backup restore process.")

        run_readiness_explanation(self.organization, provider=fake_provider)

        expected_score = compute_readiness_score(critical_count=0, high_count=1, medium_count=0)
        self.assertIn(f"Overall score: {expected_score}%", fake_provider.last_prompt)
        self.assertIn("Backup & Recovery (HIGH RISK)", fake_provider.last_prompt)
        self.assertIn("No recent backup restore test", fake_provider.last_prompt)

    def test_pipeline_returns_display_ready_result_using_fake_provider(self):
        fake_response = (
            "Your readiness score is low mainly because of an untested backup restore "
            "process. Prioritize scheduling a real restore test this month."
        )
        fake_provider = _FakeProvider(fake_response)

        result = run_readiness_explanation(self.organization, provider=fake_provider)

        self.assertEqual(result["organization_id"], self.organization.id)
        self.assertEqual(result["model"], "claude-sonnet-5-fake")
        self.assertEqual(result["explanation"], fake_response)
        self.assertIn("generated_at", result)

    def test_pipeline_propagates_the_provider_missing_key_error(self):
        unconfigured_provider = AnthropicProvider(api_key=None)
        unconfigured_provider.api_key = None

        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            run_readiness_explanation(self.organization, provider=unconfigured_provider)


class RunReadinessQuestionTestCase(TestCase):
    """Coverage for the on-demand "Ask AI Advisor" Q&A pipeline
    (run_readiness_question): same real-context-injection proof as
    RunReadinessExplanationTestCase above, plus the typed question
    itself reaching the prompt -- mirrors tests_risk_advisor.py's
    RunRiskQuestionTestCase exactly, scoped to Organization instead of
    GapFinding.
    """

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

    def test_prompt_sent_to_provider_includes_real_readiness_data_and_the_typed_question(self):
        fake_provider = _FakeProvider("Your backup restore process is the main gap right now.")

        run_readiness_question(
            self.organization, "What should we check first?", provider=fake_provider
        )

        expected_score = compute_readiness_score(critical_count=0, high_count=1, medium_count=0)
        self.assertIn(f"Overall score: {expected_score}%", fake_provider.last_prompt)
        self.assertIn("Backup & Recovery (HIGH RISK)", fake_provider.last_prompt)
        self.assertIn("No recent backup restore test", fake_provider.last_prompt)
        self.assertIn("## Question\nWhat should we check first?", fake_provider.last_prompt)

    def test_pipeline_returns_display_ready_result_using_fake_provider(self):
        fake_provider = _FakeProvider("Prioritize a real restore test this month.")

        result = run_readiness_question(
            self.organization, "What should we check first?", provider=fake_provider
        )

        self.assertEqual(result["organization_id"], self.organization.id)
        self.assertEqual(result["model"], "claude-sonnet-5-fake")
        self.assertEqual(result["question"], "What should we check first?")
        self.assertEqual(result["answer"], "Prioritize a real restore test this month.")
        self.assertIn("generated_at", result)

    def test_pipeline_propagates_the_provider_missing_key_error(self):
        unconfigured_provider = AnthropicProvider(api_key=None)
        unconfigured_provider.api_key = None

        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            run_readiness_question(
                self.organization, "What should we check first?", provider=unconfigured_provider
            )
