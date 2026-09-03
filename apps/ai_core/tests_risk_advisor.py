"""Coverage for the Risk Advisor agent (apps/ai_core/modules/risk_advisor.py):

- build_risk_context (apps/ai_core/services/risk_context.py) assembles a
  single gap's real detail, its paired risk assessment, and a short
  incident blurb into one prompt.
- run_risk_narration is the full pipeline -- gather context -> build
  prompt -> call provider -> handle response -- proven correct with a
  fake provider standing in for what Claude would actually return. No
  API key needed, nothing spent.

Same mocking pattern as tests_analyst.py / tests_writer.py /
tests_readiness_advisor.py.
"""

from django.test import TestCase

from apps.ai_core.modules.risk_advisor import run_risk_narration, run_risk_question
from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.risk_context import build_risk_context
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.risk.models import GapFinding, RiskAssessment


class _FakeProvider:
    model = "claude-sonnet-5-fake"

    def __init__(self, response_text):
        self.response_text = response_text
        self.last_prompt = None

    def send_message(self, prompt, **kwargs):
        self.last_prompt = prompt
        return self.response_text


class BuildRiskContextTestCase(TestCase):
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
            evidence="13 failed logins from a single external IP within 20 minutes.",
            priority=GapFinding.Priority.HIGH,
        )
        self.risk = RiskAssessment.objects.create(
            organization=self.organization,
            incident=self.incident,
            gap=self.gap,
            risk_title="Authentication control exposure",
            likelihood=4,
            impact=4,
            risk_level=RiskAssessment.Level.HIGH,
            reasoning="Repeated authentication activity increases the likelihood of unauthorized access without MFA.",
            recommended_priority=RiskAssessment.RecommendedPriority.URGENT,
        )

    def test_context_includes_the_real_gap_and_risk_detail(self):
        context = build_risk_context(self.gap)

        self.assertIn("## Gap Finding", context)
        self.assertIn("Authentication monitoring or MFA evidence needs review", context)
        self.assertIn("13 failed logins from a single external IP within 20 minutes.", context)

        self.assertIn("## Risk Assessment", context)
        self.assertIn("Authentication control exposure", context)
        self.assertIn("Likelihood: 4/5", context)
        self.assertIn("Impact: 4/5", context)
        self.assertIn(f"Risk score: {self.risk.risk_score}/25", context)
        self.assertIn(
            "Repeated authentication activity increases the likelihood of unauthorized access without MFA.",
            context,
        )

        self.assertIn("## Linked Incident", context)
        self.assertIn("Possible brute-force attempt against privileged account", context)

    def test_context_handles_a_gap_with_no_risk_assessment_yet(self):
        bare_gap = GapFinding.objects.create(
            organization=self.organization,
            gap_name="Unreviewed gap",
            description="No risk scored yet.",
            source=GapFinding.Source.MANUAL,
        )

        context = build_risk_context(bare_gap)

        self.assertIn("## Risk Assessment\nNo formal risk assessment recorded for this gap yet.", context)
        self.assertIn("## Linked Incident\nNo incident is linked to this gap.", context)


class RunRiskNarrationTestCase(TestCase):
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
            evidence="13 failed logins from a single external IP within 20 minutes.",
            priority=GapFinding.Priority.HIGH,
        )
        RiskAssessment.objects.create(
            organization=self.organization,
            incident=self.incident,
            gap=self.gap,
            risk_title="Authentication control exposure",
            likelihood=4,
            impact=4,
            risk_level=RiskAssessment.Level.HIGH,
            reasoning="Repeated authentication activity increases the likelihood of unauthorized access without MFA.",
            recommended_priority=RiskAssessment.RecommendedPriority.URGENT,
        )

    def test_prompt_sent_to_provider_includes_the_real_gap_and_risk_data(self):
        # Same context-injection proof pattern as tests_analyst.py /
        # tests_writer.py / tests_readiness_advisor.py.
        fake_provider = _FakeProvider("This gap matters because MFA evidence is missing.")

        run_risk_narration(self.gap, provider=fake_provider)

        self.assertIn("13 failed logins from a single external IP within 20 minutes.", fake_provider.last_prompt)
        self.assertIn("Authentication control exposure", fake_provider.last_prompt)
        self.assertIn("Likelihood: 4/5", fake_provider.last_prompt)

    def test_pipeline_returns_display_ready_result_using_fake_provider(self):
        fake_response = (
            "This gap matters because 13 failed logins in 20 minutes went unnoticed. "
            "Enable MFA on this account and add an alert for repeated failed logins."
        )
        fake_provider = _FakeProvider(fake_response)

        result = run_risk_narration(self.gap, provider=fake_provider)

        self.assertEqual(result["gap_id"], self.gap.id)
        self.assertEqual(result["model"], "claude-sonnet-5-fake")
        self.assertEqual(result["narration"], fake_response)
        self.assertIn("generated_at", result)

    def test_pipeline_propagates_the_provider_missing_key_error(self):
        unconfigured_provider = AnthropicProvider(api_key=None)
        unconfigured_provider.api_key = None

        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            run_risk_narration(self.gap, provider=unconfigured_provider)


class RunRiskQuestionTestCase(TestCase):
    """Mirrors RunIncidentAnalysisTestCase's run_incident_question
    coverage in tests_analyst.py, scoped to GapFinding the way
    run_risk_narration is (see BuildRiskContextTestCase docstring above).
    """

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
            evidence="13 failed logins from a single external IP within 20 minutes.",
            priority=GapFinding.Priority.HIGH,
        )
        RiskAssessment.objects.create(
            organization=self.organization,
            incident=self.incident,
            gap=self.gap,
            risk_title="Authentication control exposure",
            likelihood=4,
            impact=4,
            risk_level=RiskAssessment.Level.HIGH,
            reasoning="Repeated authentication activity increases the likelihood of unauthorized access without MFA.",
            recommended_priority=RiskAssessment.RecommendedPriority.URGENT,
        )

    def test_prompt_sent_to_provider_includes_the_real_gap_risk_and_question(self):
        fake_provider = _FakeProvider("MFA is not mentioned anywhere in the evidence for this gap.")

        run_risk_question(
            self.gap, "Was MFA enabled for the affected account?", provider=fake_provider
        )

        self.assertIn("13 failed logins from a single external IP within 20 minutes.", fake_provider.last_prompt)
        self.assertIn("Authentication control exposure", fake_provider.last_prompt)
        self.assertIn("Likelihood: 4/5", fake_provider.last_prompt)
        self.assertIn("## Question\nWas MFA enabled for the affected account?", fake_provider.last_prompt)

    def test_pipeline_returns_display_ready_result_using_fake_provider(self):
        fake_provider = _FakeProvider(
            "The evidence does not include MFA configuration, so a confident answer isn't possible."
        )

        result = run_risk_question(
            self.gap, "Was MFA enabled for the affected account?", provider=fake_provider
        )

        self.assertEqual(result["gap_id"], self.gap.id)
        self.assertEqual(result["model"], "claude-sonnet-5-fake")
        self.assertEqual(result["question"], "Was MFA enabled for the affected account?")
        self.assertEqual(
            result["answer"],
            "The evidence does not include MFA configuration, so a confident answer isn't possible.",
        )
        self.assertIn("generated_at", result)

    def test_pipeline_propagates_the_provider_missing_key_error(self):
        unconfigured_provider = AnthropicProvider(api_key=None)
        unconfigured_provider.api_key = None

        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            run_risk_question(self.gap, "Any question", provider=unconfigured_provider)
