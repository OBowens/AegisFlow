"""Coverage for the Workflow Advisor agent
(apps/ai_core/modules/workflow_advisor.py) and its context feed-forward
through build_incident_context:

- WorkflowStepGuidance saved at earlier stages reaches
  build_incident_context's "## Workflow Guidance So Far" section, the
  same feed-forward mechanism verification_results already uses.
- The next-step and step-question prompts actually sent to the provider
  carry the "phrase as a check, never assert as fact" grounding rule --
  proven against the real prompt text, not just the preamble constants.
"""

from unittest.mock import patch

from django.test import TestCase

from apps.ai_core.modules.workflow_advisor import run_workflow_next_step, run_workflow_step_question
from apps.ai_core.services.analyst_context import build_incident_context
from apps.incidents.models import IncidentGroup, WorkflowStepGuidance
from apps.organizations.models import Organization


class _FakeProvider:
    """Stands in for a real AI provider -- returns a canned response
    instead of calling out to Claude, and records the exact prompt it
    was sent so tests can assert on it directly."""

    model = "claude-sonnet-5-fake"

    def __init__(self, response_text):
        self.response_text = response_text
        self.last_prompt = None

    def send_message(self, prompt, **kwargs):
        self.last_prompt = prompt
        return self.response_text


class WorkflowGuidanceFeedForwardTestCase(TestCase):
    """Later stages' context genuinely includes earlier stages'
    AI-generated guidance, mirroring how verification_results already
    feeds forward via _workflow_verification_section.
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
            title="High severity database activity on DB01",
            incident_type="database",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="DB01",
        )

    def test_context_reports_no_guidance_yet_when_nothing_saved(self):
        context = build_incident_context(self.incident)
        self.assertIn(
            "## Workflow Guidance So Far\nNo AI-recommended step guidance has been generated yet.",
            context,
        )

    def test_context_includes_earlier_stage_guidance_by_stage_label(self):
        WorkflowStepGuidance.objects.create(
            incident=self.incident,
            stage="understand",
            next_step_text="Check whether DB01's failure is still ongoing.",
            model_used="claude-sonnet-5",
        )

        context = build_incident_context(self.incident)

        self.assertIn("## Workflow Guidance So Far", context)
        self.assertIn("- Understand: Check whether DB01's failure is still ongoing.", context)

    def test_context_shows_only_the_latest_guidance_per_stage(self):
        WorkflowStepGuidance.objects.create(
            incident=self.incident, stage="verify", next_step_text="Old recommendation.",
        )
        WorkflowStepGuidance.objects.create(
            incident=self.incident, stage="verify", next_step_text="Updated recommendation.",
        )

        context = build_incident_context(self.incident)

        self.assertIn("- Verify: Updated recommendation.", context)
        self.assertNotIn("Old recommendation.", context)

    def test_generating_respond_guidance_sees_understand_and_verify_guidance_in_its_prompt(self):
        # This is the actual feed-forward path end to end: two earlier
        # stages already have saved guidance (as they would by the time
        # a real user reaches "respond"), and generating respond's own
        # guidance must genuinely carry that into the prompt sent to the
        # provider -- not just into build_incident_context in isolation.
        WorkflowStepGuidance.objects.create(
            incident=self.incident,
            stage="understand",
            next_step_text="Check whether the failure is still ongoing.",
        )
        WorkflowStepGuidance.objects.create(
            incident=self.incident,
            stage="verify",
            next_step_text="Confirm DB01's service status with the system owner.",
        )
        fake_provider = _FakeProvider("Restart the database service and monitor for recovery.")

        run_workflow_next_step(self.incident, "respond", provider=fake_provider)

        self.assertIn("## Workflow Guidance So Far", fake_provider.last_prompt)
        self.assertIn(
            "- Understand: Check whether the failure is still ongoing.", fake_provider.last_prompt
        )
        self.assertIn(
            "- Verify: Confirm DB01's service status with the system owner.", fake_provider.last_prompt
        )
        # "respond" itself has no saved guidance yet at generation time --
        # nothing after Verify should appear (there's nothing to appear).
        self.assertNotIn("- Resolve:", fake_provider.last_prompt)


class WorkflowNextStepPromptTestCase(TestCase):
    """The next-step prompt actually sent to the provider carries the
    "phrase as a check, never assert as fact" grounding rule, and stays
    stage-specific.
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
            title="High severity database activity on DB01",
            incident_type="database",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="DB01",
        )

    def test_prompt_carries_the_check_dont_assert_grounding_rule(self):
        fake_provider = _FakeProvider("Check whether DB01 is still reachable.")

        result = run_workflow_next_step(self.incident, "verify", provider=fake_provider)

        prompt = fake_provider.last_prompt
        self.assertIn(
            "Phrase your recommendation as an action to take or check", prompt
        )
        self.assertIn(
            "'Check whether...', 'Confirm...', 'Review...'", prompt
        )
        self.assertIn("never as an assertion of fact about what has happened", prompt)
        self.assertIn(
            "Be explicit about what verification has and has not actually confirmed", prompt
        )
        self.assertIn("Do not invent details that are not present in the context", prompt)
        # Stays scoped to the requested stage, not some other one.
        self.assertIn("## Current Stage\nVerify", prompt)

        self.assertEqual(result["stage"], "verify")
        self.assertEqual(result["next_step"], "Check whether DB01 is still reachable.")
        self.assertEqual(result["model"], "claude-sonnet-5-fake")

    def test_prompt_includes_real_incident_context_not_a_stub(self):
        fake_provider = _FakeProvider("Check whether DB01 is still reachable.")

        run_workflow_next_step(self.incident, "understand", provider=fake_provider)

        self.assertIn("## Incident Overview", fake_provider.last_prompt)
        self.assertIn("High severity database activity on DB01", fake_provider.last_prompt)
        self.assertIn("## Evidence", fake_provider.last_prompt)


class WorkflowStepQuestionPromptTestCase(TestCase):
    """The step-question prompt carries the same grounding rule, plus the
    current recommended step and the specific question -- scoped to the
    step, not the whole incident.
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
            title="High severity database activity on DB01",
            incident_type="database",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="DB01",
        )

    def test_prompt_carries_grounding_rule_and_current_step_and_question(self):
        fake_provider = _FakeProvider("Ping DB01 or check your monitoring tool.")

        result = run_workflow_step_question(
            self.incident,
            "verify",
            "Check whether DB01 is still reachable.",
            "How do I check reachability?",
            provider=fake_provider,
        )

        prompt = fake_provider.last_prompt
        self.assertIn(
            "Phrase your recommendation as an action to take or check", prompt
        )
        self.assertIn("never as an assertion of fact about what has happened", prompt)
        self.assertIn(
            "If the evidence in the context does not support a confident answer, "
            "say so plainly instead of guessing",
            prompt,
        )
        self.assertIn("## Current Stage\nVerify", prompt)
        self.assertIn(
            "## Current Recommended Step\nCheck whether DB01 is still reachable.", prompt
        )
        self.assertIn("## Question\nHow do I check reachability?", prompt)

        self.assertEqual(result["answer"], "Ping DB01 or check your monitoring tool.")
        self.assertEqual(result["question"], "How do I check reachability?")

    def test_pipeline_propagates_the_provider_missing_key_error(self):
        from apps.ai_core.providers.anthropic_provider import AnthropicProvider

        unconfigured_provider = AnthropicProvider(api_key=None)
        unconfigured_provider.api_key = None

        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            run_workflow_next_step(self.incident, "verify", provider=unconfigured_provider)
