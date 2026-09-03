"""Coverage for the AI-guidance layer on the guided
Understand/Verify/Respond/Resolve workflow (WorkflowStepGuidance,
WorkflowStepQuestion): a stage's "do this next" recommendation is
generated once and persists across reloads, a "how do I do this"
question is scoped to the current step and always renders back on
workflow.html at the same stage (never bounces to detail.html, unlike
the whole-incident incident_ask endpoint), and later stages regenerate
their guidance when the real state-mutating POST handlers run.

Same mocking pattern as tests_workflow_guidance.py and
tests_ask_view.py: mocked run_workflow_next_step/run_workflow_step_question
stand in for real Claude calls -- no network, no API key, nothing spent.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.audit.models import AIRun
from apps.incidents.models import IncidentGroup, WorkflowStepGuidance, WorkflowStepQuestion
from apps.organizations.models import Organization


class WorkflowStepGuidanceGenerationTestCase(AuthedTestCase):
    """Generation trigger: NEVER on a plain GET (that was a silent
    15-60s synchronous Claude call on page load). Only an explicit POST
    -- the "Generate AI guidance" button, or the verify/respond/resolve
    state-mutating handlers -- generates. Once a row exists a reload
    reuses it verbatim.
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
        self.understand_url = reverse("incidents:workflow", args=[self.incident.id, "understand"])

    def _generate(self, url, next_step):
        with patch(
            "apps.incidents.views.run_workflow_next_step",
            return_value={"model": "claude-sonnet-5", "next_step": next_step},
        ) as mock_next_step:
            response = self.client.post(
                url, {"workflow_action": "regenerate_guidance"}, follow=True
            )
        return response, mock_next_step

    def test_first_visit_does_not_call_the_ai_and_offers_a_generate_button(self):
        with patch(
            "apps.incidents.views.run_workflow_next_step",
            side_effect=AssertionError("a plain GET must never call the AI"),
        ) as mock_next_step:
            response = self.client.get(self.understand_url)

        self.assertEqual(response.status_code, 200)
        mock_next_step.assert_not_called()
        self.assertEqual(WorkflowStepGuidance.objects.count(), 0)
        self.assertEqual(AIRun.objects.filter(ai_module="workflow_advisor").count(), 0)
        # The user is offered an explicit button instead of a silent wait.
        self.assertContains(response, "Generate AI guidance")

    def test_generate_button_generates_and_persists_guidance(self):
        response, mock_next_step = self._generate(
            self.understand_url, "Check whether DB01 is still reachable."
        )

        self.assertEqual(response.status_code, 200)
        mock_next_step.assert_called_once_with(self.incident, "understand")
        self.assertContains(response, "Check whether DB01 is still reachable.")

        self.assertEqual(WorkflowStepGuidance.objects.count(), 1)
        guidance = WorkflowStepGuidance.objects.get()
        self.assertEqual(guidance.incident, self.incident)
        self.assertEqual(guidance.stage, "understand")
        self.assertEqual(guidance.next_step_text, "Check whether DB01 is still reachable.")
        self.assertEqual(guidance.model_used, "claude-sonnet-5")

        ai_run = AIRun.objects.get(ai_module="workflow_advisor")
        self.assertEqual(ai_run.status, AIRun.Status.SUCCESS)
        self.assertEqual(ai_run.output_id, str(guidance.id))

    def test_reload_reuses_saved_guidance_without_regenerating(self):
        first_response, _ = self._generate(
            self.understand_url, "Check whether DB01 is still reachable."
        )
        self.assertContains(first_response, "Check whether DB01 is still reachable.")
        self.assertEqual(WorkflowStepGuidance.objects.count(), 1)

        # A second, third, ... plain GET must NOT call the AI again -- the
        # existing row is reused verbatim.
        with patch(
            "apps.incidents.views.run_workflow_next_step",
            side_effect=AssertionError("must not regenerate guidance on a plain reload"),
        ) as mock_next_step_on_reload:
            second_response = self.client.get(self.understand_url)
            third_response = self.client.get(self.understand_url)

        mock_next_step_on_reload.assert_not_called()
        self.assertEqual(second_response.status_code, 200)
        self.assertEqual(third_response.status_code, 200)
        self.assertContains(second_response, "Check whether DB01 is still reachable.")
        self.assertContains(third_response, "Check whether DB01 is still reachable.")

        # Still exactly one saved row and one AIRun -- survives multiple
        # reloads without duplicating anything.
        self.assertEqual(WorkflowStepGuidance.objects.count(), 1)
        self.assertEqual(AIRun.objects.filter(ai_module="workflow_advisor").count(), 1)

    def test_manual_regenerate_action_creates_a_new_row_and_calls_the_ai_again(self):
        self._generate(self.understand_url, "First recommendation.")
        self.assertEqual(WorkflowStepGuidance.objects.count(), 1)

        response, mock_next_step = self._generate(self.understand_url, "Updated recommendation.")

        mock_next_step.assert_called_once_with(self.incident, "understand")
        self.assertContains(response, "Updated recommendation.")
        self.assertEqual(WorkflowStepGuidance.objects.count(), 2)
        # "Latest wins" -- the newest row is the one shown.
        latest = WorkflowStepGuidance.objects.filter(incident=self.incident, stage="understand").first()
        self.assertEqual(latest.next_step_text, "Updated recommendation.")

    def test_missing_api_key_shows_friendly_message_not_a_500(self):
        with patch(
            "apps.incidents.views.run_workflow_next_step",
            side_effect=RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment "
                "before calling AnthropicProvider.send_message()."
            ),
        ):
            response = self.client.post(
                self.understand_url, {"workflow_action": "regenerate_guidance"}, follow=True
            )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "AI analysis isn&#x27;t available yet")
        self.assertEqual(WorkflowStepGuidance.objects.count(), 0)
        ai_run = AIRun.objects.get(ai_module="workflow_advisor")
        self.assertEqual(ai_run.status, AIRun.Status.FAILED)

    def test_resubmitting_verify_regenerates_verify_guidance_but_not_other_stages(self):
        verify_url = reverse("incidents:workflow", args=[self.incident.id, "verify"])
        answers = {
            "workflow_action": "continue",
            "verification_reachable": "not_sure",
            "verification_service_health": "not_sure",
            "verification_expected_change": "not_sure",
            "verification_scope": "not_sure",
        }

        self._generate(verify_url, "First verify recommendation.")
        first_guidance = WorkflowStepGuidance.objects.get()
        self.assertEqual(first_guidance.next_step_text, "First verify recommendation.")

        # Resubmitting verify's own form (not all confirmed, so it stays
        # on verify) must regenerate verify's guidance to reflect the
        # newly saved answers.
        with patch(
            "apps.incidents.views.run_workflow_next_step",
            return_value={"model": "claude-sonnet-5", "next_step": "Updated verify recommendation."},
        ) as mock_next_step:
            self.client.post(verify_url, answers)

        mock_next_step.assert_called_once_with(self.incident, "verify")
        self.assertEqual(WorkflowStepGuidance.objects.filter(stage="verify").count(), 2)
        latest_verify = WorkflowStepGuidance.objects.filter(incident=self.incident, stage="verify").first()
        self.assertEqual(latest_verify.next_step_text, "Updated verify recommendation.")
        # respond's guidance was never touched by this -- no row exists
        # for it yet since it hasn't been entered.
        self.assertFalse(WorkflowStepGuidance.objects.filter(stage="respond").exists())


class WorkflowStepAskViewTestCase(AuthedTestCase):
    """The "how do I do this" endpoint (incidents:workflow_ask): must
    always render workflow.html back at the SAME stage it was asked
    from, never bounce to detail.html the way the whole-incident
    incident_ask endpoint does.
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
        self.verify_url = reverse("incidents:workflow", args=[self.incident.id, "verify"])
        self.verify_ask_url = reverse("incidents:workflow_ask", args=[self.incident.id, "verify"])
        self.detail_url = reverse("incidents:detail", args=[self.incident.id])

        # Seed guidance for the verify stage so the question is scoped to
        # a real recommended step, same as it would be in normal use.
        # Guidance is no longer auto-generated on GET -- generate it via
        # the explicit "Generate AI guidance" POST.
        with patch(
            "apps.incidents.views.run_workflow_next_step",
            return_value={"model": "claude-sonnet-5", "next_step": "Check whether DB01 is reachable."},
        ):
            self.client.post(self.verify_url, {"workflow_action": "regenerate_guidance"})

    def test_question_renders_workflow_html_at_the_same_stage_not_detail_html(self):
        with patch(
            "apps.incidents.views.run_workflow_step_question",
            return_value={
                "model": "claude-sonnet-5",
                "question": "How do I check reachability?",
                "answer": "Ping DB01 or check your monitoring tool for its current status.",
            },
        ) as mock_qa:
            response = self.client.post(self.verify_ask_url, {"question": "How do I check reachability?"})

        self.assertEqual(response.status_code, 200)
        # The response must be the workflow page for the verify stage --
        # not a redirect, and not detail.html's markup.
        self.assertTemplateUsed(response, "incidents/workflow.html")
        self.assertTemplateNotUsed(response, "incidents/detail.html")
        self.assertContains(response, "Verify the incident")
        self.assertContains(response, "How do I check reachability?")
        self.assertContains(response, "Ping DB01 or check your monitoring tool for its current status.")

        mock_qa.assert_called_once_with(
            self.incident, "verify", "Check whether DB01 is reachable.", "How do I check reachability?"
        )

        self.assertEqual(WorkflowStepQuestion.objects.count(), 1)
        saved = WorkflowStepQuestion.objects.get()
        self.assertEqual(saved.stage, "verify")
        self.assertEqual(saved.question_text, "How do I check reachability?")

        ai_run = AIRun.objects.get(ai_module="workflow_advisor_qa")
        self.assertEqual(ai_run.status, AIRun.Status.SUCCESS)

    def test_get_request_redirects_back_to_the_same_stage_without_asking(self):
        with patch(
            "apps.incidents.views.run_workflow_step_question",
            side_effect=AssertionError("must not be called for a GET"),
        ) as mock_qa:
            response = self.client.get(self.verify_ask_url)

        self.assertRedirects(response, self.verify_url)
        mock_qa.assert_not_called()

    def test_blank_question_redirects_back_without_calling_the_ai(self):
        with patch(
            "apps.incidents.views.run_workflow_step_question",
            side_effect=AssertionError("must not be called for a blank question"),
        ) as mock_qa:
            response = self.client.post(self.verify_ask_url, {"question": "   "})

        self.assertRedirects(response, self.verify_url)
        mock_qa.assert_not_called()

    def test_missing_api_key_renders_workflow_html_with_a_friendly_error(self):
        with patch(
            "apps.incidents.views.run_workflow_step_question",
            side_effect=RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment "
                "before calling AnthropicProvider.send_message()."
            ),
        ):
            response = self.client.post(self.verify_ask_url, {"question": "How do I check this?"})

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/workflow.html")
        self.assertContains(response, "AI analysis isn&#x27;t available yet")
        self.assertEqual(WorkflowStepQuestion.objects.count(), 0)

    def test_close_stage_is_not_a_guidance_stage_and_redirects_to_investigate(self):
        close_ask_url = reverse("incidents:workflow_ask", args=[self.incident.id, "close"])
        response = self.client.post(close_ask_url, {"question": "Anything?"})
        self.assertRedirects(response, reverse("incidents:investigate", args=[self.incident.id]))
