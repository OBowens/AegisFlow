"""Coverage for the shared return-target mechanism
(apps.incidents.views._resolve_incident_return_target /
_render_incident_action_result) that all six incident-scoped AI action
views (analyze, ask, compare, explain, generate_report,
generate_playbook) now go through instead of each unconditionally
rendering incidents/detail.html regardless of caller.

Same open-redirect-guard spirit as
apps/playbooks/views.py::_safe_playbook_url: return_to is checked
against an exact allowlist of this incident's own real pages (its
Incident Detail overview, or any of its own workflow stages) -- never
followed blindly.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.ai_core.models import AliasMapping
from apps.incidents.models import AnalystQuestion, IncidentComparison, IncidentGroup
from apps.organizations.models import Organization


class IncidentActionReturnTargetTestCase(AuthedTestCase):
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
        self.ask_url = reverse("incidents:ask", args=[self.incident.id])
        self.overview_url = reverse("incidents:detail", args=[self.incident.id])
        self.verify_url = reverse("incidents:workflow", args=[self.incident.id, "verify"])
        self.understand_url = reverse("incidents:workflow", args=[self.incident.id, "understand"])

        # Landing on a workflow.html stage with no saved guidance yet
        # triggers guidance auto-generation (see _render_workflow_stage) --
        # mock it everywhere in this file so nothing here ever makes a
        # real (and, with a real ANTHROPIC_API_KEY configured, billed)
        # call. Individual tests don't care about guidance content, only
        # about which template/stage the *_result being tested lands on.
        self.enterContext(
            patch(
                "apps.incidents.views.run_workflow_next_step",
                return_value={"model": "claude-sonnet-5", "next_step": "Check the relevant system."},
            )
        )

    # -- default / backward-compatible behavior --------------------------

    def test_no_return_to_still_renders_detail_html_unchanged(self):
        answer = {"model": "claude-sonnet-5", "question": "What happened?", "answer": "Brute force."}
        with patch("apps.incidents.views.run_incident_question", return_value=answer):
            response = self.client.post(self.ask_url, {"question": "What happened?"})

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/detail.html")
        self.assertTemplateNotUsed(response, "incidents/investigation_overview.html")
        self.assertTemplateNotUsed(response, "incidents/workflow.html")

    # -- returns to Incident Detail's overview page -----------------------

    def test_ask_with_return_to_overview_renders_investigation_overview(self):
        answer = {"model": "claude-sonnet-5", "question": "What happened?", "answer": "Brute force."}
        with patch("apps.incidents.views.run_incident_question", return_value=answer) as mock_run:
            response = self.client.post(
                self.ask_url, {"question": "What happened?", "return_to": self.overview_url}
            )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/investigation_overview.html")
        self.assertTemplateNotUsed(response, "incidents/detail.html")
        # The answer must actually be visible on the page it landed on,
        # not just correctly routed but silently invisible.
        self.assertContains(response, "What happened?")
        self.assertContains(response, "Brute force.")
        mock_run.assert_called_once_with(self.incident, "What happened?")
        self.assertEqual(AnalystQuestion.objects.count(), 1)

    # -- returns to a workflow.html stage ----------------------------------

    def test_explain_plain_language_with_return_to_workflow_renders_that_stage(self):
        explanation = {
            "model": "claude-sonnet-5",
            "explanation": "In plain terms: someone tried many passwords on DB01.",
        }
        explain_url = reverse("incidents:explain_plain_language", args=[self.incident.id])
        with patch("apps.incidents.views.run_incident_explanation", return_value=explanation):
            response = self.client.post(
                explain_url, {"return_to": self.understand_url}
            )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/workflow.html")
        self.assertTemplateNotUsed(response, "incidents/detail.html")
        # AI prose renders through {% alias_prose %}: the affected system
        # is aliased inside the sentence, the rest is intact. (DB01 still
        # appears in the page <title> -- plain-text surfaces are a later part.)
        host_alias = AliasMapping.objects.get(
            organization=self.organization, identifier_type="HOST", real_value="DB01"
        ).display_alias
        self.assertContains(
            response, f'In plain terms: someone tried many passwords on '
            f'<span class="af-alias">{host_alias}</span>.'
        )

    def test_compare_with_return_to_workflow_renders_that_stage_not_detail(self):
        other = IncidentGroup.objects.create(
            organization=self.organization,
            title="Suspicious login on WEB01",
            incident_type="unauthorized_access",
            severity=IncidentGroup.Severity.MEDIUM,
            affected_systems="WEB01",
        )
        compare_url = reverse("incidents:compare", args=[self.incident.id])
        comparison = {"model": "claude-sonnet-5", "comparison": "Both target the same source IP."}
        with patch("apps.incidents.views.run_incident_comparison", return_value=comparison):
            response = self.client.post(
                compare_url,
                {"other_incident_id": str(other.id), "return_to": self.verify_url},
            )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/workflow.html")
        self.assertTemplateNotUsed(response, "incidents/detail.html")
        self.assertEqual(IncidentComparison.objects.count(), 1)

    def test_compare_validation_error_also_honors_return_to(self):
        # The early-return validation-failure branch in incident_compare
        # must go through the same return-target logic as the success
        # path, not bypass it back to detail.html. (workflow.html has no
        # dedicated compare-error display slot -- comparison isn't part
        # of the guided workflow's own UI -- so this only proves routing,
        # not that the message is shown; test_ask_with_return_to_overview
        # above already proves a result/error is genuinely visible when
        # the calling page does have a slot for it.)
        compare_url = reverse("incidents:compare", args=[self.incident.id])
        response = self.client.post(
            compare_url, {"other_incident_id": "not-a-number", "return_to": self.verify_url}
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/workflow.html")
        self.assertTemplateNotUsed(response, "incidents/detail.html")

    def test_analyze_generate_playbook_and_generate_report_all_honor_return_to(self):
        # Proves the mechanism is uniform across the remaining three views
        # too, not just ask/explain/compare -- all six go through the same
        # shared helper.
        analyze_url = reverse("incidents:analyze", args=[self.incident.id])
        with patch(
            "apps.incidents.views.run_incident_analysis",
            return_value={"model": "claude-sonnet-5", "analysis": "Looks like a brute-force attempt."},
        ):
            response = self.client.post(analyze_url, {"return_to": self.verify_url})
        self.assertTemplateUsed(response, "incidents/workflow.html")

        playbook_url = reverse("incidents:generate_playbook", args=[self.incident.id])
        with patch(
            "apps.incidents.views.run_playbook_generation",
            return_value={"model": "claude-sonnet-5", "steps": [{"action": "Reset credentials."}]},
        ):
            response = self.client.post(playbook_url, {"return_to": self.understand_url})
        self.assertTemplateUsed(response, "incidents/workflow.html")

        report_url = reverse("incidents:generate_technical_report", args=[self.incident.id])
        with patch(
            "apps.incidents.views.run_report_generation",
            return_value={"model": "claude-sonnet-5", "summary": "Summary.", "report_text": "Full report."},
        ):
            response = self.client.post(report_url, {"return_to": self.overview_url})
        self.assertTemplateUsed(response, "incidents/investigation_overview.html")

    # -- open-redirect guard ------------------------------------------------

    def test_foreign_url_in_return_to_falls_back_to_detail_html(self):
        answer = {"model": "claude-sonnet-5", "question": "What happened?", "answer": "Brute force."}
        with patch("apps.incidents.views.run_incident_question", return_value=answer):
            response = self.client.post(
                self.ask_url,
                {"question": "What happened?", "return_to": "https://evil.example.com/steal-session"},
            )

        self.assertTemplateUsed(response, "incidents/detail.html")
        self.assertTemplateNotUsed(response, "incidents/investigation_overview.html")

    def test_another_incidents_workflow_url_in_return_to_falls_back_to_detail_html(self):
        # An attacker-controlled return_to pointing at a DIFFERENT
        # incident's real workflow URL must not be honored -- the
        # allowlist is scoped to *this* incident specifically.
        other = IncidentGroup.objects.create(
            organization=self.organization,
            title="Unrelated incident",
            incident_type="other",
            severity=IncidentGroup.Severity.LOW,
        )
        other_workflow_url = reverse("incidents:workflow", args=[other.id, "verify"])
        answer = {"model": "claude-sonnet-5", "question": "What happened?", "answer": "Brute force."}
        with patch("apps.incidents.views.run_incident_question", return_value=answer):
            response = self.client.post(
                self.ask_url, {"question": "What happened?", "return_to": other_workflow_url}
            )

        self.assertTemplateUsed(response, "incidents/detail.html")
        self.assertTemplateNotUsed(response, "incidents/workflow.html")
