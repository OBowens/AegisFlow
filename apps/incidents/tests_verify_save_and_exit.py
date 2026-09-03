"""Coverage for the Verify stage's "Save & Exit" control: it used to be
a plain <a> sitting inside the verification <form>, so clicking it
discarded any selected-but-unsubmitted radio answers. It is now a real
submit button (workflow_action=save_and_exit, formnovalidate so a
partial set of answers doesn't get blocked by the per-item `required`
attribute) that saves whatever was answered before navigating away.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization


class VerifySaveAndExitTestCase(AuthedTestCase):
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
        self.queue_url = f"{reverse('incidents:index')}?tab=queue"

        # Every verify POST (save_and_exit included) and every render of
        # the verify stage regenerates/auto-generates its guidance --
        # mock it so nothing here makes a real (billed) provider call.
        self.enterContext(
            patch(
                "apps.incidents.views.run_workflow_next_step",
                return_value={"model": "claude-sonnet-5", "next_step": "Check the relevant system."},
            )
        )

    def test_save_and_exit_persists_partial_answers_and_redirects_to_queue(self):
        # Only 2 of the 4 checks answered -- previously the old <a> would
        # have discarded these entirely on the way out.
        response = self.client.post(
            self.verify_url,
            {
                "workflow_action": "save_and_exit",
                "verification_reachable": "confirmed",
                "verification_service_health": "not_confirmed",
                # expected_change and scope intentionally left unanswered
            },
        )

        self.assertRedirects(response, self.queue_url)
        self.incident.refresh_from_db()
        self.assertEqual(
            self.incident.workflow_state["verification_results"],
            {"reachable": "confirmed", "service_health": "not_confirmed"},
        )

    def test_save_and_exit_with_zero_answers_still_navigates_away_without_erroring(self):
        response = self.client.post(self.verify_url, {"workflow_action": "save_and_exit"})

        self.assertRedirects(response, self.queue_url)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.workflow_state["verification_results"], {})

    def test_answers_saved_by_save_and_exit_are_still_there_on_a_later_visit(self):
        self.client.post(
            self.verify_url,
            {"workflow_action": "save_and_exit", "verification_reachable": "confirmed"},
        )

        persisted = self.client.get(self.verify_url)
        self.assertContains(persisted, 'value="confirmed" checked')

    def test_continue_action_still_requires_all_items_answered_to_advance(self):
        # Sanity check that "continue" behavior (unlike save_and_exit)
        # wasn't loosened by this fix -- a partial submission via
        # "continue" still stays on verify rather than advancing.
        response = self.client.post(
            self.verify_url,
            {"workflow_action": "continue", "verification_reachable": "confirmed"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/workflow.html")
        respond_url = reverse("incidents:workflow", args=[self.incident.id, "respond"])
        self.assertNotEqual(response.request["PATH_INFO"], respond_url)

    def test_save_and_exit_button_is_present_with_formnovalidate(self):
        response = self.client.get(self.verify_url)
        self.assertContains(
            response,
            '<button type="submit" name="workflow_action" value="save_and_exit" formnovalidate',
        )
