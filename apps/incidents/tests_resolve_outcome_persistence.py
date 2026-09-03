"""Coverage for persisting the Resolve stage's outcome
("Partially resolved" / "Still happening" / "Not sure" / "Resolved") to
workflow_state["resolve_outcome"] -- previously the value was read only
to pick a redirect target and then discarded, leaving no record for
later-stage AI context to read. Also proves it actually reaches
build_incident_context, the same feed-forward path
verification_results and workflow guidance already use.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.ai_core.services.analyst_context import build_incident_context
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization


class ResolveOutcomePersistenceTestCase(AuthedTestCase):
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
        self.resolve_url = reverse("incidents:workflow", args=[self.incident.id, "resolve"])
        self.respond_url = reverse("incidents:workflow", args=[self.incident.id, "respond"])
        self.close_url = reverse("incidents:workflow", args=[self.incident.id, "close"])

        # A non-"resolved" outcome explicitly regenerates respond's
        # guidance, and rendering resolve itself auto-generates on first
        # need -- mock it so nothing here makes a real (billed) provider
        # call. build_incident_context itself never calls a provider, so
        # the context-only tests below don't need this, but sharing one
        # setUp mock is simpler than special-casing which tests do.
        self.enterContext(
            patch(
                "apps.incidents.views.run_workflow_next_step",
                return_value={"model": "claude-sonnet-5", "next_step": "Check the relevant system."},
            )
        )

    def test_context_reports_no_outcome_recorded_yet_by_default(self):
        context = build_incident_context(self.incident)
        self.assertIn(
            "## Resolve Stage Outcome\nNo outcome has been recorded at the Resolve stage yet.",
            context,
        )

    def test_partial_outcome_persists_and_redirects_to_respond(self):
        response = self.client.post(self.resolve_url, {"outcome": "partial"})

        self.assertRedirects(response, self.respond_url)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.workflow_state["resolve_outcome"], "partial")

    def test_still_happening_outcome_persists(self):
        response = self.client.post(self.resolve_url, {"outcome": "happening"})

        self.assertRedirects(response, self.respond_url)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.workflow_state["resolve_outcome"], "happening")

    def test_unsure_outcome_persists(self):
        self.client.post(self.resolve_url, {"outcome": "unsure"})

        self.incident.refresh_from_db()
        self.assertEqual(self.incident.workflow_state["resolve_outcome"], "unsure")

    def test_resolved_outcome_persists_and_advances_to_close(self):
        response = self.client.post(self.resolve_url, {"outcome": "resolved"})

        self.assertRedirects(response, self.close_url)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.workflow_state["resolve_outcome"], "resolved")
        self.assertEqual(self.incident.status, IncidentGroup.Status.RESOLVED)

    def test_persisted_outcome_reaches_build_incident_context_with_a_readable_label(self):
        self.client.post(self.resolve_url, {"outcome": "happening"})
        self.incident.refresh_from_db()

        context = build_incident_context(self.incident)

        self.assertIn(
            "## Resolve Stage Outcome\nAnalyst-recorded outcome at the Resolve stage: Still happening.",
            context,
        )

    def test_invalid_outcome_is_not_persisted_and_stays_on_resolve(self):
        response = self.client.post(self.resolve_url, {"outcome": "not-a-real-choice"})

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/workflow.html")
        self.incident.refresh_from_db()
        self.assertNotIn("resolve_outcome", self.incident.workflow_state)
