"""Item 2 of the round-2 audit follow-up: the Response Playbook toolbar's
"Regenerate Playbook" button used to be an <a href> that just re-GET the
same page (?incident=<id>) -- it generated nothing. It now posts to the
real incidents:generate_playbook endpoint and returns to the playbook
page with a flash message.

Same no-network mocking pattern as
apps/incidents/tests_generate_playbook_view.py.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.playbooks.models import PlaybookStep, ResponsePlaybook


class RegeneratePlaybookToolbarTestCase(AuthedTestCase):
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
        self.index_url = reverse("playbooks:index")
        self.scoped_url = f"{self.index_url}?incident={self.incident.id}"
        self.generate_url = reverse("incidents:generate_playbook", args=[self.incident.id])

    def test_toolbar_renders_a_post_form_to_the_real_endpoint(self):
        response = self.client.get(self.scoped_url)

        self.assertContains(response, f'action="{self.generate_url}"')
        self.assertContains(response, f'value="{self.scoped_url}"')
        self.assertNotContains(response, "Regenerate Playbook")

    def test_no_incident_means_no_ai_button(self):
        IncidentGroup.objects.all().delete()
        ResponsePlaybook.objects.all().delete()

        response = self.client.get(self.index_url)

        self.assertNotContains(response, self.generate_url)
        self.assertNotContains(response, "Add AI Steps")
        self.assertNotContains(response, "Generate AI Playbook</span>")

    def test_clicking_it_generates_steps_and_returns_to_the_playbook_page(self):
        fake_result = {
            "incident_id": self.incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "steps": [
                {"action": "Review authentication logs.", "requires_approval": False},
                {"action": "Disable the compromised account.", "requires_approval": True},
            ],
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.incidents.views.run_playbook_generation", return_value=fake_result
        ) as mock_run:
            response = self.client.post(
                self.generate_url, {"return_to": self.scoped_url}, follow=True
            )

        mock_run.assert_called_once_with(self.incident)
        # Landed back on the Response Playbook page, not incident detail.
        self.assertTemplateUsed(response, "playbooks/index.html")
        self.assertContains(response, "Added AI-generated steps")
        self.assertContains(response, "Review authentication logs.")

        ai_steps = PlaybookStep.objects.filter(source=PlaybookStep.Source.AI_GENERATED)
        self.assertEqual(ai_steps.count(), 2)

    def test_failed_generation_returns_with_an_error_message(self):
        with patch(
            "apps.incidents.views.run_playbook_generation",
            side_effect=RuntimeError("ANTHROPIC_API_KEY is not set."),
        ):
            response = self.client.post(
                self.generate_url, {"return_to": self.scoped_url}, follow=True
            )

        self.assertTemplateUsed(response, "playbooks/index.html")
        self.assertContains(response, "API key not configured")
        self.assertEqual(PlaybookStep.objects.filter(source=PlaybookStep.Source.AI_GENERATED).count(), 0)

    def test_return_to_is_restricted_to_the_playbook_page(self):
        # An attacker-supplied return_to is ignored; the view falls back to
        # its normal inline render (incident detail) rather than redirecting
        # anywhere it was told to.
        fake_result = {
            "incident_id": self.incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "steps": [{"action": "Notify the owner.", "requires_approval": False}],
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.incidents.views.run_playbook_generation", return_value=fake_result
        ):
            response = self.client.post(
                self.generate_url, {"return_to": "https://evil.example/steal"}
            )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/detail.html")
