"""Item 1 of the round-2 audit follow-up: the AegisFlow Assistant Q&A on
the investigation overview (incidents/investigation_overview.html, rendered
by incidents:detail) previously rendered its answers ONLY inside the
visually-hidden .af-legacy-contract block -- so asking a question spent a
real Claude call and showed the user nothing. The answer (and any error)
must now render in the visible Assistant card, the same as it does on
incidents/detail.html and the guided workflow.

Same no-network mocking pattern as tests_ask_view.py.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.incidents.models import AnalystQuestion, IncidentGroup
from apps.organizations.models import Organization


class InvestigationOverviewAssistantTestCase(AuthedTestCase):
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
        self.ask_url = reverse("incidents:ask", args=[self.incident.id])
        self.detail_url = reverse("incidents:detail", args=[self.incident.id])

    def _ask(self, question, answer):
        result = {
            "incident_id": self.incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant for this test",
            "question": question,
            "answer": answer,
            "generated_at": timezone.now(),
        }
        with patch(
            "apps.incidents.views.run_incident_question", return_value=result
        ) as mock_run:
            response = self.client.post(
                self.ask_url,
                {"question": question, "return_to": self.detail_url},
            )
        mock_run.assert_called_once_with(self.incident, question)
        return response

    def test_answer_renders_in_the_visible_assistant_card_not_only_the_legacy_block(self):
        question = "Was the source IP seen before on this account?"
        answer = "Yes -- the same source IP appears in one prior alert on this account."

        response = self._ask(question, answer)

        self.assertTemplateUsed(response, "incidents/investigation_overview.html")
        body = response.content.decode()
        # The answer must appear in real page content, before the
        # visually-hidden legacy contract block.
        self.assertIn(answer, body)
        self.assertIn('class="af-qa-thread"', body)
        self.assertLess(
            body.index(answer),
            body.index("af-legacy-contract"),
            "the answer must render in the visible Assistant card",
        )
        # It is inside the Assistant card specifically.
        assistant_start = body.index('id="assistant"')
        assistant_end = body.index("</article>", assistant_start)
        self.assertTrue(assistant_start < body.index(answer) < assistant_end)

    def test_thread_persists_visibly_on_a_plain_reload(self):
        self._ask("First question about the incident?", "First answer, visible.")
        self._ask("Second question about the incident?", "Second answer, visible.")

        with patch(
            "apps.incidents.views.run_incident_question",
            side_effect=AssertionError("must not call the model on a plain GET"),
        ):
            response = self.client.get(self.detail_url)

        self.assertTemplateUsed(response, "incidents/investigation_overview.html")
        body = response.content.decode()
        legacy_at = body.index("af-legacy-contract")
        for text in (
            "First question about the incident?",
            "First answer, visible.",
            "Second question about the incident?",
            "Second answer, visible.",
        ):
            self.assertIn(text, body)
            self.assertLess(body.index(text), legacy_at)
        self.assertLess(
            body.index("First answer, visible."),
            body.index("Second answer, visible."),
            "oldest Q&A first",
        )
        self.assertEqual(AnalystQuestion.objects.count(), 2)

    def test_friendly_error_renders_visibly_in_the_assistant_card(self):
        with patch(
            "apps.incidents.views.run_incident_question",
            side_effect=RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment."
            ),
        ):
            response = self.client.post(
                self.ask_url,
                {"question": "What happened here?", "return_to": self.detail_url},
            )

        self.assertTemplateUsed(response, "incidents/investigation_overview.html")
        body = response.content.decode()
        self.assertIn("API key not configured", body)
        self.assertLess(
            body.index("API key not configured"),
            body.index("af-legacy-contract"),
        )
        self.assertNotContains(response, "ANTHROPIC_API_KEY is not set")
        self.assertEqual(AnalystQuestion.objects.count(), 0)
