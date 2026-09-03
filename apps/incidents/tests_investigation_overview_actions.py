"""Item 7 of the round-2 audit backlog: the investigation overview
(incidents/investigation_overview.html, rendered by incidents:detail)
must offer a real, visible "generate or view report" affordance and a
real, visible "compare with another incident" entry point -- previously
the only compare markup lived in the visually-hidden .af-legacy-contract
block, so there was no way for a user to actually reach it.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.incidents.models import IncidentComparison, IncidentGroup
from apps.organizations.models import Organization
from apps.reports.models import GeneratedReport


class InvestigationOverviewActionsTestCase(AuthedTestCase):
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
        )
        self.other_incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Suspicious database access from external IP",
            incident_type="unauthorized_access",
            severity=IncidentGroup.Severity.MEDIUM,
            status=IncidentGroup.Status.OPEN,
            affected_systems="DB-02",
        )
        self.detail_url = reverse("incidents:detail", args=[self.incident.id])
        self.compare_url = reverse("incidents:compare", args=[self.incident.id])

    # -- reports --------------------------------------------------------

    def test_reports_card_offers_generation_when_no_report_exists(self):
        response = self.client.get(self.detail_url)

        self.assertTemplateUsed(response, "incidents/investigation_overview.html")
        self.assertContains(response, 'id="incident-reports"')
        self.assertContains(response, "Generate technical report")
        self.assertContains(response, "Generate incident report")
        self.assertContains(response, "No technical report generated yet.")

    def test_reports_card_links_to_an_existing_generated_report(self):
        report = GeneratedReport.objects.create(
            organization=self.organization,
            incident=self.incident,
            report_type=GeneratedReport.ReportType.TECHNICAL,
            title="Technical Report",
            summary="Summary",
            body="Full technical write-up.",
        )

        response = self.client.get(self.detail_url)

        self.assertContains(response, reverse("reports:detail", args=[report.id]))
        self.assertContains(response, "View full report")
        self.assertNotContains(response, "No technical report generated yet.")

    def test_report_generation_form_returns_to_the_overview_not_legacy_detail(self):
        with patch(
            "apps.incidents.views.run_report_generation",
            return_value={
                "report_text": "Generated technical report body.",
                "summary": "Short summary.",
                "model": "claude-sonnet-5",
            },
        ):
            response = self.client.post(
                reverse("incidents:generate_technical_report", args=[self.incident.id]),
                {"return_to": self.detail_url},
            )

        self.assertTemplateUsed(response, "incidents/investigation_overview.html")
        # The freshly generated report is now linkable from the overview.
        report = GeneratedReport.objects.get(incident=self.incident)
        self.assertContains(response, reverse("reports:detail", args=[report.id]))
        self.assertContains(response, "Regenerate technical report")

    # -- compare -------------------------------------------------------

    def test_visible_compare_entry_point_exists_outside_the_legacy_block(self):
        response = self.client.get(self.detail_url)
        body = response.content.decode()

        self.assertIn('id="incident-compare"', body)
        # The visible card must come before the visually-hidden legacy
        # contract block, i.e. it is real page content.
        self.assertLess(
            body.index('id="incident-compare"'),
            body.index("af-legacy-contract"),
        )
        self.assertContains(response, self.compare_url)

    def test_prior_related_incident_gets_a_one_click_compare_button(self):
        # Give both incidents a shared source IP so the prior-activity
        # correlation links them.
        from apps.incidents.models import IncidentSourceIPLink

        IncidentSourceIPLink.objects.create(
            incident=self.incident,
            related_incident=self.other_incident,
            source_ip="203.0.113.9",
        )

        response = self.client.get(self.detail_url)

        self.assertContains(
            response, "Compare with Suspicious database access from external IP"
        )

    def test_comparison_result_renders_visibly_on_the_overview(self):
        fake_result = {
            "incident_id": self.incident.id,
            "other_incident_id": self.other_incident.id,
            "model": "claude-sonnet-5",
            "prompt": "irrelevant",
            "comparison": "These two incidents share an attacker IP and are likely related.",
            "generated_at": timezone.now(),
        }

        with patch(
            "apps.incidents.views.run_incident_comparison", return_value=fake_result
        ):
            response = self.client.post(
                self.compare_url,
                {
                    "other_incident_id": str(self.other_incident.id),
                    "return_to": self.detail_url,
                },
            )

        self.assertTemplateUsed(response, "incidents/investigation_overview.html")
        body = response.content.decode()
        self.assertIn("likely related", body)
        # Rendered inside the visible compare card, not only the hidden
        # legacy contract block.
        self.assertIn("af-compare-thread", body)
        self.assertEqual(IncidentComparison.objects.count(), 1)
