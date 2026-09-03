"""Item 4 of the round-2 audit follow-up: the hero toolbar button on
incidents/detail.html was labelled "Generate Report" but only ever linked
to a report view/list (reports:detail / reports:index) -- it generated
nothing. The real generation forms live further down the same page
("Generate Technical Report" / "Generate Incident Report"). The hero
button is now labelled honestly for what it does: view.
"""

from unittest.mock import patch

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.reports.models import GeneratedReport


class DetailReportButtonTestCase(AuthedTestCase):
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
        # incidents:detail GET renders the overview; detail.html is the
        # inline-render target when one of its own action forms is posted
        # without a return_to. A mocked analyze call gets us there.
        self.analyze_url = reverse("incidents:analyze", args=[self.incident.id])

    def _render_detail_html(self):
        with patch(
            "apps.incidents.views.run_incident_analysis",
            return_value={
                "incident_id": self.incident.id,
                "model": "claude-sonnet-5",
                "prompt": "irrelevant",
                "analysis": "Assessment text.",
                "generated_at": timezone.now(),
            },
        ):
            response = self.client.post(self.analyze_url)
        self.assertTemplateUsed(response, "incidents/detail.html")
        return response

    def test_button_says_view_reports_when_no_report_exists(self):
        response = self._render_detail_html()

        self.assertNotContains(response, "<span>Generate Report</span>")
        self.assertContains(response, "<span>View Reports</span>")
        self.assertContains(response, reverse("reports:index"))
        # The real generation actions are still present, unchanged.
        self.assertContains(response, "Generate Technical Report")
        self.assertContains(response, "Generate Incident Report")

    def test_button_says_view_report_and_links_to_it_when_one_exists(self):
        report = GeneratedReport.objects.create(
            organization=self.organization,
            incident=self.incident,
            report_type=GeneratedReport.ReportType.TECHNICAL,
            title="Technical Report",
            summary="Summary",
            body="Full technical write-up.",
        )

        response = self._render_detail_html()

        self.assertNotContains(response, "<span>Generate Report</span>")
        self.assertContains(response, "<span>View Report</span>")
        self.assertContains(response, reverse("reports:detail", args=[report.id]))
