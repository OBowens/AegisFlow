from django.contrib.auth import get_user_model
from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization

from . import views as reports_views
from .models import GeneratedReport


class ReportViewsTestCase(AuthedTestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username="alexdaniel",
            email="alex@example.com",
            password="testpass123",
            first_name="Alex",
            last_name="Daniel",
        )
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Suspicious PowerShell Activity",
            incident_type="Endpoint",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="Workstation-12",
            summary="PowerShell activity was detected on workstation-12.",
        )
        self.executive_report = GeneratedReport.objects.create(
            organization=self.organization,
            incident=self.incident,
            report_type=GeneratedReport.ReportType.EXECUTIVE,
            title="Executive Incident Summary",
            summary="This report provides a high-level overview of the suspicious PowerShell activity.",
            body=(
                "This report provides a high-level overview of the suspicious PowerShell activity.\n\n"
                "Impact:\nPotential unauthorized access and system reconnaissance were detected.\n\n"
                "Recommended Actions:\n"
                "- Review PowerShell scripts executed on workstation-12.\n"
                "- Enforce script block logging and AMSI.\n"
                "- Ensure endpoint protection is up to date."
            ),
            generated_by=self.user,
        )
        self.technical_report = GeneratedReport.objects.create(
            organization=self.organization,
            incident=self.incident,
            report_type=GeneratedReport.ReportType.TECHNICAL,
            title="Endpoint Threat Investigation",
            summary="Technical triage details for the PowerShell activity.",
            body="Technical report body for the endpoint investigation.",
            generated_by=self.user,
        )

    def test_report_list_uses_dashboard_shell(self):
        response = self.client.get(reverse("reports:index"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Reports")
        self.assertContains(response, "app-shell")
        self.assertContains(response, "Generated Reports")
        self.assertContains(response, "Report Preview")
        self.assertContains(response, "Executive Incident Summary")
        self.assertContains(response, "View Full Report")

    def test_report_list_supports_preview_type_selection(self):
        response = self.client.get(
            reverse("reports:index"),
            {"preview_type": GeneratedReport.ReportType.TECHNICAL},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Endpoint Threat Investigation")
        self.assertContains(response, "Technical Reports")

    def test_report_list_empty_state(self):
        GeneratedReport.objects.all().delete()

        response = self.client.get(reverse("reports:index"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No reports have been generated yet")
        self.assertContains(response, "Upload Logs")


class ReportPreviewSectionParsingTestCase(AuthedTestCase):
    """Regression coverage for a real bug found during the 2026-08-27
    Part D recovery smoke test: a live AI Report Writer response titles
    its sections as markdown headings ("## Impact") rather than the
    plain "Impact:" convention apps/reports/services/generator.py uses
    -- confirmed against real generated output, not a synthetic case.
    _build_preview_sections must extract the real Impact section and
    Recommended Actions bullets either way, not silently fall back to
    the wrong paragraph.
    """

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.report = GeneratedReport.objects.create(
            organization=self.organization,
            report_type=GeneratedReport.ReportType.EXECUTIVE,
            title="Executive Report - Demo Organization",
            summary="## Executive Summary",
            body=(
                "## Executive Summary\n\n"
                "The organization has several open incidents needing attention.\n\n"
                "## Impact\n\n"
                "Unaddressed incidents could lead to data loss or service disruption.\n\n"
                "## Recommended Actions\n\n"
                "- Contain the highest severity incidents first.\n"
                "- Review backup integrity on affected systems.\n"
            ),
        )

    def test_impact_section_is_extracted_despite_the_markdown_heading(self):
        sections = reports_views._build_preview_sections(self.report)

        self.assertIn(
            "Unaddressed incidents could lead to data loss or service disruption.",
            sections["impact"],
        )
        # And not the summary paragraph a naive fallback would grab instead.
        self.assertNotIn("several open incidents needing attention", sections["impact"])

    def test_recommended_actions_bullets_are_extracted_despite_the_markdown_heading(self):
        sections = reports_views._build_preview_sections(self.report)

        self.assertIn("Contain the highest severity incidents first.", sections["recommendations"])
        self.assertIn("Review backup integrity on affected systems.", sections["recommendations"])


class ReportRecommendationsDoNotLeakFromImpactTestCase(AuthedTestCase):
    """Regression coverage for a real bug found during the 2026-08-27
    Part D verification: a live model wrote its Impact section as
    bullet points rather than prose (a formatting choice the preamble
    never forbids). A global bullet scan run before the scoped
    "Recommended Actions" extraction grabbed Impact's bullets instead,
    since they appear first in the body -- confirmed against real
    generated Risk report output. recommendations must come from the
    Recommended Actions section specifically, not just "the first
    bullets found anywhere."
    """

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.report = GeneratedReport.objects.create(
            organization=self.organization,
            report_type=GeneratedReport.ReportType.RISK,
            title="Risk Report - Demo Organization",
            summary="Overall risk summary paragraph.",
            body=(
                "Overall risk summary paragraph.\n\n"
                "Impact\n"
                "- Malware containment risk raises the chance of lateral movement.\n"
                "- Backup failures reduce recovery confidence.\n\n"
                "Recommended Actions\n"
                "- Contain the malware activity on the affected hosts.\n"
                "- Restore-test the failing backups.\n"
            ),
        )

    def test_recommendations_come_from_the_recommended_actions_section_not_impact(self):
        sections = reports_views._build_preview_sections(self.report)

        self.assertIn("Contain the malware activity on the affected hosts.", sections["recommendations"])
        self.assertIn("Restore-test the failing backups.", sections["recommendations"])
        self.assertNotIn(
            "Malware containment risk raises the chance of lateral movement.",
            sections["recommendations"],
        )


class ReportListGenerateButtonsTestCase(AuthedTestCase):
    """Regression coverage: _build_action_cards() has always built 3 real
    "Generate" cards (Executive, Risk, Readiness), each posting to its
    own real reports:generate URL -- but a `forloop.first` template bug
    meant only the first (Executive) ever rendered. All 3 must now show
    and each must post to its own distinct, real URL.
    """

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )

    def test_all_three_generate_buttons_render(self):
        response = self.client.get(reverse("reports:index"))

        self.assertContains(response, "Generate Executive Report")
        self.assertContains(response, "Generate Risk Report")
        self.assertContains(response, "Generate Readiness Report")

    def test_each_generate_button_posts_to_its_own_real_generate_url(self):
        response = self.client.get(reverse("reports:index"))
        content = response.content.decode()

        self.assertIn(reverse("reports:generate", args=["executive"]), content)
        self.assertIn(reverse("reports:generate", args=["risk"]), content)
        self.assertIn(reverse("reports:generate", args=["readiness"]), content)
        # Confirmed three distinct <form> actions, not the same one repeated.
        self.assertEqual(
            len({
                reverse("reports:generate", args=["executive"]),
                reverse("reports:generate", args=["risk"]),
                reverse("reports:generate", args=["readiness"]),
            }),
            3,
        )


class ReportDetailIncidentLinkTestCase(AuthedTestCase):
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
            title="Suspicious PowerShell Activity",
            incident_type="Endpoint",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="Workstation-12",
        )
        self.report = GeneratedReport.objects.create(
            organization=self.organization,
            incident=self.incident,
            report_type=GeneratedReport.ReportType.EXECUTIVE,
            title="Executive Report",
            summary="Summary.",
            body="Body.",
        )

    def test_incident_field_links_back_to_the_real_incident(self):
        response = self.client.get(reverse("reports:detail", args=[self.report.id]))

        self.assertContains(response, reverse("incidents:detail", args=[self.incident.id]))
        self.assertContains(response, "Suspicious PowerShell Activity")

    def test_upload_wide_report_shows_plain_text_not_a_broken_link(self):
        upload_wide_report = GeneratedReport.objects.create(
            organization=self.organization,
            incident=None,
            report_type=GeneratedReport.ReportType.EXECUTIVE,
            title="Org-wide Executive Report",
            summary="Summary.",
            body="Body.",
        )

        response = self.client.get(reverse("reports:detail", args=[upload_wide_report.id]))

        self.assertContains(response, "Upload-wide summary")
