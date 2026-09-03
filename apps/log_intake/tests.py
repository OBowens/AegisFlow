from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.incidents.models import IncidentEvidence, IncidentGroup
from apps.log_intake.models import ParsedAlert, UploadedLogFile
from apps.organizations.models import Organization


class LogIntakeViewsTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.uploaded_file = UploadedLogFile.objects.create(
            organization=self.organization,
            file_name="wazuh_alerts.json",
            source_type=UploadedLogFile.SourceType.WAZUH,
            storage_path="demo/wazuh_alerts.json",
            status=UploadedLogFile.Status.PARSED,
            notes="Demo upload",
        )

    def test_upload_page_renders(self):
        response = self.client.get(reverse("log_intake:upload"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Upload Logs")
        self.assertContains(response, "Analyze Logs")

    def test_file_list_page_redirects_to_incidents(self):
        # Analysis Results (org-wide) was merged into incidents:index's
        # Overview/Alerts tabs -- this route now just redirects there,
        # carrying the query string through so a filtered link still lands
        # on the right tab.
        response = self.client.get(reverse("log_intake:file_list"))
        self.assertRedirects(response, reverse("incidents:index"))

        response = self.client.get(
            reverse("log_intake:file_list"), {"alert_severity": "high,critical"}
        )
        self.assertRedirects(
            response, f"{reverse('incidents:index')}?alert_severity=high%2Ccritical"
        )

    def test_incidents_page_shows_merged_overview_and_alerts_content(self):
        ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="Microsoft Sentinel",
            timestamp=timezone.now(),
            affected_system="WS-15",
            event_type="Suspicious scheduled task",
            severity_hint=ParsedAlert.SeverityHint.MEDIUM,
            raw_message="Scheduled task created unexpectedly",
            normalized_summary="Suspicious scheduled task creation detected",
        )

        response = self.client.get(reverse("incidents:index"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Incidents")
        self.assertContains(response, "app-shell")
        self.assertContains(response, "Upload Logs")
        self.assertContains(response, "Suspicious scheduled task creation detected")

    def test_results_page_renders_dashboard_layout(self):
        alert = ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="Microsoft Defender",
            timestamp=timezone.now(),
            affected_system="DC-01",
            account="admin",
            source_ip="10.0.0.10",
            destination_ip="10.0.0.20",
            event_type="Failed login attempts",
            severity_hint=ParsedAlert.SeverityHint.HIGH,
            raw_message="Multiple failed logins detected",
            normalized_summary="Possible brute-force attempt against privileged account",
        )
        incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible brute-force attempt against privileged account",
            incident_type="Authentication",
            severity=IncidentGroup.Severity.CRITICAL,
            status=IncidentGroup.Status.OPEN,
            affected_systems="DC-01",
            summary="Authentication alerts grouped into a single incident.",
        )
        IncidentEvidence.objects.create(
            incident=incident,
            alert=alert,
            evidence_reason="Matched on privileged account failures.",
        )

        response = self.client.get(
            reverse("log_intake:results", args=[self.uploaded_file.id])
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Analysis Results")
        self.assertContains(
            response,
            "Possible brute-force attempt against privileged account",
        )
        self.assertContains(response, "AI Summary")
        self.assertContains(response, "Export Alerts (CSV)")
        # No fabricated per-metric trend line: there is no per-day history
        # behind these cards, so no sparkline should be rendered at all.
        self.assertNotContains(response, "metric-card__spark")
        self.assertNotContains(response, "0,17 8,14 16,15.5")

    def test_export_alerts_csv_returns_file(self):
        ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="Wazuh",
            timestamp=timezone.now(),
            affected_system="SRV-APP-02",
            account="svc_backup",
            source_ip="10.10.0.2",
            destination_ip="10.10.0.3",
            event_type="Suspicious PowerShell",
            severity_hint=ParsedAlert.SeverityHint.CRITICAL,
            raw_message="Encoded PowerShell command detected",
            normalized_summary="PowerShell encoded command execution",
        )

        response = self.client.get(
            reverse("log_intake:export_alerts_csv", args=[self.uploaded_file.id])
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv")
        self.assertIn("attachment;", response["Content-Disposition"])
        self.assertIn("Event Type,Source Tool,Severity", response.content.decode("utf-8"))
        self.assertIn("Suspicious PowerShell", response.content.decode("utf-8"))
