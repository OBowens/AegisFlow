import csv
from datetime import datetime, time, timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.incidents.models import IncidentGroup
from apps.log_intake.models import UploadedLogFile
from apps.organizations.models import Organization
from apps.reports.models import GeneratedReport

from . import views as audit_views
from .models import AIRun, AuditLog
from .views import CARIBBEAN_TIMEZONE


class AuditViewsTestCase(AuthedTestCase):
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
        self.upload = UploadedLogFile.objects.create(
            organization=self.organization,
            uploaded_by=self.user,
            file_name="power_logs_2025-05-16.log",
            source_type=UploadedLogFile.SourceType.WAZUH,
            storage_path="demo/power_logs_2025-05-16.log",
            status=UploadedLogFile.Status.PARSED,
            notes="User uploaded a log file via the Upload Logs module.",
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible brute-force attempt against admin account",
            incident_type="Authentication Attack",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="Email Server",
            summary="Grouped incident created from uploaded logs.",
        )
        self.report = GeneratedReport.objects.create(
            organization=self.organization,
            incident=self.incident,
            report_type=GeneratedReport.ReportType.UPLOAD_SUMMARY,
            title="Manager Incident Summary",
            summary="Manager-ready overview of the incident.",
            body="Recommended Actions:\n- Review authentication logs.\n- Reset credentials.",
            generated_by=self.user,
        )
        AIRun.objects.create(
            organization=self.organization,
            ai_module="demo_log_workflow",
            input_type="UploadedLogFile",
            input_id=str(self.upload.id),
            output_type="GeneratedReport",
            output_id=str(self.report.id),
            status=AIRun.Status.SUCCESS,
        )
        AuditLog.objects.create(
            organization=self.organization,
            user=self.user,
            action="demo_log_workflow_completed",
            target_type="UploadedLogFile",
            target_id=str(self.upload.id),
            ip_address="10.0.5.23",
            details="Workflow completed and the manager report was generated.",
        )

    def test_audit_index_uses_dashboard_shell(self):
        response = self.client.get(reverse("audit:index"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Audit History")
        self.assertContains(response, "app-shell")
        self.assertContains(response, "Audit Events")
        self.assertContains(response, "Selected Event Details")
        self.assertContains(response, "Manager Incident Summary")
        self.assertContains(response, "Log file uploaded")
        # No fabricated per-metric trend line: there is no per-day history
        # behind these cards, so no sparkline should be rendered at all.
        self.assertNotContains(response, "metric-card__spark")
        self.assertNotContains(response, "0,17 8,14 16,15.5")

    def test_download_csv_link_points_to_the_real_export_endpoint(self):
        response = self.client.get(reverse("audit:index"))

        self.assertContains(response, reverse("audit:export_csv"))

    def test_export_csv_returns_a_real_attachment_with_the_event_rows(self):
        response = self.client.get(reverse("audit:export_csv"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv")
        self.assertIn("attachment;", response["Content-Disposition"])
        self.assertIn(".csv", response["Content-Disposition"])

        rows = list(csv.reader(response.content.decode().splitlines()))
        self.assertEqual(rows[0][0], "Event ID")
        body = response.content.decode()
        self.assertIn("Manager Incident Summary", body)
        self.assertIn("Log file uploaded", body)
        # One header row plus one row per assembled event.
        self.assertGreater(len(rows), 1)

    def test_export_csv_honours_the_action_type_filter(self):
        response = self.client.get(reverse("audit:export_csv"), {"action": "upload"})

        rows = list(csv.reader(response.content.decode().splitlines()))
        header, data_rows = rows[0], rows[1:]
        action_type_col = header.index("Action Type")
        self.assertTrue(data_rows)
        self.assertTrue(
            all(row[action_type_col] == "Upload Actions" for row in data_rows)
        )

    def test_export_csv_date_range_filter_can_exclude_old_events(self):
        old_upload = UploadedLogFile.objects.create(
            organization=self.organization,
            uploaded_by=self.user,
            file_name="ancient.log",
            source_type=UploadedLogFile.SourceType.WAZUH,
            storage_path="demo/ancient.log",
            status=UploadedLogFile.Status.PARSED,
        )
        UploadedLogFile.objects.filter(pk=old_upload.pk).update(
            uploaded_at=timezone.now() - timedelta(days=90)
        )

        recent = self.client.get(reverse("audit:export_csv"), {"range": "7d"})
        all_time = self.client.get(reverse("audit:export_csv"), {"range": "all"})

        self.assertNotIn("ancient.log", recent.content.decode())
        self.assertIn("ancient.log", all_time.content.decode())

    def test_no_mislabeled_audit_analytics_link(self):
        # There is no separate "audit analytics" page -- the old footer
        # link just cleared the selection on this same page.
        response = self.client.get(reverse("audit:index"))

        self.assertNotContains(response, "View full audit analytics")
        self.assertNotContains(response, "View Full Audit Analytics")

    def test_selected_event_with_incident_links_to_real_incident_evidence(self):
        response = self.client.get(
            reverse("audit:index"), {"event": f"incident-{self.incident.id}"}
        )

        selected = response.context["selected_event"]
        self.assertEqual(selected["detail_secondary_label"], "View Incident Evidence")
        self.assertEqual(
            selected["detail_secondary_url"],
            reverse("incidents:evidence", args=[self.incident.id]),
        )
        self.assertNotContains(response, "View Full Activity for Incident")

    def test_selected_event_without_incident_has_no_fabricated_secondary_link(self):
        response = self.client.get(
            reverse("audit:index"), {"event": f"upload-{self.upload.id}"}
        )

        selected = response.context["selected_event"]
        self.assertEqual(selected["related_incident_url"], "")
        self.assertEqual(selected["detail_secondary_url"], "")
        self.assertEqual(selected["detail_secondary_label"], "")

    def test_audit_index_empty_state(self):
        AuditLog.objects.all().delete()
        AIRun.objects.all().delete()
        GeneratedReport.objects.all().delete()
        IncidentGroup.objects.all().delete()
        UploadedLogFile.objects.all().delete()

        response = self.client.get(reverse("audit:index"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No audit events yet")


class AIRunsTodayTimezoneTestCase(AuthedTestCase):
    """_build_audit_metrics's "AI Runs Today" count used bare
    timezone.localdate() (UTC, from settings.TIME_ZONE) while every
    other date grouping on this page explicitly localizes to AST --
    an AI run late in the AST day could fall on the "wrong" UTC
    calendar date and silently drop out of "today".
    """

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )

    def _make_ai_run_at(self, local_dt):
        run = AIRun.objects.create(
            organization=self.organization,
            ai_module="analyst",
            input_type="IncidentGroup",
            input_id="1",
            output_type="AnalystResult",
            output_id="",
            status=AIRun.Status.SUCCESS,
        )
        AIRun.objects.filter(pk=run.pk).update(created_at=local_dt)
        run.refresh_from_db()
        return run

    def test_ai_run_late_in_the_ast_day_still_counts_as_today(self):
        # 11:30 PM AST is already the next calendar day in UTC (AST is
        # UTC-4) -- must still count as "today" in AST terms.
        ast_today = timezone.localdate(timezone.now(), CARIBBEAN_TIMEZONE)
        late_ast_run = self._make_ai_run_at(
            datetime.combine(ast_today, time(23, 30), tzinfo=CARIBBEAN_TIMEZONE)
        )

        metrics = audit_views._build_audit_metrics(
            all_events=[], ai_runs=[late_ast_run], reports=[], uploads=[]
        )

        ai_runs_today = next(m["value"] for m in metrics if m["title"] == "AI Runs Today")
        self.assertEqual(ai_runs_today, "1")

    def test_ai_run_from_yesterday_ast_does_not_count_as_today(self):
        ast_today = timezone.localdate(timezone.now(), CARIBBEAN_TIMEZONE)
        yesterday_ast_run = self._make_ai_run_at(
            datetime.combine(ast_today, time(0, 30), tzinfo=CARIBBEAN_TIMEZONE) - timedelta(days=1)
        )

        metrics = audit_views._build_audit_metrics(
            all_events=[], ai_runs=[yesterday_ast_run], reports=[], uploads=[]
        )

        ai_runs_today = next(m["value"] for m in metrics if m["title"] == "AI Runs Today")
        self.assertEqual(ai_runs_today, "0")
