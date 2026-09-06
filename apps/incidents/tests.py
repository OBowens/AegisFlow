import tempfile
from pathlib import Path

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.ai_core.models import AliasMapping
from apps.ai_core.orchestrator import run_demo_log_workflow
from apps.log_intake.models import ParsedAlert, UploadedLogFile
from apps.organizations.models import Organization
from apps.playbooks.models import PlaybookStep, ResponsePlaybook
from apps.reports.models import GeneratedReport
from apps.resilience.models import DisasterReadinessFinding
from apps.risk.models import GapFinding, RiskAssessment

from .models import IncidentEvidence, IncidentGroup, IncidentSourceIPLink


class IncidentViewsTestCase(AuthedTestCase):
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
            file_name="incident_demo.json",
            source_type=UploadedLogFile.SourceType.WAZUH,
            storage_path="demo/incident_demo.json",
            status=UploadedLogFile.Status.PARSED,
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible brute-force attempt against privileged account",
            incident_type="Authentication Attack",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="EMAIL SERVER",
            summary="Brute-force activity detected against a privileged account.",
        )
        self.alert = ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="Microsoft Entra ID",
            timestamp=timezone.now(),
            affected_system="EMAIL SERVER",
            account="admin@demo.local",
            source_ip="203.0.113.45",
            event_type="Failed Login Events",
            severity_hint=ParsedAlert.SeverityHint.HIGH,
            raw_message="Repeated failed sign-ins detected.",
            normalized_summary="Repeated failed sign-ins from a single external IP.",
        )
        IncidentEvidence.objects.create(
            incident=self.incident,
            alert=self.alert,
            evidence_reason="Matched account and source IP across multiple alerts.",
        )
        self.gap = GapFinding.objects.create(
            organization=self.organization,
            incident=self.incident,
            gap_name="No MFA Evidence",
            description="No multi-factor authentication detected for the targeted account.",
            affected_system="EMAIL SERVER",
            priority=GapFinding.Priority.HIGH,
        )
        self.risk = RiskAssessment.objects.create(
            organization=self.organization,
            incident=self.incident,
            gap=self.gap,
            risk_title="Privileged account takeover risk",
            likelihood=4,
            impact=4,
            risk_level=RiskAssessment.Level.HIGH,
            reasoning="Successful compromise could expose mailboxes and internal systems.",
            recommended_priority=RiskAssessment.RecommendedPriority.HIGH,
        )
        self.readiness = DisasterReadinessFinding.objects.create(
            organization=self.organization,
            incident=self.incident,
            risk=self.risk,
            readiness_issue="Hurricane response contacts not validated",
            disaster_impact="A severe storm could delay incident escalation.",
            recovery_concern="Alternate communications are not documented.",
            priority=DisasterReadinessFinding.Priority.MEDIUM,
        )
        self.playbook = ResponsePlaybook.objects.create(
            organization=self.organization,
            incident=self.incident,
            risk=self.risk,
            readiness_finding=self.readiness,
            title="Credential compromise playbook",
            summary="Containment and recovery steps for credential abuse.",
            priority=ResponsePlaybook.Priority.HIGH,
            status=ResponsePlaybook.Status.ACTIVE,
        )
        PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=1,
            action="Force reset the targeted account password.",
        )
        self.report = GeneratedReport.objects.create(
            organization=self.organization,
            incident=self.incident,
            report_type=GeneratedReport.ReportType.UPLOAD_SUMMARY,
            title="Incident manager summary",
            summary="Executive summary for the incident.",
            body="Manager report body.",
        )

    def test_incident_detail_renders_redesigned_page(self):
        response = self.client.get(reverse("incidents:detail", args=[self.incident.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Incident Detail")
        self.assertContains(
            response,
            "Possible brute-force attempt against privileged account",
        )
        self.assertContains(response, "AI Summary")
        self.assertContains(response, "Generate Playbook")
        self.assertContains(response, "Recommended Next Actions")
        self.assertContains(response, "No MFA Evidence")
        self.assertContains(response, "EMAIL SERVER")

    def test_incident_list_uses_dashboard_shell(self):
        # A bare GET (no ?tab=) now genuinely resolves to the Overview
        # tab (see _resolve_active_tab), which doesn't list individual
        # incidents by title -- ?tab=queue is the tab that does, so that's
        # what actually proves an incident renders inside the shell.
        response = self.client.get(f"{reverse('incidents:index')}?tab=queue")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Incidents")
        self.assertContains(response, "app-shell")
        self.assertContains(
            response,
            "Possible brute-force attempt against privileged account",
        )

    def test_incident_detail_no_longer_has_the_dead_view_all_links(self):
        response = self.client.get(reverse("incidents:detail", args=[self.incident.id]))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "View all evidence")
        self.assertNotContains(response, "View all detected gaps")

    def test_incident_detail_links_to_the_real_evidence_and_gaps_pages(self):
        response = self.client.get(reverse("incidents:detail", args=[self.incident.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "View Evidence")
        self.assertContains(response, reverse("incidents:evidence", args=[self.incident.id]))
        self.assertContains(response, "View Gaps")
        self.assertContains(response, reverse("incidents:gaps", args=[self.incident.id]))


class IncidentDetailEvidenceAndGapsFullListTestCase(AuthedTestCase):
    """Regression coverage for the 2026-08-27 Part F.5 fix: real
    incidents only ever have a handful of evidence items (max 13 in the
    dev DB) and exactly one gap finding each, so
    _build_evidence_groups/_build_gap_cards no longer cap to 2 -- every
    real item shows inline instead of silently hiding some behind a
    dead "view all" link.
    """

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
            file_name="many_alerts.json",
            source_type=UploadedLogFile.SourceType.WAZUH,
            storage_path="demo/many_alerts.json",
            status=UploadedLogFile.Status.PARSED,
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Widespread suspicious activity across multiple systems",
            incident_type="Multi-System Activity",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="WEB-01",
        )

        # 3 distinct event types, several alerts each -- more than the
        # old [:2] group cap and [:3] per-group item cap.
        distinctive_ips = [f"203.0.113.{n}" for n in range(1, 8)]
        event_types = ["Failed Login Events", "Malware Alert", "Firewall Denied"]
        for index, source_ip in enumerate(distinctive_ips):
            alert = ParsedAlert.objects.create(
                uploaded_file=self.uploaded_file,
                organization=self.organization,
                source_tool="test",
                timestamp=timezone.now(),
                affected_system="WEB-01",
                source_ip=source_ip,
                event_type=event_types[index % len(event_types)],
                severity_hint=ParsedAlert.SeverityHint.HIGH,
                raw_message=f"Event referencing distinctive IP {source_ip}",
            )
            IncidentEvidence.objects.create(
                incident=self.incident,
                alert=alert,
                evidence_reason="Grouped for this test.",
            )

        self.gap_names = [f"Distinctive gap finding #{n}" for n in range(1, 4)]
        for gap_name in self.gap_names:
            GapFinding.objects.create(
                organization=self.organization,
                incident=self.incident,
                gap_name=gap_name,
                description="Test gap description.",
                priority=GapFinding.Priority.MEDIUM,
            )

    def test_all_seven_evidence_source_ips_are_shown_not_just_a_capped_subset(self):
        response = self.client.get(reverse("incidents:detail", args=[self.incident.id]))

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        for source_ip in ("203.0.113.1", "203.0.113.4", "203.0.113.7"):
            self.assertIn(source_ip, content)
        # All 3 event-type groups, not just the top 2 by count.
        self.assertContains(response, "Failed Login Events")
        self.assertContains(response, "Malware Alert")
        self.assertContains(response, "Firewall Denied")

    def test_all_three_gap_findings_are_shown_not_just_a_capped_subset(self):
        response = self.client.get(reverse("incidents:detail", args=[self.incident.id]))

        self.assertEqual(response.status_code, 200)
        for gap_name in self.gap_names:
            self.assertContains(response, gap_name)

    def test_dedicated_evidence_page_shows_all_evidence_for_this_incident(self):
        response = self.client.get(reverse("incidents:evidence", args=[self.incident.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.incident.title)
        content = response.content.decode()
        # Each evidence card's source IP renders as its stable structured
        # alias (Part 4), never the real value -- one distinct alias per
        # distinct IP, so all 7 items appearing proves no per-group cap.
        ip_aliases = {
            mapping.display_alias
            for mapping in AliasMapping.objects.filter(
                organization=self.organization, identifier_type="IP"
            )
        }
        self.assertEqual(len(ip_aliases), 7)
        for alias in ip_aliases:
            self.assertIn(alias, content)
        for source_ip in ("203.0.113.1", "203.0.113.4", "203.0.113.7"):
            self.assertNotIn(source_ip, content)
        self.assertContains(response, "Failed Login Events")
        self.assertContains(response, "Malware Alert")
        self.assertContains(response, "Firewall Denied")
        self.assertContains(response, reverse("incidents:detail", args=[self.incident.id]))

    def test_dedicated_gaps_page_shows_all_gaps_for_this_incident(self):
        response = self.client.get(reverse("incidents:gaps", args=[self.incident.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.incident.title)
        for gap_name in self.gap_names:
            self.assertContains(response, gap_name)
        self.assertContains(response, reverse("incidents:detail", args=[self.incident.id]))

    def test_evidence_and_gaps_pages_are_scoped_to_the_right_incident_not_another_ones(self):
        other_incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Unrelated incident on a different system",
            incident_type="Other",
            severity=IncidentGroup.Severity.LOW,
            status=IncidentGroup.Status.OPEN,
            affected_systems="OTHER-SYS",
        )
        other_alert = ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="test",
            timestamp=timezone.now(),
            affected_system="OTHER-SYS",
            source_ip="198.51.100.99",
            event_type="Other Event Type",
            severity_hint=ParsedAlert.SeverityHint.LOW,
            raw_message="Unrelated event.",
        )
        IncidentEvidence.objects.create(
            incident=other_incident, alert=other_alert, evidence_reason="Unrelated."
        )
        GapFinding.objects.create(
            organization=self.organization,
            incident=other_incident,
            gap_name="Unrelated gap finding",
            description="Should not appear on this incident's pages.",
            priority=GapFinding.Priority.LOW,
        )

        evidence_response = self.client.get(reverse("incidents:evidence", args=[self.incident.id]))
        self.assertNotIn("198.51.100.99", evidence_response.content.decode())
        self.assertNotContains(evidence_response, "Other Event Type")

        gaps_response = self.client.get(reverse("incidents:gaps", args=[self.incident.id]))
        self.assertNotContains(gaps_response, "Unrelated gap finding")

        other_evidence_response = self.client.get(reverse("incidents:evidence", args=[other_incident.id]))
        other_ip_alias = AliasMapping.objects.get(
            organization=self.organization,
            identifier_type="IP",
            real_value="198.51.100.99",
        ).display_alias
        self.assertContains(other_evidence_response, other_ip_alias)
        self.assertNotIn("198.51.100.99", other_evidence_response.content.decode())
        for gap_name in self.gap_names:
            self.assertNotIn(gap_name, other_evidence_response.content.decode())


class SourceIPCorrelationTestCase(AuthedTestCase):
    """Uploading the same fixture twice should link the second incident
    back to the first via their shared source IP, instead of leaving two
    disconnected incidents.
    """

    def setUp(self):
        # Use a recent timestamp so the parsed alerts stay inside the
        # source-IP correlation lookback window regardless of the wall
        # clock on the day the suite runs.
        event_time = (timezone.now() - timezone.timedelta(days=3)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        self.FIXTURE_LOG = (
            f"{event_time} host WEB-01 failed login for user admin "
            "from 198.51.100.77\n"
        )

        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_dir.cleanup)

    def _upload_fixture(self, file_name):
        file_path = Path(self.tmp_dir.name) / file_name
        file_path.write_text(self.FIXTURE_LOG, encoding="utf-8")

        return UploadedLogFile.objects.create(
            organization=self.organization,
            file_name=file_name,
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path=str(file_path),
            status=UploadedLogFile.Status.UPLOADED,
        )

    def test_second_upload_surfaces_connection_to_first(self):
        first_upload = self._upload_fixture("week1_auth.log")
        first_summary = run_demo_log_workflow(first_upload)
        self.assertEqual(first_summary["status"], "success")
        self.assertEqual(first_summary["incidents"], 1)

        first_incident = IncidentGroup.objects.get(evidence_items__alert__uploaded_file=first_upload)
        # Simulate this upload having happened two weeks before the second one.
        IncidentGroup.objects.filter(pk=first_incident.pk).update(
            created_at=timezone.now() - timezone.timedelta(days=14)
        )

        # No link should exist yet -- there's nothing prior to link to.
        self.assertEqual(IncidentSourceIPLink.objects.count(), 0)

        second_upload = self._upload_fixture("week3_auth.log")
        second_summary = run_demo_log_workflow(second_upload)
        self.assertEqual(second_summary["status"], "success")
        self.assertEqual(second_summary["incidents"], 1)

        second_incident = IncidentGroup.objects.get(evidence_items__alert__uploaded_file=second_upload)

        links = list(second_incident.source_ip_links.all())
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].source_ip, "198.51.100.77")
        self.assertEqual(links[0].related_incident_id, first_incident.id)

        # The first (older) incident should NOT show a forward link to the
        # second one -- only the second incident looks back at prior ones.
        self.assertEqual(first_incident.source_ip_links.count(), 0)

        response = self.client.get(reverse("incidents:detail", args=[second_incident.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Related Prior Activity")
        self.assertContains(response, "198.51.100.77")
        # The prior incident's title is prose with an affected system in it,
        # so it renders through {% alias_prose %} -- the system is aliased,
        # the rest of the title is intact.
        self.assertNotContains(response, first_incident.title)
        self.assertContains(response, "High severity authentication activity on")
        self.assertContains(response, "1 prior incident")
        self.assertContains(response, "14 day")

    def test_unrelated_source_ip_does_not_link(self):
        first_upload = self._upload_fixture("unrelated_week1.log")
        run_demo_log_workflow(first_upload)

        second_file_path = Path(self.tmp_dir.name) / "unrelated_week2.log"
        second_file_path.write_text(
            "2026-06-08 09:00:00 host WEB-01 failed login for user admin "
            "from 203.0.113.9\n",
            encoding="utf-8",
        )
        second_upload = UploadedLogFile.objects.create(
            organization=self.organization,
            file_name="unrelated_week2.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path=str(second_file_path),
            status=UploadedLogFile.Status.UPLOADED,
        )
        run_demo_log_workflow(second_upload)

        second_incident = IncidentGroup.objects.get(evidence_items__alert__uploaded_file=second_upload)
        self.assertEqual(second_incident.source_ip_links.count(), 0)
