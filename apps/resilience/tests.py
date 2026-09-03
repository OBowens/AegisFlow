from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.log_intake.models import ParsedAlert, UploadedLogFile
from apps.organizations.models import Organization
from apps.risk.models import GapFinding

from .models import DisasterReadinessFinding, ReadinessAnswer, ReadinessPlan
from .services.contradictions import find_contradictions_for_organization


class ResilienceViewsTestCase(AuthedTestCase):
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
            file_name="backup_failure.json",
            source_type=UploadedLogFile.SourceType.WAZUH,
            storage_path="demo/backup_failure.json",
            status=UploadedLogFile.Status.PARSED,
        )
        ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="PRTG",
            timestamp=timezone.now(),
            affected_system="Finance VM",
            event_type="Backup job failed",
            severity_hint=ParsedAlert.SeverityHint.HIGH,
            raw_message="Finance VM backup did not complete successfully.",
            normalized_summary="Finance VM backup failure detected",
        )
        DisasterReadinessFinding.objects.create(
            organization=self.organization,
            readiness_issue="Finance VM backup failure",
            disaster_impact="Backup disruption could slow recovery during hurricane season.",
            recovery_concern="Recovery confidence is reduced until restore readiness is confirmed.",
            priority=DisasterReadinessFinding.Priority.HIGH,
        )
        ReadinessPlan.objects.create(
            organization=self.organization,
            scenario="Backup and continuity review",
            checklist="Verify offsite copies and restoration steps.",
            recommended_actions="Run restore test for critical systems.",
        )

    def test_resilience_page_renders_dashboard_shell(self):
        response = self.client.get(reverse("resilience:index"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Disaster Readiness Advisor")
        self.assertContains(response, "Assess from Logs")
        self.assertContains(response, "Ask a Readiness Question")
        self.assertContains(response, "Overall Readiness")
        self.assertContains(response, "app-shell")
        self.assertContains(response, "Finance VM backup failure")


class ReadinessContradictionTestCase(AuthedTestCase):
    """A readiness answer claiming backups are fine should be flagged,
    not silently trusted, when a recent GapFinding says otherwise.
    """

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )

    def test_conflicting_gap_finding_is_flagged(self):
        answer = ReadinessAnswer.objects.create(
            organization=self.organization,
            question_text="Are nightly backups working?",
            answer_text="Yes, nightly backups are working and confirmed daily.",
        )
        gap = GapFinding.objects.create(
            organization=self.organization,
            gap_name="Backup restore assurance gap",
            description="Backup failure evidence suggests recovery readiness needs review.",
            priority=GapFinding.Priority.HIGH,
        )

        conflicts = find_contradictions_for_organization(self.organization)

        self.assertEqual(len(conflicts), 1)
        conflict = conflicts[0]
        self.assertEqual(conflict["topic"], "backup")
        self.assertEqual(conflict["answer"], answer)
        self.assertEqual(conflict["finding"], gap)
        self.assertIn("Yes, nightly backups are working", conflict["answer_text"])
        self.assertIn("Backup restore assurance gap", conflict["finding_text"])

        response = self.client.get(reverse("resilience:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Readiness Contradictions")
        self.assertContains(response, "Are nightly backups working?")
        self.assertContains(response, "Yes, nightly backups are working and confirmed daily.")
        self.assertContains(response, "Backup restore assurance gap")

    def test_non_positive_answer_is_not_flagged(self):
        ReadinessAnswer.objects.create(
            organization=self.organization,
            question_text="Are nightly backups working?",
            answer_text="Not sure, we have not tested restores recently.",
        )
        GapFinding.objects.create(
            organization=self.organization,
            gap_name="Backup restore assurance gap",
            description="Backup failure evidence suggests recovery readiness needs review.",
            priority=GapFinding.Priority.HIGH,
        )

        conflicts = find_contradictions_for_organization(self.organization)

        self.assertEqual(conflicts, [])

    def test_positive_answer_on_different_topic_is_not_flagged(self):
        ReadinessAnswer.objects.create(
            organization=self.organization,
            question_text="Is the generator working?",
            answer_text="Yes, the generator is working and was tested last month.",
        )
        GapFinding.objects.create(
            organization=self.organization,
            gap_name="Backup restore assurance gap",
            description="Backup failure evidence suggests recovery readiness needs review.",
            priority=GapFinding.Priority.HIGH,
        )

        conflicts = find_contradictions_for_organization(self.organization)

        self.assertEqual(conflicts, [])
