"""Coverage for the backfill_incident_confidence management command:
defaults to a dry run (reports, writes nothing), only writes with
--apply, never touches an incident whose confidence is already set, and
correctly leaves confidence unset for incidents with no
confidence-scored evidence rather than inventing a value.
"""

from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from apps.incidents.models import IncidentEvidence, IncidentGroup
from apps.log_intake.models import ParsedAlert, UploadedLogFile
from apps.organizations.models import Organization


class BackfillIncidentConfidenceCommandTestCase(TestCase):
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
            file_name="backfill_demo.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path="demo/backfill_demo.log",
            status=UploadedLogFile.Status.PARSED,
        )

    def _make_alert(self, confidence_score):
        return ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="test",
            affected_system="DB01",
            event_type="database",
            severity_hint="high",
            raw_message="test",
            normalized_summary="test",
            confidence_score=confidence_score,
        )

    def _make_incident(self, *, confidence, alerts=()):
        incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Test incident",
            incident_type="database",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="DB01",
            confidence=confidence,
        )
        for alert in alerts:
            IncidentEvidence.objects.create(incident=incident, alert=alert, evidence_reason="test")
        return incident

    def test_dry_run_reports_but_writes_nothing(self):
        alert = self._make_alert(confidence_score=0.9)
        incident = self._make_incident(confidence=None, alerts=[alert])

        out = StringIO()
        call_command("backfill_incident_confidence", stdout=out)

        incident.refresh_from_db()
        self.assertIsNone(incident.confidence)
        self.assertIn("would get a real, computed confidence value", out.getvalue())
        self.assertIn("Dry run only", out.getvalue())

    def test_apply_actually_writes_the_computed_value(self):
        alert = self._make_alert(confidence_score=0.9)
        incident = self._make_incident(confidence=None, alerts=[alert])

        out = StringIO()
        call_command("backfill_incident_confidence", "--apply", stdout=out)

        incident.refresh_from_db()
        self.assertEqual(incident.confidence, 0.9)
        self.assertIn("Updated 1 IncidentGroup row(s)", out.getvalue())

    def test_already_set_confidence_is_never_touched(self):
        alert = self._make_alert(confidence_score=0.9)
        incident = self._make_incident(confidence=0.4, alerts=[alert])

        out = StringIO()
        call_command("backfill_incident_confidence", "--apply", stdout=out)

        incident.refresh_from_db()
        self.assertEqual(incident.confidence, 0.4)

    def test_incident_with_no_confidence_scored_evidence_stays_unset(self):
        alert = self._make_alert(confidence_score=None)
        incident = self._make_incident(confidence=None, alerts=[alert])

        out = StringIO()
        call_command("backfill_incident_confidence", "--apply", stdout=out)

        incident.refresh_from_db()
        self.assertIsNone(incident.confidence)
        self.assertIn("would stay unset", out.getvalue())

    def test_incident_with_no_evidence_at_all_stays_unset(self):
        incident = self._make_incident(confidence=None, alerts=[])

        call_command("backfill_incident_confidence", "--apply", stdout=StringIO())

        incident.refresh_from_db()
        self.assertIsNone(incident.confidence)
