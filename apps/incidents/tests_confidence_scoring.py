"""Coverage for apps.incidents.services.confidence.compute_incident_confidence
and its wiring into group_alerts_for_upload: IncidentGroup.confidence is
now genuinely derived from real per-alert confidence_score data (set by
the per-source parsers) and how much corroborating evidence exists --
not a severity-based lookup table, and not populated at all when there's
no real signal to base it on.
"""

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.incidents.services.confidence import compute_incident_confidence
from apps.incidents.services.grouping import group_alerts_for_upload
from apps.log_intake.models import ParsedAlert, UploadedLogFile
from apps.organizations.models import Organization


class ComputeIncidentConfidenceTestCase(TestCase):
    """Unit-level coverage of the pure scoring function -- no DB grouping
    involved, just proving the math reflects real inputs.
    """

    def _alert(self, confidence_score):
        # A bare, unsaved ParsedAlert is enough here -- the function only
        # reads .confidence_score off whatever it's handed.
        return ParsedAlert(confidence_score=confidence_score)

    def test_no_alerts_returns_none(self):
        self.assertIsNone(compute_incident_confidence([]))

    def test_alerts_with_no_confidence_score_at_all_returns_none(self):
        self.assertIsNone(compute_incident_confidence([self._alert(None), self._alert(None)]))

    def test_single_alert_returns_its_own_score_with_no_boost(self):
        self.assertEqual(compute_incident_confidence([self._alert(0.9)]), 0.9)

    def test_higher_per_alert_confidence_produces_a_higher_result(self):
        low = compute_incident_confidence([self._alert(0.4)])
        high = compute_incident_confidence([self._alert(0.95)])
        self.assertLess(low, high)
        self.assertEqual(low, 0.4)
        self.assertEqual(high, 0.95)

    def test_more_corroborating_alerts_at_the_same_base_score_increases_confidence(self):
        one_alert = compute_incident_confidence([self._alert(0.8)])
        five_alerts = compute_incident_confidence([self._alert(0.8) for _ in range(5)])
        self.assertGreater(five_alerts, one_alert)
        # Exactly the documented boost: 4 corroborating alerts beyond the
        # first, capped at MAX_EVIDENCE_BOOST (0.08).
        self.assertEqual(five_alerts, 0.88)

    def test_result_is_capped_at_one_even_with_many_high_confidence_alerts(self):
        result = compute_incident_confidence([self._alert(0.99) for _ in range(10)])
        self.assertLessEqual(result, 1.0)

    def test_partial_confidence_data_only_averages_the_alerts_that_have_it(self):
        # One alert has no score at all (some parsers/edge cases leave it
        # null) -- it must not silently drag the average toward zero or
        # get treated as a 0.0 confidence data point.
        mixed = compute_incident_confidence([self._alert(0.9), self._alert(None)])
        self.assertEqual(mixed, 0.9)


class GroupingPersistsRealConfidenceTestCase(TestCase):
    """End-to-end: group_alerts_for_upload actually persists a confidence
    value derived from the real ParsedAlert rows it grouped, and leaves
    it unset when there's nothing to base one on.
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
            file_name="confidence_demo.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path="demo/confidence_demo.log",
            status=UploadedLogFile.Status.PARSED,
        )
        self.base_time = timezone.now() - timedelta(days=1)

    def _make_alert(self, *, minutes_offset, confidence_score):
        return ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="test",
            timestamp=self.base_time + timedelta(minutes=minutes_offset),
            affected_system="WEB-01",
            event_type="authentication_failure",
            severity_hint="high",
            raw_message="failed login for user admin",
            normalized_summary="Failed login detected",
            confidence_score=confidence_score,
        )

    def test_incident_confidence_matches_its_own_evidence_not_a_severity_table(self):
        for offset in (0, 10, 20):
            self._make_alert(minutes_offset=offset, confidence_score=0.95)

        incidents = group_alerts_for_upload(self.uploaded_file)

        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(incident.severity, "high")
        # The old bug would have shown 82% for "high" regardless of
        # evidence. The real computation for three 0.95-confidence
        # alerts is 0.95 + 2*0.02 = 0.99 -- not 0.82.
        self.assertEqual(incident.confidence, 0.99)

    def test_weaker_evidence_produces_a_lower_persisted_confidence_at_the_same_severity(self):
        for offset in (0, 10, 20):
            self._make_alert(minutes_offset=offset, confidence_score=0.5)

        incidents = group_alerts_for_upload(self.uploaded_file)

        self.assertEqual(incidents[0].severity, "high")
        self.assertEqual(incidents[0].confidence, 0.54)
        # Same severity as the strong-evidence test above, genuinely
        # different (lower) confidence -- proves it tracks evidence
        # quality, not severity.
        self.assertLess(incidents[0].confidence, 0.99)

    def test_alerts_with_no_confidence_score_leave_incident_confidence_unset(self):
        self._make_alert(minutes_offset=0, confidence_score=None)

        incidents = group_alerts_for_upload(self.uploaded_file)

        self.assertIsNone(incidents[0].confidence)
