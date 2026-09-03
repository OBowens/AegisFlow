"""Coverage for the time-gap splitting behavior in
apps.incidents.services.grouping.group_alerts_for_upload: within a
matching (event_type, affected_system, severity_hint) bucket, a gap of
more than 2 hours between consecutive (by timestamp) alerts starts a new
IncidentGroup instead of silently folding genuinely separated activity
into one incident.
"""

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.log_intake.models import ParsedAlert, UploadedLogFile
from apps.organizations.models import Organization

from .models import IncidentGroup
from .services.grouping import TIME_GAP_SPLIT_THRESHOLD, group_alerts_for_upload


class TimeGapSplittingTestCase(TestCase):
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
            file_name="gap_split_demo.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path="demo/gap_split_demo.log",
            status=UploadedLogFile.Status.PARSED,
        )
        self.base_time = timezone.now() - timedelta(days=1)

    def _make_alert(self, *, minutes_offset, event_type="authentication_failure",
                     affected_system="WEB-01", severity="high"):
        return ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="test",
            timestamp=self.base_time + timedelta(minutes=minutes_offset),
            affected_system=affected_system,
            event_type=event_type,
            severity_hint=severity,
            raw_message="failed login for user admin",
            normalized_summary="Failed login detected",
        )

    def test_burst_within_two_hours_stays_one_incident(self):
        for offset in (0, 30, 60, 90, 115):
            self._make_alert(minutes_offset=offset)

        incidents = group_alerts_for_upload(self.uploaded_file)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].evidence_items.count(), 5)

    def test_gap_over_two_hours_splits_into_two_incidents(self):
        # Cluster A: 3 alerts within the first hour.
        for offset in (0, 20, 45):
            self._make_alert(minutes_offset=offset)
        # Cluster B: starts 130 minutes (>2h) after the last alert in cluster A.
        gap_start = 45 + TIME_GAP_SPLIT_THRESHOLD.total_seconds() / 60 + 10
        for offset in (gap_start, gap_start + 15, gap_start + 40):
            self._make_alert(minutes_offset=offset)

        incidents = group_alerts_for_upload(self.uploaded_file)

        self.assertEqual(len(incidents), 2)
        counts = sorted(incident.evidence_items.count() for incident in incidents)
        self.assertEqual(counts, [3, 3])

        ordered = sorted(incidents, key=lambda incident: incident.first_seen)
        self.assertLess(ordered[0].last_seen, ordered[1].first_seen)
        self.assertGreater(ordered[1].first_seen - ordered[0].last_seen, TIME_GAP_SPLIT_THRESHOLD)

    def test_gap_exactly_at_threshold_does_not_split(self):
        self._make_alert(minutes_offset=0)
        self._make_alert(minutes_offset=TIME_GAP_SPLIT_THRESHOLD.total_seconds() / 60)

        incidents = group_alerts_for_upload(self.uploaded_file)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].evidence_items.count(), 2)

    def test_untimestamped_alerts_fall_back_to_one_shared_group(self):
        # Two dated clusters, split by a >2h gap...
        self._make_alert(minutes_offset=0)
        self._make_alert(minutes_offset=200)
        # ...plus alerts with no timestamp at all, in the same bucket.
        ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="test",
            timestamp=None,
            affected_system="WEB-01",
            event_type="authentication_failure",
            severity_hint="high",
            raw_message="failed login for user admin",
            normalized_summary="Failed login detected",
        )
        ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="test",
            timestamp=None,
            affected_system="WEB-01",
            event_type="authentication_failure",
            severity_hint="high",
            raw_message="failed login for user admin",
            normalized_summary="Failed login detected",
        )

        incidents = group_alerts_for_upload(self.uploaded_file)

        # 2 time-based clusters + 1 shared group for the undated alerts.
        self.assertEqual(len(incidents), 3)
        counts = sorted(incident.evidence_items.count() for incident in incidents)
        self.assertEqual(counts, [1, 1, 2])

        undated_incident = next(incident for incident in incidents if incident.evidence_items.count() == 2)
        self.assertIsNone(undated_incident.first_seen)
        self.assertIsNone(undated_incident.last_seen)

    def test_different_buckets_still_split_independently(self):
        # A different affected_system is always its own bucket, regardless
        # of timestamp -- unaffected by gap splitting.
        self._make_alert(minutes_offset=0, affected_system="WEB-01")
        self._make_alert(minutes_offset=0, affected_system="DB-02")

        incidents = group_alerts_for_upload(self.uploaded_file)

        self.assertEqual(len(incidents), 2)


class GroupingMeasurementReplayTestCase(TestCase):
    """Reconstructs the 111-alert / one bucket / ~3h39m internal-gap shape
    referenced for this feature (single-upload, single event_type +
    affected_system + severity bucket, one large internal gap) directly via
    ParsedAlert rows, since real uploads are capped at 50 parsed alerts
    (MAX_EVENTS in services/parser.py) and can't produce a 111-alert bucket
    through the actual upload path. This is a fresh measurement built to
    the same shape, not a stored artifact from a prior run -- nothing under
    this shape (script, fixture, or recorded numbers) exists in the repo.
    """

    FIRST_CLUSTER_SIZE = 60
    SECOND_CLUSTER_SIZE = 51
    GAP = timedelta(hours=3, minutes=39)

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
            file_name="measurement_111_alerts.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path="demo/measurement_111_alerts.log",
            status=UploadedLogFile.Status.PARSED,
        )
        base_time = timezone.now() - timedelta(days=2)

        # First cluster: 60 alerts, 1 minute apart (a burst).
        for i in range(self.FIRST_CLUSTER_SIZE):
            self._make_alert(base_time + timedelta(minutes=i))

        # A single ~3h39m gap, then a second burst of 51 alerts.
        second_cluster_start = (
            base_time
            + timedelta(minutes=self.FIRST_CLUSTER_SIZE - 1)
            + self.GAP
        )
        for i in range(self.SECOND_CLUSTER_SIZE):
            self._make_alert(second_cluster_start + timedelta(minutes=i))

        self.total_alerts = self.FIRST_CLUSTER_SIZE + self.SECOND_CLUSTER_SIZE

    def _make_alert(self, timestamp):
        ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="test",
            timestamp=timestamp,
            affected_system="AUTH-GATEWAY-01",
            event_type="authentication_failure",
            severity_hint="high",
            raw_message="failed login for user admin",
            normalized_summary="Failed login detected",
        )

    def test_bucket_has_111_alerts_before_grouping(self):
        self.assertEqual(self.total_alerts, 111)
        self.assertEqual(
            ParsedAlert.objects.filter(uploaded_file=self.uploaded_file).count(), 111
        )

    def test_111_alert_3h39m_bucket_now_splits_into_two_incidents(self):
        incidents = group_alerts_for_upload(self.uploaded_file)

        self.assertEqual(
            len(incidents), 2,
            "A single bucket with a >2h internal gap must split into 2 incidents, "
            "not silently merge into 1.",
        )

        ordered = sorted(incidents, key=lambda incident: incident.first_seen)
        first_incident, second_incident = ordered

        self.assertEqual(first_incident.evidence_items.count(), self.FIRST_CLUSTER_SIZE)
        self.assertEqual(second_incident.evidence_items.count(), self.SECOND_CLUSTER_SIZE)
        self.assertEqual(
            first_incident.evidence_items.count() + second_incident.evidence_items.count(),
            111,
        )

        actual_gap = second_incident.first_seen - first_incident.last_seen
        self.assertEqual(actual_gap, self.GAP)
        self.assertGreater(actual_gap, TIME_GAP_SPLIT_THRESHOLD)

        # A burst stays one incident: neither cluster is internally split.
        self.assertEqual(
            IncidentGroup.objects.filter(
                evidence_items__alert__uploaded_file=self.uploaded_file
            ).distinct().count(),
            2,
        )
