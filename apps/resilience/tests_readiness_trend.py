"""Coverage for real readiness-score history tracking:
ReadinessScoreSnapshot, apps.resilience.services.scoring.build_readiness_trend,
and the two places that use it -- the Disaster Readiness page (which
creates the real history points) and the Work Queue Overview tab's
Readiness Snapshot panel (which only ever reads real points, never
fabricates any).

Confirms: 0 points renders no chart at all; exactly 1 point renders a
single marker with no connecting line (never stretched into looking
like a fuller trend); 2+ points renders a real polyline/area from a
fixed 0-100 scale (never autoscaled to make small real fluctuations
look bigger); visiting the Disaster Readiness page is the one thing
that creates a snapshot -- the sidebar badge and dashboard/Work Queue
cards, which also call compute_readiness_score, do not.
"""

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.organizations.models import Organization
from apps.resilience.models import DisasterReadinessFinding, ReadinessScoreSnapshot
from apps.resilience.services.scoring import build_readiness_trend


class BuildReadinessTrendTestCase(AuthedTestCase):
    """Pure function tests -- no DB, just fake snapshot-shaped objects."""

    class _FakeSnapshot:
        def __init__(self, score, computed_at=None):
            self.score = score
            self.computed_at = computed_at

    def test_no_snapshots_has_no_data(self):
        trend = build_readiness_trend([])
        self.assertFalse(trend["has_data"])
        self.assertFalse(trend["is_single_point"])
        self.assertEqual(trend["point_count"], 0)
        self.assertIsNone(trend["latest_score"])
        self.assertEqual(trend["polyline"], "")
        self.assertEqual(trend["area_path"], "")
        self.assertIsNone(trend["marker"])

    def test_exactly_one_snapshot_is_a_single_marker_not_a_line(self):
        trend = build_readiness_trend([self._FakeSnapshot(72)])

        self.assertTrue(trend["has_data"])
        self.assertTrue(trend["is_single_point"])
        self.assertEqual(trend["point_count"], 1)
        self.assertEqual(trend["latest_score"], 72)
        # No line and no filled area for a single point -- nothing to
        # connect it to. This is the "not stretched to look like a
        # fuller trend" requirement.
        self.assertEqual(trend["polyline"], "")
        self.assertEqual(trend["area_path"], "")
        self.assertIsNotNone(trend["marker"])

    def test_two_snapshots_produce_a_real_two_point_polyline(self):
        trend = build_readiness_trend([self._FakeSnapshot(50), self._FakeSnapshot(90)])

        self.assertTrue(trend["has_data"])
        self.assertFalse(trend["is_single_point"])
        self.assertEqual(trend["point_count"], 2)
        self.assertEqual(trend["latest_score"], 90)
        self.assertNotEqual(trend["polyline"], "")
        self.assertNotEqual(trend["area_path"], "")
        # Exactly two coordinate pairs in the polyline.
        self.assertEqual(len(trend["polyline"].split(" ")), 2)

    def test_fixed_scale_not_autoscaled_to_observed_range(self):
        # Two runs with the same *relative* gap (10 points apart) but at
        # different absolute levels must NOT produce the same y-distance
        # if the scale were autoscaled to each run's own min/max -- a
        # fixed 0-100 scale means the same 10-point gap always maps to
        # the same y-distance regardless of where it sits.
        low_range = build_readiness_trend([self._FakeSnapshot(10), self._FakeSnapshot(20)])
        high_range = build_readiness_trend([self._FakeSnapshot(80), self._FakeSnapshot(90)])

        def y_values(trend):
            return [float(pair.split(",")[1]) for pair in trend["polyline"].split(" ")]

        low_ys = y_values(low_range)
        high_ys = y_values(high_range)
        low_delta = abs(low_ys[0] - low_ys[1])
        high_delta = abs(high_ys[0] - high_ys[1])
        self.assertAlmostEqual(low_delta, high_delta, places=3)

    def test_score_of_100_stays_within_the_chart_area_not_clipped_at_the_edge(self):
        trend = build_readiness_trend([self._FakeSnapshot(100)])
        self.assertGreater(trend["marker"]["y"], 0)

    def test_score_of_zero_stays_within_the_chart_area_not_clipped_at_the_edge(self):
        trend = build_readiness_trend([self._FakeSnapshot(0)])
        self.assertLess(trend["marker"]["y"], 32)


class ReadinessPageCreatesRealSnapshotsTestCase(AuthedTestCase):
    """Only an explicit readiness refresh records a real snapshot."""

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.readiness_url = reverse("resilience:index")

    def test_explicit_refresh_creates_exactly_one_snapshot(self):
        self.assertEqual(ReadinessScoreSnapshot.objects.count(), 0)

        response = self.client.get(self.readiness_url, {"refresh": "1"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(ReadinessScoreSnapshot.objects.count(), 1)
        snapshot = ReadinessScoreSnapshot.objects.get()
        self.assertEqual(snapshot.organization, self.organization)
        self.assertEqual(snapshot.score, 100)  # no findings yet -> compute_readiness_score returns 100

    def test_a_second_refresh_creates_a_genuinely_second_point(self):
        self.client.get(self.readiness_url, {"refresh": "1"})
        self.assertEqual(ReadinessScoreSnapshot.objects.count(), 1)

        # Change real underlying data between visits so the second real
        # computation is a genuinely different score, not a duplicate.
        DisasterReadinessFinding.objects.create(
            organization=self.organization,
            readiness_issue="No offsite backup copy confirmed.",
            disaster_impact="A single-site failure could mean unrecoverable data loss.",
            recovery_concern="No alternate backup location has been documented.",
            priority=DisasterReadinessFinding.Priority.CRITICAL,
            source=DisasterReadinessFinding.Source.MANUAL,
        )

        self.client.get(self.readiness_url, {"refresh": "1"})

        self.assertEqual(ReadinessScoreSnapshot.objects.count(), 2)
        scores = list(
            ReadinessScoreSnapshot.objects.order_by("computed_at").values_list("score", flat=True)
        )
        self.assertEqual(scores[0], 100)
        self.assertLess(scores[1], scores[0])

        # The trend passed to the template now reflects both real points.
        response = self.client.get(self.readiness_url)
        self.assertEqual(response.context["readiness_trend"]["point_count"], 2)
        self.assertFalse(response.context["readiness_trend"]["is_single_point"])

    def test_ordinary_page_view_does_not_create_a_point(self):
        self.client.get(self.readiness_url)
        # Ordinary views remain read-only.
        self.assertEqual(ReadinessScoreSnapshot.objects.count(), 0)


class WorkQueueReadinessSnapshotPanelTestCase(AuthedTestCase):
    """The Work Queue Overview tab's Readiness Snapshot panel only ever
    reads real ReadinessScoreSnapshot rows -- it never creates one
    itself (that would snapshot on nearly every page view app-wide) and
    never fabricates chart data when none exist yet.
    """

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.overview_url = f"{reverse('incidents:index')}?tab=overview"
        self.readiness_url = reverse("resilience:index")

    def test_visiting_the_work_queue_does_not_create_a_snapshot(self):
        self.client.get(self.overview_url)
        self.assertEqual(ReadinessScoreSnapshot.objects.count(), 0)

    def test_panel_shows_no_data_state_before_any_real_readiness_check(self):
        response = self.client.get(self.overview_url)

        self.assertContains(response, "No readiness checks recorded yet.")
        self.assertNotContains(response, "af-readiness-trend__chart")
        self.assertFalse(response.context["queue_readiness_trend"]["has_data"])

    def test_panel_reflects_the_one_real_snapshot_after_an_explicit_refresh(self):
        self.client.get(self.readiness_url, {"refresh": "1"})

        response = self.client.get(self.overview_url)

        self.assertContains(response, "af-readiness-trend__chart")
        self.assertContains(response, "1 reading so far")
        trend = response.context["queue_readiness_trend"]
        self.assertTrue(trend["is_single_point"])
        self.assertEqual(trend["latest_score"], 100)

    def test_readiness_score_metric_no_longer_in_the_generic_metrics_list(self):
        # "Readiness score" moved into its own dedicated trend widget --
        # confirms it isn't still duplicated in queue_readiness_metrics.
        response = self.client.get(self.overview_url)
        labels = [metric["label"] for metric in response.context["queue_readiness_metrics"]]
        self.assertNotIn("Readiness score", labels)
        self.assertIn("Controls mapped", labels)
        self.assertIn("Open gaps", labels)
