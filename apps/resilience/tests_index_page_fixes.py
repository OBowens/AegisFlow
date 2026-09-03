"""Coverage for three real bugs found during the round-2 site audit and
fixed on the Disaster Readiness page:

1. The domain-card detail dialogs' wiring script was placed inside
   `{% block title %}`, which the base layout renders as literal text
   inside `<title>...</title>` -- the script never executed, so
   clicking any of the 5 domain cards did nothing. Moved to
   `{% block page_scripts %}`.
2. The overall score's status label always fell back to "Current
   score" because `_build_readiness_overview()` never set a
   `status_label` key at all. Added one, using the same 80/50
   thresholds already driving the ring gauge's color.
3. The "Readiness trend" panel showed stale, now-false copy claiming
   "no historical score snapshots" are stored, even though
   ReadinessScoreSnapshot/build_readiness_trend (built earlier this
   session) were already computing real trend data that this page
   just never rendered. Wired in the same chart widget used on the
   Work Queue Overview tab.
"""

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.organizations.models import Organization
from apps.resilience.models import DisasterReadinessFinding, ReadinessScoreSnapshot


class ReadinessOverviewStatusLabelTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.readiness_url = reverse("resilience:index")

    def test_high_score_shows_good_label_not_the_fallback(self):
        # No findings at all -> compute_readiness_score returns 100.
        response = self.client.get(self.readiness_url)

        self.assertEqual(response.context["readiness_overview"]["status_label"], "GOOD")
        self.assertNotContains(response, "Current score")

    def test_low_score_shows_high_risk_label(self):
        for _ in range(5):
            DisasterReadinessFinding.objects.create(
                organization=self.organization,
                readiness_issue="No offsite backup copy confirmed.",
                disaster_impact="Unrecoverable data loss on a single-site failure.",
                recovery_concern="No alternate backup location documented.",
                priority=DisasterReadinessFinding.Priority.CRITICAL,
                source=DisasterReadinessFinding.Source.MANUAL,
            )

        response = self.client.get(self.readiness_url)

        self.assertEqual(response.context["readiness_overview"]["status_label"], "HIGH RISK")


class ReadinessDomainDialogScriptPlacementTestCase(AuthedTestCase):
    def test_dialog_wiring_script_is_in_a_real_script_block_not_the_page_title(self):
        response = self.client.get(reverse("resilience:index"))
        content = response.content.decode()

        title_start = content.index("<title>")
        title_end = content.index("</title>")
        title_content = content[title_start:title_end]

        self.assertNotIn("showModal", title_content)
        self.assertIn("data-ready-domain-open", content)
        self.assertIn("showModal", content)
        # The script must appear as a real <script> tag in the body, not
        # swallowed as literal text inside <title>.
        script_index = content.index("showModal")
        self.assertGreater(script_index, content.index("</title>"))


class ReadinessTrendRendersOnTheReadinessPageTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.readiness_url = reverse("resilience:index")

    def test_explicit_refresh_creates_and_renders_a_real_single_point_chart(self):
        response = self.client.get(self.readiness_url, {"refresh": "1"})

        self.assertContains(response, "af-readiness-trend__chart")
        self.assertContains(response, "Percentage")
        self.assertContains(response, "Time")
        self.assertContains(response, "Latest score")
        self.assertNotContains(response, "No readiness history available yet")
        self.assertNotContains(response, "No trend line is fabricated in the meantime")

    def test_stale_false_claim_about_no_history_is_gone(self):
        self.client.get(self.readiness_url)
        response = self.client.get(self.readiness_url)

        # The old copy falsely claimed the data model doesn't store
        # historical snapshots -- it does now, and this page uses it.
        self.assertNotContains(response, "the current data model stores findings and plans, but not historical score snapshots")

    def test_second_explicit_refresh_shows_two_real_points(self):
        self.client.get(self.readiness_url, {"refresh": "1"})
        response = self.client.get(self.readiness_url, {"refresh": "1"})

        self.assertEqual(ReadinessScoreSnapshot.objects.count(), 2)
        self.assertEqual(response.context["readiness_trend"]["point_count"], 2)
