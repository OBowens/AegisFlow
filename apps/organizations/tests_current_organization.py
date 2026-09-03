"""Coverage for the single shared organization resolution
(get_current_organization) that replaced six independent, divergent
implementations across incidents, resilience, reports, playbooks,
organizations, audit, log_intake, risk, and core -- most of which
degraded to "whichever record was touched most recently", the exact
fragility that let a stray "T"/"A" contamination organization hijack
the Work Queue Overview panel.
"""

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.organizations.services.current_organization import get_current_organization
from apps.resilience.models import DisasterReadinessFinding, ReadinessScoreSnapshot


class GetCurrentOrganizationTestCase(AuthedTestCase):
    def test_returns_the_oldest_organization_when_multiple_exist(self):
        older = Organization.objects.create(
            name="AegisFlow AI Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        Organization.objects.create(
            name="T",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )

        self.assertEqual(get_current_organization(), older)

    def test_auto_creates_a_real_organization_when_none_exists(self):
        self.assertEqual(Organization.objects.count(), 0)

        organization = get_current_organization()

        self.assertEqual(Organization.objects.count(), 1)
        self.assertEqual(organization, Organization.objects.get())
        self.assertEqual(organization.name, "AegisFlow AI Demo Organization")

    def test_is_idempotent_does_not_create_duplicates_on_repeat_calls(self):
        get_current_organization()
        get_current_organization()
        get_current_organization()

        self.assertEqual(Organization.objects.count(), 1)


class OrganizationResolutionConsistencyAcrossPagesTestCase(AuthedTestCase):
    """The exact scenario from tonight's bug: a real organization with
    real data, plus a newer, more-recently-touched contamination
    organization with a stray incident -- every page that resolves "the
    current organization" must agree, and none may be hijacked by the
    contamination org.
    """

    def setUp(self):
        self.real_org = Organization.objects.create(
            name="AegisFlow AI Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        IncidentGroup.objects.create(
            organization=self.real_org,
            title="High severity database activity on DB01",
            incident_type="database",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="DB01",
        )
        ReadinessScoreSnapshot.objects.create(organization=self.real_org, score=91)

        self.contamination_org = Organization.objects.create(
            name="T",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        # Created and touched AFTER the real org's incident -- this is
        # exactly what hijacked resolution before the fix.
        IncidentGroup.objects.create(
            organization=self.contamination_org,
            title="T",
            incident_type="",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="A",
        )

    def test_work_queue_overview_shows_the_real_orgs_readiness_data(self):
        response = self.client.get(f"{reverse('incidents:index')}?tab=overview")

        self.assertEqual(response.context["organization_name"], "AegisFlow AI Demo Organization")
        trend = response.context["queue_readiness_trend"]
        self.assertTrue(trend["has_data"])
        self.assertEqual(trend["latest_score"], 91)
        self.assertContains(response, "91%")

    def test_disaster_readiness_page_resolves_the_same_organization(self):
        response = self.client.get(reverse("resilience:index"))

        self.assertEqual(response.context["organization_name"], "AegisFlow AI Demo Organization")

    def test_sidebar_badge_reflects_only_the_real_orgs_findings(self):
        DisasterReadinessFinding.objects.create(
            organization=self.real_org,
            readiness_issue="No offsite backup copy confirmed.",
            disaster_impact="Unrecoverable data loss on a single-site failure.",
            recovery_concern="No alternate backup location documented.",
            priority=DisasterReadinessFinding.Priority.CRITICAL,
            source=DisasterReadinessFinding.Source.MANUAL,
        )

        response = self.client.get(reverse("resilience:index"))

        # Real org has one CRITICAL finding -> score below 100.
        self.assertLess(response.context["sidebar_readiness_score"], 100)

    def test_reports_and_playbooks_and_audit_all_resolve_the_same_org(self):
        for url_name in ("reports:index", "playbooks:index", "audit:index"):
            with self.subTest(url_name=url_name):
                response = self.client.get(reverse(url_name))
                self.assertEqual(
                    response.context["organization_name"], "AegisFlow AI Demo Organization"
                )
