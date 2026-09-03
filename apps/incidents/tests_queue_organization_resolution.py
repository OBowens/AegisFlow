"""Coverage for incident_list's organization resolution: the Work
Queue's org-scoped Overview panels (Recent Activity, Readiness
Snapshot, Recommended Focus) must reflect the real, canonical
organization -- not whichever organization happens to own the most
recently updated incident, which a single stray/test incident (like
the "T"/"A" contamination record found earlier tonight) can hijack.
"""

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditLog
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.resilience.models import ReadinessScoreSnapshot


class QueueOrganizationResolutionTestCase(AuthedTestCase):
    def setUp(self):
        self.real_org = Organization.objects.create(
            name="AegisFlow AI Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        # A real incident under the real org, created/updated first.
        IncidentGroup.objects.create(
            organization=self.real_org,
            title="High severity database activity on DB01",
            incident_type="database",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="DB01",
        )
        self.overview_url = f"{reverse('incidents:index')}?tab=overview"

    def test_org_scoped_panels_use_the_real_org_even_after_a_stray_incident_is_more_recent(self):
        # A contamination-style org + incident, created AFTER the real
        # one, touched most recently -- this used to hijack organization
        # resolution for the whole Overview tab.
        contamination_org = Organization.objects.create(
            name="T",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        IncidentGroup.objects.create(
            organization=contamination_org,
            title="T",
            incident_type="",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="A",
        )

        # Real activity that should show up once org resolution is fixed.
        AuditLog.objects.create(
            organization=self.real_org,
            action="incident_status_changed",
            target_type="IncidentGroup",
            target_id="1",
            details="Real audit event for the real org.",
        )

        response = self.client.get(self.overview_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Real audit event for the real org.")
        self.assertNotContains(response, "No recent account activity.")

    def test_readiness_trend_reflects_the_real_org_not_the_contamination_org(self):
        contamination_org = Organization.objects.create(
            name="T",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        IncidentGroup.objects.create(
            organization=contamination_org,
            title="T",
            incident_type="",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="A",
        )
        ReadinessScoreSnapshot.objects.create(organization=self.real_org, score=77)

        response = self.client.get(self.overview_url)

        trend = response.context["queue_readiness_trend"]
        self.assertTrue(trend["has_data"])
        self.assertEqual(trend["latest_score"], 77)
        self.assertContains(response, "77%")

    def test_organization_name_in_header_is_the_real_org_not_the_contamination_org(self):
        contamination_org = Organization.objects.create(
            name="T",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        IncidentGroup.objects.create(
            organization=contamination_org,
            title="T",
            incident_type="",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="A",
        )

        response = self.client.get(self.overview_url)

        self.assertEqual(response.context["organization_name"], "AegisFlow AI Demo Organization")
