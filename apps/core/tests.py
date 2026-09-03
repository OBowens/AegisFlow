from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization


class DashboardViewTestCase(AuthedTestCase):
    def test_dashboard_renders(self):
        response = self.client.get(reverse("core:index"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Dashboard")
        self.assertContains(response, "AegisFlow AI")

    def test_dashboard_shows_the_real_organization_name_not_a_hardcoded_placeholder(self):
        # organization_name used to be a hardcoded "Demo Organization"
        # literal even when a real Organization row existed -- confirm
        # it now reflects the actual record.
        Organization.objects.create(
            name="Coral Bay Credit Union",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Finance",
            risk_profile="medium",
        )

        response = self.client.get(reverse("core:index"))

        self.assertEqual(response.context["organization_name"], "Coral Bay Credit Union")
        self.assertContains(response, "Coral Bay Credit Union")

    def test_dashboard_creates_a_real_demo_organization_when_none_exists(self):
        # get_current_organization() auto-creates a real Organization row
        # when none exists at all, rather than the page showing a bare
        # hardcoded string with nothing behind it.
        self.assertEqual(Organization.objects.count(), 0)

        response = self.client.get(reverse("core:index"))

        self.assertEqual(Organization.objects.count(), 1)
        created = Organization.objects.get()
        self.assertEqual(response.context["organization_name"], created.name)


class PriorityIncidentsTestCase(AuthedTestCase):
    """The "Priority incidents" section is labelled as the work that
    matters most / needs attention. Its list and count must be filtered
    by severity (critical + high) -- not "the 5 most recent incidents
    regardless of severity", and not a status filter.
    """

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )

    def _incident(self, title, severity, *, status=IncidentGroup.Status.OPEN, days_ago=0):
        incident = IncidentGroup.objects.create(
            organization=self.organization,
            title=title,
            incident_type="Authentication",
            severity=severity,
            status=status,
            affected_systems="DC-01",
            summary="Grouped incident.",
        )
        if days_ago:
            IncidentGroup.objects.filter(pk=incident.pk).update(
                created_at=timezone.now() - timezone.timedelta(days=days_ago)
            )
        return incident

    def test_count_and_list_only_include_critical_and_high_severity(self):
        self._incident("Brute force on DC", IncidentGroup.Severity.CRITICAL)
        self._incident("Suspicious PowerShell", IncidentGroup.Severity.HIGH)
        self._incident("Noisy informational alert", IncidentGroup.Severity.LOW)
        self._incident("Routine policy drift", IncidentGroup.Severity.MEDIUM)

        response = self.client.get(reverse("core:index"))

        self.assertEqual(response.context["priority_incident_count"], 2)
        titles = [item["title"] for item in response.context["priority_incidents"]]
        self.assertCountEqual(
            titles, ["Brute force on DC", "Suspicious PowerShell"]
        )
        severities = {item["severity"] for item in response.context["priority_incidents"]}
        self.assertEqual(severities, {"critical", "high"})

    def test_resolved_high_severity_incidents_are_still_counted_not_status_filtered(self):
        self._incident(
            "Contained ransomware",
            IncidentGroup.Severity.CRITICAL,
            status=IncidentGroup.Status.RESOLVED,
        )

        response = self.client.get(reverse("core:index"))

        self.assertEqual(response.context["priority_incident_count"], 1)

    def test_list_is_ordered_by_severity_then_recency(self):
        self._incident("Older high", IncidentGroup.Severity.HIGH, days_ago=10)
        self._incident("Newer high", IncidentGroup.Severity.HIGH, days_ago=1)
        self._incident("Older critical", IncidentGroup.Severity.CRITICAL, days_ago=20)

        response = self.client.get(reverse("core:index"))

        titles = [item["title"] for item in response.context["priority_incidents"]]
        self.assertEqual(titles, ["Older critical", "Newer high", "Older high"])

    def test_no_priority_incidents_shows_honest_empty_state(self):
        self._incident("Just noise", IncidentGroup.Severity.LOW)

        response = self.client.get(reverse("core:index"))

        self.assertEqual(response.context["priority_incident_count"], 0)
        self.assertEqual(list(response.context["priority_incidents"]), [])
        self.assertContains(response, "No urgent incidents")
