"""Coverage for the "Use Existing Incident" dropdown scoping
(apps.playbooks.views._build_source_options): by default the select
lists only open/investigating incidents, resolved/closed incidents are
excluded unless ?show_all=1 (or already selected), and a "Show all
incidents" link exposes the full list.
"""

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization


class IncidentDropdownScopingTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.open_incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Open brute-force attempt",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="WEB-01",
            summary="Still open.",
        )
        self.investigating_incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Investigating suspicious login",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.MEDIUM,
            status=IncidentGroup.Status.INVESTIGATING,
            affected_systems="WEB-02",
            summary="Being investigated.",
        )
        self.closed_incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Closed brute-force attempt from last month",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.LOW,
            status=IncidentGroup.Status.CLOSED,
            affected_systems="WEB-03",
            summary="Long resolved.",
        )
        self.resolved_incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Resolved sensor down alert",
            incident_type="sensor_down",
            severity=IncidentGroup.Severity.LOW,
            status=IncidentGroup.Status.RESOLVED,
            affected_systems="SENSOR-01",
            summary="Resolved.",
        )
        self.index_url = reverse("playbooks:index")

    def test_default_view_shows_only_open_and_investigating_incidents(self):
        response = self.client.get(self.index_url)

        self.assertEqual(response.status_code, 200)
        # Assert against the <option> tags themselves (not raw title text,
        # which can legitimately also appear in the Incident Summary panel
        # for whichever incident got auto-selected).
        self.assertContains(response, f'<option value="{self.open_incident.id}"')
        self.assertContains(response, f'<option value="{self.investigating_incident.id}"')
        self.assertNotContains(response, f'<option value="{self.closed_incident.id}"')
        self.assertNotContains(response, f'<option value="{self.resolved_incident.id}"')
        self.assertContains(response, "Show all incidents")
        self.assertContains(response, "Showing 2 open/investigating incidents")

    def test_show_all_param_reveals_the_full_list(self):
        response = self.client.get(self.index_url, {"show_all": "1"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f'<option value="{self.open_incident.id}"')
        self.assertContains(response, f'<option value="{self.investigating_incident.id}"')
        self.assertContains(response, f'<option value="{self.closed_incident.id}"')
        self.assertContains(response, f'<option value="{self.resolved_incident.id}"')
        self.assertContains(response, "Show open/investigating only")
        self.assertContains(response, "Showing all 4 incidents")

    def test_deep_link_to_an_out_of_scope_incident_still_shows_it_selected(self):
        response = self.client.get(self.index_url, {"incident": self.closed_incident.id})

        self.assertEqual(response.status_code, 200)
        # Closed incident is out of the default open/investigating scope,
        # but since it's the explicitly selected one it must not disappear.
        self.assertContains(
            response, f'<option value="{self.closed_incident.id}" selected'
        )
        # The other out-of-scope incident is still excluded.
        self.assertNotContains(response, f'<option value="{self.resolved_incident.id}"')

    def test_type_to_filter_input_and_search_data_are_rendered(self):
        response = self.client.get(self.index_url)

        self.assertContains(response, 'id="incident-filter-input"')
        self.assertContains(response, 'id="incident-select"')
        self.assertContains(response, "data-search=")

    def test_plain_select_element_is_still_used_no_framework_widget(self):
        response = self.client.get(self.index_url)

        self.assertContains(response, "<select name=\"incident\"")
