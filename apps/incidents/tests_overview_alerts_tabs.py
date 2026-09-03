"""Coverage for the restored Overview/Alerts/Queue tabs on
incidents:index (list.html): _resolve_active_tab and
build_overview_and_alerts_context were always real -- this proves the
template branching that was missing now genuinely renders tab-specific
content, and that every dangling ?tab= link elsewhere in the app now
lands on real content instead of always rendering the same Queue markup.
"""

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.incidents.models import IncidentEvidence, IncidentGroup
from apps.log_intake.models import ParsedAlert, UploadedLogFile
from apps.organizations.models import Organization


class OverviewAlertsQueueTabsTestCase(AuthedTestCase):
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
            file_name="tabs_demo.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path="demo/tabs_demo.log",
            status=UploadedLogFile.Status.PARSED,
        )
        self.alert = ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="Microsoft Sentinel",
            timestamp=timezone.now(),
            affected_system="WS-15",
            event_type="suspicious_scheduled_task",
            severity_hint=ParsedAlert.SeverityHint.MEDIUM,
            raw_message="Scheduled task created unexpectedly",
            normalized_summary="Suspicious scheduled task creation detected",
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible brute-force attempt against privileged account",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="WEB-01",
        )
        IncidentEvidence.objects.create(
            incident=self.incident, alert=self.alert, evidence_reason="test"
        )
        self.index_url = reverse("incidents:index")

    def test_bare_get_resolves_to_overview_and_shows_real_overview_content(self):
        response = self.client.get(self.index_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<a class="is-active" href="/incidents/?tab=overview">Overview</a>')
        # Overview-tab-only content: the results metrics grid and AI summary.
        self.assertContains(response, "Parsed Alerts")
        self.assertContains(response, "Grouped Incidents")
        self.assertContains(response, "Key Findings")
        self.assertContains(response, "Recommended Next Step")
        # Queue-tab-only content must NOT be present on Overview.
        self.assertNotContains(response, "af-incident-stack")
        self.assertNotContains(response, "Start Investigation")

    def test_tab_overview_explicit_param_matches_bare_get(self):
        response = self.client.get(f"{self.index_url}?tab=overview")
        self.assertContains(response, "Recommended Next Step")
        self.assertContains(
            response, f'<a class="is-active" href="{self.index_url}?tab=overview">Overview</a>'
        )

    def test_tab_alerts_shows_the_real_parsed_alert_table_and_filters(self):
        response = self.client.get(f"{self.index_url}?tab=alerts")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Suspicious scheduled task creation detected")
        self.assertContains(response, "Microsoft Sentinel")
        self.assertContains(response, 'id="incidents-alert-severity"')
        self.assertContains(response, 'id="incidents-alert-source"')
        self.assertContains(response, 'id="incidents-alert-system"')
        self.assertContains(
            response, f'<a class="is-active" href="{self.index_url}?tab=alerts">Alerts</a>'
        )
        # Queue-tab-only content must NOT be present on Alerts.
        self.assertNotContains(response, "af-incident-stack")

    def test_tab_alerts_filter_form_preserves_tab_param(self):
        response = self.client.get(f"{self.index_url}?tab=alerts")
        self.assertContains(response, '<input type="hidden" name="tab" value="alerts">')

    def test_tab_alerts_severity_filter_actually_filters(self):
        ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="Wazuh",
            timestamp=timezone.now(),
            affected_system="DB-01",
            event_type="low_priority_event",
            severity_hint=ParsedAlert.SeverityHint.LOW,
            raw_message="benign",
            normalized_summary="A totally unrelated low-severity finding",
        )

        response = self.client.get(f"{self.index_url}?tab=alerts&alert_severity=medium")

        self.assertContains(response, "Suspicious scheduled task creation detected")
        self.assertNotContains(response, "A totally unrelated low-severity finding")

    def test_tab_queue_still_shows_the_incident_list_unchanged(self):
        response = self.client.get(f"{self.index_url}?tab=queue")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Possible brute-force attempt against privileged account")
        self.assertContains(response, "af-incident-stack")
        self.assertContains(
            response, f'<a class="is-active" href="{self.index_url}?tab=queue">Queue</a>'
        )
        # Overview/Alerts-only content must NOT leak onto Queue.
        self.assertNotContains(response, "Recommended Next Step")

    def test_severity_status_query_params_alone_still_resolve_to_queue(self):
        # _resolve_active_tab's existing signal-param inference (real,
        # pre-existing logic, untouched) -- proves the restored template
        # branching respects it correctly.
        response = self.client.get(f"{self.index_url}?severity=high")
        self.assertContains(response, "af-incident-stack")
        self.assertNotContains(response, "Recommended Next Step")

    def test_alert_query_params_alone_still_resolve_to_alerts(self):
        response = self.client.get(f"{self.index_url}?alert_severity=medium")
        self.assertContains(response, "Suspicious scheduled task creation detected")
        self.assertNotContains(response, "af-incident-stack")


class DanglingTabLinksNowLandOnRealContentTestCase(AuthedTestCase):
    """Every entry point elsewhere in the app that links to
    incidents:index with a ?tab= param used to render the exact same
    Queue markup regardless of which tab it claimed to target. Confirms
    each of those concrete destinations now shows genuinely different,
    tab-appropriate content.
    """

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )

    def test_help_popover_and_get_agent_ask_aegisflow_link_lands_on_real_overview(self):
        # apps/organizations/templates/organizations/get_agent.html and the
        # global nav's Help popover both link to exactly this URL.
        response = self.client.get(f"{reverse('incidents:index')}?tab=overview")
        self.assertContains(response, "Recommended Next Step")
        self.assertNotContains(response, "af-incident-stack")

    def test_queue_overview_modal_view_all_alerts_link_lands_on_real_alerts_tab(self):
        # The Queue page's own "How to use the queue" modal links to
        # ?tab=alerts as a "quick action" -- must not just reopen Queue.
        response = self.client.get(f"{reverse('incidents:index')}?tab=alerts")
        self.assertContains(response, 'id="incidents-alert-severity"')
        self.assertNotContains(response, "af-incident-stack")

    def test_queue_overview_modal_ask_ai_assistant_link_lands_on_real_overview(self):
        response = self.client.get(f"{reverse('incidents:index')}?tab=overview")
        self.assertContains(response, "Key Findings")
        self.assertNotContains(response, "af-incident-stack")

    def test_all_three_tab_links_are_distinct_pages(self):
        # A stronger end-to-end proof than checking each individually --
        # the three tabs must not all reduce to identical HTML.
        overview = self.client.get(f"{reverse('incidents:index')}?tab=overview").content
        alerts = self.client.get(f"{reverse('incidents:index')}?tab=alerts").content
        queue = self.client.get(f"{reverse('incidents:index')}?tab=queue").content

        self.assertNotEqual(overview, alerts)
        self.assertNotEqual(overview, queue)
        self.assertNotEqual(alerts, queue)
