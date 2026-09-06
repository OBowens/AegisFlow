"""Business Mode per-item action buttons must link to the real
destination for that item, the same as their SOC Mode counterparts --
not to the generic Aegis Assistant chat page.

Three buttons were wired to ``{% url 'organizations:app_assistant' %}``,
ignoring the incident/recommendation they belong to:

* incidents/business_list.html  -- "Start Guided Fix"     (per incident)
* core/business_dashboard.html  -- "Let AegisFlow guide me" (per incident)
* resilience/business_index.html -- "Show me how"          (per recommendation)

SOC Mode's equivalents link to, respectively, the incident's guided
workflow (``investigation_action_url``), the incident detail page, and
the response-plans page (``readiness_plan_url``).
"""

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.resilience.models import DisasterReadinessFinding


def _enable_business_mode(client):
    session = client.session
    session["experience_mode"] = "business"
    session.save()


class BusinessListGuidedFixLinkTests(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization", organization_type="Demo"
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Unusual sign-in attempts on the finance account",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="ACCT-PC",
        )

    def test_start_guided_fix_links_to_the_incident_workflow_not_the_assistant(self):
        _enable_business_mode(self.client)

        response = self.client.get(reverse("incidents:index"))

        self.assertEqual(response.status_code, 200)
        workflow_url = reverse("incidents:investigate", args=[self.incident.id])
        self.assertContains(response, f'href="{workflow_url}">Start Guided Fix</a>')
        self.assertNotContains(
            response, f'{reverse("organizations:app_assistant")}">Start Guided Fix'
        )

    def test_urgent_items_use_the_red_priority_style(self):
        _enable_business_mode(self.client)
        response = self.client.get(reverse("incidents:index"))
        self.assertContains(response, 'class="is-urgent">Urgent</em>')

    def test_guided_fix_uses_the_simple_business_workflow(self):
        _enable_business_mode(self.client)
        response = self.client.get(reverse("incidents:investigate", args=[self.incident.id]))
        self.assertTemplateUsed(response, "incidents/business_workflow.html")
        self.assertContains(response, "Protect your administrator accounts")
        self.assertContains(response, "Step 1 of 3")
        self.assertContains(response, "I've Done This")
        self.assertNotContains(response, "Evidence at a glance")

    def test_soc_mode_keeps_the_existing_analyst_workflow(self):
        response = self.client.get(reverse("incidents:investigate", args=[self.incident.id]))
        self.assertTemplateUsed(response, "incidents/workflow.html")
        self.assertContains(response, "Evidence at a glance")


class BusinessDashboardGuideMeLinkTests(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization", organization_type="Demo"
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Malware blocked on a workstation",
            incident_type="malware",
            severity=IncidentGroup.Severity.CRITICAL,
            status=IncidentGroup.Status.OPEN,
            affected_systems="WS-14",
        )

    def test_guide_me_links_to_the_guided_workflow_not_the_assistant(self):
        _enable_business_mode(self.client)

        response = self.client.get(reverse("core:index"))

        self.assertEqual(response.status_code, 200)
        workflow_url = reverse("incidents:investigate", args=[self.incident.id])
        self.assertContains(response, f'href="{workflow_url}">Let AegisFlow guide me</a>')
        self.assertNotContains(
            response, f'{reverse("organizations:app_assistant")}">Let AegisFlow guide me'
        )


class BusinessReadinessShowMeHowLinkTests(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization", organization_type="Demo"
        )
        for _ in range(3):
            DisasterReadinessFinding.objects.create(
                organization=self.organization,
                readiness_issue="No offsite backup copy confirmed.",
                disaster_impact="Unrecoverable data loss on a single-site failure.",
                recovery_concern="No alternate backup location documented.",
                priority=DisasterReadinessFinding.Priority.CRITICAL,
                source=DisasterReadinessFinding.Source.MANUAL,
            )

    def test_show_me_how_links_to_the_response_plans_page_not_the_assistant(self):
        _enable_business_mode(self.client)

        response = self.client.get(reverse("resilience:index"))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["advisor_recommendations"])
        plan_url = reverse("playbooks:index")
        self.assertContains(response, f'href="{plan_url}">Show me how</a>')
        self.assertNotContains(
            response, f'{reverse("organizations:app_assistant")}">Show me how'
        )
