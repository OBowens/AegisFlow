"""Coverage for the real Linked SOP / Checklist toggle
(apps.playbooks.views.playbook_toggle_checklist_item): confirms the
decorative aria-hidden span is gone, a real checkbox POSTs to a real
endpoint, completion persists to ChecklistItemState across a fresh page
load, and that state is scoped per incident -- checking an item on one
incident sharing the same SOPChecklist does not check it on another.
"""

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.playbooks.models import ChecklistItemState, PlaybookStep, ResponsePlaybook, SOPChecklist
from apps.playbooks.services.text_parsing import checklist_item_key


class ChecklistItemToggleTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.checklist = SOPChecklist.objects.create(
            name="Authentication attack checklist",
            incident_type="Authentication Attack",
            checklist_items=(
                "Verify incident details and affected account\n"
                "Collect and preserve relevant logs\n"
                "Lock account and reset credentials"
            ),
            version="1.0",
            is_active=True,
        )

        self.incident_a = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible brute-force attempt against admin account",
            incident_type="Authentication Attack",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="Email Server",
            summary="Credential abuse requires containment.",
        )
        self.playbook_a = ResponsePlaybook.objects.create(
            organization=self.organization,
            incident=self.incident_a,
            title="Credential abuse response playbook A",
            status=ResponsePlaybook.Status.ACTIVE,
        )
        PlaybookStep.objects.create(
            playbook=self.playbook_a,
            step_number=1,
            action="Review failed login attempts",
            status=PlaybookStep.Status.PENDING,
        )

        self.incident_b = IncidentGroup.objects.create(
            organization=self.organization,
            title="Second, unrelated brute-force attempt",
            incident_type="Authentication Attack",
            severity=IncidentGroup.Severity.MEDIUM,
            status=IncidentGroup.Status.OPEN,
            affected_systems="VPN Gateway",
            summary="Same SOP applies, independent incident.",
        )
        self.playbook_b = ResponsePlaybook.objects.create(
            organization=self.organization,
            incident=self.incident_b,
            title="Credential abuse response playbook B",
            status=ResponsePlaybook.Status.ACTIVE,
        )
        PlaybookStep.objects.create(
            playbook=self.playbook_b,
            step_number=1,
            action="Review failed login attempts",
            status=PlaybookStep.Status.PENDING,
        )

        self.item_key = checklist_item_key("Verify incident details and affected account")
        self.toggle_url_a = reverse(
            "playbooks:toggle_checklist_item", args=[self.incident_a.id, self.checklist.id]
        )
        self.toggle_url_b = reverse(
            "playbooks:toggle_checklist_item", args=[self.incident_b.id, self.checklist.id]
        )
        self.playbook_page_a = f"{reverse('playbooks:index')}?playbook={self.playbook_a.id}"
        self.playbook_page_b = f"{reverse('playbooks:index')}?playbook={self.playbook_b.id}"

    def test_checkbox_is_a_real_input_not_a_decorative_span(self):
        response = self.client.get(self.playbook_page_a)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'class="playbook-checklist-reference__checkbox"')
        self.assertContains(response, self.toggle_url_a)
        self.assertNotContains(
            response, '<span class="playbook-checklist-reference__box" aria-hidden="true"></span>'
        )

    def test_get_request_does_not_toggle(self):
        response = self.client.get(self.toggle_url_a)

        self.assertRedirects(response, reverse("playbooks:index"))
        self.assertEqual(ChecklistItemState.objects.count(), 0)

    def test_toggle_persists_across_a_fresh_page_load(self):
        response = self.client.post(
            self.toggle_url_a,
            {"item_key": self.item_key, "next": self.playbook_page_a},
        )
        self.assertRedirects(response, self.playbook_page_a)

        state = ChecklistItemState.objects.get(incident=self.incident_a, checklist=self.checklist)
        self.assertTrue(state.is_completed)
        self.assertIsNotNone(state.completed_at)

        page = self.client.get(self.playbook_page_a)
        self.assertContains(page, "is-checked")
        self.assertContains(page, 'checked')

        # Toggling again flips it back off and clears completed_at.
        self.client.post(self.toggle_url_a, {"item_key": self.item_key, "next": self.playbook_page_a})
        state.refresh_from_db()
        self.assertFalse(state.is_completed)
        self.assertIsNone(state.completed_at)

    def test_toggle_is_scoped_per_incident_not_per_sop_template(self):
        self.client.post(self.toggle_url_a, {"item_key": self.item_key, "next": self.playbook_page_a})

        state_a = ChecklistItemState.objects.get(incident=self.incident_a, checklist=self.checklist)
        self.assertTrue(state_a.is_completed)

        # Same checklist, different incident: must still read as unchecked.
        self.assertFalse(
            ChecklistItemState.objects.filter(
                incident=self.incident_b, checklist=self.checklist, is_completed=True
            ).exists()
        )

        page_b = self.client.get(self.playbook_page_b)
        self.assertNotContains(page_b, "is-checked")

        page_a = self.client.get(self.playbook_page_a)
        self.assertContains(page_a, "is-checked")

    def test_missing_item_key_is_ignored(self):
        response = self.client.post(self.toggle_url_a, {"next": self.playbook_page_a})

        self.assertRedirects(response, self.playbook_page_a)
        self.assertEqual(ChecklistItemState.objects.count(), 0)

    def test_next_param_outside_playbooks_is_ignored_for_safety(self):
        response = self.client.post(
            self.toggle_url_a,
            {"item_key": self.item_key, "next": "https://evil.example.com/"},
        )

        self.assertRedirects(response, reverse("playbooks:index"))
