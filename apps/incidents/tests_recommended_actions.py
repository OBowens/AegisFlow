"""Coverage for the merged "Recommended Next Actions" panel on Incident
Detail (apps.incidents.views._build_recommended_actions /
_resolve_primary_playbook): replaces the old unfiltered/unordered raw
step dump (and the separate "AI-Generated Playbook Steps" panel) with a
single ranked, status-filtered list sourced from one deterministically
chosen playbook, plus real empty/all-done states with no synthetic
guessed text, and a real status control wired to the shared
playbooks:update_step_status endpoint that redirects back to Incident
Detail (not the Playbooks page).
"""

from datetime import timedelta

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditLog
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.playbooks.models import PlaybookStep, ResponsePlaybook

# Fragments of the old incidents/views.py synthetic fallback text
# (_build_recommended_actions used to guess these when no playbook steps
# existed). None of this must ever render again -- the empty state must
# be a real, honest "no data yet" state instead.
OLD_SYNTHETIC_FRAGMENTS = [
    "Force reset of",
    "Enable and enforce MFA for",
    "Contain access to the affected",
    "Review account activity and active sessions for additional signs",
    "Block source IP",
    "Block suspicious inbound sources at the firewall",
    "Increase monitoring and verify backups before returning",
]


class RecommendedActionsRankingTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible brute-force attempt against admin account",
            incident_type="Authentication Attack",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="Email Server",
            summary="Credential abuse requires containment.",
        )
        self.playbook = ResponsePlaybook.objects.create(
            organization=self.organization,
            incident=self.incident,
            title="Credential abuse response playbook",
            status=ResponsePlaybook.Status.ACTIVE,
        )
        self.detail_url = reverse("incidents:detail", args=[self.incident.id])

    def test_completed_and_skipped_steps_are_excluded_from_the_primary_list(self):
        pending = PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=1,
            action="Still pending action.",
            status=PlaybookStep.Status.PENDING,
        )
        completed = PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=2,
            action="Already completed action.",
            status=PlaybookStep.Status.COMPLETED,
        )
        skipped = PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=3,
            action="Skipped action.",
            status=PlaybookStep.Status.SKIPPED,
        )

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, pending.action)
        self.assertNotContains(response, completed.action)
        self.assertNotContains(response, skipped.action)
        # Footer note about the 2 already-resolved steps.
        self.assertContains(response, "2 steps already completed")

    def test_urgency_and_in_progress_ranking_matches_the_approved_ranking(self):
        # Deliberately out of both step_number and urgency order so a
        # correct result can only come from the real sort, not accidental
        # DB / creation order.
        in_progress_low = PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=3,
            action="In-progress low-urgency step.",
            status=PlaybookStep.Status.IN_PROGRESS,
            urgency=PlaybookStep.Urgency.LOW,
        )
        pending_urgent_early = PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=2,
            action="Pending urgent step, step number 2.",
            status=PlaybookStep.Status.PENDING,
            urgency=PlaybookStep.Urgency.URGENT,
        )
        pending_urgent_late = PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=6,
            action="Pending urgent step, step number 6.",
            status=PlaybookStep.Status.PENDING,
            urgency=PlaybookStep.Urgency.URGENT,
        )
        pending_low = PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=1,
            action="Pending low-urgency step.",
            status=PlaybookStep.Status.PENDING,
            urgency=PlaybookStep.Urgency.LOW,
        )
        # Excluded entirely, so it must not affect ranking of the rest.
        PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=4,
            action="Completed urgent step (must be excluded).",
            status=PlaybookStep.Status.COMPLETED,
            urgency=PlaybookStep.Urgency.URGENT,
        )

        response = self.client.get(self.detail_url)
        content = response.content.decode()

        expected_order = [
            in_progress_low.action,   # in-progress beats urgency
            pending_urgent_early.action,  # urgent, lower step_number tie-break
            pending_urgent_late.action,   # urgent, higher step_number
            pending_low.action,       # low urgency, ranks last
        ]
        positions = [content.index(action) for action in expected_order]
        self.assertEqual(positions, sorted(positions))

    def test_undefined_playbook_ordering_bug_is_fixed_with_two_playbooks(self):
        # A second playbook on the SAME incident, created after the first
        # (so it would have a higher PK / later insertion position) --
        # exercising exactly the "which of two playbooks wins" ambiguity
        # the old playbooks[0]-with-no-order_by code had.
        second_playbook = ResponsePlaybook.objects.create(
            organization=self.organization,
            incident=self.incident,
            title="Second, later playbook for the same incident",
            status=ResponsePlaybook.Status.ACTIVE,
        )
        PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=1,
            action="First-created playbook step.",
            status=PlaybookStep.Status.PENDING,
        )
        PlaybookStep.objects.create(
            playbook=second_playbook,
            step_number=1,
            action="Second-created playbook step.",
            status=PlaybookStep.Status.PENDING,
        )

        # Force the FIRST-created playbook to be the most recently updated
        # one -- deliberately inconsistent with creation/PK order, so a
        # passing test can only mean selection is driven by updated_at,
        # not by insertion order (which is what made the old bug undefined
        # in the first place: unordered .all() happens to often return rows
        # in insertion order, which would silently mask this exact case).
        ResponsePlaybook.objects.filter(pk=self.playbook.pk).update(
            updated_at=timezone.now() + timedelta(hours=1)
        )

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "First-created playbook step.")
        self.assertNotContains(response, "Second-created playbook step.")

    def test_no_playbook_shows_a_real_empty_state_with_no_synthetic_text(self):
        # No playbook at all for this incident (self.playbook belongs to a
        # different incident here).
        bare_incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Incident with no playbook yet",
            incident_type="sensor_down",
            severity=IncidentGroup.Severity.MEDIUM,
            status=IncidentGroup.Status.OPEN,
            affected_systems="SENSOR-01",
        )

        response = self.client.get(reverse("incidents:detail", args=[bare_incident.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No response actions yet")
        self.assertContains(response, "Generate AI Playbook")
        self.assertContains(response, reverse("incidents:generate_playbook", args=[bare_incident.id]))
        for fragment in OLD_SYNTHETIC_FRAGMENTS:
            self.assertNotContains(response, fragment)

    def test_playbook_with_zero_steps_also_shows_the_real_empty_state(self):
        empty_playbook_incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Incident whose playbook has no steps yet",
            incident_type="sensor_down",
            severity=IncidentGroup.Severity.MEDIUM,
            status=IncidentGroup.Status.OPEN,
            affected_systems="SENSOR-02",
        )
        ResponsePlaybook.objects.create(
            organization=self.organization,
            incident=empty_playbook_incident,
            title="Playbook with no steps",
            status=ResponsePlaybook.Status.DRAFT,
        )

        response = self.client.get(reverse("incidents:detail", args=[empty_playbook_incident.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No response actions yet")
        for fragment in OLD_SYNTHETIC_FRAGMENTS:
            self.assertNotContains(response, fragment)

    def test_all_steps_completed_or_skipped_shows_the_all_done_state(self):
        PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=1,
            action="Completed step.",
            status=PlaybookStep.Status.COMPLETED,
        )
        PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=2,
            action="Skipped step.",
            status=PlaybookStep.Status.SKIPPED,
        )

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "All response actions complete")
        self.assertNotContains(response, "No response actions yet")
        for fragment in OLD_SYNTHETIC_FRAGMENTS:
            self.assertNotContains(response, fragment)


class RecommendedActionsStatusUpdateTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible brute-force attempt against admin account",
            incident_type="Authentication Attack",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="Email Server",
            summary="Credential abuse requires containment.",
        )
        self.playbook = ResponsePlaybook.objects.create(
            organization=self.organization,
            incident=self.incident,
            title="Credential abuse response playbook",
            status=ResponsePlaybook.Status.ACTIVE,
        )
        self.step = PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=1,
            action="Lock the targeted account.",
            status=PlaybookStep.Status.PENDING,
        )
        # A second step stays pending throughout, so completing self.step
        # exercises the "items" branch's done-count footer rather than
        # flipping the whole panel into the separate all-done state.
        self.other_step = PlaybookStep.objects.create(
            playbook=self.playbook,
            step_number=2,
            action="Notify the account owner.",
            status=PlaybookStep.Status.PENDING,
        )
        self.detail_url = reverse("incidents:detail", args=[self.incident.id])
        self.status_url = reverse("playbooks:update_step_status", args=[self.step.id])

    def test_status_update_from_incident_detail_persists_and_redirects_there(self):
        next_value = f"{self.detail_url}#next-actions-panel"

        response = self.client.post(
            self.status_url,
            {"status": PlaybookStep.Status.COMPLETED, "next": next_value},
        )

        # Redirects back to Incident Detail, not the Playbooks page.
        self.assertRedirects(response, next_value, fetch_redirect_response=False)

        self.step.refresh_from_db()
        self.assertEqual(self.step.status, PlaybookStep.Status.COMPLETED)

        self.assertEqual(AuditLog.objects.count(), 1)
        audit_log = AuditLog.objects.get()
        self.assertEqual(audit_log.action, "playbook_step_status_changed")
        self.assertEqual(audit_log.target_id, str(self.step.id))

        # Reloading Incident Detail reflects the change: the step drops out
        # of the actionable list and the done-count picks it up.
        reload_response = self.client.get(self.detail_url)
        self.assertNotContains(reload_response, "Lock the targeted account.")
        self.assertContains(reload_response, "1 step already completed")

    def test_incident_detail_renders_the_status_form_pointed_at_the_shared_endpoint(self):
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.status_url)
        self.assertContains(response, 'name="status"')
        self.assertNotContains(response, "incident-qa-thread__answer")
