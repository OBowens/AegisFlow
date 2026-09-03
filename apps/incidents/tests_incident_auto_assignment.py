"""Coverage for real incident ownership (IncidentGroup.assigned_to, a
proper FK -- see apps/incidents/migrations/0011_incidentgroup_assigned_to.py,
replacing the old workflow_state["assigned_to"] display-name string):

- Starting the guided workflow auto-assigns the current user, but only
  when the incident is unassigned (apps.incidents.views.
  _auto_assign_investigator, called from incident_workflow's two
  earliest forward-progress POST transitions -- see that function's
  docstring for why both, and why never on a GET).
- incident_assign_to_me (tests_assignment.py covers assigning an
  unassigned incident; this file adds the takeover case) stays the one
  action that can always overwrite an existing assignment.
- The workflow flowbar pill and the two incident-detail "Assigned to"
  spots all say "you"/"Your investigation" for the current user's own
  assignment, and the real name for anyone else's.
- The Work Queue's "Mine" filter pill filters on the real FK.
"""

from django.contrib.auth import get_user_model
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.organizations.models import Organization

from .models import IncidentGroup

User = get_user_model()


def _make_incident(organization, **overrides):
    defaults = {
        "organization": organization,
        "title": "High severity log activity on DB01",
        "incident_type": "log_activity",
        "severity": IncidentGroup.Severity.HIGH,
        "status": IncidentGroup.Status.OPEN,
    }
    defaults.update(overrides)
    return IncidentGroup.objects.create(**defaults)


class AutoAssignOnStartTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Island Tech", organization_type="Business")
        self.incident = _make_incident(self.organization)

    def _post_continue_from_understand(self):
        return self.client.post(
            reverse("incidents:workflow", args=[self.incident.id, "understand"]),
            {"workflow_action": "continue"},
        )

    def test_starting_a_fresh_incidents_workflow_auto_assigns_the_current_user(self):
        self.assertIsNone(self.incident.assigned_to_id)

        response = self._post_continue_from_understand()

        self.assertRedirects(
            response, reverse("incidents:workflow", args=[self.incident.id, "verify"])
        )
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.assigned_to.username, "test-analyst")

    def test_starting_an_already_assigned_incidents_workflow_does_not_reassign_it(self):
        original_owner = User.objects.create_user(username="jane", first_name="Jane", last_name="Ortiz")
        self.incident.assigned_to = original_owner
        self.incident.save(update_fields=["assigned_to"])

        # AuthedTestCase's client logs in as a *different* user
        # ("test-analyst") the moment it makes its first request.
        self._post_continue_from_understand()

        self.incident.refresh_from_db()
        self.assertEqual(self.incident.assigned_to, original_owner)

    def test_merely_viewing_the_workflow_page_never_assigns_anyone(self):
        # GET must never have this side effect -- a page view is not a
        # commitment to work the incident.
        self.client.get(reverse("incidents:workflow", args=[self.incident.id, "understand"]))

        self.incident.refresh_from_db()
        self.assertIsNone(self.incident.assigned_to_id)

    def test_the_overview_stages_own_continue_action_also_auto_assigns(self):
        # Defensive coverage for the other _auto_assign_investigator
        # call site -- the overview stage's own "Start Guided Response"
        # continue action, which no current template actually links to
        # (every real "Start Investigation" entry point goes straight
        # to a GET on "understand"), but the code path exists and must
        # behave the same way if ever reached.
        response = self.client.post(
            reverse("incidents:workflow", args=[self.incident.id, "overview"]),
            {"workflow_action": "continue"},
        )

        self.assertRedirects(
            response, reverse("incidents:workflow", args=[self.incident.id, "understand"])
        )
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.assigned_to.username, "test-analyst")


class AssignToMeTakeoverTestCase(AuthedTestCase):
    """tests_assignment.py already proves incident_assign_to_me assigns
    an unassigned incident; this proves it can also take one over."""

    def setUp(self):
        self.organization = Organization.objects.create(name="Island Tech", organization_type="Business")
        self.original_owner = User.objects.create_user(
            username="jane", first_name="Jane", last_name="Ortiz"
        )
        self.incident = _make_incident(self.organization, assigned_to=self.original_owner)

    def test_assign_to_me_takes_over_an_incident_already_assigned_to_someone_else(self):
        response = self.client.post(reverse("incidents:assign_to_me", args=[self.incident.id]))

        self.assertRedirects(response, f"{reverse('incidents:index')}?tab=queue")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.assigned_to.username, "test-analyst")
        self.assertNotEqual(self.incident.assigned_to, self.original_owner)


class AssignmentRenderingTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Island Tech", organization_type="Business")
        self.colleague = User.objects.create_user(username="jane", first_name="Jane", last_name="Ortiz")

    def test_detail_page_says_you_for_the_current_users_own_assignment(self):
        # "test-analyst" is AuthedTestCase's default login identity --
        # trigger it once so self.client.force_login below is switching
        # *away* from, not establishing for the first time.
        self.client.get(reverse("core:index"))
        current_user = User.objects.get(username="test-analyst")
        incident = _make_incident(self.organization, assigned_to=current_user)

        response = self.client.get(reverse("incidents:detail", args=[incident.id]))
        html = response.content.decode()

        self.assertIn("<small>Assigned to</small><strong>You</strong>", html)
        self.assertIn("<dt>Assigned to</dt><dd>You</dd>", html)
        self.assertNotIn("Test Analyst", html.split("Assigned to")[1][:60])

    def test_detail_page_shows_the_real_name_for_someone_elses_assignment(self):
        incident = _make_incident(self.organization, assigned_to=self.colleague)

        response = self.client.get(reverse("incidents:detail", args=[incident.id]))
        html = response.content.decode()

        self.assertIn("<small>Assigned to</small><strong>Jane Ortiz</strong>", html)
        self.assertIn("<dt>Assigned to</dt><dd>Jane Ortiz</dd>", html)

    def test_detail_page_says_unassigned_when_nobody_owns_it(self):
        incident = _make_incident(self.organization)

        response = self.client.get(reverse("incidents:detail", args=[incident.id]))
        html = response.content.decode()

        self.assertIn("<small>Assigned to</small><strong>Unassigned</strong>", html)

    def test_workflow_flowbar_pill_says_your_investigation_for_the_current_user(self):
        self.client.get(reverse("core:index"))
        current_user = User.objects.get(username="test-analyst")
        incident = _make_incident(self.organization, assigned_to=current_user)

        response = self.client.get(reverse("incidents:workflow", args=[incident.id, "understand"]))
        html = response.content.decode()

        self.assertIn('<p class="af-assignment-pill is-you">', html)
        self.assertIn("Your investigation", html)

    def test_workflow_flowbar_pill_shows_the_real_name_for_someone_else(self):
        incident = _make_incident(self.organization, assigned_to=self.colleague)

        response = self.client.get(reverse("incidents:workflow", args=[incident.id, "understand"]))
        html = response.content.decode()

        self.assertIn('<p class="af-assignment-pill is-other">', html)
        self.assertIn("Assigned to Jane Ortiz", html)

    def test_workflow_flowbar_pill_says_unassigned_when_nobody_owns_it(self):
        incident = _make_incident(self.organization)

        response = self.client.get(reverse("incidents:workflow", args=[incident.id, "understand"]))
        html = response.content.decode()

        self.assertIn('<p class="af-assignment-pill is-unassigned">', html)
        self.assertIn(">Unassigned</p>", html)


class MineFilterPillTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Island Tech", organization_type="Business")
        self.colleague = User.objects.create_user(username="jane", first_name="Jane", last_name="Ortiz")

        # Establish the default logged-in identity before creating
        # per-user fixtures.
        self.client.get(reverse("core:index"))
        self.current_user = User.objects.get(username="test-analyst")

        self.mine = _make_incident(
            self.organization, title="Assigned to me", assigned_to=self.current_user
        )
        self.someone_elses = _make_incident(
            self.organization, title="Assigned to Jane", assigned_to=self.colleague
        )
        self.unassigned = _make_incident(self.organization, title="Not assigned yet")

    def test_mine_pill_shows_only_the_current_users_assigned_incidents(self):
        response = self.client.get(f"{reverse('incidents:index')}?tab=queue&assigned=me")
        html = response.content.decode()

        self.assertContains(response, "Assigned to me")
        self.assertNotContains(response, "Assigned to Jane")
        self.assertNotContains(response, "Not assigned yet")
        self.assertIn(
            f'<a class="af-filter-pill is-active" href="{reverse("incidents:index")}?tab=queue&amp;assigned=me">Mine <span>1</span></a>',
            html,
        )

    def test_all_pill_still_shows_every_incident_and_the_correct_mine_count(self):
        response = self.client.get(f"{reverse('incidents:index')}?tab=queue")
        html = response.content.decode()

        self.assertContains(response, "Assigned to me")
        self.assertContains(response, "Assigned to Jane")
        self.assertContains(response, "Not assigned yet")
        self.assertIn(f'<a class="af-filter-pill is-active" href="{reverse("incidents:index")}?tab=queue">All', html)
        self.assertIn("Mine <span>1</span>", html)
