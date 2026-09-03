from django.contrib.auth import get_user_model
from django.test import Client
from config.testcase import AuthedTestCase
from django.urls import reverse

from .models import Organization


class OrganizationProfileViewTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Small Business",
            country="St. Vincent and the Grenadines",
            sector="Retail",
            risk_profile="medium",
        )
        self.profile_url = reverse("organizations:profile")

    def test_get_shows_the_current_organization_fields(self):
        response = self.client.get(self.profile_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Organization Profile")
        self.assertContains(response, "Demo Organization")
        self.assertContains(response, "Small Business")
        self.assertContains(response, "St. Vincent and the Grenadines")
        self.assertContains(response, "Retail")

    def test_post_updates_the_organization_in_place(self):
        response = self.client.post(
            self.profile_url,
            {
                "name": "Renamed Organization",
                "organization_type": "Nonprofit",
                "country": "Barbados",
                "sector": "Healthcare",
                "risk_profile": "high",
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Organization profile updated.")

        self.organization.refresh_from_db()
        self.assertEqual(self.organization.name, "Renamed Organization")
        self.assertEqual(self.organization.organization_type, "Nonprofit")
        self.assertEqual(self.organization.country, "Barbados")
        self.assertEqual(self.organization.sector, "Healthcare")
        self.assertEqual(self.organization.risk_profile, "high")

        # Still exactly one Organization row -- this edits in place, it
        # does not create a second one.
        self.assertEqual(Organization.objects.count(), 1)

    def test_missing_required_field_does_not_save_and_shows_errors(self):
        response = self.client.post(
            self.profile_url,
            {
                "name": "",
                "organization_type": "Nonprofit",
                "country": "Barbados",
                "sector": "Healthcare",
                "risk_profile": "high",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.organization.refresh_from_db()
        self.assertEqual(self.organization.name, "Demo Organization")

    def test_profile_requires_login(self):
        anon = Client()
        response = anon.get(self.profile_url)

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("accounts:login"), response["Location"])

    def test_team_roster_shows_the_authenticated_user_without_invented_fields(self):
        user = get_user_model().objects.create_user(
            username="osreah",
            email="osreah@example.com",
            password="testpass123",
            first_name="Osreah",
            last_name="Bowens",
        )
        self.client.force_login(user)

        response = self.client.get(self.profile_url)

        self.assertContains(response, "Osreah Bowens")
        self.assertContains(response, "osreah@example.com")
        # Still no fabricated status or role.
        self.assertNotContains(response, "audit-status-pill--completed")
        self.assertNotContains(response, ">Active<")
        self.assertNotContains(response, "No user accounts are linked")

    def test_nav_link_present_and_distinct_from_settings(self):
        response = self.client.get(self.profile_url)

        self.assertContains(response, 'href="/organizations/profile/"')
        self.assertContains(response, ">Organization<")
        self.assertContains(response, ">Settings<")


class ProfileExperienceViewTestCase(AuthedTestCase):
    def test_profile_pages_render_with_the_real_user(self):
        for name in ("organizations:my_profile", "organizations:about", "organizations:get_agent"):
            response = self.client.get(reverse(name))
            self.assertEqual(response.status_code, 200)
        response = self.client.get(reverse("organizations:my_profile"))
        # The real logged-in user, not the old hardcoded "Osreah Bowens".
        self.assertContains(response, "Test Analyst")
        self.assertNotContains(response, "Osreah Bowens")
        self.assertNotContains(response, "SOC Analyst")

    def test_experience_mode_is_saved_in_session_only(self):
        response = self.client.post(reverse("organizations:set_experience_mode"), {"mode": "business"})
        self.assertEqual(response.status_code, 200)
        # No invented role in the payload -- there is no role model.
        self.assertEqual(response.json(), {"mode": "business"})
        self.assertEqual(self.client.session["experience_mode"], "business")

    def test_invalid_experience_mode_is_rejected(self):
        response = self.client.post(reverse("organizations:set_experience_mode"), {"mode": "admin"})
        self.assertEqual(response.status_code, 400)

    def test_profile_information_can_be_updated(self):
        response = self.client.post(reverse("organizations:my_profile"), {
            "department": "Security Operations",
            "responsibilities": "Incident response and monitoring",
        }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Incident response and monitoring")
