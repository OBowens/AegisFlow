"""apps/ai_core/views.py's reveal_alias endpoint.

Covers the three cases the view is responsible for logging (allowed,
denied, not-found), the organization-scoped lookup, and -- the one fact
that has to be verified empirically rather than assumed -- exactly what
happens to a genuinely raw, cookie-less anonymous POST: does it reach the
view at all, and is it logged.
"""

from __future__ import annotations

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.audit.models import AuditLog
from apps.ai_core.models import AliasMapping
from apps.organizations.models import Organization
from config.testcase import AuthedTestCase


def _make_org(name="Northwind Trading Co"):
    return Organization.objects.create(
        name=name,
        organization_type="SMB",
        country="St. Vincent and the Grenadines",
        sector="Retail",
        risk_profile="medium",
    )


def _make_alias(organization, real_value="203.0.113.9", identifier_type="IP", sequence=1):
    return AliasMapping.objects.create(
        organization=organization,
        identifier_type=identifier_type,
        normalized_value=real_value,
        real_value=real_value,
        sequence=sequence,
    )


class RevealAliasViewTests(AuthedTestCase):
    def setUp(self):
        self.organization = _make_org()

    def test_reveal_allowed_returns_real_value_and_is_logged(self):
        alias = _make_alias(self.organization)

        with patch(
            "apps.ai_core.views.get_current_organization",
            return_value=self.organization,
        ):
            response = self.client.post(reverse("ai_core:reveal_alias", args=[alias.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["real_value"], "203.0.113.9")

        log = AuditLog.objects.get()
        self.assertEqual(log.action, "reveal_alias")
        self.assertEqual(log.target_type, "AliasMapping")
        self.assertEqual(log.target_id, str(alias.pk))
        self.assertEqual(log.organization, self.organization)
        self.assertIsNotNone(log.user)

    def test_reveal_not_found_for_another_organizations_alias_and_is_logged(self):
        other_org = _make_org("Someone Else Ltd")
        other_orgs_alias = _make_alias(other_org)

        with patch(
            "apps.ai_core.views.get_current_organization",
            return_value=self.organization,
        ):
            response = self.client.post(
                reverse("ai_core:reveal_alias", args=[other_orgs_alias.pk])
            )

        self.assertEqual(response.status_code, 404)

        log = AuditLog.objects.get()
        self.assertEqual(log.action, "reveal_alias_not_found")
        self.assertEqual(log.target_id, str(other_orgs_alias.pk))
        self.assertEqual(log.organization, self.organization)

    def test_reveal_not_found_for_nonexistent_pk_is_logged(self):
        with patch(
            "apps.ai_core.views.get_current_organization",
            return_value=self.organization,
        ):
            response = self.client.post(reverse("ai_core:reveal_alias", args=[999999]))

        self.assertEqual(response.status_code, 404)
        log = AuditLog.objects.get()
        self.assertEqual(log.action, "reveal_alias_not_found")
        self.assertEqual(log.target_id, "999999")

    def test_denied_reveal_is_logged_even_though_can_reveal_is_unreachable_via_http_today(self):
        # can_reveal() only checks is_authenticated, and LoginRequiredMiddleware
        # already blocks every unauthenticated request before it reaches any
        # view -- so this branch can't actually be hit over real HTTP today.
        # It is exercised directly here so the logging behaviour for it is
        # proven now, before real per-user/per-role rules make it reachable.
        alias = _make_alias(self.organization)

        with patch(
            "apps.ai_core.views.get_current_organization",
            return_value=self.organization,
        ), patch("apps.ai_core.views.can_reveal", return_value=False):
            response = self.client.post(reverse("ai_core:reveal_alias", args=[alias.pk]))

        self.assertEqual(response.status_code, 403)
        log = AuditLog.objects.get()
        self.assertEqual(log.action, "reveal_alias_denied")
        self.assertEqual(log.target_id, str(alias.pk))


class RevealAliasCsrfTests(TestCase):
    """What actually happens to a raw anonymous request with no CSRF
    cookie at all -- not the test client's default CSRF-exempt behaviour.
    """

    def setUp(self):
        self.organization = _make_org()
        self.alias = _make_alias(self.organization)

    def test_raw_anonymous_request_without_csrf_token_never_reaches_the_view(self):
        raw_client = Client(enforce_csrf_checks=True)

        with patch(
            "apps.ai_core.views.get_current_organization",
            return_value=self.organization,
        ):
            response = raw_client.post(
                reverse("ai_core:reveal_alias", args=[self.alias.pk])
            )

        # CsrfViewMiddleware runs (and rejects) before LoginRequiredMiddleware
        # even gets a chance to redirect the anonymous request, and long
        # before the view itself runs -- so this is a 403 from CSRF, not a
        # login redirect, and no AuditLog row exists for it at all.
        self.assertEqual(response.status_code, 403)
        self.assertEqual(AuditLog.objects.count(), 0)

    def test_authenticated_request_still_requires_a_valid_csrf_token(self):
        user = get_user_model().objects.create_user(
            username="analyst", password="not-used-in-this-test"
        )
        raw_client = Client(enforce_csrf_checks=True)
        raw_client.force_login(user)

        with patch(
            "apps.ai_core.views.get_current_organization",
            return_value=self.organization,
        ):
            response = raw_client.post(
                reverse("ai_core:reveal_alias", args=[self.alias.pk])
            )

        # Authenticated, but no CSRF token: still rejected before the view,
        # still not logged. Confirms CSRF -- not just login -- gates entry.
        self.assertEqual(response.status_code, 403)
        self.assertEqual(AuditLog.objects.count(), 0)
