"""HTTP coverage for POST /endpoints/api/enroll/.

Uses a plain (unauthenticated) client on purpose: the agent has no
Django session, and these tests double as proof that
`LoginRequiredMiddleware` does not intercept the endpoint.
"""

from __future__ import annotations

import json

from django.test import Client, TestCase
from django.urls import reverse

from apps.endpoints.models import Endpoint
from apps.organizations.models import Organization


def _make_org(name="AegisFlow AI Demo Organization"):
    return Organization.objects.create(
        name=name,
        organization_type="Demo",
        country="St. Vincent and the Grenadines",
        sector="Demo",
        risk_profile="medium",
    )


class EnrollApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse("endpoints:enroll")
        self.org = _make_org()
        self.endpoint, self.token = Endpoint.issue(
            organization=self.org, display_name="PILOT-3"
        )

    def _post(self, body):
        return self.client.post(
            self.url, data=json.dumps(body), content_type="application/json"
        )

    def test_valid_token_binds_name_without_a_login(self):
        response = self._post(
            {"token": self.token, "display_name": "WEB-01"}
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["endpoint"]["display_name"], "WEB-01")
        self.assertEqual(payload["endpoint"]["organization"], self.org.name)
        self.assertFalse(payload["name_was_adjusted"])
        self.endpoint.refresh_from_db()
        self.assertEqual(self.endpoint.display_name, "WEB-01")

    def test_name_collision_is_reported_in_the_response(self):
        Endpoint.objects.create(organization=self.org, display_name="WEB-01")
        response = self._post(
            {"token": self.token, "display_name": "WEB-01"}
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["name_was_adjusted"])
        self.assertEqual(payload["endpoint"]["display_name"], "WEB-01-2")

    def test_unknown_token_is_401(self):
        response = self._post({"token": "nope", "display_name": "WEB-01"})
        self.assertEqual(response.status_code, 401)

    def test_missing_token_is_400(self):
        response = self._post({"display_name": "WEB-01"})
        self.assertEqual(response.status_code, 400)

    def test_non_string_display_name_is_400(self):
        response = self._post(
            {"token": self.token, "display_name": 5}
        )
        self.assertEqual(response.status_code, 400)

    def test_malformed_json_is_400(self):
        response = self.client.post(
            self.url, data="{not json", content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)

    def test_get_is_405(self):
        self.assertEqual(self.client.get(self.url).status_code, 405)

    def test_no_csrf_token_required(self):
        # CsrfViewMiddleware is active project-wide; an enforced client
        # would get a 403 here if the view were not exempt.
        enforced = Client(enforce_csrf_checks=True)
        response = enforced.post(
            self.url,
            data=json.dumps(
                {"token": self.token, "display_name": "WEB-09"}
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
