"""HTTP coverage for POST /endpoints/api/ingest/."""

from __future__ import annotations

import json

from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.endpoints.models import Endpoint, EndpointEvent
from apps.endpoints.views import MAX_EVENTS_PER_BATCH
from apps.organizations.models import Organization


def _make_org(name="AegisFlow AI Demo Organization"):
    return Organization.objects.create(
        name=name,
        organization_type="Demo",
        country="St. Vincent and the Grenadines",
        sector="Demo",
        risk_profile="medium",
    )


def _event(event_type="Security/4625", occurred_at="2026-09-02T12:00:00Z", **payload):
    return {"event_type": event_type, "occurred_at": occurred_at, "payload": payload}


class IngestApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse("endpoints:ingest")
        self.org = _make_org()
        self.endpoint, self.token = Endpoint.issue(
            organization=self.org, display_name="WEB-01"
        )

    def _post(self, body, token=None, **extra):
        headers = {}
        if token is not None:
            headers["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        return self.client.post(
            self.url,
            data=json.dumps(body),
            content_type="application/json",
            **headers,
            **extra,
        )

    def test_valid_batch_is_stored_and_updates_last_seen(self):
        before = timezone.now()
        response = self._post(
            {"events": [_event(logon_type="3"), _event(event_type="System/7045")]},
            token=self.token,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"accepted": 2})

        events = list(EndpointEvent.objects.order_by("id"))
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].endpoint, self.endpoint)
        self.assertEqual(events[0].organization, self.org)
        self.assertEqual(events[0].event_type, "Security/4625")
        self.assertEqual(events[0].payload, {"logon_type": "3"})
        self.assertEqual(events[0].occurred_at.year, 2026)

        self.endpoint.refresh_from_db()
        self.assertIsNotNone(self.endpoint.last_seen)
        self.assertGreaterEqual(self.endpoint.last_seen, before)

    def test_empty_event_list_is_accepted_and_still_touches_last_seen(self):
        response = self._post({"events": []}, token=self.token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"accepted": 0})
        self.endpoint.refresh_from_db()
        self.assertIsNotNone(self.endpoint.last_seen)

    def test_missing_token_is_401(self):
        response = self._post({"events": [_event()]})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(EndpointEvent.objects.count(), 0)

    def test_bad_token_is_401(self):
        response = self._post({"events": [_event()]}, token="wrong-token")
        self.assertEqual(response.status_code, 401)

    def test_stored_hash_is_not_accepted_as_a_bearer_token(self):
        response = self._post(
            {"events": [_event()]}, token=self.endpoint.token_hash
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(EndpointEvent.objects.count(), 0)

    def test_bare_authorization_header_without_scheme_is_accepted(self):
        response = self.client.post(
            self.url,
            data=json.dumps({"events": [_event()]}),
            content_type="application/json",
            HTTP_AUTHORIZATION=self.token,
        )
        self.assertEqual(response.status_code, 200)

    def test_malformed_json_is_400(self):
        response = self.client.post(
            self.url,
            data="{ bad",
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        self.assertEqual(response.status_code, 400)

    def test_events_not_a_list_is_400(self):
        response = self._post({"events": {}}, token=self.token)
        self.assertEqual(response.status_code, 400)

    def test_event_missing_event_type_rejects_whole_batch(self):
        bad = {"occurred_at": "2026-09-02T12:00:00Z"}
        response = self._post(
            {"events": [_event(), bad]}, token=self.token
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(EndpointEvent.objects.count(), 0)

    def test_event_with_unparseable_timestamp_is_400(self):
        response = self._post(
            {"events": [_event(occurred_at="last tuesday")]},
            token=self.token,
        )
        self.assertEqual(response.status_code, 400)

    def test_event_payload_must_be_object(self):
        response = self._post(
            {"events": [{"event_type": "x", "occurred_at": "2026-09-02T12:00:00Z", "payload": []}]},
            token=self.token,
        )
        self.assertEqual(response.status_code, 400)

    def test_payload_defaults_to_empty_dict_when_omitted(self):
        response = self._post(
            {"events": [{"event_type": "x", "occurred_at": "2026-09-02T12:00:00Z"}]},
            token=self.token,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(EndpointEvent.objects.get().payload, {})

    def test_batch_over_limit_is_400(self):
        response = self._post(
            {"events": [_event() for _ in range(MAX_EVENTS_PER_BATCH + 1)]},
            token=self.token,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(EndpointEvent.objects.count(), 0)

    def test_get_is_405(self):
        self.assertEqual(self.client.get(self.url).status_code, 405)

    def test_naive_timestamp_is_made_aware(self):
        response = self._post(
            {"events": [_event(occurred_at="2026-09-02T12:00:00")]},
            token=self.token,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(timezone.is_aware(EndpointEvent.objects.get().occurred_at))
