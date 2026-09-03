"""Model + enrollment-service coverage for the Windows Endpoint Analyzer
data layer (feature Part 1).
"""

from __future__ import annotations

import hashlib

from django.db import IntegrityError, transaction
from django.test import TestCase

from apps.endpoints.models import (
    Endpoint,
    generate_raw_token,
    hash_token,
)
from apps.endpoints.services import enroll_endpoint, resolve_available_name
from apps.organizations.models import Organization


def _make_org(name="AegisFlow AI Demo Organization"):
    return Organization.objects.create(
        name=name,
        organization_type="Demo",
        country="St. Vincent and the Grenadines",
        sector="Demo",
        risk_profile="medium",
    )


class TokenHashingTests(TestCase):
    def test_hash_token_is_plain_sha256_hex(self):
        self.assertEqual(
            hash_token("abc"),
            hashlib.sha256(b"abc").hexdigest(),
        )
        self.assertEqual(len(hash_token("abc")), 64)

    def test_hash_token_strips_surrounding_whitespace(self):
        self.assertEqual(hash_token("  abc\n"), hash_token("abc"))

    def test_generate_raw_token_returns_distinct_url_safe_values(self):
        a, b = generate_raw_token(), generate_raw_token()
        self.assertNotEqual(a, b)
        self.assertNotIn("/", a)
        self.assertNotIn("+", a)


class EndpointModelTests(TestCase):
    def setUp(self):
        self.org = _make_org()

    def test_issue_returns_raw_token_and_stores_only_its_hash(self):
        endpoint, raw_token = Endpoint.issue(
            organization=self.org, display_name="WEB-01"
        )
        self.assertTrue(raw_token)
        self.assertEqual(endpoint.token_hash, hash_token(raw_token))
        # The raw token appears nowhere on the persisted row.
        endpoint.refresh_from_db()
        self.assertEqual(endpoint.token_hash, hash_token(raw_token))
        self.assertNotEqual(endpoint.token_hash, raw_token)
        row = Endpoint.objects.filter(pk=endpoint.pk).values().get()
        self.assertNotIn(raw_token, [str(v) for v in row.values()])

    def test_token_hash_auto_populates_for_a_plain_create(self):
        one = Endpoint.objects.create(organization=self.org, display_name="A")
        two = Endpoint.objects.create(organization=self.org, display_name="B")
        self.assertEqual(len(one.token_hash), 64)
        self.assertNotEqual(one.token_hash, two.token_hash)

    def test_issued_tokens_and_hashes_are_unique(self):
        raws = set()
        hashes = set()
        for i in range(25):
            endpoint, raw = Endpoint.issue(
                organization=self.org, display_name=f"HOST-{i}"
            )
            raws.add(raw)
            hashes.add(endpoint.token_hash)
        self.assertEqual(len(raws), 25)
        self.assertEqual(len(hashes), 25)

    def test_last_seen_defaults_to_null(self):
        endpoint, _ = Endpoint.issue(organization=self.org, display_name="WEB-01")
        self.assertIsNone(endpoint.last_seen)

    def test_display_name_unique_per_org(self):
        Endpoint.objects.create(organization=self.org, display_name="WEB-01")
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Endpoint.objects.create(organization=self.org, display_name="WEB-01")

    def test_same_display_name_allowed_in_a_different_org(self):
        other = _make_org(name="Second Org")
        Endpoint.objects.create(organization=self.org, display_name="WEB-01")
        Endpoint.objects.create(organization=other, display_name="WEB-01")


class ResolveAvailableNameTests(TestCase):
    def setUp(self):
        self.org = _make_org()

    def test_free_name_is_returned_unchanged(self):
        self.assertEqual(resolve_available_name(self.org, "WEB-01"), "WEB-01")

    def test_taken_name_gets_numeric_suffix(self):
        Endpoint.objects.create(organization=self.org, display_name="WEB-01")
        self.assertEqual(resolve_available_name(self.org, "WEB-01"), "WEB-01-2")

    def test_suffix_walks_past_multiple_collisions(self):
        Endpoint.objects.create(organization=self.org, display_name="WEB-01")
        Endpoint.objects.create(organization=self.org, display_name="WEB-01-2")
        self.assertEqual(resolve_available_name(self.org, "WEB-01"), "WEB-01-3")

    def test_collision_check_is_case_insensitive(self):
        Endpoint.objects.create(organization=self.org, display_name="web-01")
        self.assertEqual(resolve_available_name(self.org, "WEB-01"), "WEB-01-2")

    def test_excluded_pk_is_not_treated_as_a_collision(self):
        endpoint = Endpoint.objects.create(organization=self.org, display_name="WEB-01")
        self.assertEqual(
            resolve_available_name(self.org, "WEB-01", exclude_pk=endpoint.pk), "WEB-01"
        )


class EnrollEndpointServiceTests(TestCase):
    def setUp(self):
        self.org = _make_org()
        self.endpoint, self.token = Endpoint.issue(
            organization=self.org, display_name="PILOT-3"
        )

    def test_unknown_token_returns_none(self):
        self.assertIsNone(enroll_endpoint("not-a-real-token", "WEB-01"))

    def test_blank_token_returns_none(self):
        self.assertIsNone(enroll_endpoint("   ", "WEB-01"))

    def test_lookup_is_by_hash_not_raw_value(self):
        # Passing the stored hash itself must NOT authenticate.
        self.assertIsNone(enroll_endpoint(self.endpoint.token_hash, "WEB-01"))

    def test_binds_requested_name(self):
        result = enroll_endpoint(self.token, "WEB-01")
        self.assertIsNotNone(result)
        self.assertFalse(result.name_was_suffixed)
        self.endpoint.refresh_from_db()
        self.assertEqual(self.endpoint.display_name, "WEB-01")

    def test_same_name_is_idempotent_noop(self):
        result = enroll_endpoint(self.token, "pilot-3")
        self.assertFalse(result.name_was_suffixed)
        self.endpoint.refresh_from_db()
        self.assertEqual(self.endpoint.display_name, "PILOT-3")

    def test_empty_name_keeps_provisioning_name(self):
        result = enroll_endpoint(self.token, "")
        self.assertFalse(result.name_was_suffixed)
        self.endpoint.refresh_from_db()
        self.assertEqual(self.endpoint.display_name, "PILOT-3")

    def test_collision_with_another_endpoint_is_auto_suffixed(self):
        Endpoint.objects.create(organization=self.org, display_name="WEB-01")
        result = enroll_endpoint(self.token, "WEB-01")
        self.assertTrue(result.name_was_suffixed)
        self.assertEqual(result.endpoint.display_name, "WEB-01-2")
        self.endpoint.refresh_from_db()
        self.assertEqual(self.endpoint.display_name, "WEB-01-2")
