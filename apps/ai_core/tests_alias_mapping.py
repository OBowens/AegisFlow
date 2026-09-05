"""AliasMapping + the persistent/ephemeral alias stores
(apps/ai_core/models.py, apps/ai_core/services/alias_engine.py).

Proves the guarantees the display-default overhaul depends on:

1. Get-or-create is idempotent for a repeat real value.
2. Case/format variants of the same real value collapse to one row (the
   normalization-collapse case that would otherwise silently give the same
   entity two different aliases and break cross-incident correlation).
3. identifier_type is part of the identity -- the same string as two
   different types gets two different aliases.
4. Two organizations never share rows or numbering.
5. Aliases are stable across separate sanitize_for_ai() calls (the actual
   new guarantee -- numbering used to reset to 1 every call).
6. organization=None stays fully ephemeral: zero AliasMapping rows, exact
   original per-call behaviour.
7. A genuine concurrent get-or-create race (multiple threads, multiple real
   DB connections, Postgres) is handled correctly: no duplicate rows for
   the same value, no duplicate sequence numbers for different values, no
   unhandled exception.
"""

from __future__ import annotations

import threading

from django.test import TestCase, TransactionTestCase

from apps.ai_core.models import AliasMapping
from apps.ai_core.sanitizer import sanitize_for_ai
from apps.ai_core.services.alias_engine import EphemeralAliasStore, PersistentAliasStore
from apps.organizations.models import Organization


def _make_org(name="Northwind Trading Co"):
    return Organization.objects.create(
        name=name,
        organization_type="SMB",
        country="St. Vincent and the Grenadines",
        sector="Retail",
        risk_profile="medium",
    )


class PersistentAliasStoreUnitTests(TestCase):
    def setUp(self):
        self.org = _make_org()

    def test_repeat_value_returns_the_same_row_and_alias(self):
        store = PersistentAliasStore(self.org)
        first = store.token_for("203.0.113.9", "IP", key="203.0.113.9")
        second = store.token_for("203.0.113.9", "IP", key="203.0.113.9")
        self.assertEqual(first, second)
        self.assertEqual(AliasMapping.objects.filter(organization=self.org).count(), 1)

    def test_case_variants_of_the_same_username_collapse_to_one_alias(self):
        store = PersistentAliasStore(self.org)
        first = store.token_for("j.browne", "USER", key="j.browne".lower())
        second = store.token_for("J.Browne", "USER", key="J.Browne".lower())
        self.assertEqual(first, second)
        rows = AliasMapping.objects.filter(organization=self.org, identifier_type="USER")
        self.assertEqual(rows.count(), 1)
        # first-seen casing is preserved as the canonical real value
        self.assertEqual(rows.get().real_value, "j.browne")

    def test_case_variants_regardless_of_which_casing_is_seen_first(self):
        store = PersistentAliasStore(self.org)
        first = store.token_for("J.Browne", "USER", key="J.Browne".lower())
        second = store.token_for("j.browne", "USER", key="j.browne".lower())
        self.assertEqual(first, second)
        rows = AliasMapping.objects.filter(organization=self.org, identifier_type="USER")
        self.assertEqual(rows.count(), 1)
        self.assertEqual(rows.get().real_value, "J.Browne")

    def test_same_string_as_two_different_identifier_types_gets_two_aliases(self):
        store = PersistentAliasStore(self.org)
        as_host = store.token_for("db01", "HOST", key="db01")
        as_user = store.token_for("db01", "USER", key="db01")
        self.assertNotEqual(as_host, as_user)
        self.assertEqual(AliasMapping.objects.filter(organization=self.org).count(), 2)

    def test_two_organizations_never_share_rows_or_numbering(self):
        other_org = _make_org("Someone Else Ltd")
        store_a = PersistentAliasStore(self.org)
        store_b = PersistentAliasStore(other_org)
        token_a = store_a.token_for("203.0.113.9", "IP", key="203.0.113.9")
        token_b = store_b.token_for("203.0.113.9", "IP", key="203.0.113.9")
        # same first-value shape -> same sequence number, but scoped to
        # different orgs, so they are independent rows.
        self.assertEqual(token_a, token_b)
        self.assertEqual(AliasMapping.objects.filter(organization=self.org).count(), 1)
        self.assertEqual(AliasMapping.objects.filter(organization=other_org).count(), 1)

    def test_sequence_never_resets_across_separate_stores_for_the_same_org(self):
        PersistentAliasStore(self.org).token_for("203.0.113.9", "IP", key="203.0.113.9")
        second_store = PersistentAliasStore(self.org)
        token = second_store.token_for("198.51.100.4", "IP", key="198.51.100.4")
        self.assertEqual(token, "[[IP_2]]")


class SanitizeForAiStabilityTests(TestCase):
    def setUp(self):
        self.org = _make_org()

    def test_same_ip_gets_the_same_alias_across_separate_calls(self):
        first = sanitize_for_ai("seen from 203.0.113.9", organization=self.org)
        second = sanitize_for_ai("again from 203.0.113.9", organization=self.org)
        self.assertEqual(first.mapping, {"[[IP_1]]": "203.0.113.9"})
        self.assertEqual(second.mapping, {"[[IP_1]]": "203.0.113.9"})

    def test_a_new_value_in_a_later_call_continues_the_sequence(self):
        sanitize_for_ai("seen from 203.0.113.9", organization=self.org)
        second = sanitize_for_ai("also from 198.51.100.4", organization=self.org)
        self.assertEqual(second.mapping, {"[[IP_2]]": "198.51.100.4"})

    def test_organization_none_creates_no_alias_mapping_rows(self):
        result = sanitize_for_ai("seen from 203.0.113.9", organization=None)
        self.assertEqual(result.mapping, {"[[IP_1]]": "203.0.113.9"})
        self.assertEqual(AliasMapping.objects.count(), 0)

    def test_organization_none_still_resets_every_call_like_before(self):
        first = sanitize_for_ai("from 203.0.113.9", organization=None)
        second = sanitize_for_ai("from 198.51.100.4", organization=None)
        self.assertEqual(first.mapping, {"[[IP_1]]": "203.0.113.9"})
        # No org to persist against -> numbering restarts, exactly as before.
        self.assertEqual(second.mapping, {"[[IP_1]]": "198.51.100.4"})


class EphemeralAliasStoreUnchangedTests(TestCase):
    """Guards that EphemeralAliasStore is untouched byte-for-byte."""

    def test_same_value_same_token_no_db_access(self):
        store = EphemeralAliasStore()
        a = store.token_for("10.0.0.1", "IP", key="10.0.0.1")
        b = store.token_for("10.0.0.1", "IP", key="10.0.0.1")
        self.assertEqual(a, "[[IP_1]]")
        self.assertEqual(a, b)
        self.assertEqual(AliasMapping.objects.count(), 0)


# ---------------------------------------------------------------------------
# genuine concurrency: multiple threads, multiple real DB connections
# (Postgres, per config/settings.py / .env), racing the same get_or_create.
# TransactionTestCase (not TestCase) is required here -- TestCase wraps the
# whole test in one outer transaction on the main thread's connection, so
# other threads' separate connections would never see it and this
# wouldn't be a real race.
# ---------------------------------------------------------------------------


class ConcurrentGetOrCreateTests(TransactionTestCase):
    def setUp(self):
        self.org = _make_org()

    def _run_concurrently(self, jobs):
        """Run each zero-arg callable in its own thread, all released at
        once by a Barrier. Returns (results_by_index, exceptions)."""
        n = len(jobs)
        barrier = threading.Barrier(n)
        results = [None] * n
        exceptions = [None] * n

        def target(i, fn):
            try:
                barrier.wait(timeout=10)
                results[i] = fn()
            except BaseException as exc:  # noqa: BLE001 - capture for the main thread
                exceptions[i] = exc
            finally:
                from django.db import connections

                connections.close_all()

        threads = [
            threading.Thread(target=target, args=(i, fn)) for i, fn in enumerate(jobs)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        return results, exceptions

    def test_concurrent_same_value_yields_one_row_and_one_alias(self):
        n = 8

        def make_job():
            def job():
                store = PersistentAliasStore(self.org)
                return store.token_for("203.0.113.9", "IP", key="203.0.113.9")

            return job

        results, exceptions = self._run_concurrently([make_job() for _ in range(n)])

        for exc in exceptions:
            self.assertIsNone(exc, msg=f"thread raised: {exc!r}")

        rows = AliasMapping.objects.filter(organization=self.org, identifier_type="IP")
        self.assertEqual(rows.count(), 1)
        self.assertEqual(rows.get().sequence, 1)
        self.assertEqual(set(results), {"[[IP_1]]"})

    def test_concurrent_different_values_yield_no_duplicate_sequence(self):
        n = 8
        values = [f"203.0.113.{i}" for i in range(n)]

        def make_job(value):
            def job():
                store = PersistentAliasStore(self.org)
                return store.token_for(value, "IP", key=value)

            return job

        results, exceptions = self._run_concurrently([make_job(v) for v in values])

        for exc in exceptions:
            self.assertIsNone(exc, msg=f"thread raised: {exc!r}")

        rows = AliasMapping.objects.filter(organization=self.org, identifier_type="IP")
        self.assertEqual(rows.count(), n)

        sequences = list(rows.values_list("sequence", flat=True))
        self.assertEqual(len(sequences), len(set(sequences)), "duplicate sequence assigned under race")
        self.assertEqual(sorted(sequences), list(range(1, n + 1)))

        aliases = {row.real_value: row.ai_token for row in rows}
        for value, token in zip(values, results):
            self.assertEqual(aliases[value], token)
