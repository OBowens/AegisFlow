"""apps/ai_core/reveal_policy.py

Proves the one guarantee ``can_reveal`` makes today -- authentication only,
matching the access level ``LoginRequiredMiddleware`` already gives every
view -- and documents in the suite itself that this is a known, temporary
state pending real per-user/per-role authorization, not an oversight.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import TestCase

from apps.ai_core.reveal_policy import can_reveal


class CanRevealTests(TestCase):
    def test_authenticated_user_can_reveal(self):
        user = get_user_model().objects.create_user(
            username="analyst", password="not-used-in-this-test"
        )
        self.assertTrue(can_reveal(user))

    def test_anonymous_user_cannot_reveal(self):
        self.assertFalse(can_reveal(AnonymousUser()))

    def test_currently_any_authenticated_user_can_reveal_pending_real_rbac(self):
        # A second, entirely ordinary authenticated user -- no is_staff,
        # no is_superuser, no role of any kind -- also passes. This is the
        # known, deliberate current behaviour (see reveal_policy.py's
        # docstring): can_reveal does not yet distinguish between users at
        # all. This test exists so that changes to that behaviour are a
        # visible, intentional edit to this test, not a silent regression.
        second_user = get_user_model().objects.create_user(
            username="second-analyst", password="not-used-in-this-test"
        )
        self.assertFalse(second_user.is_staff)
        self.assertFalse(second_user.is_superuser)
        self.assertTrue(can_reveal(second_user))
