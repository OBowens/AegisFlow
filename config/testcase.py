"""Shared test base for a codebase where every view now requires login.

`LoginRequiredMiddleware` (see config/settings.py) gates every real view,
so a plain `self.client.get(...)` that used to return 200 now returns a
302 to the login page. Rather than add `force_login` to ~90 individual
`setUp` methods (most of which don't call `super().setUp()`), view tests
inherit from `AuthedTestCase`: its client authenticates as a throwaway
user on the first request of each test.

Explicit on purpose -- a reader sees `AuthedTestCase` in the class line
and knows requests are authenticated. Tests that specifically need an
anonymous request (e.g. "anonymous is redirected to login") should use
`django.test.Client()` directly, or call `self.client.logout()` and make
the assertion on the immediate response.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import Client, TestCase


class AutoLoginClient(Client):
    """Test client that ensures each request is made by an authenticated
    user. A test that has already logged in (its own `force_login`
    /`login`) is left alone."""

    #: subclasses / individual tests may point this at another username
    default_username = "test-analyst"

    def request(self, **request):
        if not self.session.get("_auth_user_id"):
            User = get_user_model()
            user, _created = User.objects.get_or_create(
                username=self.default_username,
                defaults={
                    "first_name": "Test",
                    "last_name": "Analyst",
                    "email": "test-analyst@example.test",
                },
            )
            self.force_login(user)
        return super().request(**request)


class AuthedTestCase(TestCase):
    client_class = AutoLoginClient
