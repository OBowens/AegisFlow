"""Proves the test-run-wide safeguard in config/test_runner.py is
actually in effect: ANTHROPIC_API_KEY is absent from the environment for
the whole duration of the test run, structurally, not because any
individual test bothered to clear it itself. If this file's tests ever
fail, the safeguard has regressed and every other test's provider mocks
are the only thing standing between the suite and a real API call.
"""

import os

from django.test import TestCase

from apps.ai_core.providers.anthropic_provider import AnthropicProvider


class NoLiveProviderCallsSafeguardTestCase(TestCase):
    def test_anthropic_api_key_is_not_present_during_tests(self):
        self.assertNotIn("ANTHROPIC_API_KEY", os.environ)

    def test_default_anthropic_provider_cannot_reach_the_network_during_tests(self):
        # Deliberately no patch.dict/pop here -- if the ambient test
        # environment genuinely has no key (via the test runner, not this
        # test defending itself), a bare AnthropicProvider() must still
        # raise its own clear error rather than attempting a real request.
        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            AnthropicProvider().send_message("hello")
