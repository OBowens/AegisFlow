"""Custom test runner: structurally prevents any test from ever making a
real, billed call to the Anthropic API, regardless of whether that
specific test remembers to mock the AI module function it goes through.

Context: a Django test in this project once made real Anthropic API
calls because ANTHROPIC_API_KEY happens to be set in .env (loaded into
os.environ by config/settings.py for real usage), and the test in
question forgot to mock the module-level function that calls out to it.
Mocking individual AI module functions is still the primary defense --
it's how tests prove the actual prompt/context wiring is correct -- but
this makes the failure mode structurally impossible to repeat: for the
duration of any test run, ANTHROPIC_API_KEY simply isn't present in the
environment, so AnthropicProvider() raises its own clear "not set"
RuntimeError instead of ever reaching the network, the exact same error
path every _friendly_analysis_error caller already expects and handles
gracefully.
"""

import os

from django.test.runner import DiscoverRunner


class NoLiveProviderCallsTestRunner(DiscoverRunner):
    _saved_anthropic_api_key = None

    def setup_test_environment(self, **kwargs):
        super().setup_test_environment(**kwargs)
        self._saved_anthropic_api_key = os.environ.pop("ANTHROPIC_API_KEY", None)

    def teardown_test_environment(self, **kwargs):
        if self._saved_anthropic_api_key is not None:
            os.environ["ANTHROPIC_API_KEY"] = self._saved_anthropic_api_key
        super().teardown_test_environment(**kwargs)
