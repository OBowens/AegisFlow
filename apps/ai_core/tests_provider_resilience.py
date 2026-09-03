"""Part G, item 1 (fixes 1, 4, 5): AnthropicProvider.send_message() must
turn EVERY realistic failure -- not just a missing key or an HTTP error --
into the same plain RuntimeError that every caller's `except RuntimeError`
already handles, so a slow/flaky Anthropic connection can never surface as
a raw 500. Plus: max_tokens is realistic for long reports, and an
empty/whitespace response is treated as a failure, not a silent success.

All of this is exercised by mocking urllib.request.urlopen -- no network.
"""

import http.client
import io
import json
import os
import socket
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.ai_core.modules.report_writer import run_report_generation
from apps.ai_core.providers.anthropic_provider import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_TIMEOUT_SECONDS,
    AnthropicProvider,
)
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization


class _FakeHTTPResponse:
    """Context-manager stand-in for urllib.request.urlopen()'s return."""

    def __init__(self, raw: bytes):
        self._raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def read(self):
        return self._raw


def _json_response(payload) -> _FakeHTTPResponse:
    return _FakeHTTPResponse(json.dumps(payload).encode("utf-8"))


_OK_BODY = {"content": [{"type": "text", "text": "A real answer."}]}


class ProviderFailureNormalisationTests(SimpleTestCase):
    def setUp(self):
        self.provider = AnthropicProvider(api_key="fake-test-key", model="claude-sonnet-5")

    def _assert_friendly(self, urlopen_side_effect=None, urlopen_return=None):
        kwargs = {}
        if urlopen_side_effect is not None:
            kwargs["side_effect"] = urlopen_side_effect
        else:
            kwargs["return_value"] = urlopen_return
        with patch("urllib.request.urlopen", **kwargs):
            with self.assertRaises(RuntimeError) as ctx:
                self.provider.send_message("hi")
        return str(ctx.exception)

    def test_response_timeout_becomes_a_runtime_error(self):
        # The classic "Anthropic accepted the socket but is slow to answer"
        # case -- urllib raises a bare TimeoutError, NOT a URLError.
        msg = self._assert_friendly(urlopen_side_effect=TimeoutError("timed out"))
        self.assertIn("Anthropic API request failed", msg)

    def test_socket_timeout_alias_becomes_a_runtime_error(self):
        msg = self._assert_friendly(urlopen_side_effect=socket.timeout("timed out"))
        self.assertIn("Anthropic API request failed", msg)

    def test_connection_reset_becomes_a_runtime_error(self):
        msg = self._assert_friendly(
            urlopen_side_effect=ConnectionResetError(104, "Connection reset by peer")
        )
        self.assertIn("Anthropic API request failed", msg)

    def test_remote_disconnected_becomes_a_runtime_error(self):
        msg = self._assert_friendly(
            urlopen_side_effect=http.client.RemoteDisconnected("Remote end closed connection")
        )
        self.assertIn("Anthropic API request failed", msg)

    def test_incomplete_read_becomes_a_runtime_error(self):
        msg = self._assert_friendly(
            urlopen_side_effect=http.client.IncompleteRead(partial=b"half a bo")
        )
        self.assertIn("Anthropic API request failed", msg)

    def test_malformed_json_body_becomes_a_runtime_error(self):
        # e.g. a captive portal / corporate proxy returning an HTML page
        # with a 200 status.
        msg = self._assert_friendly(
            urlopen_return=_FakeHTTPResponse(b"<html>Sign in to the wifi</html>")
        )
        self.assertIn("unreadable response", msg)

    def test_non_utf8_body_becomes_a_runtime_error(self):
        msg = self._assert_friendly(urlopen_return=_FakeHTTPResponse(b"\xff\xfe\x00bad"))
        self.assertIn("unreadable response", msg)

    def test_unexpected_json_shape_becomes_a_runtime_error(self):
        # Valid JSON, but not the {"content": [...]} object we expect.
        msg = self._assert_friendly(urlopen_return=_json_response(["not", "an", "object"]))
        self.assertIn("unexpected response shape", msg)

    def test_empty_text_response_is_a_failure_not_a_silent_success(self):
        msg = self._assert_friendly(
            urlopen_return=_json_response({"content": [{"type": "text", "text": "   \n  "}]})
        )
        self.assertIn("empty response", msg)

    def test_content_with_no_text_blocks_is_a_failure(self):
        msg = self._assert_friendly(
            urlopen_return=_json_response({"content": [{"type": "tool_use", "id": "x"}]})
        )
        self.assertIn("empty response", msg)

    def test_http_error_still_reports_its_status_code(self):
        http_error = __import__("urllib.error", fromlist=["HTTPError"]).HTTPError(
            url=None, code=529, msg="Overloaded", hdrs=None,
            fp=io.BytesIO(b'{"error":{"message":"overloaded"}}'),
        )
        msg = self._assert_friendly(urlopen_side_effect=http_error)
        self.assertIn("Anthropic API request failed (529)", msg)

    def test_a_normal_response_still_works(self):
        with patch("urllib.request.urlopen", return_value=_json_response(_OK_BODY)):
            self.assertEqual(self.provider.send_message("hi"), "A real answer.")


class ProviderRequestShapeTests(SimpleTestCase):
    def test_default_max_tokens_is_large_enough_for_full_reports(self):
        self.assertGreaterEqual(DEFAULT_MAX_TOKENS, 2048)

        provider = AnthropicProvider(api_key="fake-test-key")
        with patch("urllib.request.urlopen", return_value=_json_response(_OK_BODY)) as mock_urlopen:
            provider.send_message("write a long report")

        sent_body = json.loads(mock_urlopen.call_args[0][0].data.decode("utf-8"))
        self.assertEqual(sent_body["max_tokens"], DEFAULT_MAX_TOKENS)
        self.assertGreaterEqual(sent_body["max_tokens"], 2048)


class LongReportNoLongerTruncatesTests(AuthedTestCase):
    """Fix 4: a full report used to be cut off mid-sentence because every
    call was capped at 1024 output tokens. The default is now 4096, and
    it flows through run_report_generation unchanged.
    """

    # ~5 KB: comfortably past what 1024 tokens (~4 KB) could hold, ending
    # on a real sentence boundary.
    FULL_REPORT = (
        "This technical report documents a brute-force authentication "
        "attempt against a privileged account on WEB-01. "
        + ("The security team reviewed the correlated evidence in detail. " * 70)
        + "\n\nImpact\nAn unrecovered compromise of this account would expose "
        "administrative access to the core web tier.\n\nRecommended Actions\n"
        "- Rotate the affected credentials and invalidate active sessions.\n"
        "- Confirm MFA is enforced for every administrative account.\n"
        "- Block the offending source IP ranges at the perimeter."
    )

    class _TokenBudgetProvider:
        """Stand-in for the real API's max_tokens behaviour: returns the
        canned text truncated to roughly `max_tokens` worth of characters
        (~4 chars/token), so a too-small budget visibly cuts it off.
        """

        model = "claude-sonnet-5-fake"

        def __init__(self, full_text):
            self.full_text = full_text

        def send_message(
            self, prompt, *, organization=None, max_tokens=DEFAULT_MAX_TOKENS, timeout=DEFAULT_TIMEOUT_SECONDS
        ):
            return self.full_text[: max_tokens * 4]

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible brute-force attempt against privileged account",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="WEB-01",
            summary="Repeated failed logins detected.",
        )

    def test_the_old_1024_token_budget_really_did_cut_this_report_mid_sentence(self):
        self.assertGreater(len(self.FULL_REPORT), 1024 * 4)
        cut_at_1024 = self.FULL_REPORT[: 1024 * 4]
        self.assertFalse(
            cut_at_1024.rstrip().endswith((".", "-")),
            "the pre-fix budget truncated this report mid-sentence",
        )

    def test_full_report_comes_back_whole_at_the_current_default_budget(self):
        provider = self._TokenBudgetProvider(self.FULL_REPORT)
        result = run_report_generation("technical", self.incident, provider=provider)

        self.assertEqual(result["report_text"], self.FULL_REPORT.strip())
        self.assertTrue(
            result["report_text"].rstrip().endswith("."),
            "the report ends on a complete sentence, not a truncation",
        )
        # Both structural sections the reports preview parser needs survived.
        self.assertIn("Impact", result["report_text"])
        self.assertIn("Recommended Actions", result["report_text"])


class ProviderFailureReachesTheViewAsAFriendlyMessageTests(AuthedTestCase):
    """End-to-end: a timeout deep inside the provider must come out of a
    real AI view as a friendly on-page message and a 200, never a 500.
    """

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible brute-force attempt against privileged account",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="WEB-01",
            summary="Repeated failed logins detected.",
        )

    def test_provider_timeout_on_analyze_is_a_friendly_message_not_a_500(self):
        analyze_url = reverse("incidents:analyze", args=[self.incident.id])
        # A real key so the provider actually runs (the test runner pops
        # ANTHROPIC_API_KEY), and a urlopen that times out mid-exchange.
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "fake-test-key"}), patch(
            "urllib.request.urlopen", side_effect=TimeoutError("timed out")
        ):
            response = self.client.post(analyze_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "AI analysis failed. Please try again in a moment.")
        self.assertNotContains(response, "Traceback")

    def test_malformed_json_on_analyze_is_a_friendly_message_not_a_500(self):
        analyze_url = reverse("incidents:analyze", args=[self.incident.id])
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "fake-test-key"}), patch(
            "urllib.request.urlopen",
            return_value=_FakeHTTPResponse(b"<html>proxy error</html>"),
        ):
            response = self.client.post(analyze_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "AI analysis failed. Please try again in a moment.")
