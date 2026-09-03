"""AI endpoint rate limiting (apps/ai_core/rate_limit.py) -- Part G, item 3.

Proves:
* going over the per-endpoint burst limit and over the global hourly cap
  each produces the right friendly message (not a 500),
* a rejected call logs an AIRun FAILED row whose error_message starts
  "rate limited", and makes zero provider calls,
* staying under the limits is unaffected,
* the rolling windows correctly age out older calls,
* AIRun rows for demo_log_workflow (no provider call) don't count.
"""

import json
import os
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from config.testcase import AuthedTestCase
from django.urls import reverse
from django.utils import timezone

from apps.ai_core.rate_limit import check_ai_rate_limit, deny_ai_call
from apps.audit.models import AIRun
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization


def _make_ai_runs(count, *, ai_module="analyst", age_seconds=0, status=AIRun.Status.SUCCESS):
    """Create `count` AIRun rows, optionally backdated `age_seconds` into
    the past (created_at is auto_now_add, so it's set with a follow-up
    UPDATE)."""
    ids = []
    for _ in range(count):
        row = AIRun.objects.create(
            organization=None,
            ai_module=ai_module,
            input_type="test",
            input_id="",
            output_type="",
            output_id="",
            status=status,
        )
        ids.append(row.pk)
    if age_seconds:
        AIRun.objects.filter(pk__in=ids).update(
            created_at=timezone.now() - timedelta(seconds=age_seconds)
        )
    return ids


class CheckAiRateLimitTests(AuthedTestCase):
    def test_under_both_limits_returns_none(self):
        _make_ai_runs(3, ai_module="analyst")
        self.assertIsNone(check_ai_rate_limit("analyst"))

    def test_per_endpoint_burst_trips_at_the_limit(self):
        _make_ai_runs(8, ai_module="analyst")
        verdict = check_ai_rate_limit("analyst")
        self.assertIsNotNone(verdict)
        self.assertEqual(
            verdict.message, "You're generating these a bit fast — wait a moment and try again."
        )
        self.assertIn("per-endpoint burst", verdict.reason)
        self.assertIn("analyst", verdict.reason)

    def test_per_endpoint_burst_is_scoped_to_one_module(self):
        _make_ai_runs(8, ai_module="analyst")
        # A different endpoint has its own bucket, and 8 total is under the
        # global hourly cap of 40.
        self.assertIsNone(check_ai_rate_limit("comparator"))

    def test_global_hourly_cap_trips_across_all_endpoints(self):
        # 40 calls spread 5-per-module across 8 modules: no single module
        # hits the per-endpoint 8/min, but the global 40/hour is reached.
        for module in (
            "analyst", "analyst_qa", "comparator", "incident_explainer",
            "report_writer", "writer", "risk_advisor", "readiness_advisor",
        ):
            _make_ai_runs(5, ai_module=module)

        verdict = check_ai_rate_limit("prioritizer")
        self.assertIsNotNone(verdict)
        self.assertIn("hourly AI limit (40 requests)", verdict.message)
        self.assertIn("try again in about", verdict.message.lower())
        self.assertIn("global hourly", verdict.reason)

    def test_global_message_estimates_the_retry_wait(self):
        # 40 calls, all made 50 minutes ago -> a slot frees in ~10 minutes.
        _make_ai_runs(40, ai_module="report_writer", age_seconds=50 * 60)
        # (also under per-endpoint: those are 50 min old, outside the 60s window)
        verdict = check_ai_rate_limit("report_writer")
        self.assertIsNotNone(verdict)
        self.assertIn("about 10 minutes", verdict.message)

    def test_endpoint_window_rolls_off_calls_older_than_a_minute(self):
        _make_ai_runs(20, ai_module="analyst", age_seconds=90)
        self.assertIsNone(check_ai_rate_limit("analyst"))

    def test_global_window_rolls_off_calls_older_than_an_hour(self):
        _make_ai_runs(200, ai_module="report_writer", age_seconds=2 * 3600)
        self.assertIsNone(check_ai_rate_limit("report_writer"))

    def test_demo_log_workflow_rows_are_excluded_from_both_windows(self):
        _make_ai_runs(50, ai_module="demo_log_workflow")            # global
        _make_ai_runs(50, ai_module="demo_log_workflow", age_seconds=1)  # (still "now"-ish)
        self.assertIsNone(check_ai_rate_limit("analyst"))
        # a handful of real calls alongside the noise is still fine
        _make_ai_runs(5, ai_module="analyst")
        self.assertIsNone(check_ai_rate_limit("analyst"))

    @override_settings(AI_RATE_LIMIT_ENABLED=False)
    def test_escape_hatch_disables_it_entirely(self):
        _make_ai_runs(500, ai_module="analyst")
        self.assertIsNone(check_ai_rate_limit("analyst"))

    @override_settings(AI_RATE_LIMIT_ENDPOINT_PER_MINUTE=2, AI_RATE_LIMIT_GLOBAL_PER_HOUR=3)
    def test_limits_are_settings_overridable(self):
        _make_ai_runs(2, ai_module="analyst")
        self.assertIsNotNone(check_ai_rate_limit("analyst"))


class DenyAiCallTests(AuthedTestCase):
    def setUp(self):
        self.org = Organization.objects.create(
            name="Demo Org", organization_type="Demo", country="X", sector="Y", risk_profile="medium"
        )

    def test_allows_and_writes_nothing_when_under_limit(self):
        before = AIRun.objects.count()
        self.assertIsNone(deny_ai_call(self.org, "analyst"))
        self.assertEqual(AIRun.objects.count(), before)

    def test_denies_and_logs_a_failed_airun_row(self):
        _make_ai_runs(8, ai_module="analyst")
        message = deny_ai_call(self.org, "analyst")

        self.assertIn("wait a moment", message)
        logged = AIRun.objects.filter(ai_module="analyst", status=AIRun.Status.FAILED).latest("id")
        self.assertTrue(logged.error_message.startswith("rate limited:"))
        self.assertEqual(logged.organization, self.org)

    def test_the_rejection_row_itself_counts_toward_the_window(self):
        _make_ai_runs(8, ai_module="analyst")
        deny_ai_call(self.org, "analyst")
        # 8 real + 1 rejection = 9, still over -> stays denied
        self.assertEqual(AIRun.objects.filter(ai_module="analyst").count(), 9)
        self.assertIsNotNone(check_ai_rate_limit("analyst"))


class _AnthropicReply:
    def __init__(self, text):
        self._raw = json.dumps({"content": [{"type": "text", "text": text}]}).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._raw


class RateLimitedViewTests(AuthedTestCase):
    def setUp(self):
        self.org = Organization.objects.create(
            name="Demo Org", organization_type="Demo", country="X", sector="Y", risk_profile="medium"
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.org,
            title="Brute-force against a privileged account",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="WEB-01",
            summary="Repeated failed logins.",
        )
        self.analyze_url = reverse("incidents:analyze", args=[self.incident.id])

    def test_over_the_burst_limit_is_a_friendly_message_no_500_no_provider_call(self):
        _make_ai_runs(8, ai_module="analyst")
        runs_before = AIRun.objects.count()

        with patch("urllib.request.urlopen") as mock_urlopen:
            response = self.client.post(self.analyze_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "wait a moment and try again")
        self.assertNotContains(response, "Traceback")
        mock_urlopen.assert_not_called()

        # exactly one new AIRun row, FAILED, clearly labelled
        self.assertEqual(AIRun.objects.count(), runs_before + 1)
        logged = AIRun.objects.latest("id")
        self.assertEqual(logged.status, AIRun.Status.FAILED)
        self.assertEqual(logged.ai_module, "analyst")
        self.assertTrue(logged.error_message.startswith("rate limited:"))

    def test_under_the_limit_the_view_works_normally(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "fake-test-key"}), patch(
            "urllib.request.urlopen", return_value=_AnthropicReply("A real assessment.")
        ):
            response = self.client.post(self.analyze_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "A real assessment.")
        self.assertEqual(
            AIRun.objects.filter(ai_module="analyst", status=AIRun.Status.SUCCESS).count(), 1
        )
        self.assertFalse(AIRun.objects.filter(status=AIRun.Status.FAILED).exists())

    def test_global_cap_message_shows_on_a_different_endpoint(self):
        for module in (
            "analyst", "analyst_qa", "comparator", "incident_explainer",
            "report_writer", "writer", "risk_advisor", "readiness_advisor",
        ):
            _make_ai_runs(5, ai_module=module)  # 40 total, 5 each < burst limit

        with patch("urllib.request.urlopen") as mock_urlopen:
            response = self.client.post(reverse("core:explain_priorities"), follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "hourly AI limit (40 requests)")
        mock_urlopen.assert_not_called()
        self.assertTrue(
            AIRun.objects.filter(ai_module="prioritizer", status=AIRun.Status.FAILED)
            .latest("id")
            .error_message.startswith("rate limited:")
        )

    def test_demo_log_workflow_noise_does_not_rate_limit_a_real_call(self):
        _make_ai_runs(80, ai_module="demo_log_workflow")

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "fake-test-key"}), patch(
            "urllib.request.urlopen", return_value=_AnthropicReply("Assessment despite the noise.")
        ):
            response = self.client.post(self.analyze_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Assessment despite the noise.")
        self.assertEqual(
            AIRun.objects.filter(ai_module="analyst", status=AIRun.Status.SUCCESS).count(), 1
        )
