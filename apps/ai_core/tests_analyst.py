"""Coverage for the Analyst agent's structure, built ahead of having a
working ANTHROPIC_API_KEY (billing being sorted out separately):

- AnthropicProvider (apps/ai_core/providers/anthropic_provider.py): real
  request/response handling, tested here by mocking urllib.request.urlopen
  -- no network call is made.
- build_incident_context (apps/ai_core/services/analyst_context.py):
  gathers evidence/gap/risk/contradiction/source-ip/SOP context into one
  prompt string.
- run_incident_analysis (apps/ai_core/modules/analyst.py): the full
  pipeline -- gather context -> build prompt -> call provider -> handle
  response -- proven correct end to end with a fake provider standing in
  for a real Claude response.
"""

import json
import os
import urllib.error
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.ai_core.modules.analyst import run_incident_analysis
from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.analyst_context import build_incident_context
from apps.incidents.models import IncidentEvidence, IncidentGroup, IncidentSourceIPLink
from apps.log_intake.models import ParsedAlert, UploadedLogFile
from apps.organizations.models import Organization
from apps.playbooks.models import SOPChecklist
from apps.resilience.models import ReadinessAnswer
from apps.risk.models import GapFinding, RiskAssessment


class _FakeHTTPResponse:
    """Stands in for the object urllib.request.urlopen() returns, used as
    a context manager the same way the real one is."""

    def __init__(self, body: dict):
        self._body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def read(self):
        return self._body


class AnthropicProviderTestCase(TestCase):
    def test_raises_clear_error_when_api_key_missing(self):
        provider = AnthropicProvider(api_key=None)
        provider.api_key = None  # belt-and-suspenders against env leakage in CI

        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            provider.send_message("hello")

    def test_send_message_builds_request_and_parses_response(self):
        provider = AnthropicProvider(api_key="fake-test-key", model="claude-sonnet-5")
        fake_response_body = {
            "id": "msg_fake123",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "This looks like a brute-force pattern."}],
            "model": "claude-sonnet-5",
        }

        with patch("urllib.request.urlopen", return_value=_FakeHTTPResponse(fake_response_body)) as mock_urlopen:
            result = provider.send_message("Analyze this incident.")

        self.assertEqual(result, "This looks like a brute-force pattern.")

        self.assertEqual(mock_urlopen.call_count, 1)
        sent_request = mock_urlopen.call_args[0][0]
        self.assertEqual(sent_request.full_url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(sent_request.get_header("X-api-key"), "fake-test-key")
        self.assertEqual(sent_request.get_header("Anthropic-version"), "2023-06-01")
        sent_body = json.loads(sent_request.data.decode("utf-8"))
        self.assertEqual(sent_body["model"], "claude-sonnet-5")
        self.assertEqual(sent_body["messages"], [{"role": "user", "content": "Analyze this incident."}])

    def test_http_error_is_wrapped_in_a_clear_runtime_error(self):
        provider = AnthropicProvider(api_key="fake-test-key")

        http_error = urllib.error.HTTPError(
            url=None, code=401, msg="Unauthorized", hdrs=None,
            fp=__import__("io").BytesIO(b'{"error": {"message": "invalid x-api-key"}}'),
        )
        with patch("urllib.request.urlopen", side_effect=http_error):
            with self.assertRaisesMessage(RuntimeError, "Anthropic API request failed (401)"):
                provider.send_message("hello")


class _FakeProvider:
    """Stands in for a real AI provider -- returns a canned response
    instead of calling out to Claude, so the pipeline test spends nothing
    and needs no API key."""

    model = "claude-sonnet-5-fake"

    def __init__(self, response_text):
        self.response_text = response_text
        self.last_prompt = None

    def send_message(self, prompt, **kwargs):
        self.last_prompt = prompt
        return self.response_text


class AnalystContextTestCase(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.uploaded_file = UploadedLogFile.objects.create(
            organization=self.organization,
            file_name="analyst_demo.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path="demo/analyst_demo.log",
            status=UploadedLogFile.Status.PARSED,
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
        self.alert = ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="test",
            timestamp=timezone.now(),
            affected_system="WEB-01",
            account="admin",
            source_ip="198.51.100.77",
            event_type="failed_login",
            severity_hint=ParsedAlert.SeverityHint.HIGH,
            raw_message="Failed password for admin from 198.51.100.77",
            normalized_summary="Repeated failed logins for admin",
        )
        IncidentEvidence.objects.create(
            incident=self.incident,
            alert=self.alert,
            evidence_reason="Matched account and source IP.",
        )
        self.gap = GapFinding.objects.create(
            organization=self.organization,
            incident=self.incident,
            gap_name="No MFA Evidence",
            description="No multi-factor authentication detected for the targeted account.",
            priority=GapFinding.Priority.HIGH,
        )
        self.risk = RiskAssessment.objects.create(
            organization=self.organization,
            incident=self.incident,
            gap=self.gap,
            risk_title="Privileged account takeover risk",
            likelihood=4,
            impact=4,
            risk_level=RiskAssessment.Level.HIGH,
            reasoning="Successful compromise could expose internal systems.",
            recommended_priority=RiskAssessment.RecommendedPriority.HIGH,
        )

    def test_context_includes_evidence_and_gap_and_risk(self):
        context = build_incident_context(self.incident)

        self.assertIn("## Incident Overview", context)
        self.assertIn("Possible brute-force attempt against privileged account", context)
        self.assertIn("## Evidence", context)
        self.assertIn("198.51.100.77", context)
        self.assertIn("## Gap & Risk Findings", context)
        self.assertIn("No MFA Evidence", context)
        self.assertIn("Privileged account takeover risk", context)

    def test_context_reports_no_contradictions_source_ip_or_sop_when_none_exist(self):
        context = build_incident_context(self.incident)

        self.assertIn("## Readiness Contradictions\nNone found for this incident.", context)
        self.assertIn(
            "## Prior Source-IP Activity\n"
            "No prior incidents share a source IP with this one (within the last 90 days).",
            context,
        )
        self.assertIn("## Matching SOP\nNo matching SOP checklist found for this incident type.", context)

    def test_context_includes_a_contradiction_tied_to_this_incident(self):
        ReadinessAnswer.objects.create(
            organization=self.organization,
            question_text="Is authentication working properly?",
            answer_text="Yes, authentication is working, MFA is in place for all accounts.",
        )

        context = build_incident_context(self.incident)

        self.assertIn("## Readiness Contradictions", context)
        self.assertIn("Is authentication working properly?", context)
        self.assertIn("No MFA Evidence", context)

    def test_context_includes_a_matching_sop(self):
        SOPChecklist.objects.create(
            name="Failed Login Response",
            incident_type="failed_login",
            checklist_items="1. Lock the account.\n2. Notify the user.",
            version="1",
            is_active=True,
        )

        context = build_incident_context(self.incident)

        self.assertIn("## Matching SOP", context)
        self.assertIn("Failed Login Response", context)
        self.assertIn("Lock the account.", context)

    def test_context_includes_prior_source_ip_pattern_with_real_link_data(self):
        # "Has this happened before" (job 20): IncidentSourceIPLink rows
        # already recording that this incident shares a source IP with
        # prior, unrelated incidents -- prove the concrete pattern numbers
        # (incident count, distinct affected systems, day span) reach the
        # context, not just a bare list of related incidents.
        related_db = IncidentGroup.objects.create(
            organization=self.organization,
            title="Suspicious database access from external IP",
            incident_type="unauthorized_access",
            severity=IncidentGroup.Severity.MEDIUM,
            status=IncidentGroup.Status.RESOLVED,
            affected_systems="DB-02",
        )
        IncidentGroup.objects.filter(pk=related_db.pk).update(
            created_at=timezone.now() - timedelta(days=42)
        )
        related_db.refresh_from_db()

        related_mail = IncidentGroup.objects.create(
            organization=self.organization,
            title="Mail server probing from external IP",
            incident_type="reconnaissance",
            severity=IncidentGroup.Severity.LOW,
            status=IncidentGroup.Status.CLOSED,
            affected_systems="MAIL-03",
        )
        # Left at "now" (auto_now_add) so the oldest/newest span is a
        # clean, known 42 days rather than something the test has to
        # recompute from two arbitrary past timestamps.

        shared_ip = "203.0.113.50"
        IncidentSourceIPLink.objects.create(
            incident=self.incident, related_incident=related_db, source_ip=shared_ip
        )
        IncidentSourceIPLink.objects.create(
            incident=self.incident, related_incident=related_mail, source_ip=shared_ip
        )

        context = build_incident_context(self.incident)

        self.assertIn("## Prior Source-IP Activity", context)
        self.assertIn(
            f"Source IP {shared_ip}: 2 prior incidents across 2 distinct affected systems "
            "over 42 days.",
            context,
        )
        self.assertIn('Incident #{} "Suspicious database access from external IP" on DB-02'.format(
            related_db.id
        ), context)
        self.assertIn('Incident #{} "Mail server probing from external IP" on MAIL-03'.format(
            related_mail.id
        ), context)


class RunIncidentAnalysisTestCase(TestCase):
    """The full pipeline -- gather context -> build prompt -> call
    provider -> handle response -- proven correct with a fake provider
    standing in for what Claude would actually return. No API key needed,
    nothing spent.
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

    def test_pipeline_returns_display_ready_result_using_fake_provider(self):
        fake_response = (
            "This is a credential-stuffing pattern against a privileged account. "
            "Severity: high. Next steps: force a password reset, enable MFA, "
            "and block the source IP at the firewall."
        )
        fake_provider = _FakeProvider(fake_response)

        result = run_incident_analysis(self.incident, provider=fake_provider)

        self.assertEqual(result["incident_id"], self.incident.id)
        self.assertEqual(result["model"], "claude-sonnet-5-fake")
        self.assertEqual(result["analysis"], fake_response)
        self.assertIn("generated_at", result)

        # The prompt actually sent to the provider must contain the real
        # gathered context, not a stub -- proves gather -> build -> call
        # are wired together correctly, not just independently correct.
        self.assertIn("Possible brute-force attempt against privileged account", fake_provider.last_prompt)
        self.assertIn("## Incident Overview", fake_provider.last_prompt)
        self.assertIn("## Evidence", fake_provider.last_prompt)

    def test_prompt_sent_to_provider_includes_prior_source_ip_pattern_data(self):
        # Same context-injection proof as the evidence/overview assertions
        # above, for the "has this happened before" pattern data specifically:
        # real IncidentSourceIPLink rows must reach the actual prompt text
        # the provider receives, and the system preamble must instruct the
        # model to reason about reconnaissance/repeat-actor patterns when
        # that section is present.
        related_vpn = IncidentGroup.objects.create(
            organization=self.organization,
            title="Suspicious VPN login from external IP",
            incident_type="unauthorized_access",
            severity=IncidentGroup.Severity.MEDIUM,
            status=IncidentGroup.Status.RESOLVED,
            affected_systems="VPN-GW",
        )
        IncidentGroup.objects.filter(pk=related_vpn.pk).update(
            created_at=timezone.now() - timedelta(days=14)
        )
        related_mail = IncidentGroup.objects.create(
            organization=self.organization,
            title="Mail server probing from external IP",
            incident_type="reconnaissance",
            severity=IncidentGroup.Severity.LOW,
            status=IncidentGroup.Status.CLOSED,
            affected_systems="MAIL-04",
        )
        # Left at "now" (auto_now_add) so oldest-vs-newest span across the
        # two related incidents is a known, clean 14 days.
        for related in (related_vpn, related_mail):
            IncidentSourceIPLink.objects.create(
                incident=self.incident, related_incident=related, source_ip="198.51.100.9"
            )

        fake_provider = _FakeProvider("This looks like reconnaissance from a repeat actor.")

        run_incident_analysis(self.incident, provider=fake_provider)

        self.assertIn("## Prior Source-IP Activity", fake_provider.last_prompt)
        self.assertIn(
            "Source IP 198.51.100.9: 2 prior incidents across 2 distinct affected systems "
            "over 14 days.",
            fake_provider.last_prompt,
        )
        self.assertIn("reconnaissance or a repeat actor", fake_provider.last_prompt)

    def test_pipeline_propagates_the_provider_missing_key_error(self):
        unconfigured_provider = AnthropicProvider(api_key=None)
        unconfigured_provider.api_key = None

        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            run_incident_analysis(self.incident, provider=unconfigured_provider)

    def test_default_provider_is_a_real_anthropic_provider(self):
        # No provider passed in -- confirms the default wiring is the real
        # AnthropicProvider, not a hidden placeholder. Force the key absent
        # regardless of the host environment so this can't flake once
        # billing is sorted and a real key is exported somewhere.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
                run_incident_analysis(self.incident)
