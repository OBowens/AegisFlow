"""Coverage for the Incident Explainer agent (jobs 12 + 13: plain-
language explanation and "what do I tell management"):

- run_incident_explanation reuses build_incident_context (the exact same
  context as the Analyst agent) and only swaps the system preamble per
  audience -- proven here by showing the plain_language and management
  prompts share the same gathered incident context but carry genuinely
  different instructions, not just a cosmetic label on an identical
  prompt.

Same mocking pattern as tests_analyst.py / tests_risk_advisor.py.
"""

from django.test import TestCase
from django.utils import timezone

from apps.ai_core.modules.incident_explainer import (
    AUDIENCE_PREAMBLES,
    MANAGEMENT_PREAMBLE,
    PLAIN_LANGUAGE_PREAMBLE,
    run_incident_explanation,
)
from apps.incidents.models import IncidentEvidence, IncidentGroup
from apps.log_intake.models import ParsedAlert, UploadedLogFile
from apps.organizations.models import Organization


class _FakeProvider:
    model = "claude-sonnet-5-fake"

    def __init__(self, response_text):
        self.response_text = response_text
        self.last_prompt = None

    def send_message(self, prompt, **kwargs):
        self.last_prompt = prompt
        return self.response_text


class RunIncidentExplanationTestCase(TestCase):
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
            file_name="explainer_demo.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path="demo/explainer_demo.log",
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
        alert = ParsedAlert.objects.create(
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
            incident=self.incident, alert=alert, evidence_reason="Matched account and source IP."
        )

    def test_plain_language_prompt_includes_the_real_incident_data(self):
        fake_provider = _FakeProvider("Someone tried many passwords on an important account.")

        run_incident_explanation(self.incident, "plain_language", provider=fake_provider)

        self.assertIn("Possible brute-force attempt against privileged account", fake_provider.last_prompt)
        self.assertIn("198.51.100.77", fake_provider.last_prompt)
        self.assertIn("## Incident Overview", fake_provider.last_prompt)
        self.assertTrue(fake_provider.last_prompt.startswith(PLAIN_LANGUAGE_PREAMBLE))

    def test_management_prompt_includes_the_same_real_incident_data(self):
        fake_provider = _FakeProvider("This exposes a privileged account to takeover risk.")

        run_incident_explanation(self.incident, "management", provider=fake_provider)

        self.assertIn("Possible brute-force attempt against privileged account", fake_provider.last_prompt)
        self.assertIn("198.51.100.77", fake_provider.last_prompt)
        self.assertIn("## Incident Overview", fake_provider.last_prompt)
        self.assertTrue(fake_provider.last_prompt.startswith(MANAGEMENT_PREAMBLE))

    def test_plain_language_and_management_preambles_are_genuinely_different(self):
        # The key proof for this feature: the two audiences must not be a
        # cosmetic label on an identical prompt -- the actual instruction
        # text sent to the provider must differ, and each must carry its
        # own audience-specific framing language.
        plain_provider = _FakeProvider("plain response")
        management_provider = _FakeProvider("management response")

        run_incident_explanation(self.incident, "plain_language", provider=plain_provider)
        run_incident_explanation(self.incident, "management", provider=management_provider)

        self.assertNotEqual(plain_provider.last_prompt, management_provider.last_prompt)

        # Same underlying context (proves context-gathering is shared,
        # not duplicated per audience)...
        shared_context_line = "Possible brute-force attempt against privileged account"
        self.assertIn(shared_context_line, plain_provider.last_prompt)
        self.assertIn(shared_context_line, management_provider.last_prompt)

        # ...but distinct instructions.
        self.assertIn("plain, everyday language", plain_provider.last_prompt)
        self.assertNotIn("plain, everyday language", management_provider.last_prompt)
        self.assertIn("business impact and risk exposure", management_provider.last_prompt)
        self.assertNotIn("business impact and risk exposure", plain_provider.last_prompt)

    def test_pipeline_returns_display_ready_result_with_the_requested_audience(self):
        fake_provider = _FakeProvider("Plain language explanation text.")

        result = run_incident_explanation(self.incident, "plain_language", provider=fake_provider)

        self.assertEqual(result["incident_id"], self.incident.id)
        self.assertEqual(result["audience"], "plain_language")
        self.assertEqual(result["model"], "claude-sonnet-5-fake")
        self.assertEqual(result["explanation"], "Plain language explanation text.")
        self.assertIn("generated_at", result)

    def test_unknown_audience_raises_before_touching_the_provider(self):
        def _explode(*args, **kwargs):
            raise AssertionError("must not be called for an unknown audience")

        provider = _FakeProvider("unused")
        provider.send_message = _explode

        with self.assertRaisesMessage(ValueError, "Unknown audience"):
            run_incident_explanation(self.incident, "sarcastic", provider=provider)

    def test_pipeline_propagates_the_provider_missing_key_error(self):
        from apps.ai_core.providers.anthropic_provider import AnthropicProvider

        unconfigured_provider = AnthropicProvider(api_key=None)
        unconfigured_provider.api_key = None

        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            run_incident_explanation(self.incident, "management", provider=unconfigured_provider)

    def test_audience_preambles_registry_has_exactly_the_two_expected_audiences(self):
        self.assertEqual(set(AUDIENCE_PREAMBLES), {"plain_language", "management"})
