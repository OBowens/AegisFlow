"""Coverage for the Writer agent (apps/ai_core/modules/writer.py):

- run_playbook_generation gathers the same rich context build_incident_context
  already proves out for the Analyst agent (see tests_analyst.py) -- evidence,
  gap/risk findings, and a matching SOP when one exists -- and sends it to
  the provider.
- Every generated step is run through requires_human_approval (the
  deterministic approval gate) before being returned.

Same mocking pattern as tests_analyst.py: a fake provider captures the
prompt actually sent and returns a canned response -- no network, no API
key, nothing spent.
"""

from django.test import TestCase
from django.utils import timezone

from apps.ai_core.modules.writer import run_playbook_generation
from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.custom_playbook_context import build_custom_scenario_context
from apps.incidents.models import IncidentEvidence, IncidentGroup
from apps.log_intake.models import ParsedAlert, UploadedLogFile
from apps.organizations.models import CriticalSystem, Organization
from apps.playbooks.models import SOPChecklist


class _FakeProvider:
    """Stands in for a real AI provider -- returns a canned response
    instead of calling out to Claude, so the test spends nothing and
    needs no API key."""

    model = "claude-sonnet-5-fake"

    def __init__(self, response_text):
        self.response_text = response_text
        self.last_prompt = None

    def send_message(self, prompt, **kwargs):
        self.last_prompt = prompt
        return self.response_text


class RunPlaybookGenerationTestCase(TestCase):
    """The full pipeline -- gather context (incl. a matching SOP) -> build
    prompt -> call provider -> parse steps -> run the approval gate --
    proven correct with a fake provider standing in for what Claude would
    actually return.
    """

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
            file_name="writer_demo.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path="demo/writer_demo.log",
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
        # A real, distinctive SOP for this incident_type -- its exact
        # wording ("Rotate the shared VPN pre-shared key") is nowhere
        # else in the fixture data, so if it shows up in the prompt it
        # can only have come from the SOP match, not some other section.
        self.sop = SOPChecklist.objects.create(
            name="Failed Login Response SOP",
            incident_type="failed_login",
            checklist_items=(
                "1. Lock the targeted account immediately.\n"
                "2. Rotate the shared VPN pre-shared key.\n"
                "3. Notify the account owner."
            ),
            version="2",
            is_active=True,
        )

    def test_prompt_sent_to_provider_includes_the_matching_sop_content(self):
        # Proves the SOP's real content actually reached the provider --
        # same context-injection proof pattern as
        # apps/ai_core/tests_analyst.py::RunIncidentAnalysisTestCase.
        fake_provider = _FakeProvider("1. Lock the account.\n2. Notify the owner.")

        run_playbook_generation(self.incident, provider=fake_provider)

        self.assertIn("## Matching SOP", fake_provider.last_prompt)
        self.assertIn("Failed Login Response SOP", fake_provider.last_prompt)
        self.assertIn("Rotate the shared VPN pre-shared key.", fake_provider.last_prompt)
        self.assertIn("## Evidence", fake_provider.last_prompt)
        self.assertIn("198.51.100.77", fake_provider.last_prompt)

    def test_generated_steps_grounded_in_the_sop_are_parsed_out_individually(self):
        # The fake response stands in for what Claude would write once it
        # actually has the SOP content available (proven above) -- here we
        # prove the *output* side: the SOP-specific step text survives
        # parsing into a discrete, individual step rather than getting
        # mangled or dropped.
        fake_response = (
            "1. Lock the targeted account per the Failed Login Response SOP.\n"
            "2. Rotate the shared VPN pre-shared key as required by the SOP.\n"
            "3. Notify the account owner and security lead.\n"
            "4. Disable the compromised account until the investigation concludes.\n"
            "5. Document the root cause once contained."
        )
        fake_provider = _FakeProvider(fake_response)

        result = run_playbook_generation(self.incident, provider=fake_provider)

        self.assertEqual(result["incident_id"], self.incident.id)
        self.assertEqual(result["model"], "claude-sonnet-5-fake")
        self.assertIn("generated_at", result)

        actions = [step["action"] for step in result["steps"]]
        self.assertEqual(len(actions), 5)
        self.assertIn("Lock the targeted account per the Failed Login Response SOP.", actions)
        self.assertIn("Rotate the shared VPN pre-shared key as required by the SOP.", actions)

    def test_a_realistic_destructive_step_is_flagged_by_the_approval_gate(self):
        fake_response = (
            "1. Review authentication logs for the targeted account.\n"
            "2. Disable the compromised account immediately.\n"
            "3. Document the root cause in the incident report."
        )
        fake_provider = _FakeProvider(fake_response)

        result = run_playbook_generation(self.incident, provider=fake_provider)

        by_action = {step["action"]: step["requires_approval"] for step in result["steps"]}
        self.assertTrue(by_action["Disable the compromised account immediately."])
        self.assertFalse(by_action["Review authentication logs for the targeted account."])
        self.assertFalse(by_action["Document the root cause in the incident report."])

    def test_pipeline_propagates_the_provider_missing_key_error(self):
        unconfigured_provider = AnthropicProvider(api_key=None)
        unconfigured_provider.api_key = None

        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            run_playbook_generation(self.incident, provider=unconfigured_provider)


class BuildCustomScenarioContextTestCase(TestCase):
    """Coverage for the standalone, no-incident context builder (apps/
    ai_core/services/custom_playbook_context.py): a mentioned critical
    system and a matching SOP should both be resolved from the raw
    scenario text alone, with no incident_type field to lean on.
    """

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.critical_system = CriticalSystem.objects.create(
            organization=self.organization,
            system_name="PAYROLL-DB-03",
            system_type="Database",
            criticality=CriticalSystem.Criticality.CRITICAL,
            owner_name="Finance Ops Team",
            recovery_priority=CriticalSystem.RecoveryPriority.URGENT,
        )
        self.sop = SOPChecklist.objects.create(
            name="VM Reset Response SOP",
            incident_type="vm_reset",
            checklist_items=(
                "1. Snapshot the VM before reset.\n"
                "2. Notify the system owner.\n"
                "3. Reset via the safe reboot procedure."
            ),
            version="3",
            is_active=True,
        )

    def test_context_includes_the_raw_scenario_text(self):
        context = build_custom_scenario_context(
            "Give me a playbook for resetting PAYROLL-DB-03 safely.",
            organization=self.organization,
        )

        self.assertIn("## Requested Scenario", context)
        self.assertIn("Give me a playbook for resetting PAYROLL-DB-03 safely.", context)

    def test_context_includes_the_matched_critical_system(self):
        context = build_custom_scenario_context(
            "Give me a playbook for resetting PAYROLL-DB-03 safely.",
            organization=self.organization,
        )

        self.assertIn("## Critical System Match", context)
        self.assertIn("PAYROLL-DB-03", context)
        self.assertIn("Finance Ops Team", context)

    def test_context_reports_no_critical_system_when_none_is_mentioned(self):
        context = build_custom_scenario_context(
            "Give me a generic playbook for a phishing email.",
            organization=self.organization,
        )

        self.assertIn("No recognized critical system mentioned", context)

    def test_context_includes_the_matched_sop_via_token_fallback(self):
        context = build_custom_scenario_context(
            "I think this needs a vm reset after maintenance.",
            organization=self.organization,
        )

        self.assertIn("## Matching SOP", context)
        self.assertIn("VM Reset Response SOP", context)
        self.assertIn("Snapshot the VM before reset.", context)

    def test_context_reports_no_sop_when_nothing_matches(self):
        context = build_custom_scenario_context(
            "Give me a playbook for a completely unrelated scenario.",
            organization=self.organization,
        )

        self.assertIn("No matching SOP checklist found", context)


class RunPlaybookGenerationCustomScenarioTestCase(TestCase):
    """Coverage for run_playbook_generation's standalone, no-incident
    path -- proves the typed scenario text (and any resolved critical
    system / SOP) actually reaches the provider, that the result carries
    no incident_id, and that the approval gate still runs on every
    generated step exactly as it does for an incident-backed playbook.
    """

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        CriticalSystem.objects.create(
            organization=self.organization,
            system_name="PAYROLL-DB-03",
            system_type="Database",
            criticality=CriticalSystem.Criticality.CRITICAL,
            owner_name="Finance Ops Team",
            recovery_priority=CriticalSystem.RecoveryPriority.URGENT,
        )
        self.scenario_text = "Give me a playbook for resetting PAYROLL-DB-03 safely."

    def test_prompt_sent_to_provider_includes_the_typed_scenario_and_matched_system(self):
        fake_provider = _FakeProvider("1. Notify the owner.\n2. Reset the system.")

        run_playbook_generation(scenario_text=self.scenario_text, organization=self.organization, provider=fake_provider)

        self.assertIn(self.scenario_text, fake_provider.last_prompt)
        self.assertIn("PAYROLL-DB-03", fake_provider.last_prompt)
        self.assertIn("Finance Ops Team", fake_provider.last_prompt)

    def test_result_carries_no_incident_id_for_a_standalone_scenario(self):
        fake_provider = _FakeProvider("1. Notify the owner.\n2. Reset the system.")

        result = run_playbook_generation(
            scenario_text=self.scenario_text, organization=self.organization, provider=fake_provider
        )

        self.assertIsNone(result["incident_id"])
        self.assertEqual(result["model"], "claude-sonnet-5-fake")

    def test_a_destructive_step_from_a_standalone_scenario_is_still_flagged_by_the_approval_gate(self):
        # Same destructive-vs-benign proof as
        # RunPlaybookGenerationTestCase.test_a_realistic_destructive_step_is_flagged_by_the_approval_gate
        # above, just via the no-incident scenario_text path -- the
        # approval gate must not be skippable just because there's no
        # incident behind the generated steps.
        fake_response = (
            "1. Review recent access logs for PAYROLL-DB-03.\n"
            "2. Disable the compromised account immediately.\n"
            "3. Document the root cause in the incident report."
        )
        fake_provider = _FakeProvider(fake_response)

        result = run_playbook_generation(
            scenario_text=self.scenario_text, organization=self.organization, provider=fake_provider
        )

        by_action = {step["action"]: step["requires_approval"] for step in result["steps"]}
        self.assertTrue(by_action["Disable the compromised account immediately."])
        self.assertFalse(by_action["Review recent access logs for PAYROLL-DB-03."])
        self.assertFalse(by_action["Document the root cause in the incident report."])

    def test_passing_both_incident_and_scenario_text_raises_value_error(self):
        incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Some incident",
            incident_type="test",
            severity=IncidentGroup.Severity.LOW,
            status=IncidentGroup.Status.OPEN,
        )
        fake_provider = _FakeProvider("x")

        with self.assertRaises(ValueError):
            run_playbook_generation(incident, scenario_text=self.scenario_text, provider=fake_provider)

    def test_passing_neither_incident_nor_scenario_text_raises_value_error(self):
        fake_provider = _FakeProvider("x")

        with self.assertRaises(ValueError):
            run_playbook_generation(provider=fake_provider)
