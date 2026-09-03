"""Coverage for the Incident Comparator agent ("compare incidents"):

- build_comparison_context (apps/ai_core/services/comparison_context.py)
  reuses build_incident_context for each of the two incidents (rather
  than re-implementing evidence/gap/risk gathering) and adds a
  precomputed "Shared Data Points" section.
- run_incident_comparison is the full pipeline -- gather context -> build
  prompt -> call provider -> handle response -- proven correct with a
  fake provider standing in for what Claude would actually return. No
  API key needed, nothing spent.

Same mocking pattern as tests_analyst.py / tests_risk_advisor.py /
tests_prioritizer.py.
"""

from datetime import datetime, timezone as dt_timezone

from django.test import TestCase
from django.utils import timezone

from apps.ai_core.modules.comparator import run_incident_comparison
from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.comparison_context import build_comparison_context
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


class BuildComparisonContextTestCase(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.uploaded_file_a = UploadedLogFile.objects.create(
            organization=self.organization,
            file_name="incident_a.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path="demo/incident_a.log",
            status=UploadedLogFile.Status.PARSED,
        )
        self.uploaded_file_b = UploadedLogFile.objects.create(
            organization=self.organization,
            file_name="incident_b.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path="demo/incident_b.log",
            status=UploadedLogFile.Status.PARSED,
        )

        # Incident A: a brute-force attempt against WEB-01, first seen
        # 2026-08-01, from a specific external IP, on the "admin" account.
        self.incident_a = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible brute-force attempt against privileged account",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="WEB-01,VPN-GW",
            first_seen=datetime(2026, 8, 1, 10, 0, tzinfo=dt_timezone.utc),
        )
        alert_a = ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file_a,
            organization=self.organization,
            source_tool="test",
            timestamp=timezone.now(),
            affected_system="WEB-01",
            account="admin",
            source_ip="203.0.113.77",
            event_type="failed_login",
            severity_hint=ParsedAlert.SeverityHint.HIGH,
            raw_message="Failed password for admin from 203.0.113.77",
            normalized_summary="Repeated failed logins for admin",
        )
        IncidentEvidence.objects.create(
            incident=self.incident_a, alert=alert_a, evidence_reason="Matched account and IP."
        )

        # Incident B: unauthorized access on a DIFFERENT system (DB-02),
        # but the SAME source IP and account, first seen 12 days later --
        # the overlap the comparator should surface.
        self.incident_b = IncidentGroup.objects.create(
            organization=self.organization,
            title="Suspicious database access from external IP",
            incident_type="unauthorized_access",
            severity=IncidentGroup.Severity.MEDIUM,
            status=IncidentGroup.Status.OPEN,
            affected_systems="DB-02",
            first_seen=datetime(2026, 8, 13, 10, 0, tzinfo=dt_timezone.utc),
        )
        alert_b = ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file_b,
            organization=self.organization,
            source_tool="test",
            timestamp=timezone.now(),
            affected_system="DB-02",
            account="admin",
            source_ip="203.0.113.77",
            event_type="unauthorized_access",
            severity_hint=ParsedAlert.SeverityHint.MEDIUM,
            raw_message="Unauthorized query from admin at 203.0.113.77",
            normalized_summary="Unusual database access",
        )
        IncidentEvidence.objects.create(
            incident=self.incident_b, alert=alert_b, evidence_reason="Matched account and IP."
        )

    def test_context_includes_both_incidents_distinct_full_detail(self):
        context = build_comparison_context(self.incident_a, self.incident_b)

        self.assertIn(f"## Incident A (#{self.incident_a.id})", context)
        self.assertIn("Possible brute-force attempt against privileged account", context)
        self.assertIn("WEB-01", context)

        self.assertIn(f"## Incident B (#{self.incident_b.id})", context)
        self.assertIn("Suspicious database access from external IP", context)
        self.assertIn("DB-02", context)

        # Each incident's own Evidence section must carry its own
        # source_ip line -- not merged or deduped away just because the
        # two incidents happen to share an IP.
        self.assertEqual(context.count("source_ip=203.0.113.77"), 2)

    def test_shared_data_points_surfaces_the_real_overlap(self):
        context = build_comparison_context(self.incident_a, self.incident_b)

        self.assertIn("## Shared Data Points (precomputed)", context)
        self.assertIn("Same incident type: no", context)
        self.assertIn("Shared source IP(s): 203.0.113.77", context)
        self.assertIn("Shared account(s): admin", context)
        self.assertIn("Shared affected system(s): None", context)
        self.assertIn("Gap between first-seen timestamps: 12 day(s)", context)

    def test_shared_data_points_reports_none_when_nothing_overlaps(self):
        unrelated = IncidentGroup.objects.create(
            organization=self.organization,
            title="Unrelated printer outage",
            incident_type="availability",
            severity=IncidentGroup.Severity.LOW,
            status=IncidentGroup.Status.OPEN,
            affected_systems="PRINT-03",
        )

        context = build_comparison_context(self.incident_a, unrelated)

        self.assertIn("Shared source IP(s): None", context)
        self.assertIn("Shared account(s): None", context)
        self.assertIn("Shared affected system(s): None", context)
        self.assertIn(
            "Gap between first-seen timestamps: Unknown (one or both incidents "
            "are missing a first_seen timestamp)",
            context,
        )


class RunIncidentComparisonTestCase(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.incident_a = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible brute-force attempt against privileged account",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="WEB-01",
        )
        self.incident_b = IncidentGroup.objects.create(
            organization=self.organization,
            title="Suspicious database access from external IP",
            incident_type="unauthorized_access",
            severity=IncidentGroup.Severity.MEDIUM,
            status=IncidentGroup.Status.OPEN,
            affected_systems="DB-02",
        )

    def test_prompt_sent_to_provider_includes_both_incidents_real_distinct_data(self):
        # The key proof for this feature: both incidents' real, distinct
        # data -- not just one -- must reach the same prompt.
        fake_provider = _FakeProvider("These two incidents appear unrelated.")

        run_incident_comparison(self.incident_a, self.incident_b, provider=fake_provider)

        self.assertIn("Possible brute-force attempt against privileged account", fake_provider.last_prompt)
        self.assertIn("WEB-01", fake_provider.last_prompt)
        self.assertIn("Suspicious database access from external IP", fake_provider.last_prompt)
        self.assertIn("DB-02", fake_provider.last_prompt)
        self.assertIn(f"## Incident A (#{self.incident_a.id})", fake_provider.last_prompt)
        self.assertIn(f"## Incident B (#{self.incident_b.id})", fake_provider.last_prompt)

    def test_pipeline_returns_display_ready_result_using_fake_provider(self):
        fake_response = (
            "Shared account (admin) and source IP suggest these may be the same "
            "actor, but the 12-day gap and different systems make this only "
            "moderately confident -- not conclusive."
        )
        fake_provider = _FakeProvider(fake_response)

        result = run_incident_comparison(self.incident_a, self.incident_b, provider=fake_provider)

        self.assertEqual(result["incident_id"], self.incident_a.id)
        self.assertEqual(result["other_incident_id"], self.incident_b.id)
        self.assertEqual(result["model"], "claude-sonnet-5-fake")
        self.assertEqual(result["comparison"], fake_response)
        self.assertIn("generated_at", result)

    def test_pipeline_propagates_the_provider_missing_key_error(self):
        unconfigured_provider = AnthropicProvider(api_key=None)
        unconfigured_provider.api_key = None

        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            run_incident_comparison(self.incident_a, self.incident_b, provider=unconfigured_provider)
