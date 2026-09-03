"""Coverage for the Report Writer agent (apps/ai_core/modules/
report_writer.py) and its two new aggregate context builders
(apps/ai_core/services/executive_context.py and risk_report_context.py):

- build_executive_context and build_risk_report_context are
  organization-wide rollups, capped and ranked -- these tests prove
  real, distinctive org-wide data (not a stub) reaches the prompt, and
  that ranking actually orders by severity/risk score rather than
  creation order.
- run_report_generation dispatches on report_type: Executive and Risk
  take an Organization and use the two new builders above; Readiness
  takes an Organization and reuses build_readiness_context unchanged;
  Technical and Incident both take an IncidentGroup and reuse
  build_incident_context unchanged. Each is proven here with a fake
  provider capturing the actual prompt sent, so there's no ambiguity
  about which builder really ran.

Same mocking pattern as apps/ai_core/tests_analyst.py, tests_writer.py,
and tests_readiness_advisor.py.
"""

from django.test import TestCase
from django.utils import timezone

from apps.ai_core.modules.report_writer import _first_paragraph, run_report_generation
from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.executive_context import build_executive_context
from apps.ai_core.services.risk_report_context import build_risk_report_context
from apps.incidents.models import IncidentEvidence, IncidentGroup
from apps.log_intake.models import ParsedAlert, UploadedLogFile
from apps.organizations.models import Organization
from apps.reports.models import GeneratedReport
from apps.resilience.models import DisasterReadinessFinding
from apps.risk.models import GapFinding, RiskAssessment


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


class _OrgWideFixtureMixin:
    """Two incidents in one organization -- one CRITICAL/newer, one
    HIGH/older -- each with its own risk assessment, plus one readiness
    finding, so context builders have real, distinctive, rankable data
    to work with instead of a single trivial row.
    """

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.high_incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Suspicious PowerShell Activity on WEB-01",
            incident_type="endpoint",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="WEB-01",
            summary="PowerShell activity detected on WEB-01.",
        )
        self.critical_incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Ransomware Beaconing on FILE-SERVER-3",
            incident_type="ransomware",
            severity=IncidentGroup.Severity.CRITICAL,
            status=IncidentGroup.Status.OPEN,
            affected_systems="FILE-SERVER-3",
            summary="Beaconing consistent with ransomware staging.",
        )
        self.low_risk = RiskAssessment.objects.create(
            organization=self.organization,
            incident=self.high_incident,
            risk_title="Unpatched PowerShell Execution Policy Risk",
            likelihood=2,
            impact=2,
            risk_level=RiskAssessment.Level.MEDIUM,
            reasoning="Execution policy allows unsigned scripts to run.",
            recommended_priority=RiskAssessment.RecommendedPriority.MEDIUM,
        )
        self.high_risk = RiskAssessment.objects.create(
            organization=self.organization,
            incident=self.critical_incident,
            risk_title="Ransomware Encryption Risk",
            likelihood=5,
            impact=5,
            risk_level=RiskAssessment.Level.CRITICAL,
            reasoning="Beaconing pattern matches known ransomware staging behavior.",
            recommended_priority=RiskAssessment.RecommendedPriority.URGENT,
        )
        self.readiness_finding = DisasterReadinessFinding.objects.create(
            organization=self.organization,
            readiness_issue="No offsite backup for FILE-SERVER-3",
            disaster_impact="Ransomware could destroy the only copy of this data.",
            recovery_concern="No tested offsite restore procedure exists.",
            source=DisasterReadinessFinding.Source.LOG_BASED,
            priority=DisasterReadinessFinding.Priority.HIGH,
        )


class BuildExecutiveContextTestCase(_OrgWideFixtureMixin, TestCase):
    def test_context_includes_real_incidents_risks_and_readiness_across_the_org(self):
        context = build_executive_context(self.organization)

        self.assertIn(self.organization.name, context)
        self.assertIn("Suspicious PowerShell Activity on WEB-01", context)
        self.assertIn("Ransomware Beaconing on FILE-SERVER-3", context)
        self.assertIn("Ransomware Encryption Risk", context)
        self.assertIn("Unpatched PowerShell Execution Policy Risk", context)
        self.assertIn("## Readiness Snapshot", context)

    def test_open_incidents_are_ranked_critical_first_regardless_of_creation_order(self):
        # high_incident was created before critical_incident, so a
        # creation-order bug would put it first -- proving the CRITICAL
        # one appears first proves the severity ranking is real.
        context = build_executive_context(self.organization)

        critical_index = context.index("Ransomware Beaconing on FILE-SERVER-3")
        high_index = context.index("Suspicious PowerShell Activity on WEB-01")
        self.assertLess(critical_index, high_index)

    def test_risk_findings_are_ranked_by_score_not_creation_order(self):
        # low_risk (score 4) was created before high_risk (score 25) --
        # proving the CRITICAL-score risk appears first proves the
        # ranking is by risk_score, not insertion order.
        context = build_executive_context(self.organization)

        high_score_index = context.index("Ransomware Encryption Risk")
        low_score_index = context.index("Unpatched PowerShell Execution Policy Risk")
        self.assertLess(high_score_index, low_score_index)


class BuildRiskReportContextTestCase(_OrgWideFixtureMixin, TestCase):
    def test_context_includes_real_org_wide_risk_data_and_level_counts(self):
        context = build_risk_report_context(self.organization)

        self.assertIn("## Risk Overview", context)
        self.assertIn("Total risk findings: 2", context)
        self.assertIn("1 critical", context)
        self.assertIn("1 medium", context)
        self.assertIn("Ransomware Encryption Risk", context)
        self.assertIn("Unpatched PowerShell Execution Policy Risk", context)
        self.assertIn("Beaconing pattern matches known ransomware staging behavior.", context)

    def test_risks_are_ranked_by_score_not_creation_order(self):
        context = build_risk_report_context(self.organization)

        high_score_index = context.index("Ransomware Encryption Risk")
        low_score_index = context.index("Unpatched PowerShell Execution Policy Risk")
        self.assertLess(high_score_index, low_score_index)

    def test_unassessed_gap_findings_are_counted(self):
        GapFinding.objects.create(
            organization=self.organization,
            gap_name="No MFA on admin console",
            description="Admin console has no MFA enforced.",
        )

        context = build_risk_report_context(self.organization)

        self.assertIn("Gap findings without a formal risk assessment yet: 1", context)


class RunReportGenerationOrgWideTestCase(_OrgWideFixtureMixin, TestCase):
    """Executive and Risk both take the Organization and must route
    through their own new aggregate builder -- proven here by checking
    the real org-wide data each builder is known (from the TestCases
    above) to produce actually reaches the prompt.
    """

    def test_executive_report_prompt_includes_real_org_wide_data(self):
        fake_provider = _FakeProvider("Executive summary text.")

        result = run_report_generation(
            GeneratedReport.ReportType.EXECUTIVE, self.organization, provider=fake_provider
        )

        self.assertIn("Ransomware Beaconing on FILE-SERVER-3", fake_provider.last_prompt)
        self.assertIn("Ransomware Encryption Risk", fake_provider.last_prompt)
        self.assertIn("## Readiness Snapshot", fake_provider.last_prompt)
        self.assertIn("executive report", fake_provider.last_prompt.lower())
        self.assertEqual(result["report_type"], GeneratedReport.ReportType.EXECUTIVE)
        self.assertEqual(result["report_text"], "Executive summary text.")
        self.assertEqual(result["summary"], "Executive summary text.")

    def test_risk_report_prompt_includes_real_org_wide_risk_data(self):
        fake_provider = _FakeProvider("Risk report text.")

        run_report_generation(GeneratedReport.ReportType.RISK, self.organization, provider=fake_provider)

        self.assertIn("Ransomware Encryption Risk", fake_provider.last_prompt)
        self.assertIn("Total risk findings: 2", fake_provider.last_prompt)
        self.assertIn("risk report", fake_provider.last_prompt.lower())

    def test_readiness_report_reuses_the_real_readiness_context(self):
        fake_provider = _FakeProvider("Readiness report text.")

        run_report_generation(
            GeneratedReport.ReportType.READINESS, self.organization, provider=fake_provider
        )

        self.assertIn("No offsite backup for FILE-SERVER-3", fake_provider.last_prompt)
        self.assertIn("## Readiness Overview", fake_provider.last_prompt)


class RunReportGenerationIncidentScopedTestCase(TestCase):
    """Technical and Incident both take an IncidentGroup and must reuse
    build_incident_context unchanged -- proven by checking the same
    incident-specific evidence reaches the prompt for both types.
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
            file_name="report_writer_demo.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path="demo/report_writer_demo.log",
            status=UploadedLogFile.Status.PARSED,
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible brute-force attempt against admin account",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="AUTH-01",
            summary="Repeated failed logins detected.",
        )
        self.alert = ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="test",
            timestamp=timezone.now(),
            affected_system="AUTH-01",
            account="admin",
            source_ip="203.0.113.42",
            event_type="failed_login",
            severity_hint=ParsedAlert.SeverityHint.HIGH,
            raw_message="Failed password for admin from 203.0.113.42",
            normalized_summary="Repeated failed logins for admin",
        )
        IncidentEvidence.objects.create(
            incident=self.incident,
            alert=self.alert,
            evidence_reason="Matched account and source IP.",
        )

    def test_technical_report_prompt_includes_the_real_incident_evidence(self):
        fake_provider = _FakeProvider("Technical report text.")

        run_report_generation(GeneratedReport.ReportType.TECHNICAL, self.incident, provider=fake_provider)

        self.assertIn("## Evidence", fake_provider.last_prompt)
        self.assertIn("203.0.113.42", fake_provider.last_prompt)
        self.assertIn("technical report", fake_provider.last_prompt.lower())

    def test_incident_report_prompt_includes_the_same_real_incident_evidence(self):
        fake_provider = _FakeProvider("Incident report text.")

        run_report_generation(GeneratedReport.ReportType.INCIDENT, self.incident, provider=fake_provider)

        self.assertIn("## Evidence", fake_provider.last_prompt)
        self.assertIn("203.0.113.42", fake_provider.last_prompt)
        self.assertIn("incident report", fake_provider.last_prompt.lower())

    def test_technical_and_incident_use_the_same_context_but_different_preambles(self):
        technical_provider = _FakeProvider("x")
        incident_provider = _FakeProvider("x")

        run_report_generation(GeneratedReport.ReportType.TECHNICAL, self.incident, provider=technical_provider)
        run_report_generation(GeneratedReport.ReportType.INCIDENT, self.incident, provider=incident_provider)

        # Same underlying evidence context...
        self.assertIn("203.0.113.42", technical_provider.last_prompt)
        self.assertIn("203.0.113.42", incident_provider.last_prompt)
        # ...but not the same prompt (different system preamble).
        self.assertNotEqual(technical_provider.last_prompt, incident_provider.last_prompt)

    def test_pipeline_propagates_the_provider_missing_key_error(self):
        unconfigured_provider = AnthropicProvider(api_key=None)
        unconfigured_provider.api_key = None

        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            run_report_generation(
                GeneratedReport.ReportType.TECHNICAL, self.incident, provider=unconfigured_provider
            )

    def test_unknown_report_type_raises_value_error(self):
        fake_provider = _FakeProvider("x")

        with self.assertRaises(ValueError):
            run_report_generation("not_a_real_type", self.incident, provider=fake_provider)


class FirstParagraphTestCase(TestCase):
    """Regression coverage for a real bug found during the 2026-08-27
    Part D recovery smoke test: a live model reliably prepends a lone
    markdown title line ("## Executive Summary") before its actual
    summary paragraph even when told to lead with a summary and not
    give it a heading -- confirmed against real generated output. Left
    unhandled, GeneratedReport.summary ends up being just that heading
    instead of an actual summary.
    """

    def test_skips_a_lone_markdown_heading_and_returns_the_real_summary_paragraph(self):
        text = (
            "## Executive Summary\n\n"
            "The organization has several open incidents needing attention.\n\n"
            "## Impact\n\n"
            "Some impact text."
        )

        self.assertEqual(
            _first_paragraph(text),
            "The organization has several open incidents needing attention.",
        )

    def test_returns_the_first_paragraph_unchanged_when_there_is_no_heading(self):
        text = "Plain summary paragraph.\n\nMore text."

        self.assertEqual(_first_paragraph(text), "Plain summary paragraph.")
