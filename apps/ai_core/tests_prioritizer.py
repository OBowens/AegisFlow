"""Coverage for the Prioritizer agent ("what should I fix first?"):

- build_priority_context (apps/ai_core/services/priority_context.py)
  gathers an organization's real open incidents (capped and ranked by
  severity then age) and each one's paired risk assessment into one
  prompt.
- run_priority_briefing is the full pipeline -- gather context -> build
  prompt -> call provider -> handle response -- proven correct with a
  fake provider standing in for what Claude would actually return. No
  API key needed, nothing spent.

Same mocking pattern as tests_analyst.py / tests_risk_advisor.py /
tests_readiness_advisor.py.
"""

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.ai_core.modules.prioritizer import run_priority_briefing
from apps.ai_core.services.priority_context import (
    MAX_PRIORITY_INCIDENTS,
    build_priority_context,
)
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.risk.models import RiskAssessment


class _FakeProvider:
    model = "claude-sonnet-5-fake"

    def __init__(self, response_text):
        self.response_text = response_text
        self.last_prompt = None

    def send_message(self, prompt, **kwargs):
        self.last_prompt = prompt
        return self.response_text


def _age_incident(incident, days_ago):
    IncidentGroup.objects.filter(pk=incident.pk).update(
        created_at=timezone.now() - timedelta(days=days_ago)
    )
    incident.refresh_from_db()


class BuildPriorityContextTestCase(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )

        self.critical_old = IncidentGroup.objects.create(
            organization=self.organization,
            title="Old critical ransomware indicator",
            incident_type="malware",
            severity=IncidentGroup.Severity.CRITICAL,
            status=IncidentGroup.Status.OPEN,
            affected_systems="FILE-SRV-01",
        )
        _age_incident(self.critical_old, 30)

        self.critical_new = IncidentGroup.objects.create(
            organization=self.organization,
            title="Fresh critical unauthorized access",
            incident_type="unauthorized_access",
            severity=IncidentGroup.Severity.CRITICAL,
            status=IncidentGroup.Status.INVESTIGATING,
            affected_systems="VPN-GW",
        )
        _age_incident(self.critical_new, 1)

        self.high = IncidentGroup.objects.create(
            organization=self.organization,
            title="High severity failed login burst",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="WEB-01",
        )
        _age_incident(self.high, 10)

        self.low = IncidentGroup.objects.create(
            organization=self.organization,
            title="Low severity informational alert",
            incident_type="informational",
            severity=IncidentGroup.Severity.LOW,
            status=IncidentGroup.Status.OPEN,
            affected_systems="PRINT-01",
        )
        _age_incident(self.low, 5)

        # Resolved -- must not count as "open" at all.
        self.resolved = IncidentGroup.objects.create(
            organization=self.organization,
            title="Already resolved critical incident",
            incident_type="malware",
            severity=IncidentGroup.Severity.CRITICAL,
            status=IncidentGroup.Status.RESOLVED,
            affected_systems="FILE-SRV-02",
        )

        self.risk = RiskAssessment.objects.create(
            organization=self.organization,
            incident=self.critical_old,
            risk_title="Ransomware containment risk",
            likelihood=5,
            impact=5,
            risk_level=RiskAssessment.Level.CRITICAL,
            reasoning="Untriaged ransomware indicators on a file server for 30 days.",
            recommended_priority=RiskAssessment.RecommendedPriority.URGENT,
        )

    def test_total_open_count_excludes_resolved_incidents(self):
        context = build_priority_context(self.organization)

        self.assertIn("Total open incidents: 4", context)

    def test_incidents_are_ranked_by_severity_then_age(self):
        context = build_priority_context(self.organization)

        # Same severity (critical): the older one (30 days) must rank
        # ahead of the newer one (1 day) -- oldest-open-first within a tier.
        old_pos = context.index(f"Incident #{self.critical_old.id}")
        new_pos = context.index(f"Incident #{self.critical_new.id}")
        high_pos = context.index(f"Incident #{self.high.id}")
        low_pos = context.index(f"Incident #{self.low.id}")

        self.assertTrue(old_pos < new_pos < high_pos < low_pos)
        self.assertNotIn(f"Incident #{self.resolved.id}", context)

    def test_context_includes_real_severity_status_and_age(self):
        context = build_priority_context(self.organization)

        self.assertIn(
            f'Incident #{self.critical_old.id} "Old critical ransomware indicator" -- '
            "severity=Critical, status=Open, open for 30 days, "
            "affected system(s)=FILE-SRV-01",
            context,
        )

    def test_context_includes_the_paired_risk_when_present(self):
        context = build_priority_context(self.organization)

        self.assertIn(
            "Risk: Ransomware containment risk (score=25/25, level=Critical, "
            "recommended priority=Urgent)",
            context,
        )

    def test_context_notes_missing_risk_for_incidents_without_one(self):
        context = build_priority_context(self.organization)

        self.assertIn("No formal risk assessment recorded for this incident yet.", context)

    def test_context_caps_a_large_open_incident_list(self):
        # Bulk-create well past the cap to prove the prompt stays bounded
        # even when an org has hundreds of open incidents (286 in the real
        # dev DB today).
        for index in range(MAX_PRIORITY_INCIDENTS + 5):
            IncidentGroup.objects.create(
                organization=self.organization,
                title=f"Bulk medium incident {index}",
                incident_type="informational",
                severity=IncidentGroup.Severity.MEDIUM,
                status=IncidentGroup.Status.OPEN,
                affected_systems="BULK-SYS",
            )

        context = build_priority_context(self.organization)

        total_open = 4 + MAX_PRIORITY_INCIDENTS + 5
        self.assertIn(f"Total open incidents: {total_open}", context)
        self.assertIn(f"Showing the top {MAX_PRIORITY_INCIDENTS} below", context)
        self.assertEqual(context.count("Incident #"), MAX_PRIORITY_INCIDENTS)


class RunPriorityBriefingTestCase(TestCase):
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
            title="Old critical ransomware indicator",
            incident_type="malware",
            severity=IncidentGroup.Severity.CRITICAL,
            status=IncidentGroup.Status.OPEN,
            affected_systems="FILE-SRV-01",
        )
        _age_incident(self.incident, 30)
        RiskAssessment.objects.create(
            organization=self.organization,
            incident=self.incident,
            risk_title="Ransomware containment risk",
            likelihood=5,
            impact=5,
            risk_level=RiskAssessment.Level.CRITICAL,
            reasoning="Untriaged ransomware indicators on a file server for 30 days.",
            recommended_priority=RiskAssessment.RecommendedPriority.URGENT,
        )

    def test_prompt_sent_to_provider_includes_real_open_incident_and_risk_data(self):
        # Same context-injection proof pattern as tests_analyst.py /
        # tests_risk_advisor.py / tests_readiness_advisor.py.
        fake_provider = _FakeProvider("1. Incident #1 -- fix the ransomware indicator first.")

        run_priority_briefing(self.organization, provider=fake_provider)

        self.assertIn("Old critical ransomware indicator", fake_provider.last_prompt)
        self.assertIn("severity=Critical", fake_provider.last_prompt)
        self.assertIn("open for 30 days", fake_provider.last_prompt)
        self.assertIn("Ransomware containment risk", fake_provider.last_prompt)
        self.assertIn("score=25/25", fake_provider.last_prompt)

    def test_pipeline_returns_display_ready_result_using_fake_provider(self):
        fake_response = (
            "1. Incident #1 (Old critical ransomware indicator) -- fix first: "
            "critical severity, 30 days open, untriaged ransomware indicators."
        )
        fake_provider = _FakeProvider(fake_response)

        result = run_priority_briefing(self.organization, provider=fake_provider)

        self.assertEqual(result["organization_id"], self.organization.id)
        self.assertEqual(result["model"], "claude-sonnet-5-fake")
        self.assertEqual(result["briefing"], fake_response)
        self.assertIn("generated_at", result)

    def test_pipeline_propagates_the_provider_missing_key_error(self):
        from apps.ai_core.providers.anthropic_provider import AnthropicProvider

        unconfigured_provider = AnthropicProvider(api_key=None)
        unconfigured_provider.api_key = None

        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            run_priority_briefing(self.organization, provider=unconfigured_provider)
