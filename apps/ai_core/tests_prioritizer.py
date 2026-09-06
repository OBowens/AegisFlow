"""Coverage for the Prioritizer agent ("what should I fix first?").

The demo/prod dataset this feature runs against has near-identical ages
and risk scores across its whole Critical tier, so it cannot exercise
the ranking. These tests build deliberately varied synthetic incidents
-- different ages, severities, risk scores, and overlapping /
non-overlapping affected systems -- to exercise:

- ``rank_open_incident_groups`` -- grouping open incidents by shared
  affected system (connected components) and ordering the groups by
  severity -> risk -> age -> id.
- ``build_priority_context`` -- the capped, grouped prompt text plus the
  explicit coverage statement that governs when the model should hedge.
- ``run_priority_briefing`` -- the full pipeline, with a fake provider
  standing in for Claude (no API key, nothing spent).

Same mocking pattern as tests_analyst.py / tests_readiness_advisor.py.
"""

import re
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.ai_core.modules.prioritizer import run_priority_briefing
from apps.ai_core.services.priority_context import (
    MAX_INCIDENTS_PER_GROUP,
    MAX_PRIORITY_GROUPS,
    build_priority_context,
    rank_open_incident_groups,
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


def _make_org(name="Demo Organization"):
    return Organization.objects.create(
        name=name,
        organization_type="Demo",
        country="St. Vincent and the Grenadines",
        sector="Technology",
        risk_profile="medium",
    )


def _make_incident(
    org,
    title,
    *,
    severity=IncidentGroup.Severity.MEDIUM,
    systems="",
    status=IncidentGroup.Status.OPEN,
    days_ago=1,
):
    incident = IncidentGroup.objects.create(
        organization=org,
        title=title,
        incident_type="test",
        severity=severity,
        status=status,
        affected_systems=systems,
    )
    _age(incident, days_ago)
    return incident


def _age(incident, days_ago):
    IncidentGroup.objects.filter(pk=incident.pk).update(
        created_at=timezone.now() - timedelta(days=days_ago)
    )
    incident.refresh_from_db()


def _pin_created_at(*incidents, when):
    IncidentGroup.objects.filter(pk__in=[i.pk for i in incidents]).update(created_at=when)
    for incident in incidents:
        incident.refresh_from_db()


def _add_risk(
    incident,
    *,
    level=RiskAssessment.Level.HIGH,
    recommended_priority=RiskAssessment.RecommendedPriority.HIGH,
    likelihood=3,
    impact=3,
):
    return RiskAssessment.objects.create(
        organization=incident.organization,
        incident=incident,
        risk_title=f"Risk for {incident.title}",
        likelihood=likelihood,
        impact=impact,
        risk_level=level,
        reasoning="synthetic",
        recommended_priority=recommended_priority,
    )


class ClusterBySharedSystemTests(TestCase):
    def setUp(self):
        self.org = _make_org()

    def _cluster_ids(self):
        return [
            sorted(i.id for i in cluster.incidents)
            for cluster in rank_open_incident_groups(self.org)
        ]

    def test_incidents_on_the_same_system_form_one_cluster(self):
        a = _make_incident(self.org, "malware on HOST-A", systems="HOST-A")
        b = _make_incident(self.org, "log activity on HOST-A", systems="HOST-A")
        c = _make_incident(self.org, "unrelated on HOST-B", systems="HOST-B")

        clusters = self._cluster_ids()

        self.assertIn(sorted([a.id, b.id]), clusters)
        self.assertIn([c.id], clusters)
        self.assertEqual(len(clusters), 2)

    def test_overlapping_system_sets_merge_transitively(self):
        w = _make_incident(self.org, "web", systems="WEB-01")
        wd = _make_incident(self.org, "web+db", systems="WEB-01, DB-01")
        dx = _make_incident(self.org, "db+x", systems="DB-01, X-01")
        y = _make_incident(self.org, "isolated", systems="Y-99")

        clusters = rank_open_incident_groups(self.org)
        by_size = sorted((sorted(i.id for i in c.incidents) for c in clusters), key=len)

        self.assertEqual(by_size, [[y.id], sorted([w.id, wd.id, dx.id])])
        merged = next(c for c in clusters if len(c.incidents) == 3)
        self.assertEqual(merged.systems, ["DB-01", "WEB-01", "X-01"])

    def test_incidents_without_a_system_are_each_their_own_cluster(self):
        n1 = _make_incident(self.org, "no system 1", systems="")
        n2 = _make_incident(self.org, "no system 2", systems="   ")
        s = _make_incident(self.org, "has system", systems="APP-1")

        clusters = self._cluster_ids()

        self.assertEqual(sorted(clusters), sorted([[n1.id], [n2.id], [s.id]]))


class ClusterRankingTests(TestCase):
    def setUp(self):
        self.org = _make_org()

    def _ranked_lead_ids(self):
        return [c.lead_incident.id for c in rank_open_incident_groups(self.org)]

    def test_severity_is_the_primary_sort(self):
        # A fresh Critical with no risk still outranks an old High with an
        # Urgent risk assessment.
        high = _make_incident(
            self.org, "old high", severity=IncidentGroup.Severity.HIGH,
            systems="H1", days_ago=60,
        )
        _add_risk(
            high, recommended_priority=RiskAssessment.RecommendedPriority.URGENT,
            likelihood=5, impact=5,
        )
        crit = _make_incident(
            self.org, "fresh critical", severity=IncidentGroup.Severity.CRITICAL,
            systems="C1", days_ago=1,
        )

        self.assertEqual(self._ranked_lead_ids(), [crit.id, high.id])

    def test_risk_breaks_a_severity_and_age_tie(self):
        when = timezone.now() - timedelta(days=10)
        weak = _make_incident(
            self.org, "weak risk", severity=IncidentGroup.Severity.CRITICAL, systems="W1",
        )
        strong = _make_incident(
            self.org, "strong risk", severity=IncidentGroup.Severity.CRITICAL, systems="S1",
        )
        _pin_created_at(weak, strong, when=when)
        _add_risk(
            weak, recommended_priority=RiskAssessment.RecommendedPriority.LOW,
            likelihood=2, impact=3,
        )
        _add_risk(
            strong, recommended_priority=RiskAssessment.RecommendedPriority.URGENT,
            likelihood=5, impact=4,
        )

        # strong was created second (higher id); risk must still float it up.
        self.assertEqual(self._ranked_lead_ids(), [strong.id, weak.id])

    def test_age_breaks_a_severity_and_risk_tie(self):
        new = _make_incident(
            self.org, "new", severity=IncidentGroup.Severity.CRITICAL, systems="N1", days_ago=2,
        )
        old = _make_incident(
            self.org, "old", severity=IncidentGroup.Severity.CRITICAL, systems="O1", days_ago=30,
        )
        # Identical (absent) risk; old has the higher id but must rank first.
        self.assertEqual(self._ranked_lead_ids(), [old.id, new.id])

    def test_full_tie_falls_back_to_lowest_incident_id_deterministically(self):
        when = timezone.now() - timedelta(days=5)
        a = _make_incident(self.org, "a", severity=IncidentGroup.Severity.HIGH, systems="TIE-A")
        b = _make_incident(self.org, "b", severity=IncidentGroup.Severity.HIGH, systems="TIE-B")
        c = _make_incident(self.org, "c", severity=IncidentGroup.Severity.HIGH, systems="TIE-C")
        _pin_created_at(a, b, c, when=when)

        first = self._ranked_lead_ids()
        second = self._ranked_lead_ids()

        self.assertEqual(first, [a.id, b.id, c.id])
        self.assertEqual(first, second)

    def test_incidents_within_a_cluster_are_ranked_by_the_same_key(self):
        low = _make_incident(
            self.org, "low on HOST-Z", severity=IncidentGroup.Severity.LOW, systems="HOST-Z",
        )
        critical = _make_incident(
            self.org, "critical on HOST-Z", severity=IncidentGroup.Severity.CRITICAL,
            systems="HOST-Z",
        )
        high = _make_incident(
            self.org, "high on HOST-Z", severity=IncidentGroup.Severity.HIGH, systems="HOST-Z",
        )

        [cluster] = rank_open_incident_groups(self.org)

        self.assertEqual(
            [i.id for i in cluster.incidents], [critical.id, high.id, low.id]
        )


class BuildPriorityContextTests(TestCase):
    def setUp(self):
        self.org = _make_org()

    def test_total_open_excludes_resolved_and_closed(self):
        _make_incident(self.org, "open one", systems="A")
        _make_incident(
            self.org, "resolved", systems="B", status=IncidentGroup.Status.RESOLVED,
        )
        _make_incident(
            self.org, "closed", systems="C", status=IncidentGroup.Status.CLOSED,
        )
        _make_incident(
            self.org, "investigating", systems="D", status=IncidentGroup.Status.INVESTIGATING,
        )

        context = build_priority_context(self.org)

        self.assertIn("Total open incidents: 2", context)
        self.assertNotIn("resolved", context)
        self.assertNotIn("closed", context)

    def test_same_host_incidents_become_one_grouped_entry(self):
        for n in range(5):
            _make_incident(
                self.org, f"incident {n} on FILE-01",
                severity=IncidentGroup.Severity.CRITICAL, systems="FILE-01",
            )
        _make_incident(
            self.org, "lone incident on WEB-09",
            severity=IncidentGroup.Severity.CRITICAL, systems="WEB-09",
        )

        context = build_priority_context(self.org)

        # Two numbered cluster entries, not six.
        self.assertIn("1. FILE-01 -- 5 open incidents", context)
        self.assertIn("2. WEB-09 -- 1 open incident", context)
        self.assertEqual(len(re.findall(r"(?m)^\d+\. ", context)), 2)

    def test_cluster_cap_limits_the_number_of_groups_shown(self):
        for n in range(MAX_PRIORITY_GROUPS + 3):
            _make_incident(
                self.org, f"critical on HOST-{n}",
                severity=IncidentGroup.Severity.CRITICAL, systems=f"HOST-{n}",
            )

        context = build_priority_context(self.org)

        self.assertEqual(context.count("open incident ("), MAX_PRIORITY_GROUPS)
        self.assertIn(
            f"Showing {MAX_PRIORITY_GROUPS} of {MAX_PRIORITY_GROUPS + 3} incident group(s)",
            context,
        )

    def test_per_group_incident_cap_summarises_the_rest(self):
        for n in range(MAX_INCIDENTS_PER_GROUP + 4):
            _make_incident(
                self.org, f"incident {n} on BUSY-01",
                severity=IncidentGroup.Severity.HIGH, systems="BUSY-01",
            )

        context = build_priority_context(self.org)

        self.assertEqual(context.count('Incident #'), MAX_INCIDENTS_PER_GROUP)
        self.assertIn("...and 4 more open incidents on this system not shown.", context)

    def test_paired_risk_is_rendered_and_missing_risk_is_noted(self):
        with_risk = _make_incident(
            self.org, "has risk", severity=IncidentGroup.Severity.CRITICAL, systems="R1",
        )
        _add_risk(
            with_risk, level=RiskAssessment.Level.CRITICAL,
            recommended_priority=RiskAssessment.RecommendedPriority.URGENT,
            likelihood=4, impact=4,
        )
        _make_incident(
            self.org, "no risk", severity=IncidentGroup.Severity.CRITICAL, systems="R2",
        )

        context = build_priority_context(self.org)

        self.assertIn(
            "score=16/25, level=Critical, recommended priority=Urgent", context
        )
        self.assertIn("no formal risk assessment recorded yet.", context)


class CoverageStatementTests(TestCase):
    def setUp(self):
        self.org = _make_org()

    def test_states_that_all_criticals_are_shown_when_cap_hides_only_lower(self):
        for n in range(3):
            _make_incident(
                self.org, f"critical {n}", severity=IncidentGroup.Severity.CRITICAL,
                systems=f"CRIT-{n}",
            )
        for n in range(10):
            _make_incident(
                self.org, f"medium {n}", severity=IncidentGroup.Severity.MEDIUM,
                systems=f"MED-{n}",
            )

        context = build_priority_context(self.org)

        self.assertIn("every open Critical-severity incident (3)", context)
        self.assertIn("Every open incident not shown below is severity Medium or lower", context)
        self.assertNotIn("NOT listed", context)

    def test_flags_a_partial_view_when_the_cap_truncates_the_critical_tier(self):
        for n in range(MAX_PRIORITY_GROUPS + 2):
            _make_incident(
                self.org, f"critical {n}", severity=IncidentGroup.Severity.CRITICAL,
                systems=f"CRIT-{n}",
            )

        context = build_priority_context(self.org)

        self.assertIn(
            f"{MAX_PRIORITY_GROUPS} of {MAX_PRIORITY_GROUPS + 2} open "
            "Critical-severity incidents are shown",
            context,
        )
        self.assertIn("2 Critical incident(s) are NOT listed", context)
        self.assertIn("partial view of the most urgent tier", context)

    def test_no_caveat_at_all_when_everything_is_shown(self):
        _make_incident(self.org, "one", severity=IncidentGroup.Severity.HIGH, systems="A")
        _make_incident(self.org, "two", severity=IncidentGroup.Severity.LOW, systems="B")

        context = build_priority_context(self.org)

        self.assertIn("All 2 open incident(s) are shown below", context)
        self.assertNotIn("COVERAGE:", context)

    def test_states_when_there_are_no_criticals_or_highs(self):
        for n in range(MAX_PRIORITY_GROUPS + 2):
            _make_incident(
                self.org, f"medium {n}", severity=IncidentGroup.Severity.MEDIUM,
                systems=f"MED-{n}",
            )

        context = build_priority_context(self.org)

        self.assertIn("no open Critical- or High-severity incidents", context)
        self.assertIn("nothing more severe is hidden by the cap", context)

    def test_empty_organisation_reports_no_open_incidents(self):
        context = build_priority_context(self.org)

        self.assertIn("Total open incidents: 0", context)
        self.assertIn("No open incidents right now.", context)


class RunPriorityBriefingTests(TestCase):
    def setUp(self):
        self.org = _make_org()
        self.incident = _make_incident(
            self.org, "Old critical ransomware indicator",
            severity=IncidentGroup.Severity.CRITICAL, systems="FILE-SRV-01", days_ago=30,
        )
        _add_risk(
            self.incident, level=RiskAssessment.Level.CRITICAL,
            recommended_priority=RiskAssessment.RecommendedPriority.URGENT,
            likelihood=5, impact=5,
        )

    def test_prompt_includes_grouped_open_incident_and_risk_data(self):
        fake = _FakeProvider("1. FILE-SRV-01 -- fix the ransomware indicator first.")

        run_priority_briefing(self.org, provider=fake)

        self.assertIn("treat each group as one unit of work", fake.last_prompt)
        self.assertIn("grouped by affected system", fake.last_prompt)
        self.assertIn("1. FILE-SRV-01 -- 1 open incident", fake.last_prompt)
        self.assertIn("Old critical ransomware indicator", fake.last_prompt)
        self.assertIn("score=25/25", fake.last_prompt)
        self.assertIn("All 1 open incident(s) are shown below", fake.last_prompt)

    def test_pipeline_returns_display_ready_result(self):
        fake = _FakeProvider("FILE-SRV-01 -- fix first: critical, 30 days open.")

        result = run_priority_briefing(self.org, provider=fake)

        self.assertEqual(result["organization_id"], self.org.id)
        self.assertEqual(result["model"], "claude-sonnet-5-fake")
        self.assertEqual(result["briefing"], "FILE-SRV-01 -- fix first: critical, 30 days open.")
        self.assertIn("generated_at", result)

    def test_pipeline_propagates_the_provider_missing_key_error(self):
        from apps.ai_core.providers.anthropic_provider import AnthropicProvider

        unconfigured = AnthropicProvider(api_key=None)
        unconfigured.api_key = None

        with self.assertRaisesMessage(RuntimeError, "ANTHROPIC_API_KEY is not set"):
            run_priority_briefing(self.org, provider=unconfigured)
