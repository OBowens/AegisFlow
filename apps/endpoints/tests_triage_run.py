"""End-to-end correlation + triage run (apps/endpoints/services/triage_run.py)
and the manage.py triage_endpoint_events wrapper.
"""

from __future__ import annotations

import json
from datetime import timedelta
from io import StringIO

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from config.testcase import AuthedTestCase
from apps.ai_core.models import AliasMapping
from apps.audit.models import AIRun
from apps.endpoints.models import Endpoint, EndpointCorrelationCandidate, EndpointEvent
from apps.endpoints.services.triage_run import run_triage_scan
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization

BASE = timezone.now().replace(microsecond=0) - timedelta(hours=1)

ESCALATE_JSON = json.dumps(
    {
        "verdict": "escalate",
        "severity": "high",
        "summary": "Encoded PowerShell pulled a remote payload.",
        "reasoning": "The 4688 command line uses -enc; treat as suspicious until reviewed.",
    }
)
BENIGN_JSON = json.dumps(
    {"verdict": "benign", "severity": "low", "summary": "IT admin script.", "reasoning": "Matches known admin task."}
)


class _FakeProvider:
    model = "claude-sonnet-5-fake"

    def __init__(self, *responses):
        self._responses = list(responses)
        self.calls = 0

    def send_message(self, prompt, **kwargs):
        self.calls += 1
        item = self._responses.pop(0) if self._responses else BENIGN_JSON
        if isinstance(item, Exception):
            raise item
        return item


def _org():
    return Organization.objects.create(
        name="Pilot Org",
        organization_type="Demo",
        country="St. Vincent and the Grenadines",
        sector="Demo",
        risk_profile="medium",
    )


_rid = {"n": 0}


def _suspicious_powershell(endpoint, *, at=BASE, cmdline="powershell -enc SQBFAFgA"):
    _rid["n"] += 1
    return EndpointEvent.objects.create(
        endpoint=endpoint,
        organization=endpoint.organization,
        event_type="Security/4688",
        occurred_at=at,
        payload={
            "computer": endpoint.display_name,
            "record_id": _rid["n"],
            "data": {
                "new_process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "parent_process_name": r"C:\Windows\explorer.exe",
                "command_line": cmdline,
                "subject_user_name": "j.reyes",
            },
        },
    )


def _benign_proc(endpoint, *, at=BASE):
    _rid["n"] += 1
    return EndpointEvent.objects.create(
        endpoint=endpoint,
        organization=endpoint.organization,
        event_type="Security/4688",
        occurred_at=at,
        payload={"computer": endpoint.display_name, "record_id": _rid["n"],
                 "data": {"new_process_name": r"C:\Windows\System32\notepad.exe", "command_line": "notepad"}},
    )


class EscalationFlowTests(TestCase):
    def setUp(self):
        self.org = _org()
        self.endpoint, _ = Endpoint.issue(organization=self.org, display_name="WIN-PILOT-01")

    def test_escalate_verdict_creates_linked_incident(self):
        _suspicious_powershell(self.endpoint)
        _benign_proc(self.endpoint, at=BASE + timedelta(minutes=1))

        report = run_triage_scan(provider=_FakeProvider(ESCALATE_JSON))

        self.assertEqual(report.triaged_escalated, 1)
        self.assertEqual(len(report.incidents_created), 1)

        incident = IncidentGroup.objects.get(id=report.incidents_created[0])
        self.assertEqual(incident.severity, "high")
        self.assertEqual(incident.incident_type, "endpoint_activity")
        self.assertEqual(incident.affected_systems, "WIN-PILOT-01")
        self.assertIsNone(incident.assigned_to)
        self.assertIsNone(incident.confidence)  # never fabricated
        self.assertIn("remote payload", incident.summary)

        candidate = EndpointCorrelationCandidate.objects.get()
        self.assertEqual(candidate.status, EndpointCorrelationCandidate.Status.ESCALATED)
        self.assertEqual(candidate.incident_id, incident.id)
        self.assertEqual(candidate.ai_verdict, "escalate")
        self.assertIsNotNone(candidate.triaged_at)

        # every scanned event carries the marker; clustered ones link back
        self.assertFalse(EndpointEvent.objects.filter(correlation_scanned_at__isnull=True).exists())
        self.assertEqual(candidate.events.count(), 2)

        run = AIRun.objects.get(ai_module="endpoint_triage", status=AIRun.Status.SUCCESS)
        self.assertEqual(run.output_id, str(incident.id))

    def test_benign_verdict_creates_no_incident(self):
        _suspicious_powershell(self.endpoint)
        report = run_triage_scan(provider=_FakeProvider(BENIGN_JSON))

        self.assertEqual(report.triaged_benign, 1)
        self.assertEqual(IncidentGroup.objects.count(), 0)
        candidate = EndpointCorrelationCandidate.objects.get()
        self.assertEqual(candidate.status, EndpointCorrelationCandidate.Status.BENIGN)
        self.assertEqual(candidate.ai_verdict, "benign")

    def test_no_candidates_is_a_clean_noop(self):
        _benign_proc(self.endpoint)
        report = run_triage_scan(provider=_FakeProvider())
        self.assertEqual(report.candidates_created, 0)
        self.assertEqual(EndpointCorrelationCandidate.objects.count(), 0)
        # benign events are still marked scanned
        self.assertFalse(EndpointEvent.objects.filter(correlation_scanned_at__isnull=True).exists())


class TriageFailureHandlingTests(TestCase):
    def setUp(self):
        self.org = _org()
        self.endpoint, _ = Endpoint.issue(organization=self.org, display_name="WIN-PILOT-01")

    def test_provider_error_leaves_honest_not_yet_triaged_state(self):
        _suspicious_powershell(self.endpoint)
        report = run_triage_scan(provider=_FakeProvider(RuntimeError("Anthropic API request failed: 503")))

        self.assertEqual(report.triage_failed, 1)
        self.assertEqual(IncidentGroup.objects.count(), 0)

        candidate = EndpointCorrelationCandidate.objects.get()
        self.assertEqual(candidate.status, EndpointCorrelationCandidate.Status.TRIAGE_FAILED)
        self.assertEqual(candidate.ai_verdict, "")  # nothing fabricated
        self.assertEqual(candidate.ai_severity, "")
        self.assertEqual(candidate.ai_summary, "")
        self.assertIn("503", candidate.ai_error)
        self.assertEqual(candidate.attempt_count, 1)
        self.assertTrue(AIRun.objects.filter(ai_module="endpoint_triage", status=AIRun.Status.FAILED).exists())

    def test_failed_candidate_is_retried_next_run_then_succeeds(self):
        _suspicious_powershell(self.endpoint)
        run_triage_scan(provider=_FakeProvider(RuntimeError("boom")))
        self.assertEqual(EndpointCorrelationCandidate.objects.get().status,
                         EndpointCorrelationCandidate.Status.TRIAGE_FAILED)

        # nothing new to correlate, but the failed candidate is picked up
        report = run_triage_scan(provider=_FakeProvider(ESCALATE_JSON))
        self.assertEqual(report.triaged_escalated, 1)
        self.assertEqual(EndpointCorrelationCandidate.objects.get().status,
                         EndpointCorrelationCandidate.Status.ESCALATED)

    def test_repeated_failure_is_abandoned_but_stays_visible(self):
        _suspicious_powershell(self.endpoint)
        for _ in range(EndpointCorrelationCandidate.MAX_TRIAGE_ATTEMPTS):
            run_triage_scan(provider=_FakeProvider(RuntimeError("still down")))

        candidate = EndpointCorrelationCandidate.objects.get()
        self.assertEqual(candidate.status, EndpointCorrelationCandidate.Status.ABANDONED)
        self.assertEqual(candidate.attempt_count, EndpointCorrelationCandidate.MAX_TRIAGE_ATTEMPTS)
        # a subsequent run does not touch it
        report = run_triage_scan(provider=_FakeProvider(ESCALATE_JSON))
        self.assertEqual(report.triaged_escalated, 0)

    def test_rate_limited_by_deny_ai_call_does_not_burn_an_attempt(self):
        _suspicious_powershell(self.endpoint)
        with self.settings(
            AI_RATE_LIMIT_ENABLED=True,
            AI_RATE_LIMIT_ENDPOINT_PER_MINUTE=1,   # burst cap of 1/min
            AI_RATE_LIMIT_GLOBAL_PER_HOUR=100,     # plenty of global room
            AI_TRIAGE_INTERACTIVE_RESERVE=0,       # headroom gate off -> we reach deny_ai_call
        ):
            AIRun.objects.create(ai_module="endpoint_triage", input_type="x", input_id="1",
                                 output_type="", output_id="", status=AIRun.Status.SUCCESS)
            report = run_triage_scan(provider=_FakeProvider(ESCALATE_JSON))

        self.assertEqual(report.rate_limited, 1)
        candidate = EndpointCorrelationCandidate.objects.get()
        self.assertEqual(candidate.status, EndpointCorrelationCandidate.Status.RATE_LIMITED)
        self.assertEqual(candidate.attempt_count, 0)  # not spent
        self.assertEqual(IncidentGroup.objects.count(), 0)

    def test_interactive_reserve_defers_triage_without_touching_candidates(self):
        _suspicious_powershell(self.endpoint)
        with self.settings(
            AI_RATE_LIMIT_ENABLED=True,
            AI_RATE_LIMIT_GLOBAL_PER_HOUR=20,
            AI_TRIAGE_INTERACTIVE_RESERVE=15,
        ):
            # 5 interactive calls this hour -> headroom = 20 - 5 - 15 = 0
            for _ in range(5):
                AIRun.objects.create(ai_module="analyst", input_type="x", input_id="1",
                                     output_type="", output_id="", status=AIRun.Status.SUCCESS)
            provider = _FakeProvider(ESCALATE_JSON)
            report = run_triage_scan(provider=provider)

        self.assertEqual(report.deferred_for_headroom, 1)
        self.assertEqual(provider.calls, 0)          # no AI call even attempted
        self.assertEqual(IncidentGroup.objects.count(), 0)
        candidate = EndpointCorrelationCandidate.objects.get()
        self.assertEqual(candidate.status, EndpointCorrelationCandidate.Status.PENDING)
        self.assertEqual(candidate.attempt_count, 0)

        # the deferred candidate is picked up on a later run
        with self.settings(AI_RATE_LIMIT_ENABLED=True, AI_RATE_LIMIT_GLOBAL_PER_HOUR=20,
                           AI_TRIAGE_INTERACTIVE_RESERVE=0):
            report2 = run_triage_scan(provider=_FakeProvider(ESCALATE_JSON))
        self.assertEqual(report2.triaged_escalated, 1)


class RunControlsTests(TestCase):
    def setUp(self):
        self.org = _org()

    def test_max_candidates_caps_ai_calls_per_run(self):
        for i in range(4):
            endpoint, _ = Endpoint.issue(organization=self.org, display_name=f"WIN-{i}")
            _suspicious_powershell(endpoint)

        provider = _FakeProvider(*([BENIGN_JSON] * 10))
        report = run_triage_scan(provider=provider, max_candidates=2)

        self.assertEqual(report.candidates_created, 4)
        self.assertEqual(provider.calls, 2)
        self.assertEqual(
            EndpointCorrelationCandidate.objects.filter(
                status=EndpointCorrelationCandidate.Status.PENDING
            ).count(),
            2,
        )

    def test_dry_run_writes_nothing_and_calls_no_ai(self):
        endpoint, _ = Endpoint.issue(organization=self.org, display_name="WIN-PILOT-01")
        _suspicious_powershell(endpoint)
        provider = _FakeProvider(ESCALATE_JSON)

        report = run_triage_scan(provider=provider, dry_run=True)

        self.assertTrue(report.dry_run)
        self.assertEqual(report.candidates_created, 1)
        self.assertEqual(provider.calls, 0)
        self.assertEqual(EndpointCorrelationCandidate.objects.count(), 0)
        self.assertEqual(IncidentGroup.objects.count(), 0)
        self.assertFalse(EndpointEvent.objects.filter(correlation_scanned_at__isnull=False).exists())

    def test_management_command_runs(self):
        endpoint, _ = Endpoint.issue(organization=self.org, display_name="WIN-PILOT-01")
        _suspicious_powershell(endpoint)
        out = StringIO()
        # no ANTHROPIC_API_KEY in tests -> real provider raises -> candidate TRIAGE_FAILED
        call_command("triage_endpoint_events", stdout=out)
        self.assertIn("candidate", out.getvalue())
        self.assertEqual(
            EndpointCorrelationCandidate.objects.get().status,
            EndpointCorrelationCandidate.Status.TRIAGE_FAILED,
        )

    def test_management_command_dry_run(self):
        endpoint, _ = Endpoint.issue(organization=self.org, display_name="WIN-PILOT-01")
        _suspicious_powershell(endpoint)
        out = StringIO()
        call_command("triage_endpoint_events", "--dry-run", stdout=out)
        self.assertIn("DRY RUN", out.getvalue())
        self.assertEqual(EndpointCorrelationCandidate.objects.count(), 0)


class SurfacesInWorkQueueTests(AuthedTestCase):
    def test_correlation_incident_shows_in_queue_and_detail_renders(self):
        org = _org()
        endpoint, _ = Endpoint.issue(organization=org, display_name="WIN-PILOT-01")
        _suspicious_powershell(endpoint)
        report = run_triage_scan(provider=_FakeProvider(ESCALATE_JSON))
        incident_id = report.incidents_created[0]

        incident = IncidentGroup.objects.get(id=incident_id)
        # Unassigned + normal IncidentGroup -> the queue query picks it up
        # with no special-casing.
        self.assertIsNone(incident.assigned_to)

        queue = self.client.get("/incidents/?tab=queue")
        self.assertEqual(queue.status_code, 200)
        # The incident title is prose with the endpoint name in it, so the
        # queue renders it through {% alias_prose %}: name aliased, rest intact.
        host_alias = AliasMapping.objects.get(
            organization=org, identifier_type="HOST", real_value="WIN-PILOT-01"
        ).display_alias
        self.assertContains(queue, "endpoint activity on")
        self.assertContains(queue, host_alias)
        self.assertNotContains(queue, "WIN-PILOT-01")

        detail = self.client.get(f"/incidents/{incident_id}/")
        self.assertEqual(detail.status_code, 200)


def _triage_json(severity, summary="s", reasoning="r"):
    return json.dumps(
        {"verdict": "escalate", "severity": severity, "summary": summary, "reasoning": reasoning}
    )


class SustainedActivityDedupTests(TestCase):
    """Activity spanning many correlation windows on one endpoint must
    become one growing incident, not a pile of near-duplicates.
    """

    def setUp(self):
        self.org = _org()
        self.endpoint, _ = Endpoint.issue(organization=self.org, display_name="WIN-PILOT-01")

    def _first_incident(self):
        _suspicious_powershell(self.endpoint, at=BASE)
        run_triage_scan(provider=_FakeProvider(ESCALATE_JSON))
        return IncidentGroup.objects.get()

    def test_second_cluster_attaches_to_the_open_incident(self):
        incident = self._first_incident()

        _suspicious_powershell(self.endpoint, at=BASE + timedelta(minutes=45))
        report = run_triage_scan(provider=_FakeProvider(ESCALATE_JSON))

        self.assertEqual(IncidentGroup.objects.count(), 1)  # no near-duplicate
        self.assertEqual(report.incidents_created, [])
        self.assertEqual(report.incidents_updated, [incident.id])
        self.assertEqual(report.triaged_escalated, 1)

        incident.refresh_from_db()
        self.assertEqual(incident.endpoint_correlation_candidates.count(), 2)
        self.assertEqual(incident.last_seen, BASE + timedelta(minutes=45))
        self.assertIn("Update ", incident.summary)

    def test_higher_severity_cluster_raises_incident_severity(self):
        _suspicious_powershell(self.endpoint, at=BASE)
        run_triage_scan(provider=_FakeProvider(_triage_json("medium")))
        self.assertEqual(IncidentGroup.objects.get().severity, "medium")

        _suspicious_powershell(self.endpoint, at=BASE + timedelta(minutes=45))
        run_triage_scan(provider=_FakeProvider(_triage_json("critical")))

        incident = IncidentGroup.objects.get()
        self.assertEqual(incident.severity, "critical")
        self.assertIn("Critical endpoint activity on WIN-PILOT-01", incident.title)

    def test_lower_severity_cluster_does_not_downgrade(self):
        _suspicious_powershell(self.endpoint, at=BASE)
        run_triage_scan(provider=_FakeProvider(_triage_json("high")))
        _suspicious_powershell(self.endpoint, at=BASE + timedelta(minutes=45))
        run_triage_scan(provider=_FakeProvider(_triage_json("low")))
        self.assertEqual(IncidentGroup.objects.get().severity, "high")

    def test_resolved_incident_does_not_capture_new_activity(self):
        incident = self._first_incident()
        incident.status = IncidentGroup.Status.RESOLVED
        incident.save(update_fields=["status"])

        _suspicious_powershell(self.endpoint, at=BASE + timedelta(minutes=45))
        report = run_triage_scan(provider=_FakeProvider(ESCALATE_JSON))

        self.assertEqual(IncidentGroup.objects.count(), 2)
        self.assertEqual(len(report.incidents_created), 1)

    def test_different_endpoint_gets_its_own_incident(self):
        other, _ = Endpoint.issue(organization=self.org, display_name="WIN-OTHER")
        _suspicious_powershell(self.endpoint, at=BASE)
        _suspicious_powershell(other, at=BASE)
        run_triage_scan(provider=_FakeProvider(ESCALATE_JSON, ESCALATE_JSON))
        self.assertEqual(IncidentGroup.objects.count(), 2)

    def test_attach_does_not_touch_analyst_investigation_state(self):
        from django.contrib.auth import get_user_model

        incident = self._first_incident()
        user = get_user_model().objects.create(username="analyst-x")
        incident.status = IncidentGroup.Status.INVESTIGATING
        incident.workflow_state = {"stage": "verify"}
        incident.assigned_to = user
        incident.save()

        _suspicious_powershell(self.endpoint, at=BASE + timedelta(minutes=45))
        run_triage_scan(provider=_FakeProvider(ESCALATE_JSON))

        incident.refresh_from_db()
        self.assertEqual(incident.status, IncidentGroup.Status.INVESTIGATING)
        self.assertEqual(incident.workflow_state, {"stage": "verify"})
        self.assertEqual(incident.assigned_to, user)
        self.assertEqual(incident.endpoint_correlation_candidates.count(), 2)
