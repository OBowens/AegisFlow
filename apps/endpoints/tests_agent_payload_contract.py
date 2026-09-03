"""Cross-part contract check.

The Windows agent (endpoint_agent/, feature Part 2) builds its ingest
requests from ``aegis_agent.events.to_ingest_event``. The sample outputs
of that function are committed as fixtures; this test pushes them
through the *real* ingest endpoint so a change on either side that
breaks the shared contract fails here.

It deliberately reads only the JSON fixture files -- it does not import
the agent package (which is not on the Django path and needs no Django).
"""

from __future__ import annotations

import json
from pathlib import Path

from django.test import Client, TestCase

from apps.endpoints.models import Endpoint, EndpointEvent
from apps.endpoints.views import MAX_EVENTS_PER_BATCH
from apps.organizations.models import Organization

_AGENT_FIXTURES = (
    Path(__file__).resolve().parents[2] / "endpoint_agent" / "tests" / "fixtures"
)


class AgentPayloadContractTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(
            name="Pilot Org",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Demo",
            risk_profile="medium",
        )
        self.endpoint, self.token = Endpoint.issue(
            organization=self.org, display_name="WIN-PILOT-01"
        )

    def _post(self, events):
        return Client().post(
            "/endpoints/api/ingest/",
            data=json.dumps({"events": events}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

    def test_agent_sample_payloads_are_accepted_by_ingest(self):
        fixtures = sorted(_AGENT_FIXTURES.glob("payload_*.json"))
        self.assertTrue(fixtures, "agent payload fixtures are missing")

        total = 0
        for fixture in fixtures:
            events = json.loads(fixture.read_text())
            self.assertIsInstance(events, list)
            response = self._post(events)
            self.assertEqual(
                response.status_code, 200, f"{fixture.name}: {response.content!r}"
            )
            self.assertEqual(response.json()["accepted"], len(events))
            total += len(events)

        self.assertEqual(EndpointEvent.objects.count(), total)
        stored_types = set(
            EndpointEvent.objects.values_list("event_type", flat=True)
        )
        self.assertEqual(stored_types, {"Security/4688", "Microsoft-Windows-PowerShell/4104"})

    def test_agent_batch_cap_matches_this_endpoint(self):
        # The agent hard-caps at aegis_agent.client.SERVER_MAX_EVENTS_PER_BATCH,
        # which is a literal copy of this value. If this changes, bump that.
        self.assertEqual(MAX_EVENTS_PER_BATCH, 500)
