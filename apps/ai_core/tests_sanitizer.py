"""Sanitizer (apps/ai_core/sanitizer.py) + its wiring into
AnthropicProvider.send_message().

Proves the four things the sanitizer has to guarantee:

1. No real identifier -- IP, email, hostname, account, org name -- ever
   appears in the *actual bytes* POSTed to the Anthropic API. These
   tests mock the transport (urllib.request.urlopen) and inspect the
   literal request body, not the pre-sanitization prompt string.
2. The same real value maps to the same token twice within one prompt.
3. The model's placeholder-bearing reply is rehydrated back to real
   values before send_message() returns and before anything is stored.
4. The on-page evidence display is completely unaffected -- it still
   shows the real IP / account / host, because it never goes through
   the provider.
"""

import json
import os
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase, override_settings
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.ai_core.modules.analyst import run_incident_analysis
from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.sanitizer import sanitize_for_ai
from apps.incidents.models import AnalystResult, IncidentEvidence, IncidentGroup
from apps.log_intake.models import ParsedAlert, UploadedLogFile
from apps.organizations.models import CriticalSystem, Organization


class _CapturingResponse:
    """Context-manager stand-in for urllib.request.urlopen()'s return."""

    def __init__(self, raw: bytes):
        self._raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._raw


def _anthropic_reply(text: str) -> _CapturingResponse:
    return _CapturingResponse(
        json.dumps({"content": [{"type": "text", "text": text}]}).encode("utf-8")
    )


# ---------------------------------------------------------------------------
# 1. pure-function behaviour (no DB, no org)
# ---------------------------------------------------------------------------


class SanitizerUnitTests(SimpleTestCase):
    def test_same_ip_twice_gets_the_same_token(self):
        result = sanitize_for_ai(
            "Login from 203.0.113.9 failed; later 203.0.113.9 tried again.",
            organization=None,
        )
        self.assertEqual(result.text.count("[[IP_1]]"), 2)
        self.assertNotIn("203.0.113.9", result.text)
        self.assertEqual(result.mapping["[[IP_1]]"], "203.0.113.9")

    def test_two_different_ips_get_two_different_tokens(self):
        result = sanitize_for_ai("A 203.0.113.9 then B 198.51.100.4", organization=None)
        self.assertIn("[[IP_1]]", result.text)
        self.assertIn("[[IP_2]]", result.text)
        self.assertNotIn("203.0.113.9", result.text)
        self.assertNotIn("198.51.100.4", result.text)

    def test_email_and_internal_fqdn_and_path_are_replaced(self):
        result = sanitize_for_ai(
            "Mail admin@acme.local from host db01.acme.local, see /var/log/secure.",
            organization=None,
        )
        self.assertNotIn("admin@acme.local", result.text)
        self.assertNotIn("db01.acme.local", result.text)
        self.assertNotIn("/var/log/secure", result.text)
        self.assertIn("[[EMAIL_1]]", result.text)
        self.assertIn("[[HOST_1]]", result.text)
        self.assertIn("[[PATH_1]]", result.text)

    def test_non_identifier_numbers_are_left_alone(self):
        text = (
            "Agent version 1.2.3 processed a 34.6 GB backup at a 24/7 cadence; "
            "SHA256 verified; job ran 12:34:56."
        )
        result = sanitize_for_ai(text, organization=None)
        self.assertEqual(result.mapping, {})  # nothing was treated as an identifier
        for fragment in ("1.2.3", "34.6 GB", "24/7", "SHA256", "12:34:56"):
            self.assertIn(fragment, result.text)

    def test_an_inserted_token_is_never_re_tokenized(self):
        # "10.0.0.1" -> [[IP_1]]; the later passes must not touch [[IP_1]].
        result = sanitize_for_ai("host 10.0.0.1 and 10.0.0.1", organization=None)
        self.assertEqual(result.mapping, {"[[IP_1]]": "10.0.0.1"})
        self.assertNotIn("[[IP_2]]", result.text)

    def test_restore_puts_real_values_back_even_with_a_dropped_bracket(self):
        result = sanitize_for_ai("from 203.0.113.9 to host WEB-01", organization=None)
        reply = "The attacker at [[IP_1]] hit [[HOST_1]] -- note [IP_1] recurred."
        restored = result.restore(reply)
        self.assertEqual(
            restored,
            "The attacker at 203.0.113.9 hit WEB-01 -- note 203.0.113.9 recurred.",
        )

    def test_restore_leaves_an_unknown_token_untouched(self):
        result = sanitize_for_ai("from 203.0.113.9", organization=None)
        self.assertEqual(
            result.restore("saw [[IP_1]] and [[IP_7]]"),
            "saw 203.0.113.9 and [[IP_7]]",
        )

    @override_settings(AI_SANITIZER_ENABLED=False)
    def test_escape_hatch_disables_the_whole_pass(self):
        result = sanitize_for_ai("raw 203.0.113.9 stays", organization=None)
        self.assertEqual(result.text, "raw 203.0.113.9 stays")
        self.assertEqual(result.mapping, {})
        self.assertEqual(result.restore("echo 203.0.113.9"), "echo 203.0.113.9")


# ---------------------------------------------------------------------------
# 2. + 3. end-to-end through the real provider, inspecting the sent bytes
# ---------------------------------------------------------------------------


class _IncidentFixture(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Northwind Trading Co",
            organization_type="SMB",
            country="St. Vincent and the Grenadines",
            sector="Retail",
            risk_profile="medium",
        )
        CriticalSystem.objects.create(
            organization=self.organization,
            system_name="PAYROLL-DB-01",
            system_type="database",
            criticality="high",
            owner_name="Dana Whitfield",
            recovery_priority="tier_1",
        )
        self.uploaded_file = UploadedLogFile.objects.create(
            organization=self.organization,
            file_name="auth.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path="demo/auth.log",
            status=UploadedLogFile.Status.PARSED,
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Brute-force against a privileged account",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            affected_systems="PAYROLL-DB-01",
            summary="Repeated failed logins.",
        )
        self.alert = ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="wazuh",
            affected_system="PAYROLL-DB-01",
            account="d.whitfield",
            source_ip="203.0.113.77",
            event_type="failed_login",
            severity_hint=ParsedAlert.SeverityHint.HIGH,
            raw_message=(
                "Failed password for d.whitfield from 203.0.113.77; "
                "contact d.whitfield@northwind.example for follow-up. "
                "Second hit from 203.0.113.77 four minutes later."
            ),
            normalized_summary="Repeated failed logins for d.whitfield from 203.0.113.77",
        )
        IncidentEvidence.objects.create(
            incident=self.incident,
            alert=self.alert,
            evidence_reason="Matched account and source IP.",
        )

    # every real identifier that must never leave the process
    REAL_VALUES = (
        "203.0.113.77",
        "d.whitfield@northwind.example",
        "d.whitfield",
        "PAYROLL-DB-01",
        "Northwind Trading Co",
        "Dana Whitfield",
    )


class ProviderNeverSendsRealIdentifiersTests(_IncidentFixture):
    def _run_and_capture(self, reply_text="ack"):
        """Run the analyst pipeline against a mocked transport; return
        (returned_result, decoded_request_body)."""
        captured = {}

        def fake_urlopen(request, timeout=None):
            captured["body"] = request.data
            return _anthropic_reply(reply_text)

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "fake-test-key"}), patch(
            "urllib.request.urlopen", side_effect=fake_urlopen
        ):
            result = run_incident_analysis(self.incident)
        return result, captured["body"].decode("utf-8")

    def test_no_real_identifier_appears_in_the_bytes_sent_to_anthropic(self):
        _, sent_body = self._run_and_capture()

        # sanity: the request really did carry the incident context
        self.assertIn("Evidence", sent_body)
        self.assertIn("failed_login", sent_body)

        for real_value in self.REAL_VALUES:
            self.assertNotIn(
                real_value,
                sent_body,
                msg=f"{real_value!r} leaked into the Anthropic request body",
            )

    def test_the_context_reached_the_request_as_placeholder_tokens(self):
        _, sent_body = self._run_and_capture()
        for token_prefix in ("[[IP_", "[[HOST_", "[[USER_", "[[ORG_", "[[EMAIL_"):
            self.assertIn(token_prefix, sent_body)

    def test_the_same_real_ip_is_one_repeated_token_in_the_request_body(self):
        _, sent_body = self._run_and_capture()
        payload = json.loads(sent_body)
        content = payload["messages"][0]["content"]
        # the IP appears twice in raw_message + once in normalized_summary
        self.assertGreaterEqual(content.count("[[IP_1]]"), 3)
        self.assertNotIn("[[IP_2]]", content)  # only one distinct IP in the fixture

    def test_the_placeholder_note_is_prepended_so_the_model_wont_parrot_tokens(self):
        _, sent_body = self._run_and_capture()
        self.assertIn("replaced with placeholder tokens", sent_body)

    def test_max_tokens_and_shape_are_still_correct_after_sanitization(self):
        _, sent_body = self._run_and_capture()
        payload = json.loads(sent_body)
        self.assertEqual(payload["max_tokens"], 4096)
        self.assertEqual(payload["messages"][0]["role"], "user")


class ProviderRehydratesTheResponseTests(_IncidentFixture):
    REPLY_WITH_TOKENS = (
        "The account [[USER_1]] on host [[HOST_1]] was brute-forced from "
        "[[IP_1]]. Notify [[EMAIL_1]]. [[ORG_1]] should rotate the "
        "credentials for [[USER_1]] now."
    )

    def _run(self):
        def fake_urlopen(request, timeout=None):
            return _anthropic_reply(self.REPLY_WITH_TOKENS)

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "fake-test-key"}), patch(
            "urllib.request.urlopen", side_effect=fake_urlopen
        ):
            return run_incident_analysis(self.incident)

    def test_returned_analysis_has_real_values_not_tokens(self):
        result = self._run()
        analysis = result["analysis"]
        self.assertIn("d.whitfield", analysis)
        self.assertIn("PAYROLL-DB-01", analysis)
        self.assertIn("203.0.113.77", analysis)
        self.assertIn("d.whitfield@northwind.example", analysis)
        self.assertIn("Northwind Trading Co", analysis)
        self.assertNotIn("[[", analysis)
        self.assertNotIn("]]", analysis)

    def test_what_gets_stored_in_the_db_is_the_rehydrated_text(self):
        analyze_url = reverse("incidents:analyze", args=[self.incident.id])

        def fake_urlopen(request, timeout=None):
            return _anthropic_reply(self.REPLY_WITH_TOKENS)

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "fake-test-key"}), patch(
            "urllib.request.urlopen", side_effect=fake_urlopen
        ):
            response = self.client.post(analyze_url)

        self.assertEqual(response.status_code, 200)
        saved = AnalystResult.objects.get(incident=self.incident)
        self.assertIn("203.0.113.77", saved.analysis_text)
        self.assertIn("PAYROLL-DB-01", saved.analysis_text)
        self.assertNotIn("[[IP_1]]", saved.analysis_text)
        # and it's shown back on the page with the real values
        self.assertContains(response, "203.0.113.77")


# ---------------------------------------------------------------------------
# 4. the on-page evidence display is untouched
# ---------------------------------------------------------------------------


class EvidenceDisplayIsUnaffectedTests(_IncidentFixture):
    def test_incident_detail_page_still_shows_the_real_identifiers(self):
        # No AI call here at all -- just the ordinary page render.
        response = self.client.get(reverse("incidents:detail", args=[self.incident.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "203.0.113.77")
        self.assertContains(response, "d.whitfield")
        self.assertContains(response, "PAYROLL-DB-01")
        self.assertNotContains(response, "[[IP_1]]")

    def test_evidence_api_context_is_built_straight_from_the_orm(self):
        # The evidence the page shows comes from the model, not from any
        # sanitizer-touched path.
        alert = ParsedAlert.objects.get(pk=self.alert.pk)
        self.assertEqual(alert.source_ip, "203.0.113.77")
        self.assertEqual(alert.account, "d.whitfield")


# ---------------------------------------------------------------------------
# 5. the endpoint analyzer's own identifiers are in the scrub dictionary
#    (apps/endpoints -- Part 3 added Endpoint + EndpointEvent to
#    _collect_org_identifiers, same shape as the ParsedAlert entry above)
# ---------------------------------------------------------------------------


class EndpointIdentifiersAreScrubbedTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Northwind Trading Co",
            organization_type="SMB",
            country="St. Vincent and the Grenadines",
            sector="Retail",
            risk_profile="medium",
        )
        from apps.endpoints.models import Endpoint, EndpointEvent

        self.endpoint, _ = Endpoint.issue(
            organization=self.organization, display_name="WIN-PILOT-01"
        )
        EndpointEvent.objects.create(
            endpoint=self.endpoint,
            organization=self.organization,
            event_type="Security/4688",
            occurred_at="2026-02-11T14:22:07Z",
            payload={
                "computer": "WIN-PILOT-01",
                "data": {
                    "new_process_name": r"C:\Windows\System32\whoami.exe",
                    "subject_user_name": "j.reyes",
                },
            },
        )

    def test_multi_segment_endpoint_hostname_is_tokenized(self):
        # WIN-PILOT-01 has two hyphens -> the bare-host regex misses it;
        # the dictionary entry is what catches it.
        result = sanitize_for_ai(
            "Activity observed on WIN-PILOT-01 this morning.",
            organization=self.organization,
        )
        self.assertNotIn("WIN-PILOT-01", result.text)
        self.assertIn("[[HOST_", result.text)
        self.assertEqual(result.restore(result.text.split("\n")[-1]), "Activity observed on WIN-PILOT-01 this morning.")

    def test_endpoint_event_username_is_tokenized(self):
        result = sanitize_for_ai(
            "The process ran as j.reyes.", organization=self.organization
        )
        self.assertNotIn("j.reyes", result.text)
        self.assertIn("[[USER_", result.text)

    def test_no_endpoint_data_is_a_no_op(self):
        other_org = Organization.objects.create(
            name="Someone Else Ltd",
            organization_type="SMB",
            country="X",
            sector="Y",
            risk_profile="low",
        )
        result = sanitize_for_ai("host WIN-PILOT-01", organization=other_org)
        # WIN-PILOT-01 belongs to a different org -> not in this org's dict,
        # and the regex doesn't catch it either.
        self.assertIn("WIN-PILOT-01", result.text)
