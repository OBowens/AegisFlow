"""Coverage for the real evidence-tier classification behind Verify-stage
questions (apps.incidents.services.verification_evidence and its wiring
into apps.incidents.views._workflow_verification_items):

- The 6 structurally-manual questions (no possible data source anywhere
  in this app) always classify as manual_check_required, regardless of
  how much -- or what kind of -- evidence the incident has.
- The 2 conditionally-available questions (suspicious sign-ins, other
  systems affected) classify as evidence_available only when THEIR
  specific relevant evidence actually exists, not just any evidence.
- evidence_summary carries real, derived text for those two, and stays
  blank for the other 6.
- The old bug ("any evidence at all" -> every question looks backed) is
  genuinely gone: an incident with plenty of unrelated evidence still
  correctly shows manual_check_required for questions nothing backs.
"""

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from config.testcase import AuthedTestCase

from apps.incidents.models import (
    IncidentEvidence,
    IncidentGroup,
    IncidentSourceIPLink,
    VerificationItemEvidenceState,
)
from apps.incidents.services.verification_evidence import (
    STRUCTURALLY_MANUAL_ITEM_KEYS,
    refresh_verification_evidence_states,
)
from apps.incidents.views import _workflow_verification_items
from apps.log_intake.models import ParsedAlert, UploadedLogFile
from apps.organizations.models import Organization

EVIDENCE_AVAILABLE = VerificationItemEvidenceState.Tier.EVIDENCE_AVAILABLE
MANUAL_CHECK_REQUIRED = VerificationItemEvidenceState.Tier.MANUAL_CHECK_REQUIRED

ALL_EIGHT_ITEM_KEYS = (
    "link_interaction",
    "credential_entry",
    "suspicious_signin",
    "mailbox_changes",
    "reachable",
    "service_health",
    "expected_change",
    "scope",
)


class VerificationEvidenceClassificationTestCase(TestCase):
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
            file_name="verify_evidence_demo.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path="demo/verify_evidence_demo.log",
            status=UploadedLogFile.Status.PARSED,
        )
        self.incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible credential phishing against finance team",
            incident_type="phishing",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="MAIL01",
        )

    def _make_alert(self, *, event_type, source_ip="198.51.100.10"):
        return ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="test",
            timestamp=timezone.now(),
            affected_system="MAIL01",
            source_ip=source_ip,
            event_type=event_type,
            severity_hint="medium",
            raw_message="test",
            normalized_summary="test",
        )

    def _link_evidence(self, alert):
        IncidentEvidence.objects.create(incident=self.incident, alert=alert, evidence_reason="test")

    # -- the six structurally-manual questions -----------------------------

    def test_all_six_structurally_manual_keys_classify_as_manual_with_no_evidence_at_all(self):
        states = refresh_verification_evidence_states(self.incident, ALL_EIGHT_ITEM_KEYS)

        for key in STRUCTURALLY_MANUAL_ITEM_KEYS:
            self.assertEqual(states[key].tier, MANUAL_CHECK_REQUIRED)
            self.assertEqual(states[key].evidence_summary, "")

    def test_all_six_structurally_manual_keys_stay_manual_even_with_lots_of_relevant_looking_evidence(self):
        # Load the incident with plenty of evidence, including exactly
        # the kind of evidence that DOES flip the other two questions --
        # proves the six structurally-manual ones are never swayed by
        # "some evidence exists somewhere on this incident".
        self._link_evidence(self._make_alert(event_type="successful_logon"))
        self._link_evidence(self._make_alert(event_type="failed_logon"))
        other_incident = IncidentGroup.objects.create(
            organization=self.organization, title="Other", incident_type="other", severity="low"
        )
        IncidentSourceIPLink.objects.create(
            incident=self.incident, related_incident=other_incident, source_ip="198.51.100.10"
        )

        states = refresh_verification_evidence_states(self.incident, ALL_EIGHT_ITEM_KEYS)

        for key in STRUCTURALLY_MANUAL_ITEM_KEYS:
            self.assertEqual(states[key].tier, MANUAL_CHECK_REQUIRED, f"{key} should stay manual")
            self.assertEqual(states[key].evidence_summary, "")

    # -- suspicious_signin: conditional on auth-type evidence specifically --

    def test_suspicious_signin_is_manual_when_no_evidence_exists(self):
        states = refresh_verification_evidence_states(self.incident, ["suspicious_signin"])
        self.assertEqual(states["suspicious_signin"].tier, MANUAL_CHECK_REQUIRED)
        self.assertEqual(states["suspicious_signin"].evidence_summary, "")

    def test_suspicious_signin_stays_manual_with_only_unrelated_evidence(self):
        # This is the exact old-bug shape: evidence exists, but none of
        # it is auth-related -- must NOT flip to evidence_available.
        self._link_evidence(self._make_alert(event_type="backup_failure"))
        self._link_evidence(self._make_alert(event_type="firewall_denied"))

        states = refresh_verification_evidence_states(self.incident, ["suspicious_signin"])
        self.assertEqual(states["suspicious_signin"].tier, MANUAL_CHECK_REQUIRED)
        self.assertEqual(states["suspicious_signin"].evidence_summary, "")

    def test_suspicious_signin_becomes_evidence_available_with_real_auth_evidence(self):
        self._link_evidence(self._make_alert(event_type="successful_logon"))
        self._link_evidence(self._make_alert(event_type="failed_logon"))
        self._link_evidence(self._make_alert(event_type="backup_failure"))  # unrelated, shouldn't matter

        states = refresh_verification_evidence_states(self.incident, ["suspicious_signin"])

        self.assertEqual(states["suspicious_signin"].tier, EVIDENCE_AVAILABLE)
        self.assertEqual(
            states["suspicious_signin"].evidence_summary,
            "2 authentication alerts linked as evidence for this incident.",
        )

    def test_suspicious_signin_singular_wording_for_exactly_one_alert(self):
        self._link_evidence(self._make_alert(event_type="kerberos_preauth_failed"))

        states = refresh_verification_evidence_states(self.incident, ["suspicious_signin"])

        self.assertEqual(states["suspicious_signin"].tier, EVIDENCE_AVAILABLE)
        self.assertEqual(
            states["suspicious_signin"].evidence_summary,
            "1 authentication alert linked as evidence for this incident.",
        )

    # -- scope: conditional on source-IP correlation specifically ----------

    def test_scope_is_manual_when_no_source_ip_links_exist(self):
        states = refresh_verification_evidence_states(self.incident, ["scope"])
        self.assertEqual(states["scope"].tier, MANUAL_CHECK_REQUIRED)
        self.assertEqual(states["scope"].evidence_summary, "")

    def test_scope_stays_manual_with_only_unrelated_evidence(self):
        self._link_evidence(self._make_alert(event_type="successful_logon"))  # auth evidence, not source-IP links
        states = refresh_verification_evidence_states(self.incident, ["scope"])
        self.assertEqual(states["scope"].tier, MANUAL_CHECK_REQUIRED)

    def test_scope_becomes_evidence_available_with_real_source_ip_correlation(self):
        related_a = IncidentGroup.objects.create(
            organization=self.organization,
            title="Suspicious login on WEB01",
            incident_type="unauthorized_access",
            severity="medium",
            affected_systems="WEB01",
        )
        related_b = IncidentGroup.objects.create(
            organization=self.organization,
            title="Suspicious login on DB01",
            incident_type="unauthorized_access",
            severity="medium",
            affected_systems="DB01",
        )
        IncidentSourceIPLink.objects.create(
            incident=self.incident, related_incident=related_a, source_ip="198.51.100.10"
        )
        IncidentSourceIPLink.objects.create(
            incident=self.incident, related_incident=related_b, source_ip="198.51.100.10"
        )

        states = refresh_verification_evidence_states(self.incident, ["scope"])

        self.assertEqual(states["scope"].tier, EVIDENCE_AVAILABLE)
        self.assertEqual(
            states["scope"].evidence_summary,
            "2 other incidents share a source IP across 2 distinct affected systems.",
        )

    # -- persistence / upsert behavior --------------------------------------

    def test_refresh_upserts_in_place_not_duplicate_rows(self):
        refresh_verification_evidence_states(self.incident, ["scope"])
        self.assertEqual(VerificationItemEvidenceState.objects.filter(item_key="scope").count(), 1)

        refresh_verification_evidence_states(self.incident, ["scope"])
        self.assertEqual(VerificationItemEvidenceState.objects.filter(item_key="scope").count(), 1)

    def test_refresh_reflects_newly_added_evidence_on_next_call_no_caching(self):
        first = refresh_verification_evidence_states(self.incident, ["suspicious_signin"])
        self.assertEqual(first["suspicious_signin"].tier, MANUAL_CHECK_REQUIRED)

        self._link_evidence(self._make_alert(event_type="successful_logon"))

        second = refresh_verification_evidence_states(self.incident, ["suspicious_signin"])
        self.assertEqual(second["suspicious_signin"].tier, EVIDENCE_AVAILABLE)

    def test_verification_evidence_state_scoped_per_incident(self):
        other_incident = IncidentGroup.objects.create(
            organization=self.organization, title="Other", incident_type="phishing", severity="low"
        )
        self._link_evidence(self._make_alert(event_type="successful_logon"))

        refresh_verification_evidence_states(self.incident, ["suspicious_signin"])
        other_states = refresh_verification_evidence_states(other_incident, ["suspicious_signin"])

        # other_incident has no evidence of its own -- must not inherit
        # self.incident's evidence-available classification.
        self.assertEqual(other_states["suspicious_signin"].tier, MANUAL_CHECK_REQUIRED)


class WorkflowVerificationItemsIntegrationTestCase(AuthedTestCase):
    """End to end through the actual view function that feeds the Verify
    stage template, for both the phishing branch and the generic branch.
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
            file_name="verify_items_demo.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path="demo/verify_items_demo.log",
            status=UploadedLogFile.Status.PARSED,
        )

    def _make_alert(self, incident, *, event_type):
        alert = ParsedAlert.objects.create(
            uploaded_file=self.uploaded_file,
            organization=self.organization,
            source_tool="test",
            timestamp=timezone.now(),
            affected_system="MAIL01",
            event_type=event_type,
            severity_hint="medium",
            raw_message="test",
            normalized_summary="test",
        )
        IncidentEvidence.objects.create(incident=incident, alert=alert, evidence_reason="test")
        return alert

    def test_phishing_branch_items_have_correct_evidence_state_and_label(self):
        incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible credential phishing against finance team",
            incident_type="phishing",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="MAIL01",
        )
        self._make_alert(incident, event_type="failed_logon")
        self._make_alert(incident, event_type="failed_logon")

        items = {item["key"]: item for item in _workflow_verification_items(incident)}

        self.assertEqual(items["link_interaction"]["evidence_state"], "manual")
        self.assertEqual(items["link_interaction"]["evidence_label"], "Manual check required")
        self.assertEqual(items["credential_entry"]["evidence_state"], "manual")
        self.assertEqual(items["mailbox_changes"]["evidence_state"], "manual")

        self.assertEqual(items["suspicious_signin"]["evidence_state"], "evidence")
        self.assertEqual(
            items["suspicious_signin"]["evidence_label"],
            "2 authentication alerts linked as evidence for this incident.",
        )

    def test_generic_branch_scope_reflects_real_source_ip_correlation(self):
        incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="High severity database activity on DB01",
            incident_type="database",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="DB01",
        )
        related = IncidentGroup.objects.create(
            organization=self.organization,
            title="Related incident",
            incident_type="database",
            severity="medium",
            affected_systems="WEB01",
        )
        IncidentSourceIPLink.objects.create(
            incident=incident, related_incident=related, source_ip="203.0.113.5"
        )

        items = {item["key"]: item for item in _workflow_verification_items(incident)}

        self.assertEqual(items["reachable"]["evidence_state"], "manual")
        self.assertEqual(items["service_health"]["evidence_state"], "manual")
        self.assertEqual(items["expected_change"]["evidence_state"], "manual")
        self.assertEqual(items["scope"]["evidence_state"], "evidence")
        self.assertEqual(
            items["scope"]["evidence_label"],
            "1 other incident shares a source IP across 1 distinct affected system.",
        )

    def test_generic_branch_with_no_correlating_evidence_is_all_manual(self):
        # This is the direct regression proof against the old bug: this
        # incident DOES have unrelated linked evidence (a plain database
        # alert), which used to be enough to mark every single question
        # "Evidence available". Now only real per-question evidence can.
        incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="High severity database activity on DB01",
            incident_type="database",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="DB01",
        )
        self._make_alert(incident, event_type="database_error")

        items = {item["key"]: item for item in _workflow_verification_items(incident)}

        for key in ("reachable", "service_health", "expected_change", "scope"):
            self.assertEqual(items[key]["evidence_state"], "manual", f"{key} should be manual")
            self.assertEqual(items[key]["evidence_label"], "Manual check required")

    def test_verify_page_renders_the_real_tier_pills_in_html(self):
        """The pill markup itself, straight out of the rendered Verify
        page -- proof the template reads item.evidence_state /
        item.evidence_label, not static text."""
        incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible credential phishing against finance team",
            incident_type="phishing",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="MAIL01",
        )
        self._make_alert(incident, event_type="failed_logon")
        self._make_alert(incident, event_type="successful_logon")
        self._make_alert(incident, event_type="kerberos_preauth_failure")

        response = self.client.get(
            reverse("incidents:workflow", args=[incident.id, "verify"])
        )
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()

        # The one auth-backed question renders the evidence-available pill
        # with its real, derived summary -- not "Manual check required".
        self.assertIn(
            '<span class="af-evidence-state is-evidence">'
            "3 authentication alerts linked as evidence for this incident.</span>",
            html,
        )
        # The structurally-manual questions in the same page still show
        # the manual pill -- the tier is genuinely per-question.
        self.assertIn(
            '<span class="af-evidence-state is-manual">Manual check required</span>',
            html,
        )

    def test_verify_page_is_all_manual_pills_when_nothing_backs_any_question(self):
        incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="High severity database activity on DB01",
            incident_type="database",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="DB01",
        )
        self._make_alert(incident, event_type="database_error")

        response = self.client.get(
            reverse("incidents:workflow", args=[incident.id, "verify"])
        )
        html = response.content.decode()

        self.assertEqual(html.count('class="af-evidence-state is-manual"'), 4)
        self.assertNotIn("is-evidence", html)

    def test_persisted_states_match_what_the_view_returned(self):
        incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Possible credential phishing against finance team",
            incident_type="phishing",
            severity=IncidentGroup.Severity.HIGH,
            affected_systems="MAIL01",
        )
        self._make_alert(incident, event_type="successful_logon")

        _workflow_verification_items(incident)

        saved = VerificationItemEvidenceState.objects.get(incident=incident, item_key="suspicious_signin")
        self.assertEqual(saved.tier, EVIDENCE_AVAILABLE)
        self.assertIn("1 authentication alert", saved.evidence_summary)

        other_saved = VerificationItemEvidenceState.objects.get(incident=incident, item_key="link_interaction")
        self.assertEqual(other_saved.tier, MANUAL_CHECK_REQUIRED)
        self.assertEqual(other_saved.evidence_summary, "")
