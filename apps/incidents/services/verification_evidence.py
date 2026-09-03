"""Classifies each Verify-stage question
(apps.incidents.views._workflow_verification_items) into a real
evidence tier, and persists that classification via
VerificationItemEvidenceState -- EVIDENCE_AVAILABLE only when a real,
on-hand data source actually informs THIS specific question for THIS
specific incident, MANUAL_CHECK_REQUIRED otherwise.

Six of the eight known questions have no possible data source anywhere
in this app (proxy/click logs, mailbox admin audit logs, live
monitoring, a change-management calendar all don't exist as ingestion
paths) -- those are structurally manual, always, regardless of
incident. Two (suspicious sign-ins still occurring, are other systems
affected) have a real, already-ingested signal to check against, but
only when this particular incident's own evidence actually has it --
an incident with no linked authentication alerts, or no source-IP
correlation, still correctly falls back to manual for that question.

This deliberately does NOT fall back to "does this incident have any
evidence at all", the bug this replaces -- that treated every question
as backed just because *some* unrelated evidence existed.
"""

import re

from apps.incidents.models import VerificationItemEvidenceState

# The six questions with genuinely no possible real data source in this
# app today -- see the investigation this was built from for why each
# one landed here (proxy/click logs, mailbox audit logs, live
# monitoring, and a change-management calendar are all things this app
# has no ingestion path for at all).
STRUCTURALLY_MANUAL_ITEM_KEYS = frozenset(
    {
        "link_interaction",
        "credential_entry",
        "mailbox_changes",
        "reachable",
        "service_health",
        "expected_change",
    }
)

# Substring match against ParsedAlert.event_type -- covers the real
# event_type values the auth-producing parsers actually emit
# (linux_auth_parser: successful_login/failed_login/invalid_user_probe;
# windows_security_parser: successful_logon/logon_failure/
# explicit_credential_logon/privileged_logon/account_lockout/
# kerberos_*) without hardcoding an exhaustive, drift-prone list.
_AUTH_EVENT_KEYWORDS = ("login", "logon", "signin", "sign_in", "auth", "credential", "kerberos", "lockout")


def _is_auth_related_event_type(event_type: str) -> bool:
    if not event_type:
        return False
    lowered = event_type.lower()
    return any(keyword in lowered for keyword in _AUTH_EVENT_KEYWORDS)


def _split_system_names(raw_value):
    if not raw_value:
        return []
    return [segment.strip() for segment in re.split(r"[,;/\n|]+", raw_value) if segment.strip()]


def _classify_suspicious_signin(incident):
    auth_alerts = [
        evidence.alert
        for evidence in incident.evidence_items.select_related("alert")
        if _is_auth_related_event_type(evidence.alert.event_type)
    ]
    if not auth_alerts:
        return VerificationItemEvidenceState.Tier.MANUAL_CHECK_REQUIRED, ""

    count = len(auth_alerts)
    summary = f"{count} authentication alert{'s' if count != 1 else ''} linked as evidence for this incident."
    return VerificationItemEvidenceState.Tier.EVIDENCE_AVAILABLE, summary


def _classify_scope(incident):
    # Same aggregation apps.ai_core.services.analyst_context::
    # _prior_source_ip_section already does -- reused here rather than
    # reimplemented, so the two stay in agreement.
    links = list(incident.source_ip_links.select_related("related_incident"))
    if not links:
        return VerificationItemEvidenceState.Tier.MANUAL_CHECK_REQUIRED, ""

    related_incident_ids = {link.related_incident_id for link in links}
    distinct_systems = {
        system
        for link in links
        for system in _split_system_names(link.related_incident.affected_systems)
    }
    incident_count = len(related_incident_ids)
    system_count = len(distinct_systems)
    verb = "share" if incident_count != 1 else "shares"
    summary = (
        f"{incident_count} other incident{'s' if incident_count != 1 else ''} {verb} a source IP "
        f"across {system_count} distinct affected system{'s' if system_count != 1 else ''}."
    )
    return VerificationItemEvidenceState.Tier.EVIDENCE_AVAILABLE, summary


def _compute_tier_and_summary(incident, item_key):
    if item_key in STRUCTURALLY_MANUAL_ITEM_KEYS:
        return VerificationItemEvidenceState.Tier.MANUAL_CHECK_REQUIRED, ""
    if item_key == "suspicious_signin":
        return _classify_suspicious_signin(incident)
    if item_key == "scope":
        return _classify_scope(incident)
    # Any future/unrecognized key defaults to the honest, conservative
    # answer -- never invent an evidence-available claim for a question
    # this module doesn't explicitly know how to check.
    return VerificationItemEvidenceState.Tier.MANUAL_CHECK_REQUIRED, ""


def refresh_verification_evidence_states(incident, item_keys):
    """Recompute and upsert one VerificationItemEvidenceState row per
    key in `item_keys` (the incident's currently active Verify-stage
    questions -- 4 of the 8 known keys at a time, whichever branch
    applies to this incident). No caching: called fresh on every
    Verify-stage render, since the underlying queries are cheap,
    deterministic Python/DB lookups, not an AI call.

    Returns {item_key: VerificationItemEvidenceState}.
    """
    states = {}
    for item_key in item_keys:
        tier, summary = _compute_tier_and_summary(incident, item_key)
        state, _created = VerificationItemEvidenceState.objects.update_or_create(
            incident=incident,
            item_key=item_key,
            defaults={"tier": tier, "evidence_summary": summary},
        )
        states[item_key] = state
    return states
