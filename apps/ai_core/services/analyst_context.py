"""Context-gathering for the Analyst agent: given an IncidentGroup, pull
together everything already known about it -- evidence, gap/risk findings,
readiness contradictions tied to it, prior source-IP matches, and any
matching SOP -- into one structured plain-text prompt section.

This does not call any AI provider; it only builds the prompt text. See
apps/ai_core/modules/analyst.py for the piece that sends this to a provider
and handles the response.
"""

import re
from collections import defaultdict

from django.db.models import Q

from apps.incidents.models import IncidentGroup
from apps.playbooks.models import SOPChecklist
from apps.resilience.services.contradictions import find_contradictions_for_organization

# Evidence lists can run long on a heavily-grouped incident (one real
# incident in the dev DB has 32 alerts) -- cap how many go into the prompt,
# same spirit as the [:3]/[:15]-style caps used elsewhere in the view layer.
MAX_EVIDENCE_ITEMS = 15


def build_incident_context(incident: IncidentGroup) -> str:
    sections = [
        _overview_section(incident),
        _evidence_section(incident),
        _workflow_verification_section(incident),
        _workflow_resolve_outcome_section(incident),
        _workflow_guidance_section(incident),
        _gap_and_risk_section(incident),
        _readiness_contradictions_section(incident),
        _prior_source_ip_section(incident),
        _matching_sop_section(incident),
    ]
    return "\n\n".join(section for section in sections if section)


def _overview_section(incident):
    lines = [
        "## Incident Overview",
        f"Title: {incident.title}",
        f"Type: {incident.incident_type}",
        f"Severity: {incident.get_severity_display()}",
        f"Status: {incident.get_status_display()}",
        f"Affected system(s): {incident.affected_systems or 'Unknown'}",
        f"Organization: {incident.organization.name}",
        f"First seen: {incident.first_seen or 'Unknown'}",
        f"Last seen: {incident.last_seen or 'Unknown'}",
    ]
    if incident.summary:
        lines.append(f"Summary: {incident.summary}")
    return "\n".join(lines)


def _evidence_section(incident):
    evidence_items = list(
        incident.evidence_items.select_related("alert").order_by("alert__timestamp", "alert__id")
    )
    if not evidence_items:
        return "## Evidence\nNo linked evidence alerts."

    lines = ["## Evidence", f"{len(evidence_items)} alert(s) grouped into this incident:"]
    for evidence in evidence_items[:MAX_EVIDENCE_ITEMS]:
        alert = evidence.alert
        detail_bits = [
            f"[{alert.timestamp or alert.created_at}]",
            alert.event_type,
            f"severity={alert.severity_hint}",
        ]
        if alert.source_ip:
            detail_bits.append(f"source_ip={alert.source_ip}")
        if alert.account:
            detail_bits.append(f"account={alert.account}")
        message = alert.raw_message or alert.normalized_summary or "(no message)"
        lines.append(f"- {' '.join(detail_bits)} -- {message}")

    remaining = len(evidence_items) - MAX_EVIDENCE_ITEMS
    if remaining > 0:
        lines.append(f"...and {remaining} more alert(s) not shown.")
    return "\n".join(lines)


def _workflow_verification_section(incident):
    results = (incident.workflow_state or {}).get("verification_results", {})
    if not results:
        return "## Human Verification Findings\nNo verification results recorded yet."
    labels = {"confirmed": "Confirmed", "not_confirmed": "Not Confirmed", "not_sure": "Not Sure"}
    lines = ["## Human Verification Findings", "These are analyst-recorded results, not automatically inferred facts:"]
    for key, value in results.items():
        lines.append(f"- {key.replace('_', ' ').title()}: {labels.get(value, value)}")
    return "\n".join(lines)


_RESOLVE_OUTCOME_LABELS = {
    "resolved": "Resolved",
    "partial": "Partially resolved",
    "happening": "Still happening",
    "unsure": "Not sure",
}


def _workflow_resolve_outcome_section(incident):
    outcome = (incident.workflow_state or {}).get("resolve_outcome")
    if not outcome:
        return "## Resolve Stage Outcome\nNo outcome has been recorded at the Resolve stage yet."
    label = _RESOLVE_OUTCOME_LABELS.get(outcome, outcome)
    return f"## Resolve Stage Outcome\nAnalyst-recorded outcome at the Resolve stage: {label}."


# Fixed display order for the guided workflow's stages -- independent of
# whatever order rows happen to be created in, and stable even if a stage
# is regenerated (only its latest row is shown).
_WORKFLOW_STAGE_ORDER = ("understand", "verify", "respond", "resolve")


def _workflow_guidance_section(incident):
    """AI-recommended next steps already generated at earlier stages of
    this incident's guided workflow. This is how later stages "see" what
    earlier stages already recommended -- the same feed-forward mechanism
    _workflow_verification_section already uses for human-recorded
    verification answers, just for AI-generated guidance instead.
    """
    rows = list(incident.workflow_step_guidance.all())  # Meta.ordering = ["-generated_at"]
    if not rows:
        return "## Workflow Guidance So Far\nNo AI-recommended step guidance has been generated yet."

    latest_by_stage = {}
    for row in rows:  # newest first, so the first row seen per stage wins
        latest_by_stage.setdefault(row.stage, row)

    lines = [
        "## Workflow Guidance So Far",
        "AI-recommended next steps already given at other stages of this incident's guided workflow:",
    ]
    for stage in _WORKFLOW_STAGE_ORDER:
        row = latest_by_stage.get(stage)
        if row:
            lines.append(f"- {stage.title()}: {row.next_step_text}")
    return "\n".join(lines)


def _gap_and_risk_section(incident):
    gap_findings = list(incident.gap_findings.all())
    risk_assessments = list(incident.risk_assessments.all())

    if not gap_findings and not risk_assessments:
        return "## Gap & Risk Findings\nNone recorded."

    lines = ["## Gap & Risk Findings"]
    for gap in gap_findings:
        lines.append(f"- Gap ({gap.get_priority_display()}): {gap.gap_name} -- {gap.description}")
    for risk in risk_assessments:
        lines.append(
            f"- Risk ({risk.get_risk_level_display()}, score={risk.risk_score}): "
            f"{risk.risk_title} -- {risk.reasoning}"
        )
    return "\n".join(lines)


def _readiness_contradictions_section(incident):
    conflicts = [
        conflict
        for conflict in find_contradictions_for_organization(incident.organization)
        if getattr(conflict["finding"], "incident_id", None) == incident.id
    ]
    if not conflicts:
        return "## Readiness Contradictions\nNone found for this incident."

    lines = [
        "## Readiness Contradictions",
        "A readiness answer conflicts with a finding tied to this incident:",
    ]
    for conflict in conflicts:
        lines.append(
            f'- Answer to "{conflict["answer_question"]}": "{conflict["answer_text"]}" '
            f'-- but the {conflict["finding_type"]} finding says: "{conflict["finding_text"]}" '
            f'(topic: {conflict["topic"]})'
        )
    return "\n".join(lines)


def _prior_source_ip_section(incident):
    links = list(incident.source_ip_links.select_related("related_incident").order_by("created_at"))
    if not links:
        return (
            "## Prior Source-IP Activity\n"
            "No prior incidents share a source IP with this one (within the last 90 days)."
        )

    links_by_ip = defaultdict(list)
    for link in links:
        links_by_ip[link.source_ip].append(link)

    lines = ["## Prior Source-IP Activity"]
    for source_ip, ip_links in links_by_ip.items():
        related_incidents = [link.related_incident for link in ip_links]
        distinct_systems = {
            system
            for related in related_incidents
            for system in _split_affected_systems(related.affected_systems)
        }
        oldest = min(related.created_at for related in related_incidents)
        newest = max(related.created_at for related in related_incidents)
        day_span = max((newest - oldest).days, 0)
        incident_count = len(related_incidents)

        # Give the model the concrete numbers (incident count, distinct
        # system count, day span) directly, rather than leaving it to
        # infer "3 systems over 6 weeks" from a bare incident list.
        lines.append(
            f"- Source IP {source_ip}: {incident_count} prior incident{'s' if incident_count != 1 else ''} "
            f"across {len(distinct_systems)} distinct affected system{'s' if len(distinct_systems) != 1 else ''} "
            f"over {day_span} day{'s' if day_span != 1 else ''}."
        )
        for link in ip_links:
            related = link.related_incident
            lines.append(
                f'  - Incident #{related.id} "{related.title}" on {related.affected_systems or "Unknown"} '
                f"(detected {related.created_at})."
            )
    return "\n".join(lines)


def _split_affected_systems(raw_value):
    if not raw_value:
        return []
    return [segment.strip() for segment in re.split(r"[,;/\n|]+", raw_value) if segment.strip()]


def _matching_sop_section(incident):
    checklist = _resolve_matching_sop(incident)
    if not checklist:
        return "## Matching SOP\nNo matching SOP checklist found for this incident type."

    return f"## Matching SOP\n{checklist.name} (v{checklist.version}):\n{checklist.checklist_items}"


def _resolve_matching_sop(incident):
    # Same exact-then-token-fallback matching as
    # apps/playbooks/views.py::_resolve_checklist, applied directly to an
    # incident instead of a playbook.
    incident_type = (incident.incident_type or "").strip()
    if not incident_type:
        return None

    exact_match = (
        SOPChecklist.objects.filter(is_active=True, incident_type__iexact=incident_type)
        .order_by("-updated_at")
        .first()
    )
    if exact_match:
        return exact_match

    tokens = [token for token in re.split(r"[^a-z0-9]+", incident_type.lower()) if token]
    if not tokens:
        return None

    token_query = Q()
    for token in tokens:
        token_query |= Q(incident_type__icontains=token) | Q(name__icontains=token)

    return (
        SOPChecklist.objects.filter(is_active=True)
        .filter(token_query)
        .order_by("-updated_at")
        .first()
    )
