"""Context-gathering for the Writer agent's standalone path: given a
free-typed scenario description with no IncidentGroup behind it, build
a prompt section grounded in whatever real organization context can
still be resolved from the text itself.

Two lookups, both reused rather than reinvented:
- A mentioned critical system, via
  apps.organizations.services.critical_systems.resolve_affected_system
  -- already built for exactly this "free text -> real record" lookup,
  used elsewhere against an incident's affected_systems field.
- A matching SOP checklist, found the same token-fallback way
  apps.ai_core.services.analyst_context._resolve_matching_sop matches
  an incident's incident_type -- just applied to the scenario text
  directly, token-only (no exact-match step first), since there's no
  incident_type field to try exactly matching here.

This does not call any AI provider; it only builds the prompt text. See
apps/ai_core/modules/writer.py for the piece that sends this to a
provider and handles the response.
"""

import re

from django.db.models import Q

from apps.organizations.services.critical_systems import resolve_affected_system
from apps.playbooks.models import SOPChecklist


def build_custom_scenario_context(scenario_text: str, *, organization=None) -> str:
    sections = [
        _scenario_section(scenario_text),
        _critical_system_section(scenario_text, organization),
        _matching_sop_section(scenario_text),
    ]
    return "\n\n".join(section for section in sections if section)


def _scenario_section(scenario_text):
    return f"## Requested Scenario\n{scenario_text.strip()}"


def _critical_system_section(scenario_text, organization):
    match = resolve_affected_system(scenario_text, organization=organization)
    if not match:
        return "## Critical System Match\nNo recognized critical system mentioned in the request."

    return "\n".join(
        [
            "## Critical System Match",
            f"System: {match.system_name} ({match.system_type})",
            f"Criticality: {match.get_criticality_display()}",
            f"Recovery priority: {match.get_recovery_priority_display()}",
            f"Owner: {match.owner_name}",
        ]
    )


def _matching_sop_section(scenario_text):
    checklist = _resolve_matching_sop(scenario_text)
    if not checklist:
        return "## Matching SOP\nNo matching SOP checklist found for this request."

    return f"## Matching SOP\n{checklist.name} (v{checklist.version}):\n{checklist.checklist_items}"


def _resolve_matching_sop(scenario_text):
    # A minimum length avoids a bare 1-2 character token (e.g. "a", "me",
    # from ordinary sentence filler) matching almost anything via
    # icontains -- confirmed as a real false-positive against
    # apps.organizations.services.critical_systems.resolve_affected_system
    # when it was fed a full sentence instead of its usual short,
    # structured value; the same risk applies here.
    tokens = [
        token for token in re.split(r"[^a-z0-9]+", (scenario_text or "").lower()) if len(token) >= 3
    ]
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
