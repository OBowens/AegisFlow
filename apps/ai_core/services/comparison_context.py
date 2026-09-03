"""Context-gathering for the Incident Comparator agent: given two
IncidentGroups, reuse build_incident_context (apps/ai_core/services/
analyst_context.py) for each one's full detail -- evidence, gap/risk,
prior source-IP activity, matching SOP -- rather than re-implementing
that gathering a third time.

Also adds a short "Shared Data Points" section, precomputed the same
way _prior_source_ip_section hands the model concrete numbers instead
of a raw list: overlapping source IPs / accounts / affected systems /
incident type, and how far apart the two incidents' first-seen
timestamps are. This gives the model real overlap facts to reason from
up front, rather than making it infer them itself by cross-referencing
two long evidence sections.

This does not call any AI provider; it only builds the prompt text. See
apps/ai_core/modules/comparator.py for the piece that sends this to a
provider and handles the response.
"""

from apps.ai_core.services.analyst_context import _split_affected_systems, build_incident_context


def build_comparison_context(incident, other_incident) -> str:
    sections = [
        _shared_data_points_section(incident, other_incident),
        f"## Incident A (#{incident.id}) -- Full Context\n{build_incident_context(incident)}",
        f"## Incident B (#{other_incident.id}) -- Full Context\n{build_incident_context(other_incident)}",
    ]
    return "\n\n".join(sections)


def _collect_evidence_facts(incident):
    alerts = [evidence.alert for evidence in incident.evidence_items.select_related("alert")]
    source_ips = {alert.source_ip for alert in alerts if alert.source_ip}
    accounts = {alert.account for alert in alerts if alert.account}
    return source_ips, accounts


def _shared_data_points_section(incident, other_incident):
    ips_a, accounts_a = _collect_evidence_facts(incident)
    ips_b, accounts_b = _collect_evidence_facts(other_incident)
    systems_a = set(_split_affected_systems(incident.affected_systems))
    systems_b = set(_split_affected_systems(other_incident.affected_systems))

    shared_ips = sorted(ips_a & ips_b)
    shared_accounts = sorted(accounts_a & accounts_b)
    shared_systems = sorted(systems_a & systems_b)
    same_type = bool(incident.incident_type) and incident.incident_type == other_incident.incident_type

    lines = [
        "## Shared Data Points (precomputed)",
        (
            f"Same incident type: {'yes' if same_type else 'no'} "
            f"(A={incident.incident_type or 'Unknown'}, B={other_incident.incident_type or 'Unknown'})"
        ),
        f"Shared source IP(s): {', '.join(shared_ips) if shared_ips else 'None'}",
        f"Shared account(s): {', '.join(shared_accounts) if shared_accounts else 'None'}",
        f"Shared affected system(s): {', '.join(shared_systems) if shared_systems else 'None'}",
    ]

    if incident.first_seen and other_incident.first_seen:
        day_gap = abs((incident.first_seen - other_incident.first_seen).days)
        lines.append(f"Gap between first-seen timestamps: {day_gap} day(s)")
    else:
        lines.append(
            "Gap between first-seen timestamps: Unknown (one or both incidents "
            "are missing a first_seen timestamp)"
        )

    return "\n".join(lines)
