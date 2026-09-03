"""Context-gathering for the Risk Advisor agent: given a single
GapFinding, pull together its own detail, its paired RiskAssessment (one
risk per gap in this app's data model -- see
apps.risk.services.assessment.create_risk_findings_for_incidents), and a
short blurb about the incident it came from, into one structured
plain-text prompt section.

Deliberately scoped to one gap/risk pair, not organization-wide -- see
the 2026-08-26 investigation on why risk narration is its own feature
rather than folded into the incident-level Analyst agent's context.

This does not call any AI provider; it only builds the prompt text. See
apps/ai_core/modules/risk_advisor.py for the piece that sends this to a
provider and handles the response.
"""


def build_risk_context(gap) -> str:
    risk = gap.risk_assessments.order_by("id").first()

    sections = [
        _gap_section(gap),
        _risk_section(risk),
        _incident_section(gap.incident),
    ]
    return "\n\n".join(sections)


def _gap_section(gap):
    lines = [
        "## Gap Finding",
        f"Name: {gap.gap_name}",
        f"Description: {gap.description}",
        f"Priority: {gap.get_priority_display()}",
        f"Source: {gap.get_source_display()}",
    ]
    if gap.affected_system:
        lines.append(f"Affected system: {gap.affected_system}")
    if gap.evidence:
        lines.append(f"Evidence: {gap.evidence}")
    return "\n".join(lines)


def _risk_section(risk):
    if not risk:
        return "## Risk Assessment\nNo formal risk assessment recorded for this gap yet."

    return "\n".join(
        [
            "## Risk Assessment",
            f"Title: {risk.risk_title}",
            f"Likelihood: {risk.likelihood}/5",
            f"Impact: {risk.impact}/5",
            f"Risk score: {risk.risk_score}/25",
            f"Risk level: {risk.get_risk_level_display()}",
            f"Recommended priority: {risk.get_recommended_priority_display()}",
            f"Reasoning: {risk.reasoning}",
        ]
    )


def _incident_section(incident):
    if not incident:
        return "## Linked Incident\nNo incident is linked to this gap."

    return "\n".join(
        [
            "## Linked Incident",
            f"Title: {incident.title}",
            f"Type: {incident.incident_type}",
            f"Severity: {incident.get_severity_display()}",
            f"Affected system(s): {incident.affected_systems or 'Unknown'}",
        ]
    )
