"""Context-gathering for the Readiness Advisor agent: given an
Organization, pull together its overall readiness score, per-domain
status/recommendations, and any active readiness-vs-finding
contradictions into one structured plain-text prompt section.

Deliberately reuses apps.resilience.views's own domain-classification
helpers (_build_readiness_domain_cards / _build_readiness_overview)
rather than re-implementing the keyword-matching and status logic here.
That logic is exactly what decides each domain's status on the Disaster
Readiness page itself, so importing it directly guarantees the AI's
explanation can never describe a different picture than what the page
shows -- re-deriving it separately here would risk exactly that drift.

This does not call any AI provider; it only builds the prompt text. See
apps/ai_core/modules/readiness_advisor.py for the piece that sends this
to a provider and handles the response.
"""

from apps.resilience import views as resilience_views
from apps.resilience.models import DisasterReadinessFinding, ReadinessPlan
from apps.resilience.services.contradictions import find_contradictions_for_organization


def build_readiness_context(organization) -> str:
    readiness_findings = list(
        DisasterReadinessFinding.objects.filter(organization=organization)
        .select_related("incident", "risk")
        .order_by("-created_at")
    )
    readiness_plans = list(
        ReadinessPlan.objects.filter(organization=organization).order_by("-updated_at")
    )
    domain_cards = resilience_views._build_readiness_domain_cards(
        readiness_findings=readiness_findings,
        readiness_plans=readiness_plans,
    )
    readiness_overview = resilience_views._build_readiness_overview(
        readiness_findings=readiness_findings,
        readiness_plans=readiness_plans,
        domain_cards=domain_cards,
    )
    contradictions = find_contradictions_for_organization(organization)

    sections = [
        _overview_section(organization, readiness_overview),
        _domain_section(domain_cards),
        _contradictions_section(contradictions),
    ]
    return "\n\n".join(sections)


def _overview_section(organization, overview):
    lines = [
        "## Readiness Overview",
        f"Organization: {organization.name}",
        f"Overall score: {overview['score_display']}",
        f"Headline: {overview['headline']}",
        (
            f"Domain status counts: {overview['status_counts']['good']} good, "
            f"{overview['status_counts']['medium']} medium, "
            f"{overview['status_counts']['high_risk']} high risk"
        ),
        f"Last assessed: {overview['last_assessed']}",
    ]
    return "\n".join(lines)


def _domain_section(domain_cards):
    if not domain_cards:
        return "## Domain Status\nNo domains assessed yet."

    lines = ["## Domain Status"]
    for card in domain_cards:
        lines.append(f"- {card['title']} ({card['status_label']}): {card['description']}")
        for item in card["items"]:
            lines.append(f"  - {item['text']}")
        lines.append(f"  Recommended action: {card['action']}")
    return "\n".join(lines)


def _contradictions_section(contradictions):
    if not contradictions:
        return "## Readiness Contradictions\nNone found for this organization."

    lines = [
        "## Readiness Contradictions",
        "A readiness answer conflicts with a recent finding:",
    ]
    for conflict in contradictions:
        lines.append(
            f'- Answer to "{conflict["answer_question"]}": "{conflict["answer_text"]}" '
            f'-- but the {conflict["finding_type"]} finding says: "{conflict["finding_text"]}" '
            f'(topic: {conflict["topic"]})'
        )
    return "\n".join(lines)
