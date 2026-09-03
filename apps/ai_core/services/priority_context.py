"""Context-gathering for the Prioritizer agent: given an Organization,
pull together its open incidents (with each one's paired risk
assessment, if any) into one structured plain-text prompt section.

A real org here can have hundreds of open incidents (286 in the current
dev DB) -- dumping all of them into one prompt would be expensive, slow,
and mostly noise, so this caps the list to the top MAX_PRIORITY_INCIDENTS
by severity (critical first), then by age within a severity tier (oldest
open first, since an old high-severity incident that's been sitting
untouched is more urgent than a fresh one at the same severity). The
total open count is still reported, so the model knows it's seeing a
capped view rather than the whole picture.

This does not call any AI provider; it only builds the prompt text. See
apps/ai_core/modules/prioritizer.py for the piece that sends this to a
provider and handles the response.
"""

from django.db.models import Case, IntegerField, When
from django.utils import timezone

from apps.incidents.models import IncidentGroup

MAX_PRIORITY_INCIDENTS = 10

_OPEN_STATUSES = [IncidentGroup.Status.OPEN, IncidentGroup.Status.INVESTIGATING]

_SEVERITY_RANK = Case(
    When(severity=IncidentGroup.Severity.CRITICAL, then=4),
    When(severity=IncidentGroup.Severity.HIGH, then=3),
    When(severity=IncidentGroup.Severity.MEDIUM, then=2),
    When(severity=IncidentGroup.Severity.LOW, then=1),
    default=0,
    output_field=IntegerField(),
)


def build_priority_context(organization) -> str:
    open_incidents_qs = IncidentGroup.objects.filter(
        organization=organization, status__in=_OPEN_STATUSES
    ).prefetch_related("risk_assessments")
    total_open_count = open_incidents_qs.count()

    top_incidents = list(
        open_incidents_qs.annotate(_severity_rank=_SEVERITY_RANK).order_by(
            "-_severity_rank", "created_at"
        )[:MAX_PRIORITY_INCIDENTS]
    )

    sections = [
        _overview_section(organization, total_open_count, len(top_incidents)),
        _incidents_section(top_incidents),
    ]
    return "\n\n".join(sections)


def _overview_section(organization, total_open_count, shown_count):
    lines = [
        "## Open Incident Overview",
        f"Organization: {organization.name}",
        f"Total open incidents: {total_open_count}",
    ]
    if total_open_count > shown_count:
        lines.append(
            f"Showing the top {shown_count} below, ranked by severity (critical first) "
            "then by age (oldest open first within the same severity)."
        )
    elif shown_count == 0:
        lines.append("No open incidents right now.")
    return "\n".join(lines)


def _incidents_section(top_incidents):
    if not top_incidents:
        return "## Open Incidents\nNone."

    now = timezone.now()
    lines = ["## Open Incidents (most urgent first)"]
    for rank, incident in enumerate(top_incidents, start=1):
        days_open = max((now - incident.created_at).days, 0)
        risk = incident.risk_assessments.order_by("id").first()

        lines.append(
            f"{rank}. Incident #{incident.id} \"{incident.title}\" -- "
            f"severity={incident.get_severity_display()}, status={incident.get_status_display()}, "
            f"open for {days_open} day{'s' if days_open != 1 else ''}, "
            f"affected system(s)={incident.affected_systems or 'Unknown'}"
        )
        if risk:
            lines.append(
                f"   Risk: {risk.risk_title} (score={risk.risk_score}/25, "
                f"level={risk.get_risk_level_display()}, "
                f"recommended priority={risk.get_recommended_priority_display()})"
            )
        else:
            lines.append("   Risk: No formal risk assessment recorded for this incident yet.")
    return "\n".join(lines)
