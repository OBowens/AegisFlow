"""Context-gathering for the Executive Report (Report Writer agent):
given an Organization, pull together a high-level, decision-maker-facing
rollup -- open incidents (capped and ranked, same cap+rank shape as
apps.ai_core.services.priority_context), highest-scoring risk findings
(capped and ranked), and a one-line readiness snapshot -- into one
structured plain-text prompt section.

Deliberately organization-wide, not upload-scoped: this is the new
on-demand Executive report. It is NOT the same thing as the old,
automatic, upload-scoped report produced by
apps.reports.services.generator.create_upload_summary_report_for_upload
-- that one is a separate feature (GeneratedReport.ReportType.
UPLOAD_SUMMARY) kept as-is because real code still depends on it being
auto-generated per upload (apps/log_intake/views.py, apps/playbooks/
views.py); see the 2026-08-27 investigation into that naming collision.

This does not call any AI provider; it only builds the prompt text. See
apps/ai_core/modules/report_writer.py for the piece that sends this to a
provider and handles the response.
"""

from django.db.models import Case, ExpressionWrapper, F, IntegerField, When
from django.utils import timezone

from apps.incidents.models import IncidentGroup
from apps.resilience import views as resilience_views
from apps.resilience.models import DisasterReadinessFinding, ReadinessPlan
from apps.risk.models import RiskAssessment

MAX_EXECUTIVE_INCIDENTS = 10
MAX_EXECUTIVE_RISKS = 10

_OPEN_STATUSES = [IncidentGroup.Status.OPEN, IncidentGroup.Status.INVESTIGATING]

_SEVERITY_RANK = Case(
    When(severity=IncidentGroup.Severity.CRITICAL, then=4),
    When(severity=IncidentGroup.Severity.HIGH, then=3),
    When(severity=IncidentGroup.Severity.MEDIUM, then=2),
    When(severity=IncidentGroup.Severity.LOW, then=1),
    default=0,
    output_field=IntegerField(),
)

_RISK_SCORE_EXPR = ExpressionWrapper(F("likelihood") * F("impact"), output_field=IntegerField())


def build_executive_context(organization) -> str:
    open_incidents_qs = IncidentGroup.objects.filter(
        organization=organization, status__in=_OPEN_STATUSES
    )
    total_open_incidents = open_incidents_qs.count()
    top_incidents = list(
        open_incidents_qs.annotate(_severity_rank=_SEVERITY_RANK).order_by(
            "-_severity_rank", "created_at"
        )[:MAX_EXECUTIVE_INCIDENTS]
    )

    risk_qs = RiskAssessment.objects.filter(organization=organization).select_related("incident")
    total_risk_count = risk_qs.count()
    level_counts = {
        level: risk_qs.filter(risk_level=level).count() for level, _label in RiskAssessment.Level.choices
    }
    top_risks = list(
        risk_qs.annotate(_risk_score=_RISK_SCORE_EXPR).order_by("-_risk_score", "created_at")[
            :MAX_EXECUTIVE_RISKS
        ]
    )

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

    sections = [
        _overview_section(organization, total_open_incidents, total_risk_count, level_counts),
        _incidents_section(top_incidents, total_open_incidents),
        _risks_section(top_risks, total_risk_count),
        _readiness_section(readiness_overview),
    ]
    return "\n\n".join(sections)


def _overview_section(organization, total_open_incidents, total_risk_count, level_counts):
    lines = [
        "## Organization Overview",
        f"Organization: {organization.name}",
        f"Open incidents: {total_open_incidents}",
        (
            f"Risk findings: {total_risk_count} total "
            f"({level_counts.get('critical', 0)} critical, {level_counts.get('high', 0)} high, "
            f"{level_counts.get('medium', 0)} medium, {level_counts.get('low', 0)} low)"
        ),
    ]
    return "\n".join(lines)


def _incidents_section(top_incidents, total_open_incidents):
    if not top_incidents:
        return "## Open Incidents\nNone."

    now = timezone.now()
    lines = ["## Open Incidents (most severe first)"]
    if total_open_incidents > len(top_incidents):
        lines.append(
            f"Showing the top {len(top_incidents)} of {total_open_incidents} open incidents, "
            "ranked by severity (critical first) then by age (oldest open first within the "
            "same severity)."
        )
    for incident in top_incidents:
        days_open = max((now - incident.created_at).days, 0)
        lines.append(
            f"- Incident #{incident.id} \"{incident.title}\" -- severity={incident.get_severity_display()}, "
            f"status={incident.get_status_display()}, open for {days_open} day{'s' if days_open != 1 else ''}, "
            f"affected system(s)={incident.affected_systems or 'Unknown'}"
        )
    return "\n".join(lines)


def _risks_section(top_risks, total_risk_count):
    if not top_risks:
        return "## Highest Risk Findings\nNone recorded."

    lines = ["## Highest Risk Findings (highest score first)"]
    if total_risk_count > len(top_risks):
        lines.append(f"Showing the top {len(top_risks)} of {total_risk_count} risk findings.")
    for risk in top_risks:
        incident_label = (
            f'incident #{risk.incident_id} "{risk.incident.title}"' if risk.incident_id else "no linked incident"
        )
        lines.append(
            f"- {risk.risk_title} (score={risk.risk_score}/25, level={risk.get_risk_level_display()}, "
            f"recommended priority={risk.get_recommended_priority_display()}) -- {incident_label}"
        )
    return "\n".join(lines)


def _readiness_section(overview):
    return "\n".join(
        [
            "## Readiness Snapshot",
            f"Overall score: {overview['score_display']}",
            f"Headline: {overview['headline']}",
            (
                f"Domain status counts: {overview['status_counts']['good']} good, "
                f"{overview['status_counts']['medium']} medium, "
                f"{overview['status_counts']['high_risk']} high risk"
            ),
            f"Last assessed: {overview['last_assessed']}",
        ]
    )
