"""Context-gathering for the Risk Report (Report Writer agent): given an
Organization, pull together its risk assessments organization-wide,
capped and ranked by risk score (likelihood x impact) -- same cap+rank
shape as apps.ai_core.services.priority_context -- plus a risk-level
breakdown and a count of gap findings still missing a formal
assessment, into one structured plain-text prompt section.

Deliberately organization-wide and aggregate, unlike
apps.ai_core.services.risk_context.build_risk_context, which is
deliberately scoped to a single gap/risk pair for the on-demand Risk
Advisor narration (see that module's own docstring for why). This is
the wide-angle rollup a Risk Report needs instead.

This does not call any AI provider; it only builds the prompt text. See
apps/ai_core/modules/report_writer.py for the piece that sends this to a
provider and handles the response.
"""

from django.db.models import ExpressionWrapper, F, IntegerField

from apps.risk.models import GapFinding, RiskAssessment

MAX_RISK_REPORT_FINDINGS = 15

_RISK_SCORE_EXPR = ExpressionWrapper(F("likelihood") * F("impact"), output_field=IntegerField())


def build_risk_report_context(organization) -> str:
    risk_qs = RiskAssessment.objects.filter(organization=organization).select_related("incident", "gap")
    total_risk_count = risk_qs.count()
    level_counts = {
        level: risk_qs.filter(risk_level=level).count() for level, _label in RiskAssessment.Level.choices
    }
    top_risks = list(
        risk_qs.annotate(_risk_score=_RISK_SCORE_EXPR).order_by("-_risk_score", "created_at")[
            :MAX_RISK_REPORT_FINDINGS
        ]
    )

    unassessed_gap_count = GapFinding.objects.filter(
        organization=organization, risk_assessments__isnull=True
    ).count()

    sections = [
        _overview_section(organization, total_risk_count, level_counts, unassessed_gap_count),
        _risks_section(top_risks, total_risk_count),
    ]
    return "\n\n".join(sections)


def _overview_section(organization, total_risk_count, level_counts, unassessed_gap_count):
    lines = [
        "## Risk Overview",
        f"Organization: {organization.name}",
        (
            f"Total risk findings: {total_risk_count} "
            f"({level_counts.get('critical', 0)} critical, {level_counts.get('high', 0)} high, "
            f"{level_counts.get('medium', 0)} medium, {level_counts.get('low', 0)} low)"
        ),
    ]
    if unassessed_gap_count:
        lines.append(f"Gap findings without a formal risk assessment yet: {unassessed_gap_count}")
    return "\n".join(lines)


def _risks_section(top_risks, total_risk_count):
    if not top_risks:
        return "## Risk Findings\nNone recorded."

    lines = ["## Risk Findings (highest score first)"]
    if total_risk_count > len(top_risks):
        lines.append(f"Showing the top {len(top_risks)} of {total_risk_count} risk findings.")
    for risk in top_risks:
        incident_label = (
            f'incident #{risk.incident_id} "{risk.incident.title}"' if risk.incident_id else "no linked incident"
        )
        lines.append(
            f"- {risk.risk_title} (score={risk.risk_score}/25, level={risk.get_risk_level_display()}, "
            f"recommended priority={risk.get_recommended_priority_display()}) -- {incident_label} -- "
            f"{risk.reasoning}"
        )
    return "\n".join(lines)
