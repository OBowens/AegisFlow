from apps.incidents.models import IncidentGroup
from apps.playbooks.models import ResponsePlaybook
from apps.reports.models import GeneratedReport
from apps.resilience.models import DisasterReadinessFinding
from apps.risk.models import RiskAssessment


def create_upload_summary_report_for_upload(uploaded_log_file):
    incidents = list(
        IncidentGroup.objects.filter(evidence_items__alert__uploaded_file=uploaded_log_file)
        .distinct()
        .order_by("id")
    )
    risks = list(
        RiskAssessment.objects.filter(incident__in=incidents)
        .select_related("gap", "incident")
        .distinct()
        .order_by("id")
    )
    readiness_findings = list(
        DisasterReadinessFinding.objects.filter(risk__in=risks)
        .select_related("incident", "risk")
        .distinct()
        .order_by("id")
    )
    playbooks = list(
        ResponsePlaybook.objects.filter(incident__in=incidents)
        .distinct()
        .order_by("id")
    )

    parsed_alert_count = uploaded_log_file.parsed_alerts.count()
    high_critical_incident_count = sum(
        1 for incident in incidents if incident.severity in {"high", "critical"}
    )
    primary_incident = incidents[0] if incidents else None

    title = f"AegisFlow AI Upload Summary - {uploaded_log_file.file_name}"
    summary = (
        f"{parsed_alert_count} parsed alert(s), {len(incidents)} incident(s), "
        f"and {len(risks)} risk finding(s) were generated from the uploaded sample log."
    )

    body = "\n\n".join(
        [
            "Overview\n"
            f"- Uploaded file: {uploaded_log_file.file_name}\n"
            f"- Source type: {uploaded_log_file.get_source_type_display()}\n"
            f"- Parsed alerts: {parsed_alert_count}\n"
            f"- Incidents identified: {len(incidents)}",
            "Key Findings\n"
            + _as_bullets(
                [
                    incident.title for incident in incidents
                ]
                or ["No incidents were grouped from the uploaded file."]
            ),
            "Highest Risks\n"
            + _as_bullets(
                [
                    f"{risk.risk_title} ({risk.risk_level})"
                    for risk in risks
                ]
                or ["No risk assessments were created."]
            ),
            "Readiness Concerns\n"
            + _as_bullets(
                [
                    finding.readiness_issue
                    for finding in readiness_findings
                ]
                or ["No disaster-readiness concerns were triggered."]
            ),
            "Recommended Actions\n"
            + _as_bullets(
                [
                    playbook.title
                    for playbook in playbooks
                ]
                or ["Review grouped alerts manually and determine next steps."]
            ),
            "Human Review Needed\n"
            "- Validate the grouped incidents and evidence.\n"
            f"- Prioritize attention to {high_critical_incident_count} high/critical incident(s).\n"
            "- Confirm any response action before applying changes in production.",
        ]
    )

    report, _ = GeneratedReport.objects.update_or_create(
        organization=uploaded_log_file.organization,
        incident=primary_incident,
        report_type=GeneratedReport.ReportType.UPLOAD_SUMMARY,
        title=title,
        defaults={
            "summary": summary,
            "body": body,
            "generated_by": uploaded_log_file.uploaded_by,
        },
    )
    return report


def _as_bullets(items):
    return "\n".join([f"- {item}" for item in items])
