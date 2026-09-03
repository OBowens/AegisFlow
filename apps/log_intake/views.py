import csv
from collections import Counter
from datetime import timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from django.conf import settings
from django.contrib import messages
from django.db.models import Count
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.defaultfilters import filesizeformat
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.ai_core.orchestrator import run_demo_log_workflow
from apps.audit.models import AIRun
from apps.incidents.models import IncidentGroup
from apps.organizations.services.current_organization import get_current_organization
from apps.playbooks.models import ResponsePlaybook
from apps.reports.models import GeneratedReport
from apps.resilience.models import DisasterReadinessFinding
from apps.risk.models import GapFinding, RiskAssessment

from .forms import UploadLogFileForm
from .models import ParsedAlert, UploadedLogFile
from .services.sniffer import sniff_source_type
from .services.storage import save_uploaded_log_file

CARIBBEAN_TIMEZONE = ZoneInfo("America/St_Vincent")

SUPPORTED_SOURCE_CARDS = [
    {"value": "prtg", "label": "PRTG", "subtitle": "Network Monitor", "badge": "PR", "tone": "amber"},
    {"value": "graylog", "label": "Graylog", "subtitle": "Log Management", "badge": "GL", "tone": "red"},
    {"value": "wazuh", "label": "Wazuh", "subtitle": "SIEM & XDR", "badge": "WZ", "tone": "blue"},
    {"value": "proxmox", "label": "Proxmox", "subtitle": "Virtual Environment", "badge": "PX", "tone": "orange"},
    {"value": "firewall", "label": "Firewall Logs", "subtitle": "Network Security", "badge": "FW", "tone": "danger"},
    {"value": "backup", "label": "Backup Reports", "subtitle": "Backup Systems", "badge": "BK", "tone": "green"},
    {"value": "ssl_certificate", "label": "SSL/Certificate", "subtitle": "Reports", "badge": "SSL", "tone": "teal"},
    {"value": "windows", "label": "Windows Events", "subtitle": "System Logs", "badge": "WIN", "tone": "purple"},
]

UPLOAD_GUIDANCE_ITEMS = [
    {
        "icon": "shield-check",
        "tone": "blue",
        "title": "Use anonymized or demo data",
        "description": "For best results, upload anonymized or non-production logs.",
    },
    {
        "icon": "brand-shield",
        "tone": "teal",
        "title": "Your data is private and secure",
        "description": "All uploads are stored in the platform's protected private upload directory.",
    },
    {
        "icon": "upload",
        "tone": "green",
        "title": "We support multiple formats",
        "description": "Upload `.log`, `.json`, `.jsonl`, `.csv`, or `.txt` files up to 5 MB each.",
    },
    {
        "icon": "ai",
        "tone": "amber",
        "title": "Better data, better insights",
        "description": "Include useful notes like time range, host, or incident context for sharper analysis.",
    },
]


def index(request):
    return log_file_list(request)


def log_upload(request):
    if request.method == "POST":
        form = UploadLogFileForm(request.POST, request.FILES)
        if form.is_valid():
            organization = get_current_organization()
            uploaded_files = form.cleaned_data["log_file"]
            source_type = form.cleaned_data["source_type"]
            notes = form.cleaned_data["notes"]

            uploaded_log_files = []
            total_parsed_alerts = 0
            total_incidents = 0
            failed_file_names = []

            for uploaded_file in uploaded_files:
                uploaded_file.seek(0)
                raw_text = uploaded_file.read().decode("utf-8", errors="ignore")
                uploaded_file.seek(0)

                detected_source_type = sniff_source_type(raw_text, uploaded_file.name)
                effective_source_type = detected_source_type or source_type

                if detected_source_type and detected_source_type != source_type:
                    detected_label = UploadedLogFile.SourceType(detected_source_type).label
                    selected_label = UploadedLogFile.SourceType(source_type).label
                    messages.warning(
                        request,
                        f'"{uploaded_file.name}" looks like {detected_label} data, not '
                        f"{selected_label} — uploaded as {detected_label}.",
                    )

                _, _, relative_path = save_uploaded_log_file(
                    uploaded_file,
                    organization_id=organization.id,
                )

                uploaded_log_file = UploadedLogFile.objects.create(
                    organization=organization,
                    uploaded_by=request.user if request.user.is_authenticated else None,
                    file_name=uploaded_file.name,
                    source_type=effective_source_type,
                    storage_path=relative_path,
                    status=UploadedLogFile.Status.UPLOADED,
                    notes=notes,
                )
                uploaded_log_files.append(uploaded_log_file)

                workflow_summary = run_demo_log_workflow(uploaded_log_file)

                if workflow_summary["status"] == "success":
                    total_parsed_alerts += workflow_summary["parsed_alerts"]
                    total_incidents += workflow_summary["incidents"]
                else:
                    failed_file_names.append(uploaded_file.name)

            succeeded_count = len(uploaded_log_files) - len(failed_file_names)

            if succeeded_count:
                messages.success(
                    request,
                    f"Uploaded {succeeded_count} of {len(uploaded_log_files)} file(s). "
                    f"Parsed {total_parsed_alerts} alert(s) and grouped "
                    f"{total_incidents} incident(s) in total.",
                )
            if failed_file_names:
                messages.error(
                    request,
                    "The following file(s) uploaded but hit an error during analysis: "
                    + ", ".join(failed_file_names),
                )

            if len(uploaded_log_files) == 1:
                return redirect(
                    "log_intake:results",
                    uploaded_file_id=uploaded_log_files[0].id,
                )

            return redirect("incidents:index")
    else:
        form = UploadLogFileForm()
        form.fields["source_type"].initial = UploadedLogFile.SourceType.WAZUH

    context = _build_upload_page_context(form)
    return render(request, "log_intake/upload.html", context)


@require_POST
def delete_uploaded_log_file(request, uploaded_file_id: int):
    uploaded_file = get_object_or_404(UploadedLogFile, pk=uploaded_file_id)
    file_name = uploaded_file.file_name

    # IncidentGroup has no direct FK to ParsedAlert/UploadedLogFile -- it's
    # only reachable through the IncidentEvidence join table. Capture which
    # incidents this file's alerts feed *before* deleting anything, since
    # deleting the alerts will cascade-delete the evidence rows that are
    # our only way to find them.
    candidate_incident_ids = list(
        IncidentGroup.objects.filter(
            evidence_items__alert__uploaded_file=uploaded_file
        )
        .distinct()
        .values_list("id", flat=True)
    )

    file_path = settings.PRIVATE_UPLOAD_ROOT / uploaded_file.storage_path
    try:
        if file_path.exists():
            file_path.unlink()
    except OSError:
        pass

    # Cascades: ParsedAlert rows (on_delete=CASCADE) -> their IncidentEvidence
    # rows (on_delete=CASCADE) are removed automatically here.
    uploaded_file.delete()

    # Re-check each candidate incident for real, rather than assuming every
    # incident this file touched is now empty -- an incident is only
    # deleted if it genuinely has zero evidence left.
    orphaned_incidents = list(
        IncidentGroup.objects.filter(id__in=candidate_incident_ids)
        .annotate(remaining_evidence=Count("evidence_items"))
        .filter(remaining_evidence=0)
    )

    orphaned_risk_count = 0
    orphaned_playbook_count = 0

    for incident in orphaned_incidents:
        # RiskAssessment/GapFinding/ResponsePlaybook all point at IncidentGroup
        # via on_delete=SET_NULL, not CASCADE -- left alone, deleting the
        # incident would just null out their `incident` field and leave them
        # behind. Delete them explicitly first, while the FK is still intact.
        orphaned_risk_count += RiskAssessment.objects.filter(incident=incident).count()
        orphaned_risk_count += GapFinding.objects.filter(incident=incident).count()
        orphaned_playbook_count += ResponsePlaybook.objects.filter(incident=incident).count()

        RiskAssessment.objects.filter(incident=incident).delete()
        GapFinding.objects.filter(incident=incident).delete()
        # PlaybookStep cascades automatically (on_delete=CASCADE from ResponsePlaybook).
        ResponsePlaybook.objects.filter(incident=incident).delete()

    orphaned_incident_count = len(orphaned_incidents)
    IncidentGroup.objects.filter(
        id__in=[incident.id for incident in orphaned_incidents]
    ).delete()

    message = f'Deleted "{file_name}" and its parsed alerts.'
    if orphaned_incident_count:
        message += (
            f" Also removed {orphaned_incident_count} incident(s) left with no "
            f"remaining evidence, along with {orphaned_risk_count} risk finding(s) "
            f"and {orphaned_playbook_count} playbook(s) that existed only because of them."
        )

    messages.success(request, message)
    return redirect("log_intake:upload")


def log_file_list(request):
    # Retired 2026-08-28 -- org-wide Analysis Results merged into the
    # Incidents page's Overview/Alerts tabs (incidents:index). Redirect
    # rather than delete outright so old bookmarks/links still land
    # somewhere useful; carries the query string through so a filtered
    # link (e.g. ?alert_severity=high) still lands on the right tab there.
    target = reverse("incidents:index")
    if request.GET:
        target = f"{target}?{request.GET.urlencode()}"
    return redirect(target)


def build_overview_and_alerts_context(request):
    """Org-wide parsed-alert/risk/gap data for incidents:index's Overview
    and Alerts tabs. Lives here (not in apps/incidents) because it's
    fundamentally log-intake domain data -- uploads and parsed alerts --
    and log_analysis_results (the per-upload Analysis Results page, kept
    separate from the merge) already depends on the same private helpers
    below, so this just reuses them instead of duplicating the queries.
    """
    uploaded_files = (
        UploadedLogFile.objects.select_related("organization", "uploaded_by")
        .annotate(parsed_alert_count=Count("parsed_alerts"))
        .order_by("-uploaded_at")
    )
    parsed_alerts = (
        ParsedAlert.objects.select_related("uploaded_file", "organization")
        .order_by("-created_at")
    )
    incidents = (
        IncidentGroup.objects.select_related("organization")
        .prefetch_related("evidence_items__alert")
        .distinct()
        .order_by("-created_at")
    )
    risks = (
        RiskAssessment.objects.select_related("gap", "incident")
        .distinct()
        .order_by("-created_at")
    )
    playbooks = (
        ResponsePlaybook.objects.filter(incident__isnull=False)
        .prefetch_related("steps")
        .distinct()
        .order_by("-created_at")
    )
    severity_counts = {
        severity: parsed_alerts.filter(severity_hint=severity).count()
        for severity, _ in ParsedAlert.SeverityHint.choices
    }
    critical_findings_count = severity_counts["critical"] + severity_counts["high"]
    gap_count = risks.exclude(gap__isnull=True).values("gap_id").distinct().count()

    alert_severity_filter = request.GET.get("alert_severity", "").strip()
    alert_source_filter = request.GET.get("alert_source", "").strip()
    alert_system_filter = request.GET.get("alert_system", "").strip()
    filtered_parsed_alerts = _apply_alert_filters(
        parsed_alerts,
        severity=alert_severity_filter,
        source=alert_source_filter,
        affected_system=alert_system_filter,
    )
    parsed_alert_rows = _build_parsed_alert_rows(filtered_parsed_alerts)
    parsed_alert_total_filtered = filtered_parsed_alerts.count()
    alert_source_options = _distinct_values(parsed_alerts, "source_tool")
    alert_system_options = _distinct_values(parsed_alerts, "affected_system")

    # This page isn't scoped to a single upload (it spans every upload in
    # the org), so there's no uploaded_file id to hand to log_intake:alerts
    # the way _build_metric_url does below for the Critical Findings/
    # Detected Gaps cards -- instead carry over the same severity/source/
    # system filters already active on this page, so "View all" shows
    # exactly the alerts this panel's 9-row cap is hiding, not a different
    # set filtered some other way.
    alert_filter_params = {}
    if alert_severity_filter:
        alert_filter_params["severity"] = alert_severity_filter
    if alert_source_filter:
        alert_filter_params["source"] = alert_source_filter
    if alert_system_filter:
        alert_filter_params["affected_system"] = alert_system_filter
    view_all_parsed_alerts_url = _build_metric_url(
        reverse("log_intake:alerts"), **alert_filter_params
    )

    top_affected_systems = _build_top_affected_systems(parsed_alerts, incidents)
    ai_key_findings = _build_ai_key_findings(
        parsed_alerts=parsed_alerts,
        incidents=incidents,
        risks=risks,
        severity_counts=severity_counts,
        gap_count=gap_count,
        top_affected_systems=top_affected_systems,
    )
    overview_updated_at = _resolve_analysis_overview_last_updated(
        uploaded_files=uploaded_files,
        parsed_alerts=parsed_alerts,
        incidents=incidents,
        risks=risks,
    )
    workflow_summary = {
        "parsed_alerts": parsed_alerts.count(),
        "incidents": incidents.count(),
        "risks": risks.count(),
        "high_critical_incidents": incidents.filter(severity__in=["high", "critical"]).count(),
    }

    return {
        "overview_updated_at": overview_updated_at,
        "results_metrics": _build_results_metrics(
            parsed_alert_count=workflow_summary["parsed_alerts"],
            incident_count=workflow_summary["incidents"],
            critical_findings_count=critical_findings_count,
            gap_count=gap_count,
        ),
        "workflow_summary": workflow_summary,
        "parsed_alert_rows": parsed_alert_rows,
        "parsed_alert_total_filtered": parsed_alert_total_filtered,
        "view_all_parsed_alerts_url": view_all_parsed_alerts_url,
        "top_affected_systems": top_affected_systems,
        "ai_key_findings": ai_key_findings,
        "recommended_next_step": _build_recommended_next_step(
            incidents=incidents,
            playbooks=playbooks,
            critical_findings_count=critical_findings_count,
        ),
        "alert_severity_options": ParsedAlert.SeverityHint.choices,
        "alert_source_options": alert_source_options,
        "alert_system_options": alert_system_options,
        "selected_alert_severity": alert_severity_filter,
        "selected_alert_source": alert_source_filter,
        "selected_alert_system": alert_system_filter,
    }


def log_analysis_results(request, uploaded_file_id: int):
    uploaded_file = get_object_or_404(
        UploadedLogFile.objects.select_related("organization", "uploaded_by"),
        pk=uploaded_file_id,
    )
    parsed_alerts = uploaded_file.parsed_alerts.order_by("-created_at")
    incidents = (
        IncidentGroup.objects.filter(evidence_items__alert__uploaded_file=uploaded_file)
        .prefetch_related("evidence_items__alert")
        .distinct()
        .order_by("-created_at")
    )
    risks = (
        RiskAssessment.objects.filter(incident__in=incidents)
        .select_related("gap", "incident")
        .distinct()
        .order_by("-created_at")
    )
    readiness_findings = (
        DisasterReadinessFinding.objects.filter(
            Q(incident__in=incidents) | Q(risk__in=risks)
        )
        .select_related("incident", "risk")
        .distinct()
        .order_by("-created_at")
    )
    playbooks = (
        ResponsePlaybook.objects.filter(incident__in=incidents)
        .prefetch_related("steps")
        .distinct()
        .order_by("-created_at")
    )
    report = _get_generated_report_for_upload(uploaded_file, incidents)

    severity_counts = {
        severity: parsed_alerts.filter(severity_hint=severity).count()
        for severity, _ in ParsedAlert.SeverityHint.choices
    }
    workflow_summary = {
        "parsed_alerts": parsed_alerts.count(),
        "incidents": incidents.count(),
        "risks": risks.count(),
        "readiness_findings": readiness_findings.count(),
        "playbooks": playbooks.count(),
        "high_critical_incidents": incidents.filter(severity__in=["high", "critical"]).count(),
        "report_id": report.id if report else None,
    }
    gap_count = risks.exclude(gap__isnull=True).values("gap_id").distinct().count()
    critical_findings_count = severity_counts["critical"] + severity_counts["high"]
    top_affected_systems = _build_top_affected_systems(parsed_alerts, incidents)

    alert_severity_filter = request.GET.get("alert_severity", "").strip()
    alert_source_filter = request.GET.get("alert_source", "").strip()
    alert_system_filter = request.GET.get("alert_system", "").strip()
    filtered_parsed_alerts = _apply_alert_filters(
        parsed_alerts,
        severity=alert_severity_filter,
        source=alert_source_filter,
        affected_system=alert_system_filter,
    )
    parsed_alert_rows = _build_parsed_alert_rows(filtered_parsed_alerts)
    parsed_alert_total_filtered = filtered_parsed_alerts.count()
    alert_source_options = _distinct_values(parsed_alerts, "source_tool")
    alert_system_options = _distinct_values(parsed_alerts, "affected_system")

    # Same pattern as log_file_list's "View all N alerts" link, except this
    # page IS scoped to a single upload, so uploaded_file_id is passed
    # through too -- same _build_metric_url call already used below for the
    # Critical Findings/Detected Gaps cards.
    alert_filter_params = {}
    if alert_severity_filter:
        alert_filter_params["severity"] = alert_severity_filter
    if alert_source_filter:
        alert_filter_params["source"] = alert_source_filter
    if alert_system_filter:
        alert_filter_params["affected_system"] = alert_system_filter
    view_all_parsed_alerts_url = _build_metric_url(
        reverse("log_intake:alerts"),
        uploaded_file_id=uploaded_file.id,
        **alert_filter_params,
    )

    incident_severity_filter = request.GET.get("incident_severity", "").strip()
    incident_status_filter = request.GET.get("incident_status", "").strip()
    filtered_incidents_for_cards = _apply_incident_filters(
        incidents,
        severity=incident_severity_filter,
        status=incident_status_filter,
    )
    incident_cards = _build_incident_cards(filtered_incidents_for_cards)

    ai_key_findings = _build_ai_key_findings(
        parsed_alerts=parsed_alerts,
        incidents=incidents,
        risks=risks,
        severity_counts=severity_counts,
        gap_count=gap_count,
        top_affected_systems=top_affected_systems,
    )
    page_updated_at = _resolve_results_last_updated(
        uploaded_file=uploaded_file,
        parsed_alerts=parsed_alerts,
        incidents=incidents,
        risks=risks,
        readiness_findings=readiness_findings,
        report=report,
    )

    return render(
        request,
        "log_intake/results.html",
        {
            "uploaded_file": uploaded_file,
            "parsed_alerts": parsed_alerts,
            "parsed_alert_rows": parsed_alert_rows,
            "parsed_alert_total_filtered": parsed_alert_total_filtered,
            "view_all_parsed_alerts_url": view_all_parsed_alerts_url,
            "severity_counts": severity_counts,
            "workflow_summary": workflow_summary,
            "incidents": incidents,
            "incident_cards": incident_cards,
            "risks": risks,
            "readiness_findings": readiness_findings,
            "playbooks": playbooks,
            "report": report,
            "page_title": "Analysis Results",
            "page_description": "AI triage and incident grouping from uploaded logs.",
            "active_nav": "analysis_results",
            "organization_name": uploaded_file.organization.name,
            "organization_plan": "Small Business Plan",
            "dashboard_updated_at": _format_dashboard_datetime(page_updated_at),
            "results_metrics": _build_results_metrics(
                parsed_alert_count=workflow_summary["parsed_alerts"],
                incident_count=workflow_summary["incidents"],
                critical_findings_count=critical_findings_count,
                gap_count=gap_count,
                uploaded_file_id=uploaded_file.id,
            ),
            "critical_findings_count": critical_findings_count,
            "gap_count": gap_count,
            "top_affected_systems": top_affected_systems,
            "ai_key_findings": ai_key_findings,
            "recommended_next_step": _build_recommended_next_step(
                incidents=incidents,
                playbooks=playbooks,
                critical_findings_count=critical_findings_count,
            ),
            "alert_severity_options": ParsedAlert.SeverityHint.choices,
            "alert_source_options": alert_source_options,
            "alert_system_options": alert_system_options,
            "selected_alert_severity": alert_severity_filter,
            "selected_alert_source": alert_source_filter,
            "selected_alert_system": alert_system_filter,
            "incident_severity_options": IncidentGroup.Severity.choices,
            "incident_status_options": IncidentGroup.Status.choices,
            "selected_incident_severity": incident_severity_filter,
            "selected_incident_status": incident_status_filter,
        },
    )


def alert_list(request):
    uploaded_file_id = request.GET.get("uploaded_file", "").strip()
    severity_filter = request.GET.get("severity", "").strip()
    source_filter = request.GET.get("source", "").strip()
    affected_system_filter = request.GET.get("affected_system", "").strip()

    alerts = ParsedAlert.objects.select_related("uploaded_file", "organization").order_by("-created_at")

    scoped_uploaded_file = None
    if uploaded_file_id:
        scoped_uploaded_file = get_object_or_404(UploadedLogFile, pk=uploaded_file_id)
        alerts = alerts.filter(uploaded_file=scoped_uploaded_file)

    option_base = alerts
    alerts = _apply_alert_filters(
        alerts,
        severity=severity_filter,
        source=source_filter,
        affected_system=affected_system_filter,
    )

    organization = (
        scoped_uploaded_file.organization
        if scoped_uploaded_file
        else get_current_organization()
    )

    return render(
        request,
        "log_intake/alerts.html",
        {
            "page_title": (
                f"Parsed Alerts — {scoped_uploaded_file.file_name}"
                if scoped_uploaded_file
                else "Parsed Alerts"
            ),
            "page_description": "Every parsed alert, filterable by severity, source, and affected system.",
            "active_nav": "analysis_results",
            "organization_name": organization.name if organization else "Demo Organization",
            "organization_plan": "Small Business Plan",
            "dashboard_updated_at": _format_dashboard_datetime(timezone.now()),
            "scoped_uploaded_file": scoped_uploaded_file,
            "alert_cards": _build_alert_list_cards(alerts),
            "alert_count": alerts.count(),
            "severity_options": ParsedAlert.SeverityHint.choices,
            "source_options": _distinct_values(option_base, "source_tool"),
            "affected_system_options": _distinct_values(option_base, "affected_system"),
            "selected_severity": severity_filter,
            "selected_source": source_filter,
            "selected_affected_system": affected_system_filter,
        },
    )


def _build_alert_list_cards(alerts):
    cards = []
    for alert in alerts:
        timestamp_value = alert.timestamp or alert.created_at
        cards.append(
            {
                "id": alert.id,
                "summary": alert.normalized_summary or alert.event_type,
                "source_tool": alert.source_tool or "Unknown source",
                "severity": alert.severity_hint,
                "severity_label": alert.get_severity_hint_display(),
                "affected_system": alert.affected_system or "Unknown system",
                "account": alert.account,
                "uploaded_file_name": alert.uploaded_file.file_name if alert.uploaded_file_id else "",
                "time_display": _format_short_datetime(timestamp_value),
            }
        )
    return cards


def export_parsed_alerts_csv(request, uploaded_file_id: int):
    uploaded_file = get_object_or_404(UploadedLogFile, pk=uploaded_file_id)
    parsed_alerts = uploaded_file.parsed_alerts.order_by("-created_at")

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = (
        f'attachment; filename="{Path(uploaded_file.file_name).stem}_alerts.csv"'
    )

    writer = csv.writer(response)
    writer.writerow(
        [
            "Event Type",
            "Source Tool",
            "Severity",
            "Affected System",
            "Account",
            "Source IP",
            "Destination IP",
            "Timestamp",
            "Summary",
            "Raw Message",
        ]
    )

    for alert in parsed_alerts:
        timestamp_value = alert.timestamp or alert.created_at
        writer.writerow(
            [
                alert.event_type,
                alert.source_tool,
                alert.get_severity_hint_display(),
                alert.affected_system,
                alert.account,
                alert.source_ip or "",
                alert.destination_ip or "",
                timezone.localtime(timestamp_value, CARIBBEAN_TIMEZONE).isoformat(),
                alert.normalized_summary,
                alert.raw_message,
            ]
        )

    return response


def _get_generated_report_for_upload(uploaded_file, incidents):
    workflow_run = (
        AIRun.objects.filter(
            input_type="UploadedLogFile",
            input_id=str(uploaded_file.id),
            output_type="GeneratedReport",
            status=AIRun.Status.SUCCESS,
        )
        .exclude(output_id="")
        .order_by("-created_at")
        .first()
    )
    if workflow_run:
        return GeneratedReport.objects.filter(pk=workflow_run.output_id).first()

    return (
        GeneratedReport.objects.filter(
            organization=uploaded_file.organization,
            incident__in=incidents,
            report_type=GeneratedReport.ReportType.UPLOAD_SUMMARY,
        )
        .distinct()
        .order_by("-created_at")
        .first()
    )


def _build_upload_page_context(form):
    organization = get_current_organization()
    recent_uploads = _build_recent_uploads(limit=2)
    last_updated = (
        UploadedLogFile.objects.order_by("-uploaded_at").values_list("uploaded_at", flat=True).first()
        or timezone.now()
    )

    return {
        "form": form,
        "page_title": "Upload Logs",
        "page_description": "Add security, monitoring, and recovery data for AI analysis.",
        "active_nav": "upload_logs",
        "organization_name": organization.name if organization else "Demo Organization",
        "organization_plan": "Small Business Plan",
        "dashboard_updated_at": _format_dashboard_datetime(last_updated),
        "supported_source_cards": SUPPORTED_SOURCE_CARDS,
        "upload_guidance_items": UPLOAD_GUIDANCE_ITEMS,
        "recent_uploads": recent_uploads,
        "uploaded_files_count": UploadedLogFile.objects.count(),
    }


def _build_recent_uploads(limit: int):
    uploads = (
        UploadedLogFile.objects.select_related("organization")
        .annotate(parsed_alert_count=Count("parsed_alerts"))
        .order_by("-uploaded_at")[:limit]
    )
    return [
        {
            "id": uploaded_file.id,
            "file_name": uploaded_file.file_name,
            "file_kind": _file_kind_label(uploaded_file.file_name),
            "file_badge": _file_badge_label(uploaded_file.file_name),
            "file_badge_tone": _file_badge_tone(uploaded_file.file_name),
            "size_display": _resolve_upload_size_display(uploaded_file),
            "status_label": uploaded_file.get_status_display(),
            "status_tone": _status_tone(uploaded_file.status),
            "uploaded_display": _format_dashboard_datetime(uploaded_file.uploaded_at),
            "parsed_alert_count": uploaded_file.parsed_alert_count,
        }
        for uploaded_file in uploads
    ]


def _format_dashboard_datetime(value) -> str:
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)
    return (
        f"{localized.strftime('%b')} {localized.day}, {localized.year} "
        f"{localized.strftime('%I:%M %p')} AST"
    )


def _file_kind_label(file_name: str) -> str:
    suffix = Path(file_name).suffix.lower()
    mapping = {
        ".json": "JSON File",
        ".jsonl": "JSONL File",
        ".csv": "CSV File",
        ".log": "LOG File",
        ".txt": "TXT File",
    }
    return mapping.get(suffix, "Stored File")


def _file_badge_label(file_name: str) -> str:
    suffix = Path(file_name).suffix.lower().lstrip(".")
    if not suffix:
        return "FILE"
    return suffix.upper()[:4]


def _file_badge_tone(file_name: str) -> str:
    suffix = Path(file_name).suffix.lower()
    mapping = {
        ".json": "blue",
        ".jsonl": "blue",
        ".csv": "green",
        ".log": "amber",
        ".txt": "teal",
    }
    return mapping.get(suffix, "slate")


def _status_tone(status: str) -> str:
    mapping = {
        UploadedLogFile.Status.UPLOADED: "success",
        UploadedLogFile.Status.PARSING: "warning",
        UploadedLogFile.Status.PARSED: "success",
        UploadedLogFile.Status.FAILED: "danger",
    }
    return mapping.get(status, "neutral")


def _resolve_upload_size_display(uploaded_file: UploadedLogFile) -> str:
    file_path = settings.PRIVATE_UPLOAD_ROOT / uploaded_file.storage_path

    try:
        if file_path.exists():
            return filesizeformat(file_path.stat().st_size)
    except OSError:
        return "Stored privately"

    return "Stored privately"


def _resolve_results_last_updated(
    *,
    uploaded_file: UploadedLogFile,
    parsed_alerts,
    incidents,
    risks,
    readiness_findings,
    report,
):
    candidates = [
        uploaded_file.uploaded_at,
        parsed_alerts.values_list("created_at", flat=True).first(),
        incidents.values_list("updated_at", flat=True).first(),
        risks.values_list("created_at", flat=True).first(),
        readiness_findings.values_list("created_at", flat=True).first(),
        report.created_at if report else None,
    ]
    valid_candidates = [candidate for candidate in candidates if candidate is not None]
    return max(valid_candidates) if valid_candidates else timezone.now()


def _resolve_analysis_overview_last_updated(*, uploaded_files, parsed_alerts, incidents, risks):
    candidates = [
        uploaded_files.values_list("uploaded_at", flat=True).first(),
        parsed_alerts.values_list("created_at", flat=True).first(),
        incidents.values_list("updated_at", flat=True).first(),
        risks.values_list("created_at", flat=True).first(),
    ]
    valid_candidates = [candidate for candidate in candidates if candidate is not None]
    return max(valid_candidates) if valid_candidates else timezone.now()


def _build_metric_url(base_url, *, uploaded_file_id=None, **params):
    query_params = dict(params)
    if uploaded_file_id:
        query_params["uploaded_file"] = uploaded_file_id
    if not query_params:
        return base_url
    query = "&".join(f"{key}={value}" for key, value in query_params.items())
    return f"{base_url}?{query}"


def _build_results_metrics(
    *,
    parsed_alert_count: int,
    incident_count: int,
    critical_findings_count: int,
    gap_count: int,
    uploaded_file_id=None,
):
    return [
        {
            "title": "Parsed Alerts",
            "value": f"{parsed_alert_count:,}",
            "icon": "logs",
            "accent": "blue",
            "note": f"{critical_findings_count} high/critical flagged",
        },
        {
            "title": "Grouped Incidents",
            "value": f"{incident_count:,}",
            "icon": "users",
            "accent": "teal",
            "note": f"{incident_count} incident group{'' if incident_count == 1 else 's'} created",
        },
        {
            "title": "Critical Findings",
            "value": f"{critical_findings_count:,}",
            "icon": "critical",
            "accent": "red",
            "note": "Immediate review recommended" if critical_findings_count else "No critical items detected",
            "url": _build_metric_url(
                reverse("log_intake:alerts"),
                uploaded_file_id=uploaded_file_id,
                severity="high,critical",
            ),
        },
        {
            "title": "Detected Gaps",
            "value": f"{gap_count:,}",
            "icon": "gaps",
            "accent": "purple",
            "note": f"{gap_count} mapped control gap{'' if gap_count == 1 else 's'}",
            "url": _build_metric_url(reverse("risk:index"), uploaded_file_id=uploaded_file_id),
        },
    ]


def _apply_alert_filters(parsed_alerts, *, severity="", source="", affected_system=""):
    filtered = parsed_alerts
    severity_values = [value for value in severity.split(",") if value]
    if severity_values:
        filtered = filtered.filter(severity_hint__in=severity_values)
    if source:
        filtered = filtered.filter(source_tool=source)
    if affected_system:
        filtered = filtered.filter(affected_system=affected_system)
    return filtered


def _apply_incident_filters(incidents, *, severity="", status=""):
    filtered = incidents
    severity_values = [value for value in severity.split(",") if value]
    if severity_values:
        filtered = filtered.filter(severity__in=severity_values)
    if status:
        filtered = filtered.filter(status=status)
    return filtered


def _distinct_values(queryset, field_name):
    return sorted(
        value for value in queryset.values_list(field_name, flat=True).distinct() if value
    )


def _build_parsed_alert_rows(parsed_alerts):
    rows = []
    for alert in parsed_alerts[:9]:
        timestamp_value = alert.timestamp or alert.created_at
        rows.append(
            {
                "summary": alert.normalized_summary or alert.event_type,
                "source_tool": alert.source_tool or "Unknown source",
                "severity": alert.severity_hint,
                "severity_label": alert.get_severity_hint_display(),
                "affected_system": alert.affected_system or "Unknown system",
                "time_display": _format_short_datetime(timestamp_value),
            }
        )

    return rows


def _build_incident_cards(incidents):
    cards = []

    for incident in incidents[:3]:
        source_tools = {
            evidence.alert.source_tool
            for evidence in incident.evidence_items.all()
            if evidence.alert and evidence.alert.source_tool
        }
        evidence_count = incident.evidence_items.count()
        affected_system = _primary_affected_system(incident.affected_systems)

        cards.append(
            {
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "severity_label": incident.get_severity_display(),
                "source_count": len(source_tools),
                "evidence_count": evidence_count,
                "affected_system": affected_system,
                "url": f"/incidents/{incident.id}/",
            }
        )

    return cards


def _build_top_affected_systems(parsed_alerts, incidents):
    systems = Counter()

    for alert in parsed_alerts:
        if alert.affected_system:
            systems[alert.affected_system] += 1

    if not systems:
        for incident in incidents:
            for system_name in _split_system_names(incident.affected_systems):
                systems[system_name] += 1

    return [
        {"name": system_name, "count": count}
        for system_name, count in systems.most_common(5)
    ]


def _build_ai_key_findings(*, parsed_alerts, incidents, risks, severity_counts, gap_count, top_affected_systems):
    findings = []
    high_priority_total = severity_counts["critical"] + severity_counts["high"]

    if high_priority_total:
        findings.append(
            f"{high_priority_total} critical/high severity item{'s' if high_priority_total != 1 else ''} require immediate attention."
        )

    top_sources = Counter(
        alert.source_tool for alert in parsed_alerts if alert.source_tool
    ).most_common(2)
    if top_sources:
        source_names = ", ".join(source for source, _count in top_sources)
        findings.append(f"Top activity includes alerts from {source_names}.")

    if top_affected_systems:
        findings.append(
            f"Most affected systems currently include {', '.join(item['name'] for item in top_affected_systems[:3])}."
        )
    elif gap_count:
        findings.append(
            f"Detected gaps currently map to {gap_count} control area{'s' if gap_count != 1 else ''}."
        )

    if not findings:
        findings.append("No critical findings were generated for this upload yet.")

    return findings[:3]


def _build_recommended_next_step(*, incidents, playbooks, critical_findings_count: int):
    if critical_findings_count:
        return (
            "Investigate critical incidents, validate scope using the parsed alerts, "
            "and apply containment from the response playbook."
        )

    if playbooks.exists():
        return "Review the generated playbook and confirm owners for the next response actions."

    if incidents.exists():
        return "Review grouped incidents and decide which ones should be escalated for action."

    return "Review the parsed alerts, confirm severity, and upload another sample if more context is needed."


def _primary_affected_system(raw_value: str) -> str:
    systems = _split_system_names(raw_value)
    return systems[0] if systems else "Unknown system"


def _split_system_names(raw_value: str):
    if not raw_value:
        return []

    separators = ["\n", ",", ";"]
    values = [raw_value]

    for separator in separators:
        split_values = []
        for value in values:
            split_values.extend(value.split(separator))
        values = split_values

    return [value.strip() for value in values if value.strip()]


def _format_short_datetime(value) -> str:
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)
    now = timezone.localtime(timezone.now(), CARIBBEAN_TIMEZONE)

    if localized.date() == now.date():
        return localized.strftime("%I:%M %p").lstrip("0")

    if localized.date() == now.date() - timedelta(days=1):
        return "Yesterday"

    return f"{localized.strftime('%b')} {localized.day}"
