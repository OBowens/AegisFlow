import csv
from collections import Counter
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from django.conf import settings
from django.core.paginator import Paginator
from django.db.models import Count
from django.http import HttpResponse
from django.shortcuts import render
from django.template.defaultfilters import filesizeformat
from django.urls import reverse
from django.utils import timezone

from apps.incidents.models import IncidentGroup
from apps.log_intake.models import UploadedLogFile
from apps.organizations.services.current_organization import get_current_organization
from apps.playbooks.models import ResponsePlaybook
from apps.reports.models import GeneratedReport
from apps.resilience.models import DisasterReadinessFinding
from apps.risk.models import RiskAssessment

from .models import AIRun, AuditLog

CARIBBEAN_TIMEZONE = ZoneInfo("America/St_Vincent")
DATE_RANGE_OPTIONS = {
    "7d": {"label": "Last 7 Days", "days": 7},
    "30d": {"label": "Last 30 Days", "days": 30},
    "all": {"label": "All Time", "days": None},
}
ACTION_TYPE_LABELS = {
    "upload": "Upload Actions",
    "ai_run": "AI Runs",
    "incident": "Incident Events",
    "risk": "Risk Events",
    "readiness": "Readiness Events",
    "playbook": "Playbook Events",
    "report": "Report Events",
    "audit": "Audit Log Events",
}
MODULE_META = {
    "upload": {"label": "Upload", "icon": "upload", "accent": "blue"},
    "intake_ai": {"label": "Intake AI", "icon": "ai", "accent": "purple"},
    "triage_ai": {"label": "Triage AI", "icon": "users", "accent": "purple"},
    "gap_risk_ai": {"label": "Gap & Risk AI", "icon": "gaps", "accent": "teal"},
    "readiness_ai": {"label": "Disaster Readiness AI", "icon": "readiness-nav", "accent": "teal"},
    "playbook_ai": {"label": "Response Playbook AI", "icon": "playbook", "accent": "blue"},
    "reports": {"label": "Reports", "icon": "reports-nav", "accent": "blue"},
    "audit": {"label": "Audit", "icon": "audit", "accent": "amber"},
    "incidents": {"label": "Incidents", "icon": "incident-nav", "accent": "amber"},
}
STATUS_META = {
    "completed": {"label": "Completed", "tone": "completed"},
    "in_progress": {"label": "In Progress", "tone": "in_progress"},
    "failed": {"label": "Failed", "tone": "failed"},
    "queued": {"label": "Queued", "tone": "queued"},
}
SEVERITY_META = {
    "low": {"label": "Low", "tone": "low"},
    "medium": {"label": "Medium", "tone": "medium"},
    "high": {"label": "High", "tone": "high"},
    "critical": {"label": "Critical", "tone": "critical"},
}


def _load_events():
    """Assemble every audit-relevant record into the unified event list.

    Shared by the Audit History page and its CSV export so the file a
    user downloads contains exactly the rows the page is built from.
    """
    uploads = list(
        UploadedLogFile.objects.select_related("organization", "uploaded_by")
        .annotate(parsed_alert_count=Count("parsed_alerts"))
        .order_by("-uploaded_at")
    )
    ai_runs = list(
        AIRun.objects.select_related("organization").order_by("-created_at")
    )
    reports = list(
        GeneratedReport.objects.select_related("organization", "incident", "generated_by").order_by("-created_at")
    )
    incidents = list(
        IncidentGroup.objects.select_related("organization").order_by("-updated_at", "-created_at")
    )
    risks = list(
        RiskAssessment.objects.select_related("organization", "incident", "gap").order_by("-created_at")
    )
    readiness_findings = list(
        DisasterReadinessFinding.objects.select_related("organization", "incident", "risk").order_by("-created_at")
    )
    playbooks = list(
        ResponsePlaybook.objects.select_related("organization", "incident", "risk", "readiness_finding").order_by("-updated_at", "-created_at")
    )
    audit_logs = list(
        AuditLog.objects.select_related("organization", "user").order_by("-created_at")
    )

    report_by_id = {report.id: report for report in reports}
    incident_by_id = {incident.id: incident for incident in incidents}
    upload_by_id = {upload.id: upload for upload in uploads}

    all_events = _build_all_events(
        uploads=uploads,
        ai_runs=ai_runs,
        reports=reports,
        incidents=incidents,
        risks=risks,
        readiness_findings=readiness_findings,
        playbooks=playbooks,
        audit_logs=audit_logs,
        report_by_id=report_by_id,
        incident_by_id=incident_by_id,
        upload_by_id=upload_by_id,
    )
    return all_events, uploads, ai_runs, reports


def index(request):
    all_events, uploads, ai_runs, reports = _load_events()

    filtered_events = _filter_events(all_events, request)
    selected_event = _resolve_selected_event(filtered_events, request.GET.get("event"))
    paginator = Paginator(filtered_events, 9)
    page_obj = paginator.get_page(request.GET.get("page") or 1)
    event_rows = _build_event_rows(page_obj, request, selected_event)
    organization = get_current_organization()
    page_updated_at = all_events[0]["created_at"] if all_events else timezone.now()

    return render(
        request,
        "audit/index.html",
        {
            "page_title": "Audit History",
            "page_description": "Trace user actions, AI runs, and report activity across your organization.",
            "active_nav": "audit",
            "organization_name": organization.name if organization else "Demo Organization",
            "organization_plan": "Small Business Plan",
            "dashboard_updated_at": _format_dashboard_datetime(page_updated_at),
            "audit_metrics": _build_audit_metrics(
                all_events=all_events,
                ai_runs=ai_runs,
                reports=reports,
                uploads=uploads,
            ),
            "date_range_options": _build_date_range_options(request.GET.get("range", "7d")),
            "user_options": _build_filter_options(filtered_events=all_events, current_value=request.GET.get("user", "all"), option_key="user_key", label_key="user_label", all_label="All Users"),
            "action_type_options": _build_action_type_options(all_events, request.GET.get("action", "all")),
            "module_options": _build_filter_options(filtered_events=all_events, current_value=request.GET.get("module", "all"), option_key="module_key", label_key="module_label", all_label="All Modules"),
            "severity_options": _build_severity_options(request.GET.get("severity", "all")),
            "event_rows": event_rows,
            "events_count": len(filtered_events),
            "events_total_count": len(all_events),
            "page_obj": page_obj,
            "selected_event": selected_event,
            "clear_selection_url": _build_query_url(request, drop_keys={"event", "page"}),
            "activity_trend": _build_activity_trend(filtered_events),
            "pagination": _build_pagination(page_obj, request, selected_event),
            "download_csv_url": _build_query_url(
                request, drop_keys={"event", "page"}, view_name="audit:export_csv"
            ),
        },
    )


CSV_COLUMNS = [
    "Event ID",
    "Timestamp (AST)",
    "User",
    "User Email",
    "Action",
    "Description",
    "Module",
    "Action Type",
    "Severity",
    "Status",
    "Input Type",
    "Output Type",
    "Related Incident",
    "Source",
    "IP Address",
    "Summary",
]


def export_csv(request):
    """Real CSV export of the Audit History events, honouring the same
    date-range / user / action / module / severity filters as the page.
    """
    all_events = _load_events()[0]
    events = _filter_events(all_events, request)

    stamp = timezone.localtime(timezone.now(), CARIBBEAN_TIMEZONE).strftime("%Y%m%d-%H%M%S")
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = (
        f'attachment; filename="audit-history-{stamp}.csv"'
    )

    writer = csv.writer(response)
    writer.writerow(CSV_COLUMNS)
    for event in events:
        local_created = timezone.localtime(event["created_at"], CARIBBEAN_TIMEZONE)
        writer.writerow(
            [
                event["event_id"],
                local_created.isoformat(),
                event["user_label"],
                event["user_email"],
                event["action_label"],
                event["description"],
                event["module_label"],
                ACTION_TYPE_LABELS.get(event["action_type"], event["action_type"]),
                event["severity_label"],
                event["status_label"],
                event["input_type"],
                event["output_type"],
                event["related_incident_label"],
                event["file_source"],
                event["ip_address"],
                event["summary"],
            ]
        )

    return response


def _build_all_events(
    *,
    uploads,
    ai_runs,
    reports,
    incidents,
    risks,
    readiness_findings,
    playbooks,
    audit_logs,
    report_by_id,
    incident_by_id,
    upload_by_id,
):
    events = []

    for uploaded_file in uploads:
        status_key = _upload_status_to_event_status(uploaded_file.status)
        events.append(
            _make_event(
                event_kind="upload",
                object_id=uploaded_file.id,
                created_at=uploaded_file.uploaded_at,
                user=uploaded_file.uploaded_by,
                action_label="Log file uploaded",
                description=_upload_description(uploaded_file),
                module_key="upload",
                severity_key="low" if uploaded_file.status != UploadedLogFile.Status.FAILED else "high",
                status_key=status_key,
                related_incident=None,
                input_type="Log File",
                output_type="Parsed Log Data" if uploaded_file.parsed_alert_count else "Queued Upload",
                file_source=_upload_description(uploaded_file),
                ip_address="",
                summary=uploaded_file.notes or "User uploaded a log file via the Upload Logs module.",
            )
        )

    for ai_run in ai_runs:
        report = None
        if ai_run.output_type == "GeneratedReport" and ai_run.output_id.isdigit():
            report = report_by_id.get(int(ai_run.output_id))

        related_incident = report.incident if report and report.incident_id else None
        events.append(
            _make_event(
                event_kind="ai_run",
                object_id=ai_run.id,
                created_at=ai_run.created_at,
                user=None,
                action_label=_ai_run_action(ai_run),
                description=_ai_run_description(ai_run, report, upload_by_id),
                module_key="intake_ai",
                severity_key="critical" if ai_run.status == AIRun.Status.FAILED else "low",
                status_key=_ai_run_status(ai_run.status),
                related_incident=related_incident,
                input_type=ai_run.input_type,
                output_type=ai_run.output_type,
                file_source=_file_source_for_run(ai_run, upload_by_id),
                ip_address="",
                summary=ai_run.error_message or "AI workflow processed the uploaded log data.",
            )
        )

    for incident in incidents:
        events.append(
            _make_event(
                event_kind="incident",
                object_id=incident.id,
                created_at=incident.created_at,
                user=None,
                action_label="AI generated incident group",
                description=incident.title,
                module_key="triage_ai",
                severity_key=incident.severity,
                status_key="completed",
                related_incident=incident,
                input_type="Parsed Alerts",
                output_type="Incident Group",
                file_source=_primary_system(incident.affected_systems),
                ip_address="",
                summary=incident.summary or "A grouped incident was generated from uploaded log data.",
            )
        )

    for risk in risks:
        events.append(
            _make_event(
                event_kind="risk",
                object_id=risk.id,
                created_at=risk.created_at,
                user=None,
                action_label="Gap & Risk AI created finding",
                description=risk.risk_title,
                module_key="gap_risk_ai",
                severity_key=risk.risk_level,
                status_key="completed",
                related_incident=risk.incident,
                input_type="Incident Group",
                output_type="Risk Assessment",
                file_source=risk.gap.affected_system if risk.gap and risk.gap.affected_system else _primary_system(risk.incident.affected_systems if risk.incident else ""),
                ip_address="",
                summary=risk.reasoning or "Risk analysis completed for the grouped incident.",
            )
        )

    for finding in readiness_findings:
        events.append(
            _make_event(
                event_kind="readiness",
                object_id=finding.id,
                created_at=finding.created_at,
                user=None,
                action_label="Disaster Readiness AI generated issue",
                description=finding.readiness_issue,
                module_key="readiness_ai",
                severity_key=_readiness_priority_to_severity(finding.priority),
                status_key="completed",
                related_incident=finding.incident,
                input_type="Risk Assessment",
                output_type="Readiness Finding",
                file_source=_primary_system(finding.incident.affected_systems if finding.incident else ""),
                ip_address="",
                summary=finding.disaster_impact or finding.recovery_concern,
            )
        )

    for playbook in playbooks:
        events.append(
            _make_event(
                event_kind="playbook",
                object_id=playbook.id,
                created_at=playbook.updated_at,
                user=None,
                action_label="Response Playbook generated",
                description=playbook.title,
                module_key="playbook_ai",
                severity_key=_playbook_priority_to_severity(playbook.priority),
                status_key="completed" if playbook.status != ResponsePlaybook.Status.DRAFT else "queued",
                related_incident=playbook.incident,
                input_type="Incident Group",
                output_type="Response Playbook",
                file_source=_primary_system(playbook.incident.affected_systems if playbook.incident else ""),
                ip_address="",
                summary=playbook.summary or "Response guidance was generated for the linked incident.",
            )
        )

    for report in reports:
        events.append(
            _make_event(
                event_kind="report",
                object_id=report.id,
                created_at=report.created_at,
                user=report.generated_by,
                action_label=f"{report.get_report_type_display()} report generated",
                description=report.title,
                module_key="reports",
                severity_key="low",
                status_key="completed",
                related_incident=report.incident,
                input_type="Analysis Findings",
                output_type="Generated Report",
                file_source=report.title,
                ip_address="",
                summary=report.summary or "A report was generated from the AI analysis workflow.",
            )
        )

    for audit_log in audit_logs:
        events.append(
            _make_event(
                event_kind="audit",
                object_id=audit_log.id,
                created_at=audit_log.created_at,
                user=audit_log.user,
                action_label=_humanize_action(audit_log.action),
                description=_audit_description(audit_log, incident_by_id, upload_by_id),
                module_key=_audit_module_key(audit_log),
                severity_key=_audit_severity(audit_log),
                status_key=_audit_status(audit_log),
                related_incident=_audit_related_incident(audit_log, incident_by_id, report_by_id),
                input_type=audit_log.target_type or "Activity",
                output_type=_audit_output_type(audit_log),
                file_source=_audit_file_source(audit_log, upload_by_id),
                ip_address=audit_log.ip_address,
                summary=audit_log.details or "User activity was recorded in the audit log.",
            )
        )

    return sorted(events, key=lambda event: event["created_at"], reverse=True)


def _filter_events(events, request):
    range_value = request.GET.get("range", "7d")
    user_value = request.GET.get("user", "all")
    action_value = request.GET.get("action", "all")
    module_value = request.GET.get("module", "all")
    severity_value = request.GET.get("severity", "all")

    filtered = list(events)
    range_days = DATE_RANGE_OPTIONS.get(range_value, DATE_RANGE_OPTIONS["7d"])["days"]

    if range_days is not None:
        cutoff = timezone.now() - timedelta(days=range_days)
        filtered = [event for event in filtered if event["created_at"] >= cutoff]

    if user_value != "all":
        filtered = [event for event in filtered if event["user_key"] == user_value]

    if action_value != "all":
        filtered = [event for event in filtered if event["action_type"] == action_value]

    if module_value != "all":
        filtered = [event for event in filtered if event["module_key"] == module_value]

    if severity_value != "all":
        filtered = [event for event in filtered if event["severity_key"] == severity_value]

    return filtered


def _resolve_selected_event(events, selected_key):
    if selected_key:
        for event in events:
            if event["event_key"] == selected_key:
                return event
    return events[0] if events else None


def _build_event_rows(page_obj, request, selected_event):
    return [
        {
            **event,
            "row_url": _build_query_url(
                request,
                extra_params={
                    "event": event["event_key"],
                    "page": page_obj.number,
                },
            ),
            "is_selected": bool(selected_event and event["event_key"] == selected_event["event_key"]),
        }
        for event in page_obj.object_list
    ]


def _build_audit_metrics(*, all_events, ai_runs, reports, uploads):
    # Same explicit AST localization as the rest of this page's date
    # grouping (Activity Trend chart, event timestamps) -- bare
    # timezone.localdate() defaults to settings.TIME_ZONE (UTC), which
    # could silently place a run into the wrong "today" a few hours off
    # from what a Caribbean-based user would call today.
    today = timezone.localdate(timezone.now(), CARIBBEAN_TIMEZONE)
    ai_runs_today = sum(
        1 for run in ai_runs if timezone.localdate(run.created_at, CARIBBEAN_TIMEZONE) == today
    )
    critical_activity = sum(
        1 for event in all_events if event["severity_key"] in {"high", "critical"}
    )

    return [
        {
            "title": "Total Events",
            "value": f"{len(all_events):,}",
            "icon": "logs",
            "accent": "blue",
            "note": f"{sum(1 for event in all_events if event['created_at'] >= timezone.now() - timedelta(days=7))} in last 7 days",
            "direction": "up",
        },
        {
            "title": "AI Runs Today",
            "value": f"{ai_runs_today:,}",
            "icon": "ai",
            "accent": "purple",
            "note": f"{sum(1 for run in ai_runs if run.status == AIRun.Status.SUCCESS)} successful overall",
            "direction": "up",
        },
        {
            "title": "Reports Generated",
            "value": f"{len(reports):,}",
            "icon": "reports",
            "accent": "teal",
            "note": f"{sum(1 for report in reports if report.created_at >= timezone.now() - timedelta(days=7))} in last 7 days",
            "direction": "up",
        },
        {
            "title": "Upload Actions",
            "value": f"{len(uploads):,}",
            "icon": "upload",
            "accent": "blue",
            "note": f"{sum(1 for upload in uploads if upload.status == UploadedLogFile.Status.FAILED)} failed upload(s)",
            "direction": "down" if any(upload.status == UploadedLogFile.Status.FAILED for upload in uploads) else "up",
        },
        {
            "title": "Critical Activity",
            "value": f"{critical_activity:,}",
            "icon": "critical",
            "accent": "red",
            "note": f"{critical_activity} high or critical event(s)",
            "direction": "up" if critical_activity else "flat",
        },
    ]


def _build_date_range_options(current_value):
    return [
        {
            "value": key,
            "label": option["label"],
            "selected": key == current_value,
        }
        for key, option in DATE_RANGE_OPTIONS.items()
    ]


def _build_filter_options(*, filtered_events, current_value, option_key, label_key, all_label):
    options = [{"value": "all", "label": all_label, "selected": current_value == "all"}]
    seen = set()

    for event in filtered_events:
        value = event[option_key]
        label = event[label_key]
        if value in seen:
            continue
        seen.add(value)
        options.append(
            {
                "value": value,
                "label": label,
                "selected": current_value == value,
            }
        )

    return options


def _build_action_type_options(events, current_value):
    options = [{"value": "all", "label": "All Actions", "selected": current_value == "all"}]

    for key, label in ACTION_TYPE_LABELS.items():
        if any(event["action_type"] == key for event in events):
            options.append({"value": key, "label": label, "selected": current_value == key})

    return options


def _build_severity_options(current_value):
    options = [{"value": "all", "label": "All Severities", "selected": current_value == "all"}]

    for key, meta in SEVERITY_META.items():
        options.append(
            {
                "value": key,
                "label": meta["label"],
                "selected": current_value == key,
            }
        )

    return options


def _build_activity_trend(events):
    end_date = (
        timezone.localdate(events[0]["created_at"], CARIBBEAN_TIMEZONE)
        if events
        else timezone.localdate()
    )
    days = [end_date - timedelta(days=offset) for offset in range(7, -1, -1)]
    all_counts = Counter()
    ai_counts = Counter()
    critical_counts = Counter()

    for event in events:
        event_date = timezone.localdate(event["created_at"], CARIBBEAN_TIMEZONE)
        if event_date not in days:
            continue
        all_counts[event_date] += 1
        if event["action_type"] in {"ai_run", "incident", "risk", "readiness", "playbook"}:
            ai_counts[event_date] += 1
        if event["severity_key"] in {"high", "critical"}:
            critical_counts[event_date] += 1

    series = [
        {
            "label": "All Events",
            "color_class": "all",
            "values": [all_counts[day] for day in days],
        },
        {
            "label": "AI Runs",
            "color_class": "ai",
            "values": [ai_counts[day] for day in days],
        },
        {
            "label": "Critical Activity",
            "color_class": "critical",
            "values": [critical_counts[day] for day in days],
        },
    ]
    max_value = max([1] + [value for line in series for value in line["values"]])

    return {
        "days": [
            {
                "label": f"{day.strftime('%b')} {day.day}",
            }
            for day in days
        ],
        "series": [
            {
                **line,
                "points": _chart_points(line["values"], max_value),
                "dots": _chart_dots(line["values"], max_value),
            }
            for line in series
        ],
        "grid_labels": [max_value, round(max_value * 0.66), round(max_value * 0.33), 0],
    }


def _build_pagination(page_obj, request, selected_event):
    page_items = []
    total_pages = page_obj.paginator.num_pages
    current = page_obj.number
    raw_items = [1]

    if total_pages > 1:
        raw_items.extend(
            page for page in range(max(1, current - 1), min(total_pages, current + 1) + 1)
        )
        raw_items.append(total_pages)

    deduped = []
    for item in raw_items:
        if item not in deduped:
            deduped.append(item)

    previous = None
    for item in deduped:
        if previous is not None and item - previous > 1:
            page_items.append({"is_ellipsis": True})
        page_items.append(
            {
                "number": item,
                "is_active": item == current,
                "url": _build_query_url(
                    request,
                    extra_params={
                        "page": item,
                        "event": selected_event["event_key"] if selected_event else "",
                    },
                ),
                "is_ellipsis": False,
            }
        )
        previous = item

    return {
        "prev_url": _build_query_url(
            request,
            extra_params={
                "page": page_obj.previous_page_number(),
                "event": selected_event["event_key"] if selected_event else "",
            },
        )
        if page_obj.has_previous()
        else None,
        "next_url": _build_query_url(
            request,
            extra_params={
                "page": page_obj.next_page_number(),
                "event": selected_event["event_key"] if selected_event else "",
            },
        )
        if page_obj.has_next()
        else None,
        "items": page_items,
    }


def _make_event(
    *,
    event_kind,
    object_id,
    created_at,
    user,
    action_label,
    description,
    module_key,
    severity_key,
    status_key,
    related_incident,
    input_type,
    output_type,
    file_source,
    ip_address,
    summary,
):
    module_meta = MODULE_META[module_key]
    severity_meta = SEVERITY_META[severity_key]
    status_meta = STATUS_META[status_key]
    user_label = _display_name(user)
    local_created = timezone.localtime(created_at, CARIBBEAN_TIMEZONE)

    return {
        "event_key": f"{event_kind}-{object_id}",
        "created_at": created_at,
        "event_id": f"EVT-{local_created.strftime('%Y-%m%d')}-{object_id}",
        "time_label": _format_event_datetime(created_at),
        "time_full": _format_dashboard_datetime(created_at),
        "user_label": user_label,
        "user_key": _filter_key(user_label),
        "user_initials": _initials(user_label),
        "user_email": getattr(user, "email", "") if user else "",
        "action_label": action_label,
        "description": description,
        "module_label": module_meta["label"],
        "module_key": module_key,
        "module_icon": module_meta["icon"],
        "module_accent": module_meta["accent"],
        "action_type": event_kind,
        "severity_label": severity_meta["label"],
        "severity_key": severity_key,
        "status_label": status_meta["label"],
        "status_key": status_meta["tone"],
        "input_type": input_type,
        "output_type": output_type,
        "related_incident_label": related_incident.title if related_incident else "",
        "related_incident_url": reverse("incidents:detail", args=[related_incident.id]) if related_incident else "",
        "file_source": file_source,
        "ip_address": ip_address or "Not recorded",
        "summary": summary or description,
        # Secondary link is only offered when it goes somewhere distinct
        # and real -- the incident's own evidence view. There is no
        # per-incident "activity" page and no separate "audit analytics"
        # page, so those labels are not invented here.
        "detail_primary_label": "View Related Incident" if related_incident else "View Incident Queue",
        "detail_primary_url": reverse("incidents:detail", args=[related_incident.id]) if related_incident else f"{reverse('incidents:index')}?tab=queue",
        "detail_secondary_label": "View Incident Evidence" if related_incident else "",
        "detail_secondary_url": reverse("incidents:evidence", args=[related_incident.id]) if related_incident else "",
    }


def _upload_status_to_event_status(status):
    mapping = {
        UploadedLogFile.Status.UPLOADED: "queued",
        UploadedLogFile.Status.PARSING: "in_progress",
        UploadedLogFile.Status.PARSED: "completed",
        UploadedLogFile.Status.FAILED: "failed",
    }
    return mapping.get(status, "completed")


def _ai_run_status(status):
    mapping = {
        AIRun.Status.STARTED: "in_progress",
        AIRun.Status.SUCCESS: "completed",
        AIRun.Status.FAILED: "failed",
    }
    return mapping.get(status, "completed")


def _ai_run_action(ai_run):
    if ai_run.status == AIRun.Status.FAILED:
        return "AI analysis workflow failed"
    if ai_run.status == AIRun.Status.STARTED:
        return "AI analysis workflow started"
    return "AI analysis workflow completed"


def _ai_run_description(ai_run, report, upload_by_id):
    upload = None
    if ai_run.input_type == "UploadedLogFile" and ai_run.input_id.isdigit():
        upload = upload_by_id.get(int(ai_run.input_id))

    if report:
        return f"{report.title} created from {upload.file_name if upload else 'uploaded log data'}"
    if upload:
        return f"{upload.file_name} processed by the AI workflow"
    return f"{ai_run.ai_module.replace('_', ' ').title()} handled the requested input"


def _file_source_for_run(ai_run, upload_by_id):
    if ai_run.input_type == "UploadedLogFile" and ai_run.input_id.isdigit():
        upload = upload_by_id.get(int(ai_run.input_id))
        if upload:
            return _upload_description(upload)
    return ai_run.input_type


def _upload_description(uploaded_file):
    size_display = _resolve_upload_size_display(uploaded_file)
    return f"{uploaded_file.file_name} ({size_display})"


def _readiness_priority_to_severity(priority):
    mapping = {
        DisasterReadinessFinding.Priority.LOW: "low",
        DisasterReadinessFinding.Priority.MEDIUM: "medium",
        DisasterReadinessFinding.Priority.HIGH: "high",
        DisasterReadinessFinding.Priority.CRITICAL: "critical",
    }
    return mapping.get(priority, "medium")


def _playbook_priority_to_severity(priority):
    mapping = {
        ResponsePlaybook.Priority.LOW: "low",
        ResponsePlaybook.Priority.MEDIUM: "medium",
        ResponsePlaybook.Priority.HIGH: "high",
        ResponsePlaybook.Priority.URGENT: "critical",
    }
    return mapping.get(priority, "medium")


def _humanize_action(action):
    return action.replace("_", " ").strip().capitalize()


def _audit_description(audit_log, incident_by_id, upload_by_id):
    if audit_log.target_type == "UploadedLogFile" and audit_log.target_id.isdigit():
        upload = upload_by_id.get(int(audit_log.target_id))
        if upload:
            return _upload_description(upload)
    if audit_log.target_type == "IncidentGroup" and audit_log.target_id.isdigit():
        incident = incident_by_id.get(int(audit_log.target_id))
        if incident:
            return incident.title
    return audit_log.details[:120] if audit_log.details else audit_log.target_type


def _audit_module_key(audit_log):
    action = audit_log.action.lower()
    target_type = (audit_log.target_type or "").lower()

    if "workflow" in action or "ai" in action:
        return "intake_ai"
    if target_type == "uploadedlogfile" or "upload" in action:
        return "upload"
    if target_type == "incidentgroup":
        return "incidents"
    if target_type == "generatedreport" or "report" in action:
        return "reports"
    return "audit"


def _audit_severity(audit_log):
    action = audit_log.action.lower()
    if "failed" in action:
        return "critical"
    if "error" in action:
        return "high"
    if "export" in action or "completed" in action:
        return "low"
    return "medium"


def _audit_status(audit_log):
    action = audit_log.action.lower()
    if "failed" in action:
        return "failed"
    if "started" in action or "queued" in action:
        return "in_progress"
    return "completed"


def _audit_related_incident(audit_log, incident_by_id, report_by_id):
    if audit_log.target_type == "IncidentGroup" and audit_log.target_id.isdigit():
        return incident_by_id.get(int(audit_log.target_id))
    if audit_log.target_type == "GeneratedReport" and audit_log.target_id.isdigit():
        report = report_by_id.get(int(audit_log.target_id))
        if report:
            return report.incident
    return None


def _audit_output_type(audit_log):
    if "completed" in audit_log.action.lower():
        return "Workflow Result"
    return audit_log.target_type or "Audit Activity"


def _audit_file_source(audit_log, upload_by_id):
    if audit_log.target_type == "UploadedLogFile" and audit_log.target_id.isdigit():
        upload = upload_by_id.get(int(audit_log.target_id))
        if upload:
            return _upload_description(upload)
    return audit_log.target_type or "Activity"


def _build_query_url(request, extra_params=None, drop_keys=None, view_name="audit:index"):
    params = request.GET.copy()

    for key in drop_keys or set():
        params.pop(key, None)

    for key, value in (extra_params or {}).items():
        if value in ("", None):
            params.pop(key, None)
        else:
            params[key] = value

    query = params.urlencode()
    base_url = reverse(view_name)
    return f"{base_url}?{query}" if query else base_url


def _filter_key(value):
    return value.lower().replace(" ", "_")


def _display_name(user):
    if not user:
        return "AegisFlow AI"

    full_name = getattr(user, "get_full_name", lambda: "")().strip()
    if full_name:
        return full_name

    username = getattr(user, "username", "")
    if username:
        return username

    email = getattr(user, "email", "")
    return email or str(user)


def _initials(label):
    parts = [part for part in label.strip().split() if part]
    if not parts:
        return "AI"
    return "".join(part[0] for part in parts[:2]).upper()


def _primary_system(raw_value):
    if not raw_value:
        return "Not specified"
    separators = ["\n", ",", ";"]
    values = [raw_value]
    for separator in separators:
        split_values = []
        for value in values:
            split_values.extend(value.split(separator))
        values = split_values
    cleaned = [value.strip() for value in values if value.strip()]
    return cleaned[0] if cleaned else "Not specified"


def _resolve_upload_size_display(uploaded_file):
    file_path = settings.PRIVATE_UPLOAD_ROOT / uploaded_file.storage_path
    try:
        if file_path.exists():
            return filesizeformat(file_path.stat().st_size)
    except OSError:
        return "Stored privately"
    return "Stored privately"


def _format_dashboard_datetime(value):
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)
    return (
        f"{localized.strftime('%b')} {localized.day}, {localized.year} "
        f"{localized.strftime('%I:%M %p').lstrip('0')} AST"
    )


def _format_event_datetime(value):
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)
    return (
        f"{localized.strftime('%b')} {localized.day}, {localized.year}\n"
        f"{localized.strftime('%I:%M:%S %p').lstrip('0')} AST"
    )


def _chart_points(values, max_value):
    left = 24
    right = 680
    top = 22
    bottom = 150
    step = (right - left) / max(len(values) - 1, 1)
    points = []

    for index, value in enumerate(values):
        x = left + (step * index)
        y = bottom - ((value / max_value) * (bottom - top)) if max_value else bottom
        points.append(f"{x:.2f},{y:.2f}")

    return " ".join(points)


def _chart_dots(values, max_value):
    left = 24
    right = 680
    top = 22
    bottom = 150
    step = (right - left) / max(len(values) - 1, 1)
    dots = []

    for index, value in enumerate(values):
        x = left + (step * index)
        y = bottom - ((value / max_value) * (bottom - top)) if max_value else bottom
        dots.append({"cx": round(x, 2), "cy": round(y, 2)})

    return dots
