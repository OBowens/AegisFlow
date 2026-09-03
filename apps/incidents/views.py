from collections import defaultdict
from datetime import timedelta
from zoneinfo import ZoneInfo

from django.contrib import messages
from django.db.models import Max
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.urls import reverse
from django.utils import timezone

from apps.ai_core.modules.analyst import run_incident_analysis, run_incident_question
from apps.ai_core.modules.comparator import run_incident_comparison
from apps.ai_core.modules.incident_explainer import run_incident_explanation
from apps.ai_core.modules.report_writer import run_report_generation
from apps.ai_core.modules.workflow_advisor import run_workflow_next_step, run_workflow_step_question
from apps.ai_core.modules.writer import run_playbook_generation
from apps.ai_core.rate_limit import deny_ai_call
from apps.audit.models import AIRun, AuditLog
from apps.log_intake.views import build_overview_and_alerts_context
from apps.organizations.models import CriticalSystem
from apps.organizations.services.critical_systems import resolve_affected_system
from apps.organizations.services.current_organization import get_current_organization
from apps.playbooks.models import PlaybookStep
from apps.playbooks.services.approval_gate import requires_human_approval
from apps.playbooks.services.generator import create_playbooks_for_incidents, incident_to_urgency
from apps.reports.models import GeneratedReport
from apps.resilience.models import DisasterReadinessFinding, ReadinessPlan, ReadinessScoreSnapshot
from apps.resilience.services.scoring import build_readiness_trend

from .models import (
    AnalystQuestion,
    AnalystResult,
    IncidentComparison,
    IncidentExplanation,
    IncidentGroup,
    VerificationItemEvidenceState,
    WorkflowStepGuidance,
    WorkflowStepQuestion,
)
from .services.verification_evidence import refresh_verification_evidence_states

CARIBBEAN_TIMEZONE = ZoneInfo("America/St_Vincent")
SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "urgent": 4,
}
# Maps PlaybookStep.Urgency ("urgent") onto the .severity-pill--* CSS
# variants already defined for incident severity ("critical") -- same
# visual scale, no new CSS needed for the urgency badge.
URGENCY_PILL_KEY = {"low": "low", "medium": "medium", "high": "high", "urgent": "critical"}


def index(request):
    return incident_list(request)


def incident_list(request):
    incidents = (
        IncidentGroup.objects.select_related("organization", "assigned_to")
        .prefetch_related("evidence_items__alert")
        .order_by("-updated_at", "-created_at")
    )
    total_incident_count = incidents.count()
    open_incident_count = incidents.filter(status=IncidentGroup.Status.OPEN).count()
    high_count = incidents.filter(severity="high").count()
    critical_count = incidents.filter(severity="critical").count()
    latest_updated = incidents.values_list("updated_at", flat=True).first()
    # The canonical organization, not "whichever incident happened to be
    # touched most recently" -- that heuristic let a single stray/test
    # incident (wrong severity, no real evidence, etc.) silently steal
    # this page's org-scoped panels (Recent Activity, Readiness Snapshot,
    # Recommended Focus) away from the real organization's data the
    # moment it became the most-recently-updated incident.
    organization = get_current_organization()

    severity_filter = request.GET.get("severity", "").strip()
    status_filter = request.GET.get("status", "").strip()
    affected_system_filter = request.GET.get("affected_system", "").strip()
    assigned_filter = request.GET.get("assigned", "").strip()
    investigation_filter = request.GET.get("investigation_state", "").strip()

    filtered_incidents = incidents
    severity_values = [value for value in severity_filter.split(",") if value]
    if severity_values:
        filtered_incidents = filtered_incidents.filter(severity__in=severity_values)
    if status_filter:
        filtered_incidents = filtered_incidents.filter(status=status_filter)
    if affected_system_filter:
        filtered_incidents = filtered_incidents.filter(affected_systems__icontains=affected_system_filter)
    if assigned_filter == "me" and request.user.is_authenticated:
        filtered_incidents = filtered_incidents.filter(assigned_to=request.user)

    if assigned_filter == "me" and investigation_filter:
        investigation_statuses = {
            "open": [IncidentGroup.Status.OPEN, IncidentGroup.Status.INVESTIGATING, IncidentGroup.Status.CONTAINED],
            "assigned": [IncidentGroup.Status.OPEN],
            "in_progress": [IncidentGroup.Status.INVESTIGATING],
            "waiting": [IncidentGroup.Status.CONTAINED],
            "resolved": [IncidentGroup.Status.RESOLVED],
            "closed": [IncidentGroup.Status.CLOSED],
        }
        if investigation_filter in investigation_statuses:
            filtered_incidents = filtered_incidents.filter(status__in=investigation_statuses[investigation_filter])
    # Same "always the full, unfiltered count" behavior as the "All"
    # pill's incident_summary.total below -- neither pill's own count
    # should shift just because a severity/status/system filter is
    # also active.
    my_incident_count = (
        incidents.filter(assigned_to=request.user).count() if request.user.is_authenticated else 0
    )

    my_investigation_cards = _build_incident_list_cards(
        incidents.filter(assigned_to=request.user) if request.user.is_authenticated else incidents.none(),
        current_user=request.user,
    )
    priority = {"in_progress": 0, "waiting": 1, "assigned": 2, "resolved": 3, "closed": 4}
    my_investigation_cards.sort(key=lambda card: (priority[card["investigation_state"]], -card["updated_timestamp"]))
    my_investigation_counts = {
        "active": sum(card["investigation_state"] in {"in_progress", "waiting"} for card in my_investigation_cards),
        "assigned": sum(card["investigation_state"] == "assigned" for card in my_investigation_cards),
        "resolved": sum(card["investigation_state"] == "resolved" for card in my_investigation_cards),
        "closed": sum(card["investigation_state"] == "closed" for card in my_investigation_cards),
    }
    affected_system_options = sorted(
        {
            _primary_affected_system(value)
            for value in incidents.values_list("affected_systems", flat=True)
            if value
        }
    )

    # Analysis Results merged in here as Overview/Alerts tabs (see
    # build_overview_and_alerts_context) -- Queue is this view's own
    # pre-existing content, now living in a third tab, unchanged.
    overview_context = build_overview_and_alerts_context(request)
    updated_at_candidates = [
        value
        for value in (latest_updated, overview_context.pop("overview_updated_at"))
        if value is not None
    ]
    page_updated_at = max(updated_at_candidates) if updated_at_candidates else timezone.now()

    context = {
        "page_title": "Incidents",
        "page_description": (
            "AI-triaged parsed alerts and grouped incidents, from upload to resolution."
        ),
        "incidents": incidents,
        "active_nav": "incident_detail",
        "active_tab": _resolve_active_tab(request),
        "organization_name": organization.name if organization else "Demo Organization",
        "organization_plan": "Small Business Plan",
        "dashboard_updated_at": _format_dashboard_datetime(page_updated_at),
        "incident_metrics": _build_incident_list_metrics(
            total_incident_count=total_incident_count,
            open_incident_count=open_incident_count,
            high_count=high_count,
            critical_count=critical_count,
        ),
        "incident_cards": _build_incident_list_cards(filtered_incidents, current_user=request.user),
        "my_investigation_cards": [card for card in my_investigation_cards if card["investigation_state"] != "closed"][:4],
        "my_investigation_counts": my_investigation_counts,
        "incident_summary": {
            "total": total_incident_count,
            "open": open_incident_count,
            "high": high_count,
            "critical": critical_count,
        },
        "severity_options": IncidentGroup.Severity.choices,
        "status_options": IncidentGroup.Status.choices,
        "affected_system_options": affected_system_options,
        "selected_severity": severity_filter,
        "selected_status": status_filter,
        "selected_affected_system": affected_system_filter,
        "selected_assigned": assigned_filter,
        "selected_investigation_state": investigation_filter,
        "my_incident_count": my_incident_count,
    }
    context.update(overview_context)
    context.update(_build_queue_overview_extras(organization, context))

    return render(request, "incidents/business_list.html" if request.session.get("experience_mode") == "business" else "incidents/list.html", context)


@require_POST
def incident_assign_to_me(request, incident_id):
    """Assign an incident to the requesting user without starting or
    advancing its workflow -- the deliberate override/takeover action.
    Unlike _auto_assign_investigator (which only ever claims an
    unassigned incident), this always overwrites whoever, if anyone,
    is currently assigned -- that's the whole point of an explicit
    "Assign to me" button: reclaiming an incident from a colleague, or
    assigning it before ever opening the guided workflow.

    request.user.is_authenticated is always True here in practice --
    LoginRequiredMiddleware gates every view -- so there is no
    anonymous-user fallback to account for.
    """
    incident = get_object_or_404(IncidentGroup, pk=incident_id)
    incident.assigned_to = request.user
    incident.save(update_fields=["assigned_to", "updated_at"])
    analyst_name = request.user.get_full_name() or request.user.get_username()
    AuditLog.objects.create(
        organization=incident.organization,
        user=request.user,
        action="incident_assigned",
        target_type="IncidentGroup",
        target_id=str(incident.id),
        details=f"{incident.title} assigned to {analyst_name}",
    )
    return redirect(f"{reverse('incidents:index')}?tab=queue")


def _auto_assign_investigator(request, incident):
    """Claim an unassigned incident for the user advancing its guided
    workflow -- starting the workflow already IS the real "I'm working
    this" signal, so a separate explicit assign click shouldn't be
    required first. Never reassigns an incident that already has an
    owner (including this same user re-visiting later) --
    incident_assign_to_me above is the one deliberate override action.

    Called from incident_workflow's two earliest forward-progress POST
    transitions (see call sites below), not on any GET -- a page view
    must never have this side effect.
    """
    if incident.assigned_to_id is None:
        incident.assigned_to = request.user
        incident.save(update_fields=["assigned_to"])


def _build_queue_overview_extras(organization, context):
    """Small, read-only overview snapshots built from existing records."""
    audit_logs = AuditLog.objects.select_related("user").order_by("-created_at")
    findings = DisasterReadinessFinding.objects.all()
    plans = ReadinessPlan.objects.all()
    readiness_snapshots = ReadinessScoreSnapshot.objects.none()
    if organization:
        audit_logs = audit_logs.filter(organization=organization)
        findings = findings.filter(organization=organization)
        plans = plans.filter(organization=organization)
        readiness_snapshots = ReadinessScoreSnapshot.objects.filter(
            organization=organization
        ).order_by("computed_at")

    activity = []
    for event in audit_logs[:3]:
        activity.append(
            {
                "label": event.details or event.action.replace("_", " ").capitalize(),
                "time": timezone.localtime(event.created_at, CARIBBEAN_TIMEZONE).strftime("%b %d, %I:%M %p"),
            }
        )

    readiness_trend = build_readiness_trend(readiness_snapshots)
    metrics = context.get("results_metrics", [])
    gap_count = next((metric["value"] for metric in metrics if metric["title"] == "Detected Gaps"), "0")
    critical_count = next((metric["value"] for metric in metrics if metric["title"] == "Critical Findings"), "0")
    systems = context.get("top_affected_systems", [])
    focus = [f"Review {critical_count} high and critical findings"]
    if systems:
        focus.append(f"Investigate activity affecting {systems[0]['name']}")
    focus.append(f"Review {gap_count} mapped control gaps")

    return {
        "queue_recent_activity": activity,
        "queue_readiness_metrics": [
            {"label": "Controls mapped", "value": plans.count()},
            {"label": "Open gaps", "value": findings.count()},
        ],
        # Real history, not a live recomputation -- only actually
        # visiting the Disaster Readiness page records a point (see
        # apps.resilience.views.index), so this reflects real checks
        # over time rather than a number computed fresh on every load.
        "queue_readiness_trend": readiness_trend,
        "queue_recommended_focus": focus,
    }


def _resolve_active_tab(request):
    requested = request.GET.get("tab", "").strip().lower()
    if requested in {"overview", "alerts", "queue"}:
        return requested

    queue_signal_params = ("severity", "status", "affected_system")
    if any(request.GET.get(param) for param in queue_signal_params):
        return "queue"

    alerts_signal_params = ("alert_severity", "alert_source", "alert_system")
    if any(request.GET.get(param) for param in alerts_signal_params):
        return "alerts"

    return "overview"


def incident_detail(request, incident_id):
    incident = _get_incident_for_detail(incident_id)
    context = _build_incident_detail_context(incident)
    return render(request, "incidents/investigation_overview.html", context)


def incident_evidence(request, incident_id):
    incident = _get_incident_for_detail(incident_id)
    evidence_items = list(incident.evidence_items.all())

    return render(
        request,
        "incidents/evidence.html",
        {
            "page_title": f"Evidence - {incident.title}",
            "page_description": "Every evidence alert grouped into this incident.",
            "active_nav": "incident_detail",
            "organization_name": incident.organization.name,
            "organization_plan": "Small Business Plan",
            "incident": incident,
            "evidence_groups": _build_evidence_groups(evidence_items),
            "detail_url": reverse("incidents:detail", args=[incident.id]),
        },
    )


def incident_gaps(request, incident_id):
    incident = _get_incident_for_detail(incident_id)
    gap_findings = list(incident.gap_findings.all())

    return render(
        request,
        "incidents/gaps.html",
        {
            "page_title": f"Detected Gaps - {incident.title}",
            "page_description": "Every control gap detected for this incident.",
            "active_nav": "incident_detail",
            "organization_name": incident.organization.name,
            "organization_plan": "Small Business Plan",
            "incident": incident,
            "gap_cards": _build_gap_cards(gap_findings),
            "detail_url": reverse("incidents:detail", args=[incident.id]),
        },
    )


def _get_incident_for_detail(incident_id):
    return get_object_or_404(
        IncidentGroup.objects.select_related("organization").prefetch_related(
            "evidence_items__alert",
            "gap_findings",
            "risk_assessments",
            "readiness_findings",
            "response_playbooks__steps",
            "reports",
            "source_ip_links__related_incident",
        ),
        pk=incident_id,
    )


def _build_incident_detail_context(
    incident,
    *,
    analysis_result=None,
    analysis_error=None,
    qa_error=None,
    playbook_error=None,
    comparison_error=None,
    plain_language_result=None,
    plain_language_error=None,
    management_result=None,
    management_error=None,
    technical_report_result=None,
    technical_report_error=None,
    incident_report_result=None,
    incident_report_error=None,
):
    if analysis_result is None and analysis_error is None:
        analysis_result = _latest_analyst_result_context(incident)

    if plain_language_result is None and plain_language_error is None:
        plain_language_result = _latest_incident_explanation_context(
            incident, IncidentExplanation.Audience.PLAIN_LANGUAGE
        )

    if management_result is None and management_error is None:
        management_result = _latest_incident_explanation_context(
            incident, IncidentExplanation.Audience.MANAGEMENT
        )

    if technical_report_result is None and technical_report_error is None:
        technical_report_result = _latest_generated_report_context(
            incident, GeneratedReport.ReportType.TECHNICAL
        )

    if incident_report_result is None and incident_report_error is None:
        incident_report_result = _latest_generated_report_context(
            incident, GeneratedReport.ReportType.INCIDENT
        )

    evidence_items = list(incident.evidence_items.all())
    gap_findings = list(incident.gap_findings.all())
    risk_assessments = list(incident.risk_assessments.all())
    readiness_findings = list(incident.readiness_findings.all())
    playbooks = list(incident.response_playbooks.all())
    reports = list(incident.reports.all())
    source_ip_links = list(incident.source_ip_links.all())

    detected_at, ended_at = _resolve_incident_window(incident, evidence_items)
    page_updated_at = _resolve_last_updated(
        incident=incident,
        evidence_items=evidence_items,
        gap_findings=gap_findings,
        risk_assessments=risk_assessments,
        readiness_findings=readiness_findings,
        playbooks=playbooks,
        reports=reports,
    )
    primary_system = _primary_affected_system(incident.affected_systems)
    primary_report = reports[0] if reports else None
    primary_playbook = _resolve_primary_playbook(playbooks)
    critical_system_match = _build_critical_system_match(primary_system, incident.organization)
    inspection_data = _build_incident_inspection_data(evidence_items, incident, primary_playbook)
    incident_owner = (
        incident.assigned_to.get_full_name() or incident.assigned_to.get_username()
        if incident.assigned_to_id
        else ""
    )
    incident_detail_url = reverse("incidents:detail", args=[incident.id])

    return {
        "page_title": "Incident Detail",
        "page_description": (
            "AegisFlow AI incident evidence, gaps, risks, readiness concerns, and "
            "response actions."
        ),
        "active_nav": "incident_detail",
        "organization_name": incident.organization.name,
        "organization_plan": "Small Business Plan",
        "dashboard_updated_at": _format_dashboard_datetime(page_updated_at),
        "incident": incident,
        "incident_severity": incident.severity,
        "incident_identifier": _build_incident_identifier(incident),
        "incident_detected_at": _format_full_datetime(detected_at),
        "incident_duration": _humanize_duration(detected_at, ended_at),
        "primary_system": primary_system,
        "critical_system_match": critical_system_match,
        "incident_owner": incident_owner,
        "detail_evidence": inspection_data["evidence"],
        "incident_timeline": inspection_data["timeline"],
        "incident_entities": inspection_data["entities"],
        "entity_counts": inspection_data["entity_counts"],
        "incident_tasks": inspection_data["tasks"],
        "incident_summary": _build_ai_summary(
            incident=incident,
            evidence_items=evidence_items,
            gap_findings=gap_findings,
            risk_assessments=risk_assessments,
        ),
        "evidence_groups": _build_evidence_groups(evidence_items),
        "gap_cards": _build_gap_cards(gap_findings),
        "risk_snapshot": _build_risk_snapshot(risk_assessments, incident),
        "recommended_actions": _build_recommended_actions(primary_playbook),
        "step_status_options": PlaybookStep.Status.choices,
        "incident_detail_url": incident_detail_url,
        "primary_report": primary_report,
        "primary_playbook": primary_playbook,
        "playbook_url": reverse("playbooks:index"),
        "playbook_page_url": f"{reverse('playbooks:index')}?incident={incident.id}",
        "generate_playbook_url": reverse("incidents:generate_playbook", args=[incident.id]),
        "playbook_error": playbook_error,
        "readiness_url": reverse("resilience:index"),
        "report_url": (
            reverse("reports:detail", args=[primary_report.id])
            if primary_report
            else reverse("reports:index")
        ),
        "has_readiness_findings": bool(readiness_findings),
        "prior_source_ip_matches": _build_prior_source_ip_matches(source_ip_links),
        "status_options": IncidentGroup.Status.choices,
        "status_update_url": reverse("incidents:update_status", args=[incident.id]),
        "analyze_url": reverse("incidents:analyze", args=[incident.id]),
        "analysis_result": analysis_result,
        "analysis_error": analysis_error,
        "ask_url": reverse("incidents:ask", args=[incident.id]),
        "qa_thread": _build_qa_thread(incident),
        "qa_error": qa_error,
        "compare_url": reverse("incidents:compare", args=[incident.id]),
        "comparison_thread": _build_comparison_thread(incident),
        "comparison_error": comparison_error,
        "explain_plain_language_url": reverse("incidents:explain_plain_language", args=[incident.id]),
        "plain_language_result": plain_language_result,
        "plain_language_error": plain_language_error,
        "explain_management_url": reverse("incidents:explain_management", args=[incident.id]),
        "management_result": management_result,
        "management_error": management_error,
        "generate_technical_report_url": reverse("incidents:generate_technical_report", args=[incident.id]),
        "technical_report_result": technical_report_result,
        "technical_report_error": technical_report_error,
        "generate_incident_report_url": reverse("incidents:generate_incident_report", args=[incident.id]),
        "incident_report_result": incident_report_result,
        "incident_report_error": incident_report_error,
        "preparedness_banner_title": "Stay Prepared for Hurricane Season",
        "preparedness_banner_text": (
            "Hurricane season is here. Review your disaster readiness plan and "
            "ensure critical systems are protected."
        ),
    }


def incident_update_status(request, incident_id):
    incident = _get_incident_for_detail(incident_id)

    if request.method != "POST":
        return redirect("incidents:detail", incident_id=incident.id)

    new_status = request.POST.get("status")
    valid_statuses = {value for value, _label in IncidentGroup.Status.choices}
    if new_status not in valid_statuses:
        return redirect("incidents:detail", incident_id=incident.id)

    old_status = incident.status
    if new_status != old_status:
        incident.status = new_status
        incident.save(update_fields=["status"])

        # Same AuditLog shape as the only other real writer of this model,
        # apps/ai_core/orchestrator.py: organization, user, action,
        # target_type, target_id, details.
        AuditLog.objects.create(
            organization=incident.organization,
            user=request.user if request.user.is_authenticated else None,
            action="incident_status_changed",
            target_type="IncidentGroup",
            target_id=str(incident.id),
            details=f"Status changed from {old_status} to {new_status}.",
        )

    return redirect("incidents:detail", incident_id=incident.id)


def _resolve_incident_return_target(incident, return_to):
    """Validate `return_to` against an exact allowlist of this incident's
    own real pages -- Incident Detail's overview, or any workflow stage
    -- never an arbitrary URL. Same open-redirect-guard spirit as
    apps/playbooks/views.py::_safe_playbook_url, just resolved to a
    (target, stage) pair instead of a redirect URL, since these six
    views render their result inline rather than redirecting.

    Returns ("overview", None), ("workflow", stage), or ("detail", None)
    -- "detail" is the fallback when return_to is missing, invalid, or
    doesn't match anything: the historical behavior these six views have
    always had (render incidents/detail.html inline), unchanged for any
    caller that doesn't pass return_to at all (e.g. detail.html's own
    forms).
    """
    if return_to and return_to == reverse("incidents:detail", args=[incident.id]):
        return ("overview", None)

    for stage in ("overview", *WORKFLOW_STAGES):
        if return_to and return_to == reverse("incidents:workflow", args=[incident.id, stage]):
            return ("workflow", stage)

    return ("detail", None)


def _render_incident_action_result(request, incident, **context_overrides):
    """Render one of the six incident-scoped AI action views' result back
    on whichever page the action was actually triggered from, instead of
    always landing on incidents/detail.html regardless of caller.

    `context_overrides` are the same *_result/*_error kwargs each view
    already builds (analysis_result, qa_error, comparison_error, etc.) --
    passed straight through to _build_incident_detail_context (via
    _render_workflow_stage when the target is a workflow stage) so the
    just-run action's outcome shows up on whichever template renders.
    """
    return_to = request.POST.get("return_to") if request.method == "POST" else None
    target, stage = _resolve_incident_return_target(incident, return_to)

    if target == "workflow":
        return _render_workflow_stage(request, incident, stage, **context_overrides)

    template_name = (
        "incidents/investigation_overview.html" if target == "overview" else "incidents/detail.html"
    )
    context = _build_incident_detail_context(incident, **context_overrides)
    return render(request, template_name, context)


def incident_analyze(request, incident_id):
    incident = _get_incident_for_detail(incident_id)

    if request.method != "POST":
        return redirect("incidents:detail", incident_id=incident.id)

    denied = deny_ai_call(incident.organization, "analyst")
    if denied:
        return _render_incident_action_result(request, incident, analysis_error=denied)

    ai_run = AIRun.objects.create(
        organization=incident.organization,
        ai_module="analyst",
        input_type="IncidentGroup",
        input_id=str(incident.id),
        output_type="AnalystResult",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    analysis_result = None
    analysis_error = None

    try:
        raw_result = run_incident_analysis(incident)
    except RuntimeError as exc:
        analysis_error = _friendly_analysis_error(exc)
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
    else:
        saved_result = AnalystResult.objects.create(
            incident=incident,
            analysis_text=raw_result["analysis"],
            model_used=raw_result["model"],
        )
        analysis_result = _analyst_result_context(saved_result)

        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = saved_result.model_used
        ai_run.output_id = str(saved_result.id)
        ai_run.save(update_fields=["status", "model_used", "output_id"])

    return _render_incident_action_result(
        request, incident, analysis_result=analysis_result, analysis_error=analysis_error
    )


def incident_ask(request, incident_id):
    incident = _get_incident_for_detail(incident_id)

    if request.method != "POST":
        return redirect("incidents:detail", incident_id=incident.id)

    question_text = (request.POST.get("question") or "").strip()
    if not question_text:
        return redirect("incidents:detail", incident_id=incident.id)

    denied = deny_ai_call(incident.organization, "analyst_qa")
    if denied:
        return _render_incident_action_result(request, incident, qa_error=denied)

    ai_run = AIRun.objects.create(
        organization=incident.organization,
        ai_module="analyst_qa",
        input_type="IncidentGroup",
        input_id=str(incident.id),
        output_type="AnalystQuestion",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    qa_error = None

    try:
        raw_result = run_incident_question(incident, question_text)
    except RuntimeError as exc:
        qa_error = _friendly_analysis_error(exc)
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
    else:
        saved_question = AnalystQuestion.objects.create(
            incident=incident,
            question_text=raw_result["question"],
            answer_text=raw_result["answer"],
            model_used=raw_result["model"],
        )

        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = saved_question.model_used
        ai_run.output_id = str(saved_question.id)
        ai_run.save(update_fields=["status", "model_used", "output_id"])

    return _render_incident_action_result(request, incident, qa_error=qa_error)


def incident_compare(request, incident_id):
    incident = _get_incident_for_detail(incident_id)

    if request.method != "POST":
        return redirect("incidents:detail", incident_id=incident.id)

    other_incident_id_raw = (request.POST.get("other_incident_id") or "").strip()
    comparison_error = _validate_compare_target(other_incident_id_raw, incident)
    if comparison_error:
        return _render_incident_action_result(request, incident, comparison_error=comparison_error)

    other_incident = IncidentGroup.objects.select_related("organization").get(
        pk=int(other_incident_id_raw)
    )

    denied = deny_ai_call(incident.organization, "comparator")
    if denied:
        return _render_incident_action_result(request, incident, comparison_error=denied)

    ai_run = AIRun.objects.create(
        organization=incident.organization,
        ai_module="comparator",
        input_type="IncidentGroup",
        input_id=f"{incident.id},{other_incident.id}",
        output_type="IncidentComparison",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    try:
        raw_result = run_incident_comparison(incident, other_incident)
    except RuntimeError as exc:
        comparison_error = _friendly_analysis_error(exc)
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
    else:
        saved_comparison = IncidentComparison.objects.create(
            incident=incident,
            compared_incident=other_incident,
            comparison_text=raw_result["comparison"],
            model_used=raw_result["model"],
        )

        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = saved_comparison.model_used
        ai_run.output_id = str(saved_comparison.id)
        ai_run.save(update_fields=["status", "model_used", "output_id"])

    return _render_incident_action_result(request, incident, comparison_error=comparison_error)


def _validate_compare_target(other_incident_id_raw, incident):
    if not other_incident_id_raw.isdigit():
        return "Enter a valid incident ID to compare with."

    other_incident_id = int(other_incident_id_raw)
    if other_incident_id == incident.id:
        return "Choose a different incident to compare against."

    if not IncidentGroup.objects.filter(pk=other_incident_id).exists():
        return f"Incident #{other_incident_id} was not found."

    return None


def incident_explain(request, incident_id, audience):
    incident = _get_incident_for_detail(incident_id)

    if request.method != "POST":
        return redirect("incidents:detail", incident_id=incident.id)

    denied = deny_ai_call(incident.organization, "incident_explainer")
    if denied:
        return _render_incident_action_result(
            request, incident, **{f"{audience}_error": denied}
        )

    ai_run = AIRun.objects.create(
        organization=incident.organization,
        ai_module="incident_explainer",
        input_type="IncidentGroup",
        input_id=str(incident.id),
        output_type="IncidentExplanation",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    explanation_result = None
    explanation_error = None

    try:
        raw_result = run_incident_explanation(incident, audience)
    except RuntimeError as exc:
        explanation_error = _friendly_analysis_error(exc)
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
    else:
        saved_explanation = IncidentExplanation.objects.create(
            incident=incident,
            audience=audience,
            explanation_text=raw_result["explanation"],
            model_used=raw_result["model"],
        )
        explanation_result = _incident_explanation_context(saved_explanation)

        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = saved_explanation.model_used
        ai_run.output_id = str(saved_explanation.id)
        ai_run.save(update_fields=["status", "model_used", "output_id"])

    # audience is exactly "plain_language" or "management" (see urls.py),
    # matching _build_incident_detail_context's <audience>_result /
    # <audience>_error kwargs -- only the audience just run is overridden,
    # the other one still falls back to its own latest saved result.
    return _render_incident_action_result(
        request,
        incident,
        **{f"{audience}_result": explanation_result, f"{audience}_error": explanation_error},
    )


def incident_generate_report(request, incident_id, report_type):
    incident = _get_incident_for_detail(incident_id)

    if request.method != "POST":
        return redirect("incidents:detail", incident_id=incident.id)

    denied = deny_ai_call(incident.organization, "report_writer")
    if denied:
        return _render_incident_action_result(
            request, incident, **{f"{report_type}_report_error": denied}
        )

    ai_run = AIRun.objects.create(
        organization=incident.organization,
        ai_module="report_writer",
        input_type="IncidentGroup",
        input_id=str(incident.id),
        output_type="GeneratedReport",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    report_result = None
    report_error = None

    try:
        raw_result = run_report_generation(report_type, incident)
    except RuntimeError as exc:
        report_error = _friendly_analysis_error(exc)
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
    else:
        meta_title = "Technical Report" if report_type == GeneratedReport.ReportType.TECHNICAL else "Incident Report"
        saved_report = GeneratedReport.objects.create(
            organization=incident.organization,
            incident=incident,
            report_type=report_type,
            title=f"{meta_title} - {incident.title}",
            summary=raw_result["summary"],
            body=raw_result["report_text"],
            generated_by=request.user if request.user.is_authenticated else None,
        )
        report_result = _generated_report_context(saved_report)

        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = raw_result["model"]
        ai_run.output_id = str(saved_report.id)
        ai_run.save(update_fields=["status", "model_used", "output_id"])

    # report_type is exactly "technical" or "incident" (see urls.py),
    # matching _build_incident_detail_context's <report_type>_report_result /
    # <report_type>_report_error kwargs -- same override-only-what-just-ran
    # shape as incident_explain's audience kwargs above.
    return _render_incident_action_result(
        request,
        incident,
        **{f"{report_type}_report_result": report_result, f"{report_type}_report_error": report_error},
    )


def incident_generate_playbook(request, incident_id):
    incident = _get_incident_for_detail(incident_id)

    if request.method != "POST":
        return redirect("incidents:detail", incident_id=incident.id)

    denied = deny_ai_call(incident.organization, "writer")
    if denied:
        playbook_page_url = _playbook_page_return_url(request, incident)
        if playbook_page_url:
            messages.error(request, denied)
            return redirect(playbook_page_url)
        return _render_incident_action_result(request, incident, playbook_error=denied)

    ai_run = AIRun.objects.create(
        organization=incident.organization,
        ai_module="writer",
        input_type="IncidentGroup",
        input_id=str(incident.id),
        output_type="ResponsePlaybook",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    playbook_error = None

    try:
        raw_result = run_playbook_generation(incident)
    except RuntimeError as exc:
        playbook_error = _friendly_analysis_error(exc)
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
    else:
        # Reuses the same get-or-create-playbook-with-generic-steps logic
        # the intake pipeline uses, so this is safe to click more than
        # once -- it never touches steps already on the playbook (generic
        # or previously AI-generated), it only appends new ones.
        playbook = create_playbooks_for_incidents([incident])[0]
        next_step_number = (
            playbook.steps.aggregate(Max("step_number"))["step_number__max"] or 0
        ) + 1
        PlaybookStep.objects.bulk_create(
            [
                PlaybookStep(
                    playbook=playbook,
                    step_number=next_step_number + offset,
                    action=step["action"],
                    urgency=incident_to_urgency(incident.severity),
                    status=PlaybookStep.Status.PENDING,
                    source=PlaybookStep.Source.AI_GENERATED,
                )
                for offset, step in enumerate(raw_result["steps"])
            ]
        )

        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = raw_result["model"]
        ai_run.output_id = str(playbook.id)
        ai_run.save(update_fields=["status", "model_used", "output_id"])

        # _get_incident_for_detail prefetches response_playbooks__steps up
        # front -- on a first-ever generation for this incident, that cache
        # was populated before the playbook above existed, so a bare
        # incident.response_playbooks.all() would still see "none" unless
        # re-fetched here.
        incident = _get_incident_for_detail(incident.id)

    # The Response Playbook page (apps/playbooks) posts here from its
    # toolbar; send the user back there with a flash message instead of
    # swapping them onto the incident detail page.
    playbook_page_url = _playbook_page_return_url(request, incident)
    if playbook_page_url:
        if playbook_error:
            messages.error(request, playbook_error)
        else:
            messages.success(
                request, "Added AI-generated steps to this incident's response playbook."
            )
        return redirect(playbook_page_url)

    return _render_incident_action_result(request, incident, playbook_error=playbook_error)


def _playbook_page_return_url(request, incident):
    """Open-redirect guard for incidents:generate_playbook's post-generation
    redirect: the only allowed target is the Response Playbook page itself,
    scoped to this incident (same exact-match spirit as
    _resolve_incident_return_target / _safe_playbook_url).
    """
    if request.method != "POST":
        return None
    return_to = request.POST.get("return_to") or ""
    allowed = {
        reverse("playbooks:index"),
        f"{reverse('playbooks:index')}?incident={incident.id}",
    }
    return return_to if return_to in allowed else None


def _friendly_analysis_error(exc: RuntimeError) -> str:
    if "ANTHROPIC_API_KEY is not set" in str(exc):
        return "AI analysis isn't available yet — API key not configured."
    return "AI analysis failed. Please try again in a moment."


def _latest_analyst_result_context(incident):
    latest = incident.analyst_results.first()  # Meta.ordering = ["-generated_at"]
    return _analyst_result_context(latest) if latest else None


def _analyst_result_context(saved_result):
    return {
        "analysis": saved_result.analysis_text,
        "model": saved_result.model_used,
        "generated_at": saved_result.generated_at,
    }


def _latest_incident_explanation_context(incident, audience):
    # Meta.ordering = ["-generated_at"] -- "latest wins" per (incident,
    # audience) pair, same idea as _latest_analyst_result_context but
    # partitioned by audience, since one incident can have both a
    # plain-language and a management explanation at once.
    latest = incident.explanations.filter(audience=audience).first()
    return _incident_explanation_context(latest) if latest else None


def _incident_explanation_context(saved_explanation):
    return {
        "explanation": saved_explanation.explanation_text,
        "model": saved_explanation.model_used,
        "generated_at": saved_explanation.generated_at,
    }


def _latest_generated_report_context(incident, report_type):
    # No Meta.ordering on GeneratedReport (it's shared across every report
    # type, not just these two incident-scoped ones), so order explicitly --
    # same "latest wins" idea as _latest_incident_explanation_context, just
    # partitioned by report_type instead of audience.
    latest = incident.reports.filter(report_type=report_type).order_by("-created_at").first()
    return _generated_report_context(latest) if latest else None


def _generated_report_context(saved_report):
    return {
        "report_id": saved_report.id,
        "report_text": saved_report.body,
        "generated_at": saved_report.created_at,
        "detail_url": reverse("reports:detail", args=[saved_report.id]),
    }


def _build_qa_thread(incident):
    # Meta.ordering = ["asked_at"] -- oldest first, most recent last.
    return [
        {
            "question": qa.question_text,
            "answer": qa.answer_text,
            "model": qa.model_used,
            "asked_at": qa.asked_at,
        }
        for qa in incident.analyst_questions.all()
    ]


def _build_comparison_thread(incident):
    # Meta.ordering = ["generated_at"] -- oldest first, most recent last.
    return [
        {
            "compared_incident_id": comparison.compared_incident_id,
            "compared_incident_title": comparison.compared_incident.title,
            "compared_incident_url": reverse(
                "incidents:detail", args=[comparison.compared_incident_id]
            ),
            "comparison": comparison.comparison_text,
            "model": comparison.model_used,
            "generated_at": comparison.generated_at,
        }
        for comparison in incident.comparisons_started_here.all()
    ]


def _build_prior_source_ip_matches(source_ip_links):
    if not source_ip_links:
        return None

    now = timezone.now()
    items = []
    oldest_days_ago = 0

    for link in sorted(source_ip_links, key=lambda link: link.related_incident.created_at):
        related = link.related_incident
        days_ago = max((now - related.created_at).days, 0)
        oldest_days_ago = max(oldest_days_ago, days_ago)
        items.append(
            {
                "source_ip": link.source_ip,
                "incident_id": related.id,
                "incident_title": related.title,
                "incident_url": reverse("incidents:detail", args=[related.id]),
                "detected_display": _format_compact_datetime(related.created_at),
            }
        )

    days_span = max(oldest_days_ago, 1)
    incident_count = len(items)

    return {
        "count": incident_count,
        "days_span": days_span,
        "headline": (
            f"This source IP appeared in {incident_count} prior incident"
            f"{'s' if incident_count != 1 else ''} over the last {days_span} day"
            f"{'s' if days_span != 1 else ''}."
        ),
        "items": items,
    }


def _resolve_incident_window(incident, evidence_items):
    timestamps = []

    if incident.first_seen:
        timestamps.append(incident.first_seen)
    if incident.last_seen:
        timestamps.append(incident.last_seen)

    for evidence in evidence_items:
        alert = evidence.alert
        timestamps.append(alert.timestamp or alert.created_at)

    if not timestamps:
        return incident.created_at, incident.updated_at

    return min(timestamps), max(timestamps)


def _resolve_last_updated(
    *,
    incident,
    evidence_items,
    gap_findings,
    risk_assessments,
    readiness_findings,
    playbooks,
    reports,
):
    candidates = [incident.updated_at, incident.created_at]
    candidates.extend(evidence.alert.created_at for evidence in evidence_items)
    candidates.extend(gap.created_at for gap in gap_findings)
    candidates.extend(risk.created_at for risk in risk_assessments)
    candidates.extend(finding.created_at for finding in readiness_findings)
    candidates.extend(playbook.updated_at for playbook in playbooks)
    candidates.extend(report.created_at for report in reports)
    return max(candidates) if candidates else timezone.now()


def _build_incident_identifier(incident):
    localized = timezone.localtime(incident.created_at, CARIBBEAN_TIMEZONE)
    return f"INC-{localized.year}-{localized.strftime('%m%d')}-{incident.id:04d}"


def _build_ai_summary(*, incident, evidence_items, gap_findings, risk_assessments):
    if incident.ai_reasoning:
        return incident.ai_reasoning

    if incident.summary:
        return incident.summary

    evidence_count = len(evidence_items)
    gap_count = len(gap_findings)
    risk_count = len(risk_assessments)
    source_ip = next(
        (evidence.alert.source_ip for evidence in evidence_items if evidence.alert.source_ip),
        None,
    )
    account = next(
        (evidence.alert.account for evidence in evidence_items if evidence.alert.account),
        None,
    )

    fragments = [
        f"AegisFlow AI grouped {evidence_count} evidence alert{'s' if evidence_count != 1 else ''}",
        f"for a {incident.get_severity_display().lower()} {incident.incident_type.lower()} incident",
    ]

    if account:
        fragments.append(f"targeting account {account}")
    if source_ip:
        fragments.append(f"from source IP {source_ip}")

    summary = " ".join(fragments) + "."

    if gap_count or risk_count:
        summary += (
            f" The workflow also mapped {gap_count} gap{'s' if gap_count != 1 else ''} "
            f"and {risk_count} risk assessment{'s' if risk_count != 1 else ''} for follow-up."
        )

    return summary


def _build_evidence_groups(evidence_items):
    grouped = defaultdict(list)

    for evidence in evidence_items:
        alert = evidence.alert
        title = alert.event_type or "Related evidence"
        grouped[title].append(
            {
                "time_display": _format_compact_datetime(alert.timestamp or alert.created_at),
                "detail": alert.source_ip or alert.affected_system or alert.account or "Linked alert",
            }
        )

    sections = []
    for title, items in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])):
        sections.append(
            {
                "title": title,
                "count": len(items),
                "items": items,
            }
        )

    return sections


def _build_incident_inspection_data(evidence_items, incident, primary_playbook):
    evidence_rows = []
    entities = {}
    for evidence in sorted(evidence_items, key=lambda item: item.alert.timestamp or item.alert.created_at, reverse=True):
        alert = evidence.alert
        occurred_at = alert.timestamp or alert.created_at
        value = alert.normalized_summary or alert.raw_message or evidence.evidence_reason
        evidence_rows.append({
            "title": alert.event_type or "Related evidence",
            "source": alert.source_tool or alert.uploaded_file.get_source_type_display(),
            "time_display": _format_compact_datetime(occurred_at),
            "detail": value,
            "reason": evidence.evidence_reason,
            "severity": alert.severity_hint,
            "severity_label": alert.get_severity_hint_display(),
            "system": alert.affected_system,
            "account": alert.account,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
        })
        for entity_type, entity_value in (("user", alert.account), ("host", alert.affected_system), ("ip", alert.source_ip), ("ip", alert.destination_ip)):
            if not entity_value:
                continue
            key = (entity_type, str(entity_value))
            entity = entities.setdefault(key, {"type": entity_type, "value": str(entity_value), "count": 0, "severity": alert.severity_hint})
            entity["count"] += 1
            if SEVERITY_RANK.get(alert.severity_hint, 0) > SEVERITY_RANK.get(entity["severity"], 0):
                entity["severity"] = alert.severity_hint
    timeline = list(reversed(evidence_rows))
    tasks = []
    if primary_playbook:
        actionable_steps = [step for step in primary_playbook.steps.all() if step.status in {PlaybookStep.Status.PENDING, PlaybookStep.Status.IN_PROGRESS}]
        ranked_steps = sorted(actionable_steps, key=lambda step: (step.status != PlaybookStep.Status.IN_PROGRESS, -SEVERITY_RANK.get(step.urgency, 2), step.step_number))
        for step in ranked_steps:
            tasks.append({"title": step.action, "status": step.status, "status_label": step.get_status_display(), "number": step.step_number})
    entity_rows = sorted(entities.values(), key=lambda item: (item["type"], item["value"]))
    entity_counts = {kind: sum(1 for item in entity_rows if item["type"] == kind) for kind in ("user", "host", "ip", "domain")}
    return {"evidence": evidence_rows, "timeline": timeline, "entities": entity_rows, "entity_counts": entity_counts, "tasks": tasks}


def _build_gap_cards(gap_findings):
    sorted_gaps = sorted(
        gap_findings,
        key=lambda gap: (-SEVERITY_RANK.get(gap.priority, 0), gap.created_at),
    )

    return [
        {
            "title": gap.gap_name,
            "description": gap.description,
            "priority": gap.priority,
            "priority_label": gap.get_priority_display(),
        }
        for gap in sorted_gaps
    ]


def _build_risk_snapshot(risk_assessments, incident):
    if risk_assessments:
        primary_risk = max(
            risk_assessments,
            key=lambda risk: (
                SEVERITY_RANK.get(risk.risk_level, 0),
                SEVERITY_RANK.get(risk.recommended_priority, 0),
            ),
        )
        reasoning = primary_risk.reasoning
        likelihood = primary_risk.likelihood
        impact = primary_risk.impact
        overall = primary_risk.risk_level
    else:
        reasoning = (
            incident.summary
            or "This incident could lead to unauthorized access, service disruption, or data exposure."
        )
        likelihood = "high" if incident.severity in {"high", "critical"} else "medium"
        impact = "high" if incident.severity in {"high", "critical"} else incident.severity
        overall = incident.severity

    rows = [
        _build_risk_row("Likelihood", likelihood),
        _build_risk_row("Impact", impact),
        _build_risk_row("Overall Risk", overall),
    ]

    return {
        "rows": rows,
        "reasoning": reasoning,
    }


def _build_risk_row(label, level):
    if isinstance(level, (int, float)):
        normalized_level = _bucket_score_to_label(level)
    else:
        normalized_level = level if level in SEVERITY_RANK else "medium"
    active_segments = min(max(SEVERITY_RANK.get(normalized_level, 2), 1), 4)
    segments = [
        {"active": index < active_segments, "tone": normalized_level}
        for index in range(4)
    ]

    return {
        "label": label,
        "value": normalized_level,
        "value_label": normalized_level.replace("_", " ").title(),
        "segments": segments,
    }


def _bucket_score_to_label(score):
    if score <= 2:
        return "low"
    if score == 3:
        return "medium"
    if score == 4:
        return "high"
    return "critical"


def _resolve_primary_playbook(playbooks):
    # Explicit, deterministic ordering -- incident.response_playbooks.all()
    # (and the old playbooks[0]) had no ordering at all, so which playbook
    # "won" when an incident had more than one was undefined. Sorted here
    # (not a fresh .order_by(...).first() query) so the already-prefetched
    # `playbooks` list (see _get_incident_for_detail's prefetch_related) is
    # reused instead of firing an extra query for the same result.
    if not playbooks:
        return None
    return sorted(playbooks, key=lambda playbook: (playbook.updated_at, playbook.created_at))[-1]


def _build_recommended_actions(playbook):
    """The incident's actionable steps, filtered and ranked -- not a second,
    unfiltered dump of the same PlaybookStep rows the Playbooks page already
    shows in full. Only PENDING/IN_PROGRESS steps are "recommended actions";
    a completed or skipped step isn't something to still do.
    """
    if not playbook:
        return {"items": [], "has_steps": False, "all_done": False, "done_count": 0}

    steps = list(playbook.steps.all())  # PlaybookStep.Meta.ordering = [step_number, id]
    if not steps:
        return {"items": [], "has_steps": False, "all_done": False, "done_count": 0}

    actionable_statuses = {PlaybookStep.Status.PENDING, PlaybookStep.Status.IN_PROGRESS}
    actionable_steps = [step for step in steps if step.status in actionable_statuses]
    done_count = len(steps) - len(actionable_steps)

    ranked_steps = sorted(
        actionable_steps,
        key=lambda step: (
            step.status != PlaybookStep.Status.IN_PROGRESS,  # in-progress first
            -SEVERITY_RANK.get(step.urgency, 2),  # urgency high-to-low
            step.step_number,  # tie-break: the playbook's own causal order
        ),
    )

    items = [
        {
            "step_id": step.id,
            "number": index,
            "text": step.action.strip(),
            "status_key": "progress" if step.status == PlaybookStep.Status.IN_PROGRESS else "pending",
            "status_label": step.get_status_display(),
            "status_value": step.status,
            "urgency_label": step.get_urgency_display().upper(),
            "urgency_pill_key": URGENCY_PILL_KEY.get(step.urgency, "medium"),
            "requires_approval": requires_human_approval(step.action),
            "is_ai_generated": step.source == PlaybookStep.Source.AI_GENERATED,
            "status_update_url": reverse("playbooks:update_step_status", args=[step.id]),
        }
        for index, step in enumerate(ranked_steps, start=1)
    ]

    return {
        "items": items,
        "has_steps": True,
        "all_done": not actionable_steps,
        "done_count": done_count,
    }


def _build_incident_list_metrics(*, total_incident_count: int, open_incident_count: int, high_count: int, critical_count: int):
    # ?tab=queue is explicit here (not inferred) because "Total Incidents"
    # carries no severity/status param of its own to infer from -- see
    # _resolve_active_tab.
    list_url = f"{reverse('incidents:index')}?tab=queue"
    return [
        {
            "title": "Total Incidents",
            "value": f"{total_incident_count:,}",
            "icon": "incident-nav",
            "accent": "blue",
            "note": f"{open_incident_count} currently open",
            "url": list_url,
        },
        {
            "title": "Open Incidents",
            "value": f"{open_incident_count:,}",
            "icon": "warning",
            "accent": "orange",
            "note": "Requires analyst attention" if open_incident_count else "No open incidents",
            "url": f"{list_url}&status=open",
        },
        {
            "title": "High Severity",
            "value": f"{high_count:,}",
            "icon": "warning",
            "accent": "amber",
            "note": "Review recommended" if high_count else "No high-severity incidents",
            "url": f"{list_url}&severity=high",
        },
        {
            "title": "Critical",
            "value": f"{critical_count:,}",
            "icon": "critical",
            "accent": "red",
            "note": "Immediate review recommended" if critical_count else "No critical incidents",
            "url": f"{list_url}&severity=critical",
        },
    ]


CONFIDENCE_HIGH_THRESHOLD = 0.85
CONFIDENCE_MEDIUM_THRESHOLD = 0.6


def _confidence_label(value):
    """Return a qualitative label for a real stored confidence value."""
    if value is None:
        return None
    if value >= CONFIDENCE_HIGH_THRESHOLD:
        return {"key": "high", "label": "HIGH"}
    if value >= CONFIDENCE_MEDIUM_THRESHOLD:
        return {"key": "medium", "label": "MEDIUM"}
    return {"key": "low", "label": "LOW"}


def _investigation_ui(incident, current_user=None):
    status_map = {
        IncidentGroup.Status.INVESTIGATING: ("in_progress", "In Progress", "analysis"),
        IncidentGroup.Status.CONTAINED: ("waiting", "Waiting", "clock"),
        IncidentGroup.Status.RESOLVED: ("resolved", "Resolved", "circle-check"),
        IncidentGroup.Status.CLOSED: ("closed", "Closed", "archive"),
    }
    if incident.status == IncidentGroup.Status.OPEN:
        state = ("assigned", "Assigned", "user-outline") if incident.assigned_to_id else ("unassigned", "Unassigned", "user-outline")
    else:
        state = status_map.get(incident.status, ("in_progress", incident.get_status_display(), "analysis"))
    key, label, icon = state
    stored_stage = (incident.workflow_state or {}).get("stage")
    if key == "assigned":
        stage = "understand"
    elif key == "in_progress":
        stage = stored_stage if stored_stage in WORKFLOW_STAGES else "verify"
    elif key == "waiting":
        stage = stored_stage if stored_stage in WORKFLOW_STAGES else "respond"
    elif key in {"resolved", "closed"}:
        stage = "close"
    else:
        stage = "understand"
    stage_index = WORKFLOW_STAGES.index(stage) + 1
    action_map = {
        "unassigned": ("Start Investigation", reverse("incidents:investigate", args=[incident.id])),
        "assigned": ("Start Investigation", reverse("incidents:investigate", args=[incident.id])),
        "in_progress": ("Continue Investigation", reverse("incidents:workflow", args=[incident.id, stage])),
        "waiting": ("View Investigation", reverse("incidents:workflow", args=[incident.id, stage])),
        "resolved": ("Review & Close", reverse("incidents:workflow", args=[incident.id, "close"])),
        "closed": ("View Case", reverse("incidents:detail", args=[incident.id])),
    }
    action_label, action_url = action_map[key]
    owner = "Unassigned"
    if incident.assigned_to_id:
        owner = incident.assigned_to.get_full_name().strip() or incident.assigned_to.get_username()
        if current_user and current_user.is_authenticated and incident.assigned_to_id == current_user.id:
            owner = "You"
    return {"key": key, "label": label, "icon": icon, "stage": stage, "stage_label": stage.title(), "stage_index": stage_index, "action_label": action_label, "action_url": action_url, "owner": owner}


def _build_incident_list_cards(incidents, current_user=None):
    critical_system_lookup = {
        system.system_name.lower(): system for system in CriticalSystem.objects.all()
    }
    cards = []
    for incident in incidents:
        evidence_count = incident.evidence_items.count()
        affected_system = _primary_affected_system(incident.affected_systems)
        critical_system = critical_system_lookup.get(affected_system.lower())
        investigation = _investigation_ui(incident, current_user)
        cards.append({
            "id": incident.id,
            "incident_identifier": _build_incident_identifier(incident),
            "title": incident.title,
            "severity": incident.severity,
            "severity_label": incident.get_severity_display(),
            "status": incident.status,
            "status_label": incident.get_status_display(),
            "investigation_state": investigation["key"],
            "investigation_label": investigation["label"],
            "investigation_icon": investigation["icon"],
            "workflow_stage": investigation["stage"],
            "workflow_stage_label": investigation["stage_label"],
            "workflow_stage_index": investigation["stage_index"],
            "investigation_action_label": investigation["action_label"],
            "investigation_action_url": investigation["action_url"],
            "assignment_label": investigation["owner"],
            "organization_name": incident.organization.name,
            "incident_type": incident.incident_type,
            "affected_system": affected_system,
            "critical_system_criticality": critical_system.criticality if critical_system else None,
            "critical_system_criticality_label": critical_system.get_criticality_display() if critical_system else None,
            "summary": incident.summary or incident.ai_reasoning or "AegisFlow AI grouped related evidence into this incident.",
            "evidence_count": evidence_count,
            "confidence": _confidence_label(incident.confidence),
            "created_display": _format_compact_datetime(incident.created_at),
            "updated_display": _format_compact_datetime(incident.updated_at),
            "updated_at": incident.updated_at,
            "updated_timestamp": incident.updated_at.timestamp(),
            "url": reverse("incidents:investigate", args=[incident.id]),
            "view_url": reverse("incidents:detail", args=[incident.id]),
            "assign_url": reverse("incidents:assign_to_me", args=[incident.id]),
            "assigned_to": incident.assigned_to_id is not None,
        })
    return cards

def _primary_affected_system(raw_value):
    systems = _split_system_names(raw_value)
    return systems[0] if systems else "Unknown system"


def _build_critical_system_match(system_name, organization):
    match = resolve_affected_system(system_name, organization=organization)
    if not match:
        return {"matched": False, "system_name": system_name}

    owner_summary = f"{match.owner_name} · {match.get_recovery_priority_display()} recovery"
    if match.backup_required:
        owner_summary += " · Backup required"

    return {
        "matched": True,
        "system_name": match.system_name,
        "criticality": match.criticality,
        "criticality_label": match.get_criticality_display(),
        "owner_summary": owner_summary,
    }


def _split_system_names(raw_value):
    if not raw_value:
        return []

    values = [raw_value]
    for separator in ("\n", ",", ";"):
        split_values = []
        for value in values:
            split_values.extend(value.split(separator))
        values = split_values

    return [value.strip() for value in values if value.strip()]


def _humanize_duration(start, end):
    if not start or not end:
        return "Unconfirmed"

    total_seconds = max(int((end - start).total_seconds()), 0)
    if total_seconds < 60:
        return "<1 minute"

    minutes = round(total_seconds / 60)
    if minutes < 60:
        return f"~{minutes} minute{'s' if minutes != 1 else ''}"

    hours = minutes // 60
    remaining_minutes = minutes % 60
    if remaining_minutes:
        return f"~{hours} hr {remaining_minutes} min"

    return f"~{hours} hour{'s' if hours != 1 else ''}"


def _format_dashboard_datetime(value):
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)
    return (
        f"{localized.strftime('%b')} {localized.day}, {localized.year} "
        f"{localized.strftime('%I:%M %p').lstrip('0')} AST"
    )


def _format_full_datetime(value):
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)
    return (
        f"{localized.strftime('%b')} {localized.day}, {localized.year} "
        f"{localized.strftime('%I:%M %p').lstrip('0')} AST"
    )


def _format_compact_datetime(value):
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)
    now = timezone.localtime(timezone.now(), CARIBBEAN_TIMEZONE)

    if localized.date() == now.date():
        return localized.strftime("%b %d, %Y %I:%M %p").replace(" 0", " ")

    if localized.date() == now.date() - timedelta(days=1):
        return f"Yesterday {localized.strftime('%I:%M %p').lstrip('0')}"

    return localized.strftime("%b %d, %Y %I:%M %p").replace(" 0", " ")

WORKFLOW_STAGES = ("understand", "verify", "respond", "resolve", "close")
# Stages that get AI "do this next" guidance + a scoped "how do I do this"
# Q&A thread. "close" is excluded -- it's a terminal review page whose one
# action (close the incident) is already the explicit CTA, not something
# guidance would add to.
GUIDANCE_STAGES = ("understand", "verify", "respond", "resolve")


def _workflow_verification_items(incident):
    """Contextual guidance only; factual findings always come from evidence or the user."""
    subject = (incident.title + " " + incident.incident_type).lower()
    system = _split_system_names(incident.affected_systems)[0] if incident.affected_systems else "the affected system"
    if "phish" in subject or "credential" in subject:
        checks = [
            ("link_interaction", "Did the user interact with the suspicious link?", "Review email and proxy evidence, then confirm with the user.", "Ask the user whether they opened the link or attachment. Check web-proxy history for the same timestamp."),
            ("credential_entry", "Were credentials entered or exposed?", "Review identity evidence without assuming compromise.", "Ask whether credentials were entered. Then review sign-in logs for new devices, locations, or repeated failures."),
            ("suspicious_signin", "Are suspicious sign-ins still occurring?", "Compare current authentication evidence with the original alert.", "Open the identity provider sign-in log and filter for the affected user since the incident began."),
            ("mailbox_changes", "Were unexpected mailbox rules or forwarding settings created?", "Mailbox changes can indicate account takeover.", "Review inbox rules, forwarding addresses, delegates, and recent administrative changes."),
        ]
    else:
        checks = [
            ("reachable", f"Is {system} reachable?", "Use connected monitoring or a manual connectivity check.", f"Check {system} in your monitoring tool. If no live source is connected, ping it or test its normal management port."),
            ("service_health", "Is the affected service still failing?", "Compare current service evidence with the original alert.", "Check the service manager or monitoring console. Confirmed means the reported failure is still present."),
            ("expected_change", "Is this linked to an approved change or maintenance?", "Expected activity changes the safest response.", "Review the change calendar and ask the system owner about work during the incident window."),
            ("scope", "Are other systems affected?", "Correlated evidence determines scope and response priority.", "Search recent alerts for the same signature, account, source, or dependency on other systems."),
        ]
    saved = (incident.workflow_state or {}).get("verification_results", {})
    # Real, question-specific classification -- not "does this incident
    # have any evidence at all" applied uniformly to every question.
    # Recomputed fresh every render (no caching -- see
    # refresh_verification_evidence_states's docstring for why).
    evidence_states = refresh_verification_evidence_states(incident, [key for key, *_ in checks])
    return [
        {
            "key": key,
            "question": question,
            "why": why,
            "how": how,
            "answer": saved.get(key, ""),
            "evidence_state": (
                "evidence"
                if evidence_states[key].tier == VerificationItemEvidenceState.Tier.EVIDENCE_AVAILABLE
                else "manual"
            ),
            "evidence_label": evidence_states[key].evidence_summary or "Manual check required",
        }
        for key, question, why, how in checks
    ]


def _generate_workflow_response(incident):
    """Reuse Writer/playbook persistence and return a user-safe error, never a redirect."""
    denied = deny_ai_call(incident.organization, "writer")
    if denied:
        return denied
    ai_run = AIRun.objects.create(organization=incident.organization, ai_module="writer", input_type="IncidentGroup", input_id=str(incident.id), output_type="ResponsePlaybook", output_id="", status=AIRun.Status.STARTED)
    try:
        raw_result = run_playbook_generation(incident)
        playbook = create_playbooks_for_incidents([incident])[0]
        next_number = (playbook.steps.aggregate(Max("step_number"))["step_number__max"] or 0) + 1
        PlaybookStep.objects.bulk_create([PlaybookStep(playbook=playbook, step_number=next_number + offset, action=step["action"], urgency=incident_to_urgency(incident.severity), status=PlaybookStep.Status.PENDING, source=PlaybookStep.Source.AI_GENERATED) for offset, step in enumerate(raw_result["steps"])])
        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = raw_result["model"]
        ai_run.output_id = str(playbook.id)
        ai_run.save(update_fields=["status", "model_used", "output_id"])
        return ""
    except Exception as exc:
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
        return "Something prevented AegisFlow from preparing the response."



def _latest_workflow_guidance(incident, stage):
    # WorkflowStepGuidance.Meta.ordering = ["-generated_at"] -- "latest
    # wins" per (incident, stage), same overwrite pattern as
    # _latest_analyst_result_context.
    return incident.workflow_step_guidance.filter(stage=stage).first()


def _workflow_guidance_context(guidance):
    if not guidance:
        return None
    return {
        "next_step_text": guidance.next_step_text,
        "model": guidance.model_used,
        "generated_at": guidance.generated_at,
    }


def _build_workflow_step_question_thread(incident, stage):
    # Meta.ordering = ["asked_at"] -- oldest first, most recent last, same
    # shape as _build_qa_thread but scoped to one workflow stage.
    return [
        {
            "question": qa.question_text,
            "answer": qa.answer_text,
            "model": qa.model_used,
            "asked_at": qa.asked_at,
        }
        for qa in incident.workflow_step_questions.filter(stage=stage)
    ]


def _generate_workflow_guidance(incident, stage):
    """Call the Workflow Advisor for `stage`, persist the result, log the
    AIRun, and return a user-safe error string ("" on success) -- same
    shape as _generate_workflow_response.
    """
    denied = deny_ai_call(incident.organization, "workflow_advisor")
    if denied:
        return denied
    ai_run = AIRun.objects.create(
        organization=incident.organization,
        ai_module="workflow_advisor",
        input_type="IncidentGroup",
        input_id=str(incident.id),
        output_type="WorkflowStepGuidance",
        output_id="",
        status=AIRun.Status.STARTED,
    )
    try:
        raw_result = run_workflow_next_step(incident, stage)
    except RuntimeError as exc:
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
        return _friendly_analysis_error(exc)
    else:
        saved = WorkflowStepGuidance.objects.create(
            incident=incident,
            stage=stage,
            next_step_text=raw_result["next_step"],
            model_used=raw_result["model"],
        )
        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = saved.model_used
        ai_run.output_id = str(saved.id)
        ai_run.save(update_fields=["status", "model_used", "output_id"])
        return ""


def _regenerate_workflow_guidance(incident, stage):
    """Regenerate `stage`'s guidance and persist any error into
    workflow_state["guidance_errors"][stage] -- separate key from
    response_error so the two don't collide when both can be showing at
    once (e.g. respond's own response_error alongside verify's guidance
    error).
    """
    state = dict(incident.workflow_state or {})
    guidance_errors = dict(state.get("guidance_errors", {}))
    error = _generate_workflow_guidance(incident, stage)
    if error:
        guidance_errors[stage] = error
    else:
        guidance_errors.pop(stage, None)
    state["guidance_errors"] = guidance_errors
    incident.workflow_state = state
    incident.save(update_fields=["workflow_state"])


def incident_workflow(request, incident_id, stage="understand"):
    incident = _get_incident_for_detail(incident_id)
    if stage not in ("overview", *WORKFLOW_STAGES):
        return redirect("incidents:investigate", incident_id=incident.id)

    if request.method == "POST":
        action = (request.POST.get("workflow_action") or "continue").strip()
        if stage in GUIDANCE_STAGES and action == "regenerate_guidance":
            _regenerate_workflow_guidance(incident, stage)
            return redirect("incidents:workflow", incident_id=incident.id, stage=stage)
        if stage == "overview" and action == "continue":
            _auto_assign_investigator(request, incident)
            _set_workflow_status(request, incident, IncidentGroup.Status.INVESTIGATING, "Investigation opened; guided response started.")
            return redirect("incidents:workflow", incident_id=incident.id, stage="understand")
        if stage == "understand" and action == "continue":
            # The real-world "starting" trigger for most incidents --
            # "Start Investigation" links go straight to a GET on
            # understand (see incidents:investigate), skipping the
            # overview stage's own continue button above entirely, so
            # this is the first POST-based forward-progress action most
            # incidents ever see. Auto-assigning here too (not just on
            # the overview branch) means an unassigned incident gets
            # claimed the moment real work on it actually begins,
            # regardless of which entry point was used to get here.
            _auto_assign_investigator(request, incident)
            _set_workflow_status(request, incident, IncidentGroup.Status.INVESTIGATING, "Understand completed; verification started.")
            return redirect("incidents:workflow", incident_id=incident.id, stage="verify")
        if stage == "verify":
            items = _workflow_verification_items(incident)
            results = {item["key"]: (request.POST.get(f"verification_{item['key']}") or "").strip() for item in items}
            valid_results = {key: value for key, value in results.items() if value in {"confirmed", "not_confirmed", "not_sure"}}
            state = dict(incident.workflow_state or {})
            state["verification_results"] = valid_results
            incident.workflow_state = state
            incident.save(update_fields=["workflow_state"])
            # Regenerate verify's own guidance so it reflects the answers
            # just saved, not whatever was true before this submission.
            _regenerate_workflow_guidance(incident, "verify")
            if action == "save_and_exit":
                # Whatever was answered (even partially -- the form's
                # required attribute is skipped via formnovalidate for
                # this specific button) is already saved above. Exiting
                # must never lose it silently, unlike the old plain <a>
                # that sat inside this form and discarded unsubmitted
                # selections.
                return redirect(f"{reverse('incidents:index')}?tab=queue")
            if action == "continue" and len(valid_results) == len(items):
                context_now = _build_incident_detail_context(incident)
                if not context_now["recommended_actions"]["has_steps"]:
                    state = dict(incident.workflow_state or {})
                    state["response_error"] = _generate_workflow_response(incident)
                    incident.workflow_state = state
                    incident.save(update_fields=["workflow_state"])
                return redirect("incidents:workflow", incident_id=incident.id, stage="respond")
        if stage == "respond" and action == "retry":
            state = dict(incident.workflow_state or {})
            state["response_error"] = _generate_workflow_response(incident)
            incident.workflow_state = state
            incident.save(update_fields=["workflow_state"])
            # The response plan just changed -- regenerate respond's
            # guidance so it isn't talking about steps that no longer
            # exist (or don't yet reflect the newly generated ones).
            _regenerate_workflow_guidance(incident, "respond")
            return redirect("incidents:workflow", incident_id=incident.id, stage="respond")
        if stage == "respond" and action == "continue":
            return redirect("incidents:workflow", incident_id=incident.id, stage="resolve")
        if stage == "resolve":
            outcome = (request.POST.get("outcome") or "").strip()
            valid_outcomes = {"resolved", "partial", "happening", "unsure"}
            if outcome in valid_outcomes:
                # Persisted so later-stage AI context can actually read
                # what was decided here -- previously this value was used
                # only to pick a redirect target and then discarded,
                # leaving no record of why the loop continued.
                state = dict(incident.workflow_state or {})
                state["resolve_outcome"] = outcome
                incident.workflow_state = state
                incident.save(update_fields=["workflow_state"])
            if outcome == "resolved":
                _set_workflow_status(request, incident, IncidentGroup.Status.RESOLVED, "Response outcome confirmed as resolved.")
                return redirect("incidents:workflow", incident_id=incident.id, stage="close")
            if outcome in {"partial", "happening", "unsure"}:
                # The outcome just recorded is new information relevant
                # to what respond's guidance should say -- regenerate it,
                # same "real state-mutating POST handler" trigger as
                # verify's and respond's own regeneration above.
                _regenerate_workflow_guidance(incident, "respond")
                return redirect("incidents:workflow", incident_id=incident.id, stage="respond")
        if stage == "close" and action == "close":
            _set_workflow_status(request, incident, IncidentGroup.Status.CLOSED, "Guided incident workflow completed.")
            return redirect("incidents:workflow", incident_id=incident.id, stage="close")

    return _render_workflow_stage(request, incident, stage)


def incident_workflow_ask(request, incident_id, stage):
    """"How do I do this" -- a question+answer scoped to the current
    stage's recommended step, not the whole incident. Unlike
    incident_ask (which always renders detail.html regardless of who
    called it), this always renders workflow.html back at the same
    stage the question was asked from -- the guided workflow is never
    silently exited to answer a question.
    """
    incident = _get_incident_for_detail(incident_id)
    if stage not in GUIDANCE_STAGES:
        return redirect("incidents:investigate", incident_id=incident.id)

    if request.method != "POST":
        return redirect("incidents:workflow", incident_id=incident.id, stage=stage)

    question_text = (request.POST.get("question") or "").strip()
    if not question_text:
        return redirect("incidents:workflow", incident_id=incident.id, stage=stage)

    denied = deny_ai_call(incident.organization, "workflow_advisor_qa")
    if denied:
        return _render_workflow_stage(request, incident, stage, workflow_qa_error=denied)

    guidance = _latest_workflow_guidance(incident, stage)
    step_text = (
        guidance.next_step_text
        if guidance
        else "No AI-recommended step has been generated yet for this stage."
    )

    ai_run = AIRun.objects.create(
        organization=incident.organization,
        ai_module="workflow_advisor_qa",
        input_type="IncidentGroup",
        input_id=str(incident.id),
        output_type="WorkflowStepQuestion",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    workflow_qa_error = None

    try:
        raw_result = run_workflow_step_question(incident, stage, step_text, question_text)
    except RuntimeError as exc:
        workflow_qa_error = _friendly_analysis_error(exc)
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
    else:
        saved_question = WorkflowStepQuestion.objects.create(
            incident=incident,
            stage=stage,
            question_text=raw_result["question"],
            answer_text=raw_result["answer"],
            model_used=raw_result["model"],
        )
        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = saved_question.model_used
        ai_run.output_id = str(saved_question.id)
        ai_run.save(update_fields=["status", "model_used", "output_id"])

    return _render_workflow_stage(request, incident, stage, workflow_qa_error=workflow_qa_error)


def _render_workflow_stage(request, incident, stage, *, workflow_qa_error=None, **detail_context_overrides):
    # Guidance is NEVER generated on a plain GET -- a synchronous Claude
    # call on page load meant a silent 15-60s freeze (and a raw 500 if it
    # timed out). The workflow.html template shows a "Generate AI guidance"
    # button when no guidance row exists yet; generation only happens from
    # an explicit POST (that button, or the verify/respond/resolve state-
    # mutating handlers above that regenerate it).

    # detail_context_overrides is how the six shared AI action views
    # (see _render_incident_action_result) forward their *_result/*_error
    # kwargs through when they land here instead of on detail.html --
    # empty for workflow.html's own POST handlers and incident_workflow_ask.
    context = _build_incident_detail_context(incident, **detail_context_overrides)
    stage_index = WORKFLOW_STAGES.index(stage) if stage in WORKFLOW_STAGES else 0
    action_items = context["recommended_actions"]["items"]
    required_complete = context["recommended_actions"]["all_done"]
    guidance = _latest_workflow_guidance(incident, stage) if stage in GUIDANCE_STAGES else None
    context.update({
        "page_title": f"{stage.title()} - {incident.title}",
        "workflow_stage": stage,
        "workflow_stage_index": stage_index,
        "workflow_stages": [
            {
                "key": key,
                "number": index + 1,
                "label": "Resolve" if key == "resolve" else key.title(),
                "state": "completed" if index < stage_index or incident.status == IncidentGroup.Status.CLOSED else ("current" if index == stage_index else "pending"),
                "url": reverse("incidents:workflow", args=[incident.id, key]),
                "clickable": index <= stage_index or incident.status in {IncidentGroup.Status.RESOLVED, IncidentGroup.Status.CLOSED},
            }
            for index, key in enumerate(WORKFLOW_STAGES)
        ],
        "queue_url": f"{reverse('incidents:index')}?tab=queue",
        "workflow_post_url": reverse("incidents:workflow", args=[incident.id, stage]),
        "workflow_ask_url": reverse("incidents:workflow_ask", args=[incident.id, stage]) if stage in GUIDANCE_STAGES else "",
        "respond_ready": required_complete,
        "is_closed": incident.status == IncidentGroup.Status.CLOSED,
        "verification_items": _workflow_verification_items(incident),
        "verification_choices": (("confirmed", "Confirmed"), ("not_confirmed", "Not Confirmed"), ("not_sure", "Not Sure")),
        "verification_complete": all(item["answer"] for item in _workflow_verification_items(incident)),
        "response_error": (incident.workflow_state or {}).get("response_error", ""),
        "guidance_stages": list(GUIDANCE_STAGES),
        "workflow_guidance": _workflow_guidance_context(guidance),
        "workflow_guidance_error": (incident.workflow_state or {}).get("guidance_errors", {}).get(stage, ""),
        "workflow_step_question_thread": (
            _build_workflow_step_question_thread(incident, stage) if stage in GUIDANCE_STAGES else []
        ),
        "workflow_qa_error": workflow_qa_error,
    })
    return render(request, "incidents/workflow.html", context)


def _set_workflow_status(request, incident, new_status, details):
    old_status = incident.status
    if old_status == new_status:
        return
    incident.status = new_status
    incident.save(update_fields=["status"])
    AuditLog.objects.create(
        organization=incident.organization,
        user=request.user if request.user.is_authenticated else None,
        action="incident_workflow_advanced",
        target_type="IncidentGroup",
        target_id=str(incident.id),
        details=f"{details} Status changed from {old_status} to {new_status}.",
    )
