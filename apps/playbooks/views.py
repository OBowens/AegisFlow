import re
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from django.contrib import messages
from django.db.models import Prefetch, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from apps.ai_core.modules.writer import run_playbook_generation
from apps.ai_core.rate_limit import deny_ai_call
from apps.audit.models import AIRun, AuditLog
from apps.incidents.models import IncidentEvidence, IncidentGroup
from apps.organizations.services.current_organization import get_current_organization
from apps.reports.models import GeneratedReport

from .forms import SOPChecklistForm
from .models import ChecklistItemState, PlaybookStep, ResponsePlaybook, SOPChecklist
from .services.approval_gate import requires_human_approval
from .services.text_parsing import checklist_item_key as _checklist_item_key
from .services.text_parsing import normalize_sentence as _normalize_sentence
from .services.text_parsing import parse_action_text as _parse_action_text
from .services.text_parsing import unique_items as _unique_items

CARIBBEAN_TIMEZONE = ZoneInfo("America/St_Vincent")
PRIORITY_TO_SEVERITY = {
    ResponsePlaybook.Priority.LOW: "low",
    ResponsePlaybook.Priority.MEDIUM: "medium",
    ResponsePlaybook.Priority.HIGH: "high",
    ResponsePlaybook.Priority.URGENT: "critical",
}
STEP_STATUS_META = {
    PlaybookStep.Status.COMPLETED: {
        "status_key": "completed",
        "status_label": "Completed",
        "checklist_label": "Done",
        "checked": True,
    },
    PlaybookStep.Status.IN_PROGRESS: {
        "status_key": "progress",
        "status_label": "In Progress",
        "checklist_label": "In Progress",
        "checked": False,
    },
    PlaybookStep.Status.PENDING: {
        "status_key": "pending",
        "status_label": "Pending",
        "checklist_label": "To Do",
        "checked": False,
    },
    PlaybookStep.Status.SKIPPED: {
        "status_key": "skipped",
        "status_label": "Skipped",
        "checklist_label": "Skipped",
        "checked": False,
    },
}
ESCALATION_TIERS = ("Primary", "Secondary", "Tertiary")
OPEN_INCIDENT_STATUSES = {IncidentGroup.Status.OPEN, IncidentGroup.Status.INVESTIGATING}


def index(request):
    incidents = list(
        IncidentGroup.objects.select_related("organization")
        .order_by("-updated_at", "-created_at")
    )
    playbook_queryset = (
        ResponsePlaybook.objects.select_related(
            "organization",
            "incident",
            "risk",
            "risk__gap",
            "readiness_finding",
        )
        .prefetch_related(
            Prefetch(
                "steps",
                queryset=PlaybookStep.objects.order_by("step_number", "id"),
            )
        )
        .order_by("-updated_at", "-created_at")
    )
    playbooks = list(playbook_queryset)
    selected_incident_id = request.GET.get("incident", "").strip()
    selected_playbook_id = request.GET.get("playbook", "").strip()
    custom_prompt = request.GET.get("custom_prompt", "").strip()
    show_all_incidents = request.GET.get("show_all") == "1"

    playbook = _select_playbook(playbooks, selected_incident_id, selected_playbook_id)
    incident = playbook.incident if playbook else _select_incident(incidents, selected_incident_id)
    report = _resolve_upload_summary_report(playbook, incident)
    organization = get_current_organization()
    step_cards = _build_step_cards(playbook)
    checklist = _resolve_checklist(playbook)
    checklist_items = _build_checklist_items(step_cards, checklist, incident)
    escalation_contacts = _build_escalation_contacts(
        step_cards=step_cards,
        playbook=playbook,
        organization=organization,
    )
    approval_items = _build_approval_items(step_cards, playbook)
    immediate_actions = _build_action_window(
        explicit_text=playbook.immediate_steps if playbook else "",
        fallback_steps=step_cards[:3],
    )
    next_actions = _build_action_window(
        explicit_text=playbook.next_steps if playbook else "",
        fallback_steps=step_cards[3:6],
    )
    severity_key = _resolve_severity_key(playbook, incident)
    page_updated_at = _resolve_page_updated_at(playbook=playbook, report=report, incident=incident)
    source_options = _build_source_options(incidents, selected_incident_id, show_all_incidents)
    open_incident_count = len(
        [incident_row for incident_row in incidents if incident_row.status in OPEN_INCIDENT_STATUSES]
    )
    current_playbook_url = _build_playbook_url(incident.id if incident else None)

    return render(
        request,
        "playbooks/index.html",
        {
            "page_title": "Response Playbook",
            "page_description": "Recommended actions, SOPs, and escalation guidance",
            "active_nav": "playbooks",
            "organization_name": organization.name if organization else "Demo Organization",
            "organization_plan": "Small Business Plan",
            "dashboard_updated_at": _format_dashboard_datetime(page_updated_at),
            "has_playbook": playbook is not None,
            "playbook": playbook,
            "playbook_summary": _resolve_playbook_summary(playbook, incident),
            "incident_title": _resolve_incident_title(playbook, incident),
            "severity_key": severity_key,
            "severity_label": _resolve_severity_label(playbook, incident),
            "affected_system": _resolve_affected_system(playbook, incident),
            "confidence": _resolve_confidence(playbook, incident),
            "steps": step_cards,
            "checklist_title": checklist.name if checklist else "Incident response checklist",
            "checklist_items": checklist_items,
            "escalation_contacts": escalation_contacts,
            "approval_items": approval_items,
            "immediate_actions": immediate_actions,
            "next_actions": next_actions,
            "upload_summary_report_url": _resolve_upload_summary_report_url(report),
            # In-page section anchors -- these scroll to a section, they are
            # not actions (no checklist export or owner-assignment feature
            # exists on this page), so the toolbar labels them honestly.
            "checklist_section_url": "#linked-checklist",
            "escalation_section_url": "#escalation-path",
            "playbook_refresh_url": current_playbook_url,
            # Real AI generation lives in the incidents app; the toolbar
            # button posts there (and comes back here via return_to) only
            # when there is an incident to generate against.
            "incident_generate_playbook_url": (
                reverse("incidents:generate_playbook", args=[incident.id]) if incident else ""
            ),
            "incidents_url": f"{reverse('incidents:index')}?tab=queue",
            # The Escalation Path footer used to claim "View Escalation
            # Policy" and link to the incident queue. There is no escalation
            # policy page; the SOP Library is where approved response
            # procedures actually live.
            "sop_library_url": reverse("playbooks:sops"),
            "incident_detail_url": _resolve_incident_url(incident),
            "upload_logs_url": reverse("log_intake:upload"),
            "checklist_count": len(checklist_items),
            "playbook_status_label": playbook.get_status_display() if playbook else "",
            "source_options": source_options,
            "selected_incident_id": selected_incident_id,
            "show_all_incidents": show_all_incidents,
            "open_incident_count": open_incident_count,
            "total_incident_count": len(incidents),
            "show_all_incidents_url": _build_incident_scope_url(
                selected_incident_id, selected_playbook_id, show_all=True
            ),
            "scoped_incidents_url": _build_incident_scope_url(
                selected_incident_id, selected_playbook_id, show_all=False
            ),
            "step_status_options": PlaybookStep.Status.choices,
            "custom_prompt": custom_prompt,
            "playbook_source_label": "Incident-based" if incident else "Custom request",
            "detected_label": _resolve_detected_label(incident),
            "generate_custom_playbook_url": reverse("playbooks:generate_custom"),
        },
    )


def playbook_generate_custom(request):
    if request.method != "POST":
        return redirect("playbooks:index")

    scenario_text = (request.POST.get("custom_prompt") or "").strip()
    if not scenario_text:
        messages.error(request, "Describe the scenario you want a playbook for.")
        return redirect("playbooks:index")

    organization = get_current_organization()

    denied = deny_ai_call(organization, "writer")
    if denied:
        messages.error(request, denied)
        return redirect("playbooks:index")

    ai_run = AIRun.objects.create(
        organization=organization,
        ai_module="writer",
        input_type="CustomScenario",
        input_id="",
        output_type="ResponsePlaybook",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    try:
        raw_result = run_playbook_generation(scenario_text=scenario_text, organization=organization)
    except RuntimeError as exc:
        messages.error(request, _friendly_playbook_error(exc))
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
        return redirect("playbooks:index")

    playbook = ResponsePlaybook.objects.create(
        organization=organization,
        incident=None,
        title=f"Custom Playbook: {scenario_text[:80]}",
        summary=scenario_text,
        status=ResponsePlaybook.Status.ACTIVE,
    )
    PlaybookStep.objects.bulk_create(
        [
            PlaybookStep(
                playbook=playbook,
                step_number=step_number,
                action=step["action"],
                urgency=PlaybookStep.Urgency.MEDIUM,
                status=PlaybookStep.Status.PENDING,
                source=PlaybookStep.Source.AI_GENERATED,
            )
            for step_number, step in enumerate(raw_result["steps"], start=1)
        ]
    )

    ai_run.status = AIRun.Status.SUCCESS
    ai_run.model_used = raw_result["model"]
    ai_run.output_id = str(playbook.id)
    ai_run.save(update_fields=["status", "model_used", "output_id"])

    messages.success(request, "Custom playbook generated.")
    return redirect(f"{reverse('playbooks:index')}?playbook={playbook.id}")


def _friendly_playbook_error(exc: RuntimeError) -> str:
    if "ANTHROPIC_API_KEY is not set" in str(exc):
        return "AI playbook generation isn't available yet — API key not configured."
    return "AI playbook generation failed. Please try again in a moment."


def sop_checklists(request):
    if request.method == "POST":
        form = SOPChecklistForm(request.POST, request.FILES)
        if form.is_valid():
            sop = SOPChecklist.objects.create(
                name=form.cleaned_data["name"],
                incident_type=form.cleaned_data["incident_type"],
                checklist_items=form.cleaned_data["checklist_items"],
                version=form.cleaned_data["version"],
                is_active=False,
            )
            organization = get_current_organization()
            AuditLog.objects.create(
                organization=organization,
                user=request.user if request.user.is_authenticated else None,
                action="sop_draft_created",
                target_type="SOPChecklist",
                target_id=str(sop.id),
                details=f"Draft SOP {sop.name} created.",
            )
            messages.success(request, f"Created draft SOP {sop.name}.")
            return redirect(reverse("playbooks:sops") + f"?sop={sop.id}")
    else:
        form = SOPChecklistForm()

    all_checklists = SOPChecklist.objects.order_by("-updated_at")
    query = request.GET.get("q", "").strip()
    status_filter = request.GET.get("status", "all").strip().lower()
    checklists = all_checklists
    if query:
        checklists = checklists.filter(
            Q(name__icontains=query)
            | Q(incident_type__icontains=query)
            | Q(checklist_items__icontains=query)
        )
    if status_filter == "active":
        checklists = checklists.filter(is_active=True)
    elif status_filter == "draft":
        checklists = checklists.filter(is_active=False)

    selected_id = request.GET.get("sop")
    selected_sop = checklists.filter(id=selected_id).first() if selected_id else checklists.first()
    organization = get_current_organization()
    active_sops = all_checklists.filter(is_active=True).count()
    draft_sops = all_checklists.filter(is_active=False).count()
    active_guides = ResponsePlaybook.objects.filter(status=ResponsePlaybook.Status.ACTIVE).count()
    draft_guides = ResponsePlaybook.objects.filter(status=ResponsePlaybook.Status.DRAFT).count()

    return render(
        request,
        "playbooks/sop_checklists.html",
        {
            "page_title": "SOP Library",
            "page_description": "Your approved security procedures, response guides, and checklists.",
            "active_nav": "sop_checklists",
            "organization_name": organization.name if organization else "Demo Organization",
            "organization_plan": "Small Business Plan",
            "dashboard_updated_at": _format_dashboard_datetime(timezone.now()),
            "form": form,
            "checklists": checklists,
            "selected_sop": selected_sop,
            "selected_sop_steps": _parse_action_text(selected_sop.checklist_items) if selected_sop else [],
            "sop_query": query,
            "sop_status_filter": status_filter,
            "sop_metrics": [
                {"label": "Approved SOPs", "value": active_sops, "icon": "shield-check", "tone": "green"},
                {"label": "Response Guides", "value": active_guides, "icon": "playbook", "tone": "blue"},
                {"label": "Checklists", "value": all_checklists.count(), "icon": "checklist", "tone": "purple"},
                {"label": "Drafts", "value": draft_sops + draft_guides, "icon": "edit", "tone": "amber"},
            ],
        },
    )


def playbook_toggle_checklist_item(request, incident_id, checklist_id):
    incident = get_object_or_404(IncidentGroup, id=incident_id)
    checklist = get_object_or_404(SOPChecklist, id=checklist_id)
    next_url = _safe_playbook_url(request.POST.get("next") if request.method == "POST" else None)

    if request.method != "POST":
        return redirect(next_url)

    item_key = (request.POST.get("item_key") or "").strip()
    if not item_key:
        return redirect(next_url)

    state, _created = ChecklistItemState.objects.get_or_create(
        incident=incident,
        checklist=checklist,
        item_key=item_key,
    )
    state.is_completed = not state.is_completed
    state.completed_at = timezone.now() if state.is_completed else None
    state.save(update_fields=["is_completed", "completed_at", "updated_at"])

    return redirect(next_url)


def playbook_update_step_status(request, step_id):
    step = get_object_or_404(
        PlaybookStep.objects.select_related("playbook", "playbook__organization"),
        id=step_id,
    )
    next_url = _safe_playbook_url(request.POST.get("next") if request.method == "POST" else None)

    if request.method != "POST":
        return redirect(next_url)

    new_status = request.POST.get("status")
    valid_statuses = {value for value, _label in PlaybookStep.Status.choices}
    if new_status not in valid_statuses:
        return redirect(next_url)

    old_status = step.status
    if new_status != old_status:
        step.status = new_status
        step.save(update_fields=["status"])

        # Same AuditLog shape as apps/incidents/views.py's incident_update_status:
        # organization, user, action, target_type, target_id, details.
        AuditLog.objects.create(
            organization=step.playbook.organization,
            user=request.user if request.user.is_authenticated else None,
            action="playbook_step_status_changed",
            target_type="PlaybookStep",
            target_id=str(step.id),
            details=(
                f"Status changed from {old_status} to {new_status} on step "
                f'"{step.action[:80]}" ({step.playbook.title}).'
            ),
        )

    return redirect(next_url)


def _safe_playbook_url(next_url):
    # Both playbooks:update_step_status and playbooks:toggle_checklist_item
    # are posted to from the Playbooks page itself AND from Incident Detail's
    # merged Recommended Actions panel, so a safe `next` can land back on
    # either app -- never anywhere else (open-redirect guard).
    safe_prefixes = (reverse("playbooks:index"), reverse("incidents:index"))
    if next_url and any(next_url.startswith(prefix) for prefix in safe_prefixes):
        return next_url
    return reverse("playbooks:index")


def _select_playbook(playbooks, selected_incident_id, selected_playbook_id=""):
    if selected_playbook_id:
        for playbook in playbooks:
            if str(playbook.id) == selected_playbook_id:
                return playbook

    if selected_incident_id:
        for playbook in playbooks:
            if str(playbook.incident_id or "") == selected_incident_id:
                return playbook

    for playbook in playbooks:
        if playbook.status == ResponsePlaybook.Status.ACTIVE:
            return playbook

    return playbooks[0] if playbooks else None


def _select_incident(incidents, selected_incident_id):
    if selected_incident_id:
        for incident in incidents:
            if str(incident.id) == selected_incident_id:
                return incident
    return incidents[0] if incidents else None


def _build_source_options(incidents, selected_incident_id, show_all_incidents):
    if show_all_incidents:
        scoped_incidents = incidents
    else:
        scoped_incidents = [
            incident for incident in incidents if incident.status in OPEN_INCIDENT_STATUSES
        ]
        # Keep an out-of-scope selection visible instead of having it vanish
        # from the list out from under the user (e.g. ?incident=<id> deep link
        # to a resolved/closed incident, or the incident was just closed).
        if selected_incident_id and not any(
            str(incident.id) == selected_incident_id for incident in scoped_incidents
        ):
            explicit_match = next(
                (incident for incident in incidents if str(incident.id) == selected_incident_id),
                None,
            )
            if explicit_match:
                scoped_incidents = [explicit_match] + scoped_incidents

    options = []
    for incident in scoped_incidents:
        options.append(
            {
                "id": incident.id,
                "label": incident.title,
                "severity_label": incident.get_severity_display().upper(),
                "status_label": incident.get_status_display(),
                "selected": str(incident.id) == selected_incident_id,
                "search_text": f"{incident.title} {incident.get_severity_display()} "
                f"{incident.get_status_display()}".lower(),
            }
        )

    if options and not any(option["selected"] for option in options):
        options[0]["selected"] = True

    return options


def _build_incident_scope_url(selected_incident_id, selected_playbook_id, show_all):
    params = {}
    if selected_incident_id:
        params["incident"] = selected_incident_id
    if selected_playbook_id:
        params["playbook"] = selected_playbook_id
    if show_all:
        params["show_all"] = "1"

    query = urlencode(params)
    base = reverse("playbooks:index")
    return f"{base}?{query}" if query else base


def _resolve_upload_summary_report(playbook, incident):
    reports = GeneratedReport.objects.select_related("organization", "incident")

    if playbook and playbook.incident_id:
        incident_reports = reports.filter(incident=playbook.incident)
        return (
            incident_reports.filter(report_type=GeneratedReport.ReportType.UPLOAD_SUMMARY)
            .order_by("-created_at")
            .first()
            or incident_reports.order_by("-created_at").first()
        )

    if incident:
        incident_reports = reports.filter(incident=incident)
        report = (
            incident_reports.filter(report_type=GeneratedReport.ReportType.UPLOAD_SUMMARY)
            .order_by("-created_at")
            .first()
            or incident_reports.order_by("-created_at").first()
        )
        if report:
            return report

    return (
        reports.filter(report_type=GeneratedReport.ReportType.UPLOAD_SUMMARY)
        .order_by("-created_at")
        .first()
        or reports.order_by("-created_at").first()
    )




def _resolve_page_updated_at(*, playbook, report, incident):
    candidates = [
        playbook.updated_at if playbook else None,
        incident.updated_at if incident else None,
        report.created_at if report else None,
    ]
    valid_candidates = [candidate for candidate in candidates if candidate is not None]
    return max(valid_candidates) if valid_candidates else timezone.now()


def _resolve_playbook_summary(playbook, incident):
    if playbook and playbook.summary:
        return playbook.summary.strip()
    if incident and incident.summary:
        return incident.summary.strip()
    return "Track containment, evidence handling, and ownership from one coordinated response plan."


def _resolve_incident_title(playbook, incident):
    if incident and incident.title:
        return incident.title
    if playbook and playbook.title:
        return playbook.title
    return "No linked incident yet"


def _resolve_severity_key(playbook, incident):
    if incident and incident.severity:
        return incident.severity
    if playbook and playbook.priority:
        return PRIORITY_TO_SEVERITY.get(playbook.priority, "medium")
    return "medium"


def _resolve_severity_label(playbook, incident):
    if incident and incident.severity:
        return incident.get_severity_display().upper()
    if playbook and playbook.priority:
        return playbook.get_priority_display().upper()
    return "MEDIUM"


def _resolve_affected_system(playbook, incident):
    if incident and incident.affected_systems:
        primary = _split_systems(incident.affected_systems)
        if primary:
            return primary[0]

    if playbook and playbook.risk and playbook.risk.gap and playbook.risk.gap.affected_system:
        return playbook.risk.gap.affected_system

    if playbook and playbook.readiness_finding and playbook.readiness_finding.incident:
        systems = playbook.readiness_finding.incident.affected_systems
        primary = _split_systems(systems)
        if primary:
            return primary[0]

    return "Under review"


def _resolve_detected_label(incident):
    if incident is None:
        return "Awaiting incident linkage"

    detected_at = incident.first_seen or incident.created_at
    localized = timezone.localtime(detected_at, CARIBBEAN_TIMEZONE)
    return (
        f"{localized.strftime('%b')} {localized.day}, {localized.year} "
        f"{localized.strftime('%I:%M %p').lstrip('0')}"
    )


def _resolve_confidence(playbook, incident):
    evidence_count = 0
    risk_level = None

    if incident:
        evidence_count = IncidentEvidence.objects.filter(incident=incident).count()

    if playbook and playbook.risk:
        risk_level = playbook.risk.risk_level

    if risk_level in (IncidentGroup.Severity.CRITICAL, IncidentGroup.Severity.HIGH) or evidence_count >= 4:
        return {"key": "high", "label": "HIGH"}
    if incident and incident.severity in (IncidentGroup.Severity.CRITICAL, IncidentGroup.Severity.HIGH):
        return {"key": "medium", "label": "MEDIUM"}
    if evidence_count >= 2:
        return {"key": "medium", "label": "MEDIUM"}
    return {"key": "low", "label": "LOW"}


def _build_step_cards(playbook):
    if not playbook:
        return []

    raw_steps = list(playbook.steps.all())
    cards = []

    if raw_steps:
        for step in raw_steps:
            status_meta = STEP_STATUS_META[step.status]
            cards.append(
                {
                    "number": step.step_number,
                    "title": _normalize_sentence(step.action),
                    "description": _describe_step_action(step.action),
                    "status_key": status_meta["status_key"],
                    "status_label": status_meta["status_label"],
                    "checklist_label": status_meta["checklist_label"],
                    "checked": status_meta["checked"],
                    "icon": _resolve_step_icon(step.action),
                    "owner": step.owner.strip(),
                    "requires_approval": requires_human_approval(step.action),
                    "is_ai_generated": step.source == PlaybookStep.Source.AI_GENERATED,
                    "step_id": step.id,
                    "status_value": step.status,
                    "status_update_url": reverse("playbooks:update_step_status", args=[step.id]),
                }
            )
        return cards

    fallback_steps = _parse_action_text(playbook.immediate_steps)
    fallback_steps.extend(_parse_action_text(playbook.next_steps))
    fallback_steps.extend(_parse_action_text(playbook.escalation_steps))

    for index, action in enumerate(_unique_items(fallback_steps)[:8], start=1):
        cards.append(
            {
                "number": index,
                "title": action,
                "description": _describe_step_action(action),
                "status_key": "pending",
                "status_label": "Pending",
                "checklist_label": "To Do",
                "checked": False,
                "icon": _resolve_step_icon(action),
                "owner": "",
                "requires_approval": requires_human_approval(action),
                "is_ai_generated": False,
                # No underlying PlaybookStep row exists yet for these
                # text-parsed fallback cards (playbook wasn't generated with
                # real step rows), so there's nothing to persist a status
                # change against -- no update control is rendered for these.
                "step_id": None,
                "status_value": PlaybookStep.Status.PENDING,
                "status_update_url": "",
            }
        )

    return cards


def _describe_step_action(action):
    lowered = (action or "").lower()

    descriptions = (
        (("review", "failed login"), "Examine authentication logs for repeated failed login attempts to identify source IPs and patterns."),
        (("confirm", "login"), "Check for any successful sign-ins from the targeted account, unusual locations, or unfamiliar devices."),
        (("verify", "mfa"), "Confirm whether MFA is enabled for the account and review recent MFA enrollment or bypass activity."),
        (("lock",), "Lock the compromised or at-risk account to prevent any additional unauthorized access while containment is underway."),
        (("block", "ip"), "Block identified malicious IPs at the firewall, VPN, email gateway, or perimeter controls to reduce repeat attempts."),
        (("document",), "Record findings, actions taken, timestamps, and affected systems so leadership and auditors can review the response clearly."),
        (("notify",), "Inform the account owner and relevant stakeholders about the incident so approvals and communications stay coordinated."),
        (("escalate",), "Escalate to the security lead and incident response chain if signs of compromise or widening scope are confirmed."),
    )

    for keywords, description in descriptions:
        if all(keyword in lowered for keyword in keywords):
            return description

    if "reset" in lowered:
        return "Reset compromised credentials, expire active sessions, and confirm the recovery action follows the approved workflow."

    if "contain" in lowered or "quarantine" in lowered:
        return "Contain the activity quickly so the incident remains isolated while the team validates scope and business impact."

    return "Complete this action as part of the coordinated response workflow and document any approvals or system changes."


def _resolve_step_icon(text):
    lowered = (text or "").lower()

    if any(keyword in lowered for keyword in ("review", "investigate", "examine", "analyze")):
        return "analysis"
    if any(keyword in lowered for keyword in ("confirm", "identify", "owner", "account")):
        return "user-outline"
    if any(keyword in lowered for keyword in ("mfa", "verify", "validate", "secure")):
        return "shield-check"
    if any(keyword in lowered for keyword in ("lock", "block", "disable", "contain")):
        return "critical"
    if any(keyword in lowered for keyword in ("notify", "inform", "communicat", "escalat")):
        return "chat"
    if any(keyword in lowered for keyword in ("document", "record", "log", "report")):
        return "logs"
    return "playbook"


def _resolve_checklist(playbook):
    if not playbook or not playbook.incident_id:
        return None

    incident_type = (playbook.incident.incident_type or "").strip()
    if not incident_type:
        return None

    exact_match = (
        SOPChecklist.objects.filter(is_active=True, incident_type__iexact=incident_type)
        .order_by("-updated_at")
        .first()
    )
    if exact_match:
        return exact_match

    tokens = [token for token in re.split(r"[^a-z0-9]+", incident_type.lower()) if token]
    if not tokens:
        return None

    token_query = Q()
    for token in tokens:
        token_query |= Q(incident_type__icontains=token) | Q(name__icontains=token)

    return (
        SOPChecklist.objects.filter(is_active=True)
        .filter(token_query)
        .order_by("-updated_at")
        .first()
    )


def _build_checklist_items(step_cards, checklist, incident):
    source_items = _parse_action_text(checklist.checklist_items if checklist else "")

    if not source_items:
        source_items = [card["title"] for card in step_cards]

    unique_source_items = _unique_items(source_items)[:7]

    # Real, per-incident completion only exists once there's an actual
    # SOPChecklist matched to an actual incident -- see ChecklistItemState.
    # The no-checklist fallback list below (mirroring step-card status) has
    # no independent state of its own to persist; it's read-only and tracks
    # whatever the linked PlaybookStep already says.
    states_by_key = {}
    if checklist and incident:
        states_by_key = {
            state.item_key: state
            for state in ChecklistItemState.objects.filter(incident=incident, checklist=checklist)
        }

    items = []
    for index, text in enumerate(unique_source_items):
        if checklist and incident:
            item_key = _checklist_item_key(text)
            state = states_by_key.get(item_key)
            checked = bool(state and state.is_completed)
            items.append(
                {
                    "text": text,
                    "status_key": "completed" if checked else "pending",
                    "status_label": "Done" if checked else "To Do",
                    "checked": checked,
                    "item_key": item_key,
                    "interactive": True,
                    "toggle_url": reverse(
                        "playbooks:toggle_checklist_item", args=[incident.id, checklist.id]
                    ),
                }
            )
            continue

        step = step_cards[index] if index < len(step_cards) else None
        items.append(
            {
                "text": text,
                "status_key": step["status_key"] if step else "pending",
                "status_label": step["checklist_label"] if step else "To Do",
                "checked": step["checked"] if step else False,
                "item_key": "",
                "interactive": False,
                "toggle_url": "",
            }
        )

    return items


def _build_approval_items(step_cards, playbook):
    items = []

    for step in step_cards:
        if step["status_key"] == "completed":
            continue
        if step["requires_approval"]:
            items.append({"text": step["title"], "status_label": "Approval Needed"})

    if len(items) < 3 and playbook:
        fallback_actions = _parse_action_text(playbook.immediate_steps) + _parse_action_text(playbook.next_steps)
        for action in fallback_actions:
            if not requires_human_approval(action):
                continue
            if any(existing["text"].lower() == action.lower() for existing in items):
                continue
            items.append({"text": action, "status_label": "Approval Needed"})
            if len(items) >= 3:
                break

    if not items:
        for step in step_cards[:3]:
            items.append({"text": step["title"], "status_label": "Approval Needed"})

    return items[:3]


def _build_escalation_contacts(*, step_cards, playbook, organization):
    owners = []
    for card in step_cards:
        owners.extend(_split_owners(card["owner"]))

    owners = _unique_items(owners)
    contacts = []

    for index, owner in enumerate(owners[:3]):
        display_name, detail = _normalize_owner(owner, organization)
        contacts.append(
            {
                "title": display_name,
                "detail": detail,
                "tier": ESCALATION_TIERS[index],
                "initials": _build_initials(display_name),
                "tone": ("blue", "purple", "green")[index],
            }
        )

    if contacts:
        return contacts

    if playbook and playbook.escalation_steps:
        escalation_notes = _parse_action_text(playbook.escalation_steps)
        for index, note in enumerate(escalation_notes[:3]):
            contacts.append(
                {
                    "title": f"Escalation Step {index + 1}",
                    "detail": note,
                    "tier": ESCALATION_TIERS[index],
                    "initials": str(index + 1),
                    "tone": ("blue", "purple", "green")[index],
                }
            )

    return contacts


def _build_action_window(*, explicit_text, fallback_steps):
    explicit_items = _parse_action_text(explicit_text)
    if explicit_items:
        return _unique_items(explicit_items)[:3]

    return [step["title"] for step in fallback_steps[:3]]


def _resolve_upload_summary_report_url(report):
    if report:
        return reverse("reports:detail", args=[report.id])
    return reverse("reports:index")


def _resolve_incident_url(incident):
    if incident:
        return reverse("incidents:detail", args=[incident.id])
    return f"{reverse('incidents:index')}?tab=queue"


def _build_playbook_url(incident_id):
    if incident_id:
        return f"{reverse('playbooks:index')}?incident={incident_id}"
    return reverse("playbooks:index")


def _split_systems(text):
    return [segment.strip() for segment in re.split(r"[,/\n|]+", text or "") if segment.strip()]


def _split_owners(owner_text):
    if not owner_text:
        return []
    return [
        chunk.strip()
        for chunk in re.split(r"[;,/|]+", owner_text)
        if chunk.strip()
    ]


def _normalize_owner(owner_text, organization):
    cleaned = owner_text.strip()
    tag_match = re.match(r"^(?P<name>[^<]+?)\s*<(?P<email>[^>]+)>$", cleaned)
    if tag_match:
        return tag_match.group("name").strip(), tag_match.group("email").strip()

    if " - " in cleaned and "@" in cleaned:
        name, email = cleaned.split(" - ", 1)
        return name.strip(), email.strip()

    if "@" in cleaned:
        handle = cleaned.split("@", 1)[0].replace(".", " ").replace("_", " ").strip()
        display_name = handle.title() if handle else cleaned
        return display_name, cleaned

    organization_name = organization.name if organization else "Assigned owner"
    return cleaned, organization_name


def _build_initials(text):
    words = [word for word in re.split(r"\s+", text.strip()) if word]
    if not words:
        return "AO"
    initials = "".join(word[0] for word in words[:2]).upper()
    return initials or "AO"


def _format_dashboard_datetime(value):
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)
    return (
        f"{localized.strftime('%b')} {localized.day}, {localized.year} "
        f"{localized.strftime('%I:%M %p').lstrip('0')} AST"
    )
