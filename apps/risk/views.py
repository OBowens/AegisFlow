from collections import defaultdict
from zoneinfo import ZoneInfo

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from apps.ai_core.modules.risk_advisor import run_risk_narration, run_risk_question
from apps.ai_core.rate_limit import deny_ai_call
from apps.audit.models import AIRun
from apps.log_intake.models import UploadedLogFile
from apps.organizations.services.current_organization import get_current_organization

from .models import GapFinding, RiskNarration, RiskQuestion

CARIBBEAN_TIMEZONE = ZoneInfo("America/St_Vincent")


def index(request):
    uploaded_file_id = request.GET.get("uploaded_file", "").strip()
    priority_filter = request.GET.get("priority", "").strip()
    source_filter = request.GET.get("source", "").strip()

    gaps = GapFinding.objects.select_related("organization", "incident").order_by("-created_at")

    scoped_uploaded_file = None
    if uploaded_file_id:
        scoped_uploaded_file = get_object_or_404(UploadedLogFile, pk=uploaded_file_id)
        gaps = gaps.filter(
            incident__evidence_items__alert__uploaded_file=scoped_uploaded_file
        ).distinct()

    priority_values = [value for value in priority_filter.split(",") if value]
    if priority_values:
        gaps = gaps.filter(priority__in=priority_values)
    if source_filter:
        gaps = gaps.filter(source=source_filter)

    organization = (
        scoped_uploaded_file.organization
        if scoped_uploaded_file
        else get_current_organization()
    )

    return render(
        request,
        "risk/index.html",
        {
            "page_title": (
                f"Detected Gaps — {scoped_uploaded_file.file_name}"
                if scoped_uploaded_file
                else "Detected Gaps"
            ),
            "page_description": (
                "Control and evidence gaps identified from grouped incidents, "
                "filterable by priority and source."
            ),
            "active_nav": "risk",
            "organization_name": organization.name if organization else "Demo Organization",
            "organization_plan": "Small Business Plan",
            "dashboard_updated_at": _format_dashboard_datetime(timezone.now()),
            "scoped_uploaded_file": scoped_uploaded_file,
            "gap_cards": _build_gap_list_cards(gaps),
            "gap_count": gaps.count(),
            "priority_options": GapFinding.Priority.choices,
            "source_options": GapFinding.Source.choices,
            "selected_priority": priority_filter,
            "selected_source": source_filter,
        },
    )


def explain_risk(request, gap_id):
    gap = get_object_or_404(
        GapFinding.objects.select_related("organization", "incident"), pk=gap_id
    )

    if request.method != "POST":
        return redirect("risk:index")

    denied = deny_ai_call(gap.organization, "risk_advisor")
    if denied:
        messages.error(request, denied)
        return redirect(f"{reverse('risk:index')}#gap-{gap.id}")

    ai_run = AIRun.objects.create(
        organization=gap.organization,
        ai_module="risk_advisor",
        input_type="GapFinding",
        input_id=str(gap.id),
        output_type="RiskNarration",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    try:
        raw_result = run_risk_narration(gap)
    except RuntimeError as exc:
        messages.error(request, _friendly_risk_error(exc))
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
    else:
        saved_narration = RiskNarration.objects.create(
            gap=gap,
            narration_text=raw_result["narration"],
            model_used=raw_result["model"],
        )
        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = saved_narration.model_used
        ai_run.output_id = str(saved_narration.id)
        ai_run.save(update_fields=["status", "model_used", "output_id"])

    return redirect(f"{reverse('risk:index')}#gap-{gap.id}")


def ask_risk_question(request, gap_id):
    gap = get_object_or_404(
        GapFinding.objects.select_related("organization", "incident"), pk=gap_id
    )

    if request.method != "POST":
        return redirect("risk:index")

    question_text = (request.POST.get("question") or "").strip()
    if not question_text:
        return redirect(f"{reverse('risk:index')}#gap-{gap.id}")

    denied = deny_ai_call(gap.organization, "risk_advisor_qa")
    if denied:
        messages.error(request, denied)
        return redirect(f"{reverse('risk:index')}#gap-{gap.id}")

    ai_run = AIRun.objects.create(
        organization=gap.organization,
        ai_module="risk_advisor_qa",
        input_type="GapFinding",
        input_id=str(gap.id),
        output_type="RiskQuestion",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    try:
        raw_result = run_risk_question(gap, question_text)
    except RuntimeError as exc:
        messages.error(request, _friendly_risk_error(exc))
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
    else:
        saved_question = RiskQuestion.objects.create(
            gap=gap,
            question_text=raw_result["question"],
            answer_text=raw_result["answer"],
            model_used=raw_result["model"],
        )
        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = saved_question.model_used
        ai_run.output_id = str(saved_question.id)
        ai_run.save(update_fields=["status", "model_used", "output_id"])

    return redirect(f"{reverse('risk:index')}#gap-{gap.id}")


def _friendly_risk_error(exc: RuntimeError) -> str:
    if "ANTHROPIC_API_KEY is not set" in str(exc):
        return "AI risk narration isn't available yet — API key not configured."
    return "AI risk narration failed. Please try again in a moment."


def _build_gap_list_cards(gaps):
    gap_list = list(gaps)
    gap_ids = [gap.id for gap in gap_list]

    latest_narration_by_gap_id = {}
    for narration in (
        RiskNarration.objects.filter(gap_id__in=gap_ids).order_by("gap_id", "-generated_at")
    ):
        latest_narration_by_gap_id.setdefault(narration.gap_id, narration)

    questions_by_gap_id = defaultdict(list)
    for question in (
        RiskQuestion.objects.filter(gap_id__in=gap_ids).order_by("gap_id", "asked_at")
    ):
        questions_by_gap_id[question.gap_id].append(
            {
                "question": question.question_text,
                "answer": question.answer_text,
                "model": question.model_used,
                "asked_at": question.asked_at,
            }
        )

    cards = []
    for gap in gap_list:
        narration = latest_narration_by_gap_id.get(gap.id)
        cards.append(
            {
                "id": gap.id,
                "name": gap.gap_name,
                "description": gap.description,
                "priority": gap.priority,
                "priority_label": gap.get_priority_display(),
                "source_label": gap.get_source_display(),
                "affected_system": gap.affected_system,
                "incident_title": gap.incident.title if gap.incident else "",
                "incident_url": (
                    reverse("incidents:detail", args=[gap.incident_id]) if gap.incident_id else ""
                ),
                "created_display": _format_dashboard_datetime(gap.created_at),
                "explain_url": reverse("risk:explain", args=[gap.id]),
                "narration": narration.narration_text if narration else "",
                "narration_model": narration.model_used if narration else "",
                "narration_generated_display": (
                    _format_dashboard_datetime(narration.generated_at) if narration else ""
                ),
                "ask_url": reverse("risk:ask", args=[gap.id]),
                "questions": questions_by_gap_id.get(gap.id, []),
            }
        )
    return cards


def _format_dashboard_datetime(value):
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)
    return (
        f"{localized.strftime('%b')} {localized.day}, {localized.year} "
        f"{localized.strftime('%I:%M %p').lstrip('0')} AST"
    )
