from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import redirect, render

from apps.ai_core.rate_limit import deny_ai_call
from apps.audit.models import AIRun

from .forms import CriticalSystemForm, OrganizationProfileForm
from .models import AppAssistantQuestion, CriticalSystem
from .services.current_organization import get_current_organization


def index(request):
    if request.method == "POST":
        form = CriticalSystemForm(request.POST)
        if form.is_valid():
            organization = get_current_organization()
            CriticalSystem.objects.create(
                organization=organization,
                system_name=form.cleaned_data["system_name"],
                system_type=form.cleaned_data["system_type"],
                criticality=form.cleaned_data["criticality"],
                owner_name=form.cleaned_data["owner_name"],
                recovery_priority=form.cleaned_data["recovery_priority"],
                backup_required=form.cleaned_data["backup_required"],
            )
            messages.success(
                request,
                f'Added critical system "{form.cleaned_data["system_name"]}".',
            )
            return redirect("organizations:index")
    else:
        form = CriticalSystemForm()

    critical_systems = CriticalSystem.objects.select_related("organization").order_by("-updated_at")

    return render(
        request,
        "organizations/index.html",
        {
            "page_title": "Critical Systems",
            "page_description": (
                "Manage organizations, critical systems, owners, and recovery priorities used "
                "by AegisFlow AI during analysis."
            ),
            "active_nav": "settings",
            "form": form,
            "critical_systems": critical_systems,
        },
    )


def profile(request):
    organization = get_current_organization()

    if request.method == "POST":
        form = OrganizationProfileForm(request.POST)
        if form.is_valid():
            organization.name = form.cleaned_data["name"]
            organization.organization_type = form.cleaned_data["organization_type"]
            organization.country = form.cleaned_data["country"]
            organization.sector = form.cleaned_data["sector"]
            organization.risk_profile = form.cleaned_data["risk_profile"]
            organization.save(
                update_fields=["name", "organization_type", "country", "sector", "risk_profile"]
            )
            messages.success(request, "Organization profile updated.")
            return redirect("organizations:profile")
    else:
        form = OrganizationProfileForm(
            initial={
                "name": organization.name,
                "organization_type": organization.organization_type,
                "country": organization.country,
                "sector": organization.sector,
                "risk_profile": organization.risk_profile,
            }
        )

    return render(
        request,
        "organizations/profile.html",
        {
            "page_title": "Organization",
            "page_description": "View and edit your organization's own profile details.",
            "active_nav": "organization",
            "form": form,
            "organization": organization,
            "team_members": _team_members(request),
        },
    )


def _team_members(request):
    """Real roster entries only. AegisFlow AI has no organization-membership
    model, so the only user we can honestly show is the authenticated
    account making the request (if any). Anything else -- roles, an
    "Active" status, extra people -- would be invented, so the template
    falls back to an honest empty state instead.
    """
    user = getattr(request, "user", None)
    if not user or not user.is_authenticated:
        return []

    name = user.get_full_name().strip() or user.get_username()
    initials = "".join(part[0] for part in name.split()[:2]).upper() or name[:2].upper()
    return [
        {
            "name": name,
            "email": user.email or "",
            "initials": initials,
        }
    ]


def my_profile(request):
    if request.method == "POST":
        request.session["profile_department"] = (request.POST.get("department") or "Security Operations").strip()[:100]
        request.session["profile_responsibilities"] = (request.POST.get("responsibilities") or "Monitoring, incident analysis, and response").strip()[:300]
        messages.success(request, "Profile information updated.")
        return redirect("organizations:my_profile")
    return render(request, "organizations/my_profile.html", {
        "page_title": "My Profile",
        "page_description": "Manage your personal information and experience preferences.",
        "active_nav": "profile",
        "organization": get_current_organization(),
        "profile_department": request.session.get("profile_department", "Security Operations"),
        "profile_responsibilities": request.session.get("profile_responsibilities", "Monitoring, incident analysis, and response"),
    })


def about_aegisflow(request):
    return render(request, "organizations/about.html", {
        "page_title": "About AegisFlow AI",
        "page_description": "Learn more about AegisFlow AI and how it helps protect your business.",
        "active_nav": "about",
    })


def get_agent(request):
    return render(request, "organizations/get_agent.html", {
        "page_title": "Get AegisFlow Agent",
        "page_description": "Download and install the AegisFlow Agent to protect devices that do not already have security monitoring.",
        "active_nav": "agent",
    })


def app_assistant(request):
    organization = get_current_organization()
    return render(request, "organizations/app_assistant.html", {
        "page_title": "AegisFlow Assistant",
        "page_description": (
            "Ask general questions about how to use AegisFlow AI -- "
            "navigation, the guided workflow, and terminology."
        ),
        "active_nav": "app_assistant",
        "app_assistant_thread": _app_assistant_thread(organization),
    })


def _app_assistant_thread(organization):
    if not organization:
        return []
    return [
        {
            "question": question.question_text,
            "answer": question.answer_text,
            "model": question.model_used,
            "asked_at": question.asked_at,
        }
        for question in organization.app_assistant_questions.all()
    ]


def ask_app_assistant(request):
    wants_json = request.headers.get("x-requested-with") == "XMLHttpRequest"
    if request.method != "POST":
        return redirect("organizations:app_assistant")

    question_text = (request.POST.get("question") or "").strip()
    if not question_text:
        if wants_json:
            return JsonResponse({"error": "Enter a question for Aegis."}, status=400)
        return redirect("organizations:app_assistant")

    organization = get_current_organization()
    if not organization:
        if wants_json:
            return JsonResponse({"error": "No organization is available."}, status=400)
        return redirect("organizations:app_assistant")

    # Local import: app_assistant.py imports apps.organizations.models
    # (Organization) at module load time, so importing it here at
    # module load time in this file would be circular.
    from apps.ai_core.modules.app_assistant import run_app_assistant_question

    denied = deny_ai_call(organization, "app_assistant_qa")
    if denied:
        if wants_json:
            return JsonResponse({"error": denied}, status=429)
        messages.error(request, denied)
        return redirect("organizations:app_assistant")

    ai_run = AIRun.objects.create(
        organization=organization,
        ai_module="app_assistant_qa",
        input_type="Organization",
        input_id=str(organization.id),
        output_type="AppAssistantQuestion",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    try:
        raw_result = run_app_assistant_question(organization, question_text)
    except RuntimeError as exc:
        messages.error(request, _friendly_app_assistant_error(exc))
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
        if wants_json:
            return JsonResponse({"error": _friendly_app_assistant_error(exc)}, status=503)
    else:
        saved_question = AppAssistantQuestion.objects.create(
            organization=organization,
            question_text=raw_result["question"],
            answer_text=raw_result["answer"],
            model_used=raw_result["model"],
        )
        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = saved_question.model_used
        ai_run.output_id = str(saved_question.id)
        ai_run.prompt_version = raw_result["corpus_version"]
        ai_run.save(update_fields=["status", "model_used", "output_id", "prompt_version"])
        if wants_json:
            return JsonResponse({"question": saved_question.question_text, "answer": saved_question.answer_text, "model": saved_question.model_used, "asked_at": saved_question.asked_at.isoformat()})

    return redirect("organizations:app_assistant")


def _friendly_app_assistant_error(exc: RuntimeError) -> str:
    if "ANTHROPIC_API_KEY is not set" in str(exc):
        return "AegisFlow Assistant isn't available yet — API key not configured."
    return "AegisFlow Assistant failed. Please try again in a moment."


def set_experience_mode(request):
    """Persist a presentation preference without changing identity or permissions."""
    if request.method != "POST":
        return JsonResponse({"error": "POST required."}, status=405)
    mode = (request.POST.get("mode") or "").strip().lower()
    if mode not in {"business", "soc"}:
        return JsonResponse({"error": "Unsupported experience mode."}, status=400)
    request.session["experience_mode"] = mode
    return JsonResponse({"mode": mode})
