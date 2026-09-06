from __future__ import annotations

from datetime import timedelta
from zoneinfo import ZoneInfo

from django.contrib import messages
from django.db.models import Max
from django.db.utils import OperationalError, ProgrammingError
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone

from apps.ai_core.modules.prioritizer import run_priority_briefing
from apps.ai_core.rate_limit import deny_ai_call
from apps.ai_core.services.priority_context import rank_open_incident_groups
from apps.audit.models import AIRun
from apps.organizations.services.current_organization import get_current_organization

from .models import PriorityBriefing

try:
    from apps.incidents.models import IncidentGroup
except ImportError:
    IncidentGroup = None

try:
    from apps.log_intake.models import UploadedLogFile
except ImportError:
    UploadedLogFile = None

try:
    from apps.playbooks.models import ResponsePlaybook
except ImportError:
    ResponsePlaybook = None

try:
    from apps.reports.models import GeneratedReport
except ImportError:
    GeneratedReport = None

try:
    from apps.resilience.models import DisasterReadinessFinding, ReadinessPlan
except ImportError:
    DisasterReadinessFinding = None
    ReadinessPlan = None

try:
    from apps.resilience.services.scoring import compute_readiness_score
except ImportError:
    compute_readiness_score = None

try:
    from apps.risk.models import GapFinding, RiskAssessment
except ImportError:
    GapFinding = None
    RiskAssessment = None


CARIBBEAN_TIMEZONE = ZoneInfo("America/St_Vincent")
TREND_WINDOW_DAYS = 7


def dashboard(request):
    organization = get_current_organization()
    dashboard_stats = _build_dashboard_stats()
    recent_incidents = _build_recent_incidents()
    priority_incidents = _build_priority_incidents(organization)
    priority_incident_count = _safe_priority_incident_count()
    risk_distribution = _build_risk_distribution()
    readiness_summary = _build_readiness_summary()
    last_updated = _resolve_last_updated()

    return render(
        request,
        "core/business_dashboard.html" if request.session.get("experience_mode") == "business" else "core/dashboard.html",
        {
            "page_title": "Dashboard",
            "page_description": (
                "AI-powered cybersecurity and disaster readiness overview for your organization."
            ),
            "active_nav": "dashboard",
            "dashboard_stats": dashboard_stats,
            "recent_incidents": recent_incidents,
            "priority_incidents": priority_incidents,
            "priority_incident_count": priority_incident_count,
            "risk_distribution": risk_distribution,
            "readiness_summary": readiness_summary,
            "dashboard_updated_at": _format_dashboard_datetime(last_updated),
            "organization_name": organization.name if organization else "Demo Organization",
            "organization_plan": "Small Business Plan",
            "explain_priorities_url": reverse("core:explain_priorities"),
            **_build_priority_briefing_context(organization),
        },
    )


def index(request):
    return dashboard(request)


def explain_priorities(request):
    if request.method != "POST":
        return redirect("core:index")

    organization = get_current_organization()
    if not organization:
        return redirect("core:index")

    denied = deny_ai_call(organization, "prioritizer")
    if denied:
        messages.error(request, denied)
        return redirect("core:index")

    ai_run = AIRun.objects.create(
        organization=organization,
        ai_module="prioritizer",
        input_type="Organization",
        input_id=str(organization.id),
        output_type="PriorityBriefing",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    try:
        raw_result = run_priority_briefing(organization)
    except RuntimeError as exc:
        messages.error(request, _friendly_priority_error(exc))
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
    else:
        saved_briefing = PriorityBriefing.objects.create(
            organization=organization,
            briefing_text=raw_result["briefing"],
            model_used=raw_result["model"],
        )
        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = saved_briefing.model_used
        ai_run.output_id = str(saved_briefing.id)
        ai_run.save(update_fields=["status", "model_used", "output_id"])

    return redirect("core:index")


def _friendly_priority_error(exc: RuntimeError) -> str:
    if "ANTHROPIC_API_KEY is not set" in str(exc):
        return "AI prioritization isn't available yet — API key not configured."
    return "AI prioritization failed. Please try again in a moment."


def _build_priority_briefing_context(organization) -> dict[str, object]:
    if not organization:
        return {"priority_briefing": None}

    latest = (
        PriorityBriefing.objects.filter(organization=organization).first()
    )  # Meta.ordering = ["-generated_at"]
    if not latest:
        return {"priority_briefing": None}

    return {
        "priority_briefing": {
            "text": latest.briefing_text,
            "model": latest.model_used,
            "generated_display": _format_dashboard_datetime(latest.generated_at),
        }
    }


def _build_dashboard_stats() -> list[dict[str, object]]:
    open_incident_filters = {}
    critical_risk_filters = {}
    high_risk_filters = {}

    if IncidentGroup is not None:
        open_incident_filters = {"status": IncidentGroup.Status.OPEN}

    if RiskAssessment is not None:
        critical_risk_filters = {"risk_level": RiskAssessment.Level.CRITICAL}
        high_risk_filters = {"risk_level": RiskAssessment.Level.HIGH}

    stats_config = [
        {
            "title": "Total Uploaded Logs",
            "icon": "logs",
            "accent": "blue",
            "value": _safe_count(UploadedLogFile),
            "trend": _build_trend(UploadedLogFile, "uploaded_at"),
        },
        {
            "title": "Open Incidents",
            "icon": "incident",
            "accent": "orange",
            "value": _safe_count(IncidentGroup, **open_incident_filters),
            "trend": _build_trend(IncidentGroup, "created_at", **open_incident_filters),
        },
        {
            "title": "Critical Risks",
            "icon": "critical",
            "accent": "red",
            "value": _safe_count(RiskAssessment, **critical_risk_filters),
            "trend": _build_trend(RiskAssessment, "created_at", **critical_risk_filters),
        },
        {
            "title": "High Risks",
            "icon": "warning",
            "accent": "amber",
            "value": _safe_count(RiskAssessment, **high_risk_filters),
            "trend": _build_trend(RiskAssessment, "created_at", **high_risk_filters),
        },
        {
            "title": "Detected Gaps",
            "icon": "gaps",
            "accent": "purple",
            "value": _safe_count(GapFinding),
            "trend": _build_trend(GapFinding, "created_at"),
        },
        {
            "title": "Disaster Readiness Issues",
            "icon": "readiness",
            "accent": "teal",
            "value": _safe_count(DisasterReadinessFinding),
            "trend": _build_trend(DisasterReadinessFinding, "created_at"),
        },
        {
            "title": "Reports Generated",
            "icon": "reports",
            "accent": "cyan",
            "value": _safe_count(GeneratedReport),
            "trend": _build_trend(GeneratedReport, "created_at"),
        },
    ]

    return [
        {
            **stat,
            "value_display": f"{stat['value']:,}",
        }
        for stat in stats_config
    ]


def _build_recent_incidents() -> list[dict[str, object]]:
    incidents = _safe_recent_incidents()
    now = timezone.localtime(timezone.now(), CARIBBEAN_TIMEZONE)

    return [
        {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "severity_label": incident.get_severity_display(),
            "incident_type": incident.incident_type or "General incident",
            "affected_systems": incident.affected_systems or "Systems not specified",
            "created_display": _format_incident_timestamp(incident.created_at, now),
        }
        for incident in incidents
    ]


_PRIORITY_SEVERITIES = ("critical", "high")


def _build_priority_incidents(organization) -> list[dict[str, object]]:
    """The "Priority incidents" section -- the lead incident of each
    top-ranked open-incident cluster, ranked exactly the way the AI
    prioritizer ranks them (apps.ai_core.services.priority_context), so
    the hero call-to-action, the incident cards, and the "What Should I
    Fix First?" briefing never disagree about what comes first.

    Scoped to clusters that contain critical/high work -- since severity
    is the primary sort, those clusters are a strict prefix of the full
    ranking, so the ordering still matches the briefing exactly while the
    grid keeps its "urgent work" framing and honest empty state.
    """
    if IncidentGroup is None or organization is None:
        return []

    try:
        clusters = [
            cluster
            for cluster in rank_open_incident_groups(organization)
            if cluster.max_severity in _PRIORITY_SEVERITIES
        ]
    except (OperationalError, ProgrammingError):
        return []

    now = timezone.localtime(timezone.now(), CARIBBEAN_TIMEZONE)
    return [
        {
            "id": cluster.lead_incident.id,
            "title": cluster.lead_incident.title,
            "severity": cluster.lead_incident.severity,
            "severity_label": cluster.lead_incident.get_severity_display(),
            "incident_type": cluster.lead_incident.incident_type or "General incident",
            "affected_systems": cluster.lead_incident.affected_systems or "Systems not specified",
            "created_display": _format_incident_timestamp(cluster.lead_incident.created_at, now),
            "related_count": len(cluster.incidents),
        }
        for cluster in clusters[:5]
    ]


def _safe_priority_incident_count() -> int:
    if IncidentGroup is None:
        return 0

    return _safe_count(IncidentGroup, severity__in=_PRIORITY_SEVERITIES)


def _build_risk_distribution() -> dict[str, object]:
    if RiskAssessment is None:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    else:
        counts = {
            "critical": _safe_count(RiskAssessment, risk_level=RiskAssessment.Level.CRITICAL),
            "high": _safe_count(RiskAssessment, risk_level=RiskAssessment.Level.HIGH),
            "medium": _safe_count(RiskAssessment, risk_level=RiskAssessment.Level.MEDIUM),
            "low": _safe_count(RiskAssessment, risk_level=RiskAssessment.Level.LOW),
        }

    segments = [
        {"key": "critical", "label": "Critical", "count": counts["critical"], "color": "#ef4444"},
        {"key": "high", "label": "High", "count": counts["high"], "color": "#f59e0b"},
        {"key": "medium", "label": "Medium", "count": counts["medium"], "color": "#fbbf24"},
        {"key": "low", "label": "Low", "count": counts["low"], "color": "#2563eb"},
    ]
    total = sum(segment["count"] for segment in segments)

    for segment in segments:
        percentage = round((segment["count"] / total) * 100) if total else 0
        segment["percentage"] = percentage

    return {
        "total": total,
        "total_display": f"{total:,}",
        "segments": segments,
        "gradient": _build_conic_gradient(segments, total),
    }


def _build_readiness_summary() -> dict[str, object]:
    critical_count = 0
    high_count = 0
    medium_count = 0

    if DisasterReadinessFinding is not None:
        critical_count = _safe_count(
            DisasterReadinessFinding,
            priority=DisasterReadinessFinding.Priority.CRITICAL,
        )
        high_count = _safe_count(
            DisasterReadinessFinding,
            priority=DisasterReadinessFinding.Priority.HIGH,
        )
        medium_count = _safe_count(
            DisasterReadinessFinding,
            priority=DisasterReadinessFinding.Priority.MEDIUM,
        )

    open_issues = _safe_count(DisasterReadinessFinding)
    in_progress = _count_active_playbooks()
    controls_ok = _safe_count(ReadinessPlan)
    score = (
        compute_readiness_score(
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
        )
        if compute_readiness_score is not None
        else 100
    )

    return {
        "score": score,
        "score_display": f"{score}%",
        "open_issues": open_issues,
        "in_progress": in_progress,
        "controls_ok": controls_ok,
        "headline": _readiness_headline(score, open_issues),
    }


def _safe_count(model, **filters) -> int:
    if model is None:
        return 0

    try:
        queryset = model.objects.filter(**filters) if filters else model.objects.all()
        return queryset.count()
    except (OperationalError, ProgrammingError):
        return 0


def _safe_period_counts(model, date_field: str, **filters) -> tuple[int, int]:
    if model is None:
        return 0, 0

    current_end = timezone.now()
    current_start = current_end - timedelta(days=TREND_WINDOW_DAYS)
    previous_start = current_start - timedelta(days=TREND_WINDOW_DAYS)
    current_lookup = {f"{date_field}__gte": current_start, f"{date_field}__lt": current_end}
    previous_lookup = {f"{date_field}__gte": previous_start, f"{date_field}__lt": current_start}

    try:
        queryset = model.objects.filter(**filters) if filters else model.objects.all()
        current_count = queryset.filter(**current_lookup).count()
        previous_count = queryset.filter(**previous_lookup).count()
        return current_count, previous_count
    except (OperationalError, ProgrammingError):
        return 0, 0


def _build_trend(model, date_field: str, **filters) -> dict[str, object]:
    current_count, previous_count = _safe_period_counts(model, date_field, **filters)
    delta = current_count - previous_count

    if delta > 0:
        return {"tone": "up", "value": delta, "label": "vs previous 7 days"}
    if delta < 0:
        return {"tone": "down", "value": abs(delta), "label": "vs previous 7 days"}
    return {"tone": "flat", "value": 0, "label": "No change in the last 7 days"}


def _safe_recent_incidents():
    if IncidentGroup is None:
        return []

    try:
        return list(
            IncidentGroup.objects.select_related("organization")
            .order_by("-created_at")[:5]
        )
    except (OperationalError, ProgrammingError):
        return []


def _safe_max(model, field_name: str):
    if model is None:
        return None

    try:
        return model.objects.aggregate(latest=Max(field_name))["latest"]
    except (OperationalError, ProgrammingError):
        return None


def _resolve_last_updated():
    last_updated_options = [
        _safe_max(UploadedLogFile, "uploaded_at"),
        _safe_max(IncidentGroup, "updated_at"),
        _safe_max(RiskAssessment, "created_at"),
        _safe_max(DisasterReadinessFinding, "created_at"),
        _safe_max(GeneratedReport, "created_at"),
        _safe_max(ReadinessPlan, "updated_at"),
        _safe_max(ResponsePlaybook, "updated_at"),
    ]
    existing_values = [value for value in last_updated_options if value is not None]

    if not existing_values:
        return timezone.now()

    return max(existing_values)


def _count_active_playbooks() -> int:
    if ResponsePlaybook is None:
        return 0

    return _safe_count(
        ResponsePlaybook,
        status__in=[
            ResponsePlaybook.Status.DRAFT,
            ResponsePlaybook.Status.ACTIVE,
        ],
    )


def _build_conic_gradient(segments: list[dict[str, object]], total: int) -> str:
    if total <= 0:
        return "conic-gradient(#d7e2f2 0deg 360deg)"

    non_zero_segments = [segment for segment in segments if segment["count"]]
    degrees_so_far = 0.0
    gradient_parts = []

    for index, segment in enumerate(non_zero_segments):
        count = segment["count"]
        sweep = (count / total) * 360
        next_stop = 360.0 if index == len(non_zero_segments) - 1 else degrees_so_far + sweep
        gradient_parts.append(
            f"{segment['color']} {degrees_so_far:.2f}deg {next_stop:.2f}deg"
        )
        degrees_so_far = next_stop

    return "conic-gradient(" + ", ".join(gradient_parts) + ")"


def _format_dashboard_datetime(value) -> str:
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)
    return (
        f"{localized.strftime('%b')} {localized.day}, {localized.year} "
        f"{localized.strftime('%I:%M %p')} AST"
    )


def _format_incident_timestamp(value, current_time) -> str:
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)

    if localized.date() == current_time.date():
        return localized.strftime("%I:%M %p").lstrip("0")
    if localized.date() == (current_time - timedelta(days=1)).date():
        return "Yesterday"
    return f"{localized.strftime('%b')} {localized.day}"


def _readiness_headline(score: int, open_issues: int) -> str:
    if open_issues == 0:
        return "No open readiness issues are recorded right now. Keep reviewing continuity plans."
    if score >= 80:
        return "Your organization is in a strong position. Keep continuity actions current and rehearsed."
    if score >= 60:
        return "Your organization is moderately prepared. Address the open issues below to improve readiness."
    return "Preparedness needs attention. Review the highest-impact continuity gaps and action items first."
