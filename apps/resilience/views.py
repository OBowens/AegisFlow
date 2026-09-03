from collections import defaultdict
from zoneinfo import ZoneInfo

from django.contrib import messages
from django.db.models import Count
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone

from apps.ai_core.rate_limit import deny_ai_call
from apps.audit.models import AIRun
from apps.log_intake.models import UploadedLogFile
from apps.organizations.services.current_organization import get_current_organization
from apps.playbooks.models import ResponsePlaybook
from apps.reports.models import GeneratedReport

from .models import (
    DisasterReadinessFinding,
    ReadinessExplanation,
    ReadinessPlan,
    ReadinessQuestion,
    ReadinessScoreSnapshot,
)
from .services.contradictions import find_contradictions_for_organization
from .services.scoring import build_readiness_trend, compute_readiness_score

CARIBBEAN_TIMEZONE = ZoneInfo("America/St_Vincent")
PRIORITY_RANK = {
    DisasterReadinessFinding.Priority.LOW: 1,
    DisasterReadinessFinding.Priority.MEDIUM: 2,
    DisasterReadinessFinding.Priority.HIGH: 3,
    DisasterReadinessFinding.Priority.CRITICAL: 4,
}
DOMAIN_CONFIGS = [
    {
        "key": "backup",
        "title": "Backup & Recovery",
        "display_title": "Backups",
        "icon": "database",
        "keywords": ("backup", "restore", "recovery", "offsite", "snapshot", "replication"),
        "description": "Review backup recency, restore confidence, and alternate copy coverage.",
        "action": "Restore backup confidence by verifying recent backups and completing a recovery test.",
        "empty_items": [
            "No backup readiness findings are recorded yet.",
            "Review restore testing for critical systems.",
            "Confirm offsite or alternate backup coverage.",
        ],
    },
    {
        "key": "power",
        "title": "Monitoring",
        "display_title": "Monitoring",
        "icon": "analysis",
        "keywords": ("monitor", "alert", "logging", "log coverage", "detection", "sensor", "uptime", "health check"),
        "description": "Review verified monitoring, alert coverage, and detection findings.",
        "action": "Address the verified monitoring findings and confirm alerts cover critical systems.",
        "empty_items": [
            "No power continuity findings are recorded yet.",
            "Review UPS coverage for critical equipment.",
            "Confirm generator or alternate power procedures.",
        ],
    },
    {
        "key": "network",
        "title": "Access Control",
        "display_title": "Access Control",
        "icon": "lock",
        "keywords": ("access", "account", "identity", "mfa", "authentication", "login", "permission", "privileged", "admin"),
        "description": "Review verified account, authentication, and privileged-access findings.",
        "action": "Address the verified access-control findings and confirm privileged accounts are protected.",
        "empty_items": [
            "No network continuity findings are recorded yet.",
            "Review failover connectivity for critical services.",
            "Document alternate internet or hotspot procedures.",
        ],
    },
    {
        "key": "critical",
        "title": "Incident Response",
        "display_title": "Incident Response",
        "icon": "incident",
        "keywords": ("incident", "response", "playbook", "contain", "escalation", "investigation", "triage"),
        "description": "Review verified incident-response, escalation, and playbook findings.",
        "action": "Address the verified response findings and confirm escalation and playbook steps are current.",
        "empty_items": [
            "No critical-systems findings are recorded yet.",
            "Review system recovery order and owners.",
            "Confirm dependencies and manual fallbacks are documented.",
        ],
    },
    {
        "key": "communication",
        "title": "Disaster Recovery",
        "display_title": "Disaster Recovery",
        "icon": "upload",
        "keywords": ("disaster", "recovery", "continuity", "hurricane", "outage", "restore", "failover", "communication", "contact"),
        "description": "Review verified recovery, continuity, outage, and disaster-plan findings.",
        "action": "Address the verified disaster-recovery findings and confirm recovery procedures are current.",
        "empty_items": [
            "No communication-plan findings are recorded yet.",
            "Review emergency contact lists and owners.",
            "Verify alternate communication channels for outages.",
        ],
    },
]
EXAMPLE_QUESTIONS = [
    "What is my biggest readiness risk right now?",
    "Which verified gap should we address first?",
    "What still requires manual verification?",
]


def index(request):
    readiness_findings = list(
        DisasterReadinessFinding.objects.select_related("organization", "incident", "risk")
        .order_by("-created_at")
    )
    readiness_plans = list(
        ReadinessPlan.objects.select_related("organization").order_by("-updated_at")
    )
    latest_analyzed_upload = (
        UploadedLogFile.objects.select_related("organization")
        .annotate(parsed_alert_count=Count("parsed_alerts"))
        .filter(parsed_alert_count__gt=0)
        .order_by("-uploaded_at")
        .first()
    )
    latest_upload = (
        UploadedLogFile.objects.select_related("organization").order_by("-uploaded_at").first()
    )
    latest_report = (
        GeneratedReport.objects.select_related("organization", "incident")
        .order_by("-created_at")
        .first()
    )
    latest_playbook = (
        ResponsePlaybook.objects.select_related("organization", "incident")
        .order_by("-updated_at")
        .first()
    )
    organization = get_current_organization()
    domain_cards = _build_readiness_domain_cards(
        readiness_findings=readiness_findings,
        readiness_plans=readiness_plans,
    )
    readiness_overview = _build_readiness_overview(
        readiness_findings=readiness_findings,
        readiness_plans=readiness_plans,
        domain_cards=domain_cards,
    )
    # Record a real history point every time this page actually computes
    # the score -- this is the one deliberate "check readiness" moment,
    # not the sidebar badge or dashboard/Work Queue cards that also call
    # compute_readiness_score on nearly every page view elsewhere in the
    # app. No fabricated backfill: the trend is exactly as many real
    # points as this page has actually been computed for.
    if organization and request.GET.get("refresh") == "1":
        ReadinessScoreSnapshot.objects.create(
            organization=organization, score=readiness_overview["score"]
        )
    readiness_trend = build_readiness_trend(
        ReadinessScoreSnapshot.objects.filter(organization=organization).order_by("computed_at")
        if organization
        else []
    )
    latest_summary = _build_latest_readiness_summary(
        readiness_findings=readiness_findings,
        latest_analyzed_upload=latest_analyzed_upload,
    )
    recommendations = _build_prioritized_recommendations(domain_cards)
    contradictions = (
        find_contradictions_for_organization(organization) if organization else []
    )
    page_updated_at = _resolve_last_updated(
        readiness_findings=readiness_findings,
        readiness_plans=readiness_plans,
        latest_analyzed_upload=latest_analyzed_upload,
        latest_upload=latest_upload,
        latest_report=latest_report,
        latest_playbook=latest_playbook,
    )

    return render(
        request,
        "resilience/business_index.html" if request.session.get("experience_mode") == "business" else "resilience/index.html",
        {
            "page_title": "Disaster Readiness Advisor",
            "page_description": (
                "Assess cyber and operational preparedness for hurricanes, outages, and recovery events."
            ),
            "active_nav": "readiness",
            "organization_name": organization.name if organization else "Demo Organization",
            "organization_plan": "Small Business Plan",
            "dashboard_updated_at": _format_dashboard_datetime(page_updated_at),
            "assess_logs_url": _resolve_assessment_url(latest_analyzed_upload),
            "view_analysis_url": _resolve_analysis_url(latest_analyzed_upload),
            "latest_summary": latest_summary,
            "example_questions": EXAMPLE_QUESTIONS,
            "domain_cards": domain_cards,
            "readiness_overview": readiness_overview,
            "readiness_trend": readiness_trend,
            "advisor_recommendations": recommendations,
            "top_readiness_gaps": _build_top_readiness_gaps(readiness_findings),
            "readiness_contradictions": contradictions,
            "run_assessment_url": _resolve_assessment_url(latest_analyzed_upload),
            "readiness_plan_url": reverse("playbooks:index"),
            "explain_readiness_url": reverse("resilience:explain"),
            "readiness_explanation": _latest_readiness_explanation_context(organization),
            "ask_readiness_question_url": reverse("resilience:ask_question"),
            "readiness_qa_thread": _build_readiness_qa_thread(organization),
            "readiness_history_groups": _build_readiness_history_groups(organization),
        },
    )


def explain_readiness(request):
    if request.method != "POST":
        return redirect("resilience:index")

    organization = get_current_organization()
    if not organization:
        return redirect("resilience:index")

    # Local import to avoid a circular import: readiness_context.py (in
    # ai_core) imports this module's own domain-classification helpers
    # (_build_readiness_domain_cards / _build_readiness_overview) so the
    # AI's explanation can never drift from what the page displays.
    from apps.ai_core.modules.readiness_advisor import run_readiness_explanation

    denied = deny_ai_call(organization, "readiness_advisor")
    if denied:
        messages.error(request, denied)
        return redirect("resilience:index")

    ai_run = AIRun.objects.create(
        organization=organization,
        ai_module="readiness_advisor",
        input_type="Organization",
        input_id=str(organization.id),
        output_type="ReadinessExplanation",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    try:
        raw_result = run_readiness_explanation(organization)
    except RuntimeError as exc:
        messages.error(request, _friendly_readiness_error(exc))
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
    else:
        saved_explanation = ReadinessExplanation.objects.create(
            organization=organization,
            explanation_text=raw_result["explanation"],
            model_used=raw_result["model"],
        )
        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = saved_explanation.model_used
        ai_run.output_id = str(saved_explanation.id)
        ai_run.save(update_fields=["status", "model_used", "output_id"])

    return redirect("resilience:index")


def ask_readiness_question(request):
    if request.method != "POST":
        return redirect("resilience:index")

    question_text = (request.POST.get("question") or "").strip()
    if not question_text:
        return redirect("resilience:index")

    organization = get_current_organization()
    if not organization:
        return redirect("resilience:index")

    # Local import for the same reason explain_readiness's is local --
    # readiness_context.py (in ai_core) imports this module's own
    # domain-classification helpers, so importing at module load time
    # here would be circular.
    from apps.ai_core.modules.readiness_advisor import run_readiness_question

    denied = deny_ai_call(organization, "readiness_advisor_qa")
    if denied:
        messages.error(request, denied)
        return redirect("resilience:index")

    ai_run = AIRun.objects.create(
        organization=organization,
        ai_module="readiness_advisor_qa",
        input_type="Organization",
        input_id=str(organization.id),
        output_type="ReadinessQuestion",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    try:
        raw_result = run_readiness_question(organization, question_text)
    except RuntimeError as exc:
        messages.error(request, _friendly_readiness_error(exc))
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
    else:
        saved_question = ReadinessQuestion.objects.create(
            organization=organization,
            question_text=raw_result["question"],
            answer_text=raw_result["answer"],
            model_used=raw_result["model"],
        )
        ai_run.status = AIRun.Status.SUCCESS
        ai_run.model_used = saved_question.model_used
        ai_run.output_id = str(saved_question.id)
        ai_run.save(update_fields=["status", "model_used", "output_id"])

    return redirect("resilience:index")


def _friendly_readiness_error(exc: RuntimeError) -> str:
    if "ANTHROPIC_API_KEY is not set" in str(exc):
        return "AI readiness explanation isn't available yet — API key not configured."
    return "AI readiness explanation failed. Please try again in a moment."


def _latest_readiness_explanation_context(organization):
    if not organization:
        return None
    latest = (
        ReadinessExplanation.objects.filter(organization=organization).first()
    )  # Meta.ordering = ["-generated_at"]
    if not latest:
        return None
    return {
        "explanation": latest.explanation_text,
        "model": latest.model_used,
        "generated_at": latest.generated_at,
    }


def _build_readiness_qa_thread(organization):
    if not organization:
        return []
    # Meta.ordering = ["asked_at"] -- oldest first, most recent last.
    return [
        {
            "question": qa.question_text,
            "answer": qa.answer_text,
            "model": qa.model_used,
            "asked_at": qa.asked_at,
        }
        for qa in organization.readiness_questions.all()
    ]



def _build_readiness_history_groups(organization):
    if not organization:
        return []
    today = timezone.localdate()
    grouped = {"Today": [], "Yesterday": [], "Earlier": []}
    for qa in organization.readiness_questions.order_by("asked_at"):
        local_time = timezone.localtime(qa.asked_at, CARIBBEAN_TIMEZONE)
        days_ago = (today - local_time.date()).days
        label = "Today" if days_ago == 0 else "Yesterday" if days_ago == 1 else "Earlier"
        grouped[label].append({
            "id": qa.id,
            "question": qa.question_text,
            "answer": qa.answer_text,
            "asked_at": qa.asked_at,
            "time_display": local_time.strftime("%I:%M %p").lstrip("0"),
        })
    return [{"label": label, "items": grouped[label]} for label in ("Today", "Yesterday", "Earlier") if grouped[label]]


def _build_readiness_domain_cards(*, readiness_findings, readiness_plans):
    plan_lookup = defaultdict(list)
    for plan in readiness_plans:
        text = _combined_plan_text(plan)
        for config in DOMAIN_CONFIGS:
            if _matches_keywords(text, config["keywords"]):
                plan_lookup[config["key"]].append(plan)

    cards = []
    for config in DOMAIN_CONFIGS:
        matched_findings = [
            finding
            for finding in readiness_findings
            if _matches_keywords(_combined_finding_text(finding), config["keywords"])
        ]
        matched_plans = plan_lookup[config["key"]]
        status_key = _resolve_domain_status(matched_findings, matched_plans)
        items = _build_domain_items(
            matched_findings=matched_findings,
            matched_plans=matched_plans,
            empty_items=config["empty_items"],
        )
        description = _resolve_domain_description(
            matched_findings=matched_findings,
            matched_plans=matched_plans,
            fallback=config["description"],
        )
        cards.append(
            {
                "key": config["key"],
                "title": config["title"],
                "display_title": config.get("display_title", config["title"]),
                "icon": config["icon"],
                "status_key": status_key,
                "status_label": _domain_status_label(status_key),
                "description": description,
                "items": items,
                "finding_count": len(matched_findings),
                "critical_gap_count": sum(1 for finding in matched_findings if finding.priority == DisasterReadinessFinding.Priority.CRITICAL),
                "domain_score": compute_readiness_score(
                    critical_count=sum(1 for finding in matched_findings if finding.priority == DisasterReadinessFinding.Priority.CRITICAL),
                    high_count=sum(1 for finding in matched_findings if finding.priority == DisasterReadinessFinding.Priority.HIGH),
                    medium_count=sum(1 for finding in matched_findings if finding.priority == DisasterReadinessFinding.Priority.MEDIUM),
                ) if (matched_findings or matched_plans) else None,
                "has_evidence": bool(matched_findings),
                "action": config["action"],
                "anchor": f"#readiness-{config['key']}",
            }
        )

    return cards


def _build_readiness_overview(*, readiness_findings, readiness_plans, domain_cards):
    critical_count = sum(
        1
        for finding in readiness_findings
        if finding.priority == DisasterReadinessFinding.Priority.CRITICAL
    )
    high_count = sum(
        1
        for finding in readiness_findings
        if finding.priority == DisasterReadinessFinding.Priority.HIGH
    )
    medium_count = sum(
        1
        for finding in readiness_findings
        if finding.priority == DisasterReadinessFinding.Priority.MEDIUM
    )
    score = compute_readiness_score(
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
    )
    status_counts = {
        "good": sum(1 for card in domain_cards if card["status_key"] == "good"),
        "medium": sum(1 for card in domain_cards if card["status_key"] == "medium"),
        "high_risk": sum(1 for card in domain_cards if card["status_key"] == "high_risk"),
    }
    last_assessed = _resolve_overview_last_assessed(
        readiness_findings=readiness_findings,
        readiness_plans=readiness_plans,
    )

    finding_counts = {
        "high_risk": critical_count + high_count,
        "medium": medium_count,
        "low": sum(1 for finding in readiness_findings if finding.priority == DisasterReadinessFinding.Priority.LOW),
    }
    # Same score thresholds already used for the ring gauge's color tier
    # in resilience/index.html (>=80 teal, >=50 medium, else critical) --
    # reused here so the text label agrees with the color the user sees.
    if score >= 80:
        status_label = _domain_status_label("good")
    elif score >= 50:
        status_label = _domain_status_label("medium")
    else:
        status_label = _domain_status_label("high_risk")

    return {
        "score": score,
        "has_assessment": bool(readiness_findings or readiness_plans),
        "finding_counts": finding_counts,
        "score_display": f"{score}%",
        "status_label": status_label,
        "headline": _readiness_headline(score, len(readiness_findings)),
        "status_counts": status_counts,
        "last_assessed": _format_dashboard_datetime(last_assessed),
    }


def _build_latest_readiness_summary(*, readiness_findings, latest_analyzed_upload):
    if readiness_findings:
        primary_finding = max(
            readiness_findings,
            key=lambda finding: (
                PRIORITY_RANK.get(finding.priority, 0),
                finding.created_at,
            ),
        )
        return {
            "status_key": _summary_status_key(primary_finding.priority),
            "status_label": _summary_status_label(primary_finding.priority),
            "statement": _build_summary_statement(primary_finding),
            "last_analysis": _format_dashboard_datetime(primary_finding.created_at),
        }

    if latest_analyzed_upload:
        return {
            "status_key": "good",
            "status_label": "GOOD",
            "statement": "No readiness findings were generated from the latest analyzed logs.",
            "last_analysis": _format_dashboard_datetime(latest_analyzed_upload.uploaded_at),
        }

    return {
        "status_key": "good",
        "status_label": "GOOD",
        "statement": "Upload logs to identify readiness gaps and continuity concerns.",
        "last_analysis": "No assessment has been run yet.",
    }


def _build_prioritized_recommendations(domain_cards):
    prioritized = sorted(
        domain_cards,
        key=lambda card: (
            0 if card["status_key"] == "high_risk" else 1 if card["status_key"] == "medium" else 2,
            card["title"],
        ),
    )
    recommendations = []

    for card in prioritized:
        if card["status_key"] == "good":
            continue
        recommendations.append(
            {
                "priority_key": card["status_key"],
                "priority_label": "HIGH" if card["status_key"] == "high_risk" else "MEDIUM",
                "text": card["action"],
            }
        )
        if len(recommendations) == 4:
            return recommendations

    return recommendations


def _build_top_readiness_gaps(readiness_findings):
    findings = sorted(readiness_findings, key=lambda finding: (-PRIORITY_RANK.get(finding.priority, 0), -finding.created_at.timestamp()))[:5]
    return [{
        "title": finding.readiness_issue,
        "explanation": _first_sentence(finding.disaster_impact or finding.recovery_concern),
        "priority": finding.priority,
        "priority_label": finding.get_priority_display(),
        "source_label": finding.get_source_display(),
        "incident_url": reverse("incidents:detail", args=[finding.incident_id]) if finding.incident_id else "",
    } for finding in findings]


def _resolve_last_updated(
    *,
    readiness_findings,
    readiness_plans,
    latest_analyzed_upload,
    latest_upload,
    latest_report,
    latest_playbook,
):
    candidates = [
        readiness_findings[0].created_at if readiness_findings else None,
        readiness_plans[0].updated_at if readiness_plans else None,
        latest_analyzed_upload.uploaded_at if latest_analyzed_upload else None,
        latest_upload.uploaded_at if latest_upload else None,
        latest_report.created_at if latest_report else None,
        latest_playbook.updated_at if latest_playbook else None,
    ]
    valid_candidates = [candidate for candidate in candidates if candidate is not None]
    return max(valid_candidates) if valid_candidates else timezone.now()


def _resolve_overview_last_assessed(*, readiness_findings, readiness_plans):
    candidates = [
        readiness_findings[0].created_at if readiness_findings else None,
        readiness_plans[0].updated_at if readiness_plans else None,
    ]
    valid_candidates = [candidate for candidate in candidates if candidate is not None]
    return max(valid_candidates) if valid_candidates else timezone.now()


def _resolve_assessment_url(uploaded_file):
    if uploaded_file:
        return reverse("log_intake:results", args=[uploaded_file.id])
    return reverse("log_intake:upload")


def _resolve_analysis_url(uploaded_file):
    if uploaded_file:
        return reverse("log_intake:results", args=[uploaded_file.id])
    return reverse("incidents:index")


def _resolve_domain_status(matched_findings, matched_plans):
    if any(
        finding.priority in (
            DisasterReadinessFinding.Priority.CRITICAL,
            DisasterReadinessFinding.Priority.HIGH,
        )
        for finding in matched_findings
    ):
        return "high_risk"
    if any(
        finding.priority in (
            DisasterReadinessFinding.Priority.MEDIUM,
            DisasterReadinessFinding.Priority.LOW,
        )
        for finding in matched_findings
    ):
        return "medium"
    if matched_plans:
        return "good"
    return "unknown"


def _build_domain_items(*, matched_findings, matched_plans, empty_items):
    items = []

    for finding in sorted(
        matched_findings,
        key=lambda item: (-PRIORITY_RANK.get(item.priority, 0), -item.created_at.timestamp()),
    )[:3]:
        items.append(
            {
                "text": finding.readiness_issue,
                "tone": _priority_to_tone(finding.priority),
            }
        )

    for plan in matched_plans:
        if len(items) >= 3:
            break
        if plan.scenario:
            items.append(
                {
                    "text": f"Plan coverage found for {plan.scenario.lower()}.",
                    "tone": "good",
                }
            )

    if not items:
        items = [{"text": "Manual verification required. No evidence or plan is recorded for this area.", "tone": "info"}]

    return items[:3]


def _resolve_domain_description(*, matched_findings, matched_plans, fallback):
    if matched_findings:
        primary = max(
            matched_findings,
            key=lambda finding: (
                PRIORITY_RANK.get(finding.priority, 0),
                finding.created_at,
            ),
        )
        return _first_sentence(primary.disaster_impact or primary.recovery_concern or primary.readiness_issue)

    if matched_plans:
        return "Relevant readiness plans are recorded for this area. Review them before the next seasonal event."

    return fallback


def _matches_keywords(text, keywords):
    return any(keyword in text for keyword in keywords)


def _combined_finding_text(finding):
    return " ".join(
        [
            (finding.readiness_issue or "").lower(),
            (finding.disaster_impact or "").lower(),
            (finding.recovery_concern or "").lower(),
            (finding.incident.title.lower() if finding.incident else ""),
            (finding.risk.risk_title.lower() if finding.risk else ""),
        ]
    )


def _combined_plan_text(plan):
    return " ".join(
        [
            (plan.scenario or "").lower(),
            (plan.checklist or "").lower(),
            (plan.questions or "").lower(),
            (plan.recommended_actions or "").lower(),
        ]
    )


def _priority_to_tone(priority):
    if priority in (
        DisasterReadinessFinding.Priority.CRITICAL,
        DisasterReadinessFinding.Priority.HIGH,
    ):
        return "danger"
    if priority == DisasterReadinessFinding.Priority.MEDIUM:
        return "warning"
    return "good"


def _domain_status_label(status_key):
    mapping = {
        "good": "GOOD",
        "medium": "MEDIUM",
        "high_risk": "HIGH RISK",
        "unknown": "UNKNOWN",
    }
    return mapping[status_key]


def _summary_status_key(priority):
    if priority in (
        DisasterReadinessFinding.Priority.CRITICAL,
        DisasterReadinessFinding.Priority.HIGH,
    ):
        return "high_risk"
    if priority == DisasterReadinessFinding.Priority.MEDIUM:
        return "medium"
    return "good"


def _summary_status_label(priority):
    if priority in (
        DisasterReadinessFinding.Priority.CRITICAL,
        DisasterReadinessFinding.Priority.HIGH,
    ):
        return "HIGH RISK"
    if priority == DisasterReadinessFinding.Priority.MEDIUM:
        return "MEDIUM"
    return "GOOD"


def _build_summary_statement(finding):
    issue = (finding.readiness_issue or "Readiness finding").strip().rstrip(".")
    if finding.priority in (
        DisasterReadinessFinding.Priority.CRITICAL,
        DisasterReadinessFinding.Priority.HIGH,
    ):
        return f"{issue} creates high recovery risk."
    if finding.priority == DisasterReadinessFinding.Priority.MEDIUM:
        return f"{issue} needs follow-up before the next disruption event."
    return f"{issue} is recorded and should stay under review."


def _first_sentence(text):
    cleaned = (text or "").strip()
    if not cleaned:
        return ""
    first = cleaned.split(".")[0].strip()
    return first + "." if first and not first.endswith(".") else first


def _format_dashboard_datetime(value):
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)
    return (
        f"{localized.strftime('%b')} {localized.day}, {localized.year} "
        f"{localized.strftime('%I:%M %p').lstrip('0')} AST"
    )


def _readiness_headline(score, issue_count):
    if issue_count == 0:
        return "No open readiness issues are recorded right now. Keep reviewing continuity plans."
    if score >= 80:
        return "Your organization is in a strong position. Keep continuity actions current and rehearsed."
    if score >= 60:
        return "Your organization is moderately prepared. Address the current issues below to improve resilience."
    return "Preparedness needs attention. Focus on the highest-impact continuity gaps first."
