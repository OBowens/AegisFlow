import re
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from django.contrib import messages
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from apps.ai_core.modules.report_writer import run_report_generation
from apps.ai_core.rate_limit import deny_ai_call
from apps.audit.models import AIRun
from apps.organizations.services.current_organization import get_current_organization

from .models import GeneratedReport

CARIBBEAN_TIMEZONE = ZoneInfo("America/St_Vincent")
PREVIEW_TYPES = (
    GeneratedReport.ReportType.EXECUTIVE,
    GeneratedReport.ReportType.TECHNICAL,
    GeneratedReport.ReportType.INCIDENT,
    GeneratedReport.ReportType.RISK,
    GeneratedReport.ReportType.READINESS,
)
# Executive, Risk, and Readiness are organization-wide -- generated
# on-demand from this page. Technical and Incident are single-incident
# reports generated from that incident's own detail page instead (same
# split as Analyst/Writer/Explainer living on incidents/detail.html),
# so they're previewable/filterable here but not "Generate" buttons on
# this page. Upload Summary and Action Plan aren't on-demand at all.
ORG_WIDE_REPORT_TYPES = (
    GeneratedReport.ReportType.EXECUTIVE,
    GeneratedReport.ReportType.RISK,
    GeneratedReport.ReportType.READINESS,
)
TYPE_META = {
    GeneratedReport.ReportType.EXECUTIVE: {
        "label": "Executive Reports",
        "singular": "Executive Report",
        "icon": "users",
        "accent": "blue",
    },
    GeneratedReport.ReportType.TECHNICAL: {
        "label": "Technical Reports",
        "singular": "Technical Report",
        "icon": "analysis",
        "accent": "teal",
    },
    GeneratedReport.ReportType.INCIDENT: {
        "label": "Incident Reports",
        "singular": "Incident Report",
        "icon": "incident",
        "accent": "red",
    },
    GeneratedReport.ReportType.RISK: {
        "label": "Risk Reports",
        "singular": "Risk Report",
        "icon": "warning",
        "accent": "amber",
    },
    GeneratedReport.ReportType.READINESS: {
        "label": "Readiness Reports",
        "singular": "Readiness Report",
        "icon": "readiness-nav",
        "accent": "purple",
    },
    GeneratedReport.ReportType.UPLOAD_SUMMARY: {
        "label": "Upload Summaries",
        "singular": "Upload Summary",
        "icon": "upload",
        "accent": "teal",
    },
    GeneratedReport.ReportType.ACTION_PLAN: {
        "label": "Action Plan",
        "singular": "Action Plan",
        "icon": "playbook",
        "accent": "blue",
    },
}


def index(request):
    return report_list(request)


def report_list(request):
    report_queryset = GeneratedReport.objects.select_related(
        "organization",
        "incident",
        "generated_by",
    ).order_by("-created_at")
    report_list_all = list(report_queryset)
    selected_report = _resolve_selected_report(
        reports=report_list_all,
        preview_id=request.GET.get("preview"),
        preview_type=request.GET.get("preview_type"),
    )
    organization = get_current_organization()
    paginator = Paginator(report_queryset, 7)
    page_obj = paginator.get_page(request.GET.get("page") or 1)
    report_rows = _build_report_rows(page_obj, selected_report)
    preview_sections = _build_preview_sections(selected_report)
    page_updated_at = report_list_all[0].created_at if report_list_all else timezone.now()
    active_type = (
        selected_report.report_type
        if selected_report
        else request.GET.get("preview_type") if request.GET.get("preview_type") in PREVIEW_TYPES else GeneratedReport.ReportType.EXECUTIVE
    )

    return render(
        request,
        "reports/business_list.html" if request.session.get("experience_mode") == "business" else "reports/list.html",
        {
            "page_title": "Reports",
            "page_description": "Executive, technical, incident, risk, and readiness reports generated from AI analysis.",
            "active_nav": "reports",
            "organization": organization,
            "organization_name": organization.name if organization else "Demo Organization",
            "organization_plan": "Small Business Plan",
            "dashboard_updated_at": _format_dashboard_datetime(page_updated_at),
            "report_tabs": _build_report_tabs(report_list_all, active_type),
            "report_action_cards": _build_action_cards(report_list_all, selected_report),
            "report_rows": report_rows,
            "reports_count": paginator.count,
            "page_obj": page_obj,
            "pagination": _build_pagination(page_obj, selected_report, active_type),
            "selected_report": _build_selected_report_preview(selected_report),
            "preview_sections": preview_sections,
            "preview_detail_url": reverse("reports:detail", args=[selected_report.id]) if selected_report else reverse("reports:index"),
            "empty_upload_url": reverse("log_intake:upload"),
            "preview_type": active_type,
        },
    )


def report_detail(request, report_id):
    report = get_object_or_404(
        GeneratedReport.objects.select_related("organization", "incident", "generated_by"),
        pk=report_id,
    )
    return render(
        request,
        "reports/detail.html",
        {
            "page_title": report.title,
            "page_description": (
                "Structured report output created by the deterministic AegisFlow AI "
                "workflow."
            ),
            "report": report,
        },
    )


def report_generate(request, report_type):
    if report_type not in ORG_WIDE_REPORT_TYPES:
        raise Http404(f"{report_type!r} is not an organization-wide, on-demand report type.")

    if request.method != "POST":
        return redirect("reports:index")

    organization = get_current_organization()
    meta = TYPE_META[report_type]

    denied = deny_ai_call(organization, "report_writer")
    if denied:
        messages.error(request, denied)
        return redirect(f"{reverse('reports:index')}?{urlencode({'preview_type': report_type})}")

    ai_run = AIRun.objects.create(
        organization=organization,
        ai_module="report_writer",
        input_type="Organization",
        input_id=str(organization.id),
        output_type="GeneratedReport",
        output_id="",
        status=AIRun.Status.STARTED,
    )

    try:
        raw_result = run_report_generation(report_type, organization)
    except RuntimeError as exc:
        messages.error(request, _friendly_report_error(exc))
        ai_run.status = AIRun.Status.FAILED
        ai_run.error_message = str(exc)
        ai_run.save(update_fields=["status", "error_message"])
        return redirect(f"{reverse('reports:index')}?{urlencode({'preview_type': report_type})}")

    report = GeneratedReport.objects.create(
        organization=organization,
        incident=None,
        report_type=report_type,
        title=f"{meta['singular']} - {organization.name}",
        summary=raw_result["summary"],
        body=raw_result["report_text"],
        generated_by=request.user if request.user.is_authenticated else None,
    )

    ai_run.status = AIRun.Status.SUCCESS
    ai_run.model_used = raw_result["model"]
    ai_run.output_id = str(report.id)
    ai_run.save(update_fields=["status", "model_used", "output_id"])

    messages.success(request, f"{meta['singular']} generated.")
    return redirect(
        f"{reverse('reports:index')}?{urlencode({'preview': report.id, 'preview_type': report_type})}"
    )


def _friendly_report_error(exc: RuntimeError) -> str:
    if "ANTHROPIC_API_KEY is not set" in str(exc):
        return "AI report generation isn't available yet — API key not configured."
    return "AI report generation failed. Please try again in a moment."


def _resolve_selected_report(*, reports, preview_id, preview_type):
    if preview_id:
        for report in reports:
            if str(report.id) == str(preview_id):
                return report

    if preview_type in PREVIEW_TYPES:
        for report in reports:
            if report.report_type == preview_type:
                return report

    return reports[0] if reports else None


def _build_report_tabs(reports, active_type):
    counts = {report_type: 0 for report_type in PREVIEW_TYPES}
    for report in reports:
        if report.report_type in counts:
            counts[report.report_type] += 1

    tabs = []
    for report_type in PREVIEW_TYPES:
        meta = TYPE_META[report_type]
        tabs.append(
            {
                "label": meta["label"],
                "icon": meta["icon"],
                "count": counts[report_type],
                "is_active": report_type == active_type,
                "url": f"{reverse('reports:index')}?{urlencode({'preview_type': report_type})}",
            }
        )
    return tabs


def _build_action_cards(reports, selected_report):
    executive_report = _first_report_for_type(reports, GeneratedReport.ReportType.EXECUTIVE)
    target_report = selected_report or executive_report or (reports[0] if reports else None)

    generate_cards = [
        {
            "eyebrow": "Generate",
            "title": TYPE_META[report_type]["singular"],
            "icon": TYPE_META[report_type]["icon"],
            "accent": TYPE_META[report_type]["accent"],
            "method": "post",
            "url": reverse("reports:generate", args=[report_type]),
        }
        for report_type in ORG_WIDE_REPORT_TYPES
    ]

    export_cards = [
        {
            "eyebrow": "Export",
            "title": "PDF",
            "icon": "download",
            "accent": "red",
            "method": "get",
            "url": reverse("reports:detail", args=[target_report.id]) if target_report else reverse("reports:index"),
        },
        {
            "eyebrow": "Export",
            "title": "Word",
            "icon": "logs",
            "accent": "blue",
            "method": "get",
            "url": reverse("reports:detail", args=[target_report.id]) if target_report else reverse("reports:index"),
        },
    ]

    return generate_cards + export_cards


def _first_report_for_type(reports, report_type):
    for report in reports:
        if report.report_type == report_type:
            return report
    return None


def _build_report_rows(page_obj, selected_report):
    rows = []

    for report in page_obj.object_list:
        meta = TYPE_META.get(report.report_type, TYPE_META[GeneratedReport.ReportType.EXECUTIVE])
        rows.append(
            {
                "id": report.id,
                "title": report.title,
                "type_label": report.get_report_type_display(),
                "type_key": report.report_type,
                "type_accent": meta["accent"],
                "incident_title": report.incident.title if report.incident else "Upload-wide summary",
                "generated_by_name": _display_name(report.generated_by),
                "generated_by_initials": _initials(_display_name(report.generated_by)),
                "date_display": _format_report_date(report.created_at),
                "time_display": _format_report_time(report.created_at),
                "status_label": "Completed",
                "status_key": "completed",
                "preview_url": reverse("reports:index") + f"?{urlencode({'preview': report.id, 'preview_type': report.report_type, 'page': page_obj.number})}",
                "detail_url": reverse("reports:detail", args=[report.id]),
                "is_selected": bool(selected_report and report.id == selected_report.id),
            }
        )

    return rows


def _build_selected_report_preview(report):
    if not report:
        return None

    meta = TYPE_META.get(report.report_type, TYPE_META[GeneratedReport.ReportType.EXECUTIVE])
    return {
        "id": report.id,
        "title": report.title,
        "type_label": report.get_report_type_display(),
        "icon": meta["icon"],
        "accent": meta["accent"],
        "generated_display": _format_dashboard_datetime(report.created_at),
    }


def _build_preview_sections(report):
    if not report:
        return {
            "summary": "",
            "impact": "",
            "recommendations": [],
        }

    summary = (report.summary or "").strip() or _first_nonempty_paragraph(report.body)
    impact = _extract_named_section(
        report.body,
        names=("impact", "business impact", "incident impact"),
    )
    if not impact and report.incident and report.incident.summary:
        impact = report.incident.summary.strip()
    if not impact:
        impact = _second_nonempty_paragraph(report.body) or summary

    # Try the scoped "Recommended Actions" section first -- a global bullet
    # scan (_extract_bullets(report.body)) would happily grab bullets from
    # an earlier section instead (e.g. an Impact section a model chose to
    # write as bullets rather than prose -- confirmed against real
    # generated Risk report output), silently returning the wrong content.
    recommendations = _extract_named_list(
        report.body,
        names=("recommended actions", "recommendations", "next steps"),
    )
    if not recommendations:
        recommendations = _extract_bullets(report.body)
    if not recommendations:
        recommendations = _sentence_list(report.body)[1:5]
    if not recommendations and summary:
        recommendations = [summary]

    return {
        "summary": summary,
        "impact": impact,
        "recommendations": recommendations[:4],
    }


def _build_pagination(page_obj, selected_report, active_type):
    base_params = {}
    if selected_report:
        base_params["preview"] = selected_report.id
    if active_type:
        base_params["preview_type"] = active_type

    prev_url = None
    next_url = None

    if page_obj.has_previous():
        prev_params = {**base_params, "page": page_obj.previous_page_number()}
        prev_url = reverse("reports:index") + f"?{urlencode(prev_params)}"

    if page_obj.has_next():
        next_params = {**base_params, "page": page_obj.next_page_number()}
        next_url = reverse("reports:index") + f"?{urlencode(next_params)}"

    return {
        "showing_text": (
            f"Showing {page_obj.start_index()} to {page_obj.end_index()} "
            f"of {page_obj.paginator.count} reports"
        ),
        "current_page": page_obj.number,
        "prev_url": prev_url,
        "next_url": next_url,
        "has_multiple_pages": page_obj.paginator.num_pages > 1,
    }


def _display_name(user):
    if not user:
        return "AegisFlow AI"

    full_name = getattr(user, "get_full_name", lambda: "")().strip()
    if full_name:
        return full_name

    for attr in ("username", "email"):
        value = getattr(user, attr, "")
        if value:
            return value

    return str(user)


def _initials(name):
    words = [word for word in re.split(r"\s+", name.strip()) if word]
    if not words:
        return "AI"
    return "".join(word[0] for word in words[:2]).upper()


def _first_nonempty_paragraph(text):
    for paragraph in _paragraphs(text):
        if paragraph:
            return paragraph
    return ""


def _second_nonempty_paragraph(text):
    paragraphs = _paragraphs(text)
    return paragraphs[1] if len(paragraphs) > 1 else ""


def _paragraphs(text):
    cleaned = (text or "").replace("\r\n", "\n")
    return [paragraph.strip() for paragraph in re.split(r"\n\s*\n", cleaned) if paragraph.strip()]


_MARKDOWN_HEADING_PREFIX_RE = re.compile(r"^#{1,6}\s*")
_PLAIN_HEADING_RE = re.compile(r"^[A-Za-z][A-Za-z ]+:$")


def _normalize_heading_line(line):
    # Tolerate a markdown heading prefix ("## Impact") as well as the
    # plain "Impact" / "Impact:" convention the deterministic upload
    # summary generator (apps/reports/services/generator.py) uses --
    # the AI Report Writer (apps/ai_core/modules/report_writer.py) is
    # told to title sections exactly "Impact" / "Recommended Actions",
    # but a real model writing markdown-flavored prose reliably adds
    # "##" anyway (confirmed against real generated output), so the
    # parser has to tolerate it rather than assume the instruction was
    # followed literally.
    return _MARKDOWN_HEADING_PREFIX_RE.sub("", line).rstrip(":").strip().lower()


def _looks_like_a_heading_line(line):
    markdown_stripped = _MARKDOWN_HEADING_PREFIX_RE.sub("", line)
    return bool(markdown_stripped != line and re.match(r"^[A-Za-z][A-Za-z ]*:?$", markdown_stripped)) or bool(
        _PLAIN_HEADING_RE.match(line)
    )


def _collect_named_section_lines(text, names):
    lines = [line.strip() for line in (text or "").replace("\r\n", "\n").splitlines()]

    for index, line in enumerate(lines):
        if _normalize_heading_line(line) not in names:
            continue
        collected = []
        for following in lines[index + 1 :]:
            if not following:
                if collected:
                    break
                continue
            if _normalize_heading_line(following) in names:
                break
            if _looks_like_a_heading_line(following) and collected:
                break
            collected.append(following)
        if collected:
            return collected
    return []


def _extract_named_section(text, names):
    return " ".join(_collect_named_section_lines(text, names))


def _extract_named_list(text, names):
    # Re-join with newlines, not _extract_named_section's space-joined
    # prose string -- _extract_bullets splits on lines, and a
    # space-joined section merges every bullet onto one line, breaking
    # the split entirely once a section has more than one bullet
    # (confirmed against real generated Risk report output).
    lines = _collect_named_section_lines(text, names)
    return _extract_bullets("\n".join(lines))


def _extract_bullets(text):
    bullets = []
    for line in (text or "").replace("\r\n", "\n").splitlines():
        cleaned = re.sub(r"^\s*(?:[-*]|[0-9]+[.)])\s*", "", line).strip()
        if cleaned and cleaned != line.strip().rstrip(":"):
            bullets.append(cleaned.rstrip(".") + "." if not cleaned.endswith(".") else cleaned)
    return bullets


def _sentence_list(text):
    normalized = " ".join((text or "").split())
    sentences = re.split(r"(?<=[.!?])\s+", normalized)
    return [sentence.strip() for sentence in sentences if sentence.strip()]


def _format_dashboard_datetime(value):
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)
    return (
        f"{localized.strftime('%b')} {localized.day}, {localized.year} "
        f"{localized.strftime('%I:%M %p').lstrip('0')} AST"
    )


def _format_report_date(value):
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)
    return f"{localized.strftime('%b')} {localized.day}, {localized.year}"


def _format_report_time(value):
    localized = timezone.localtime(value, CARIBBEAN_TIMEZONE)
    return localized.strftime("%I:%M %p").lstrip("0")
