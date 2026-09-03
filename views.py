from django.shortcuts import get_object_or_404, render

from .models import GeneratedReport


def index(request):
    return report_list(request)


def report_list(request):
    reports = GeneratedReport.objects.select_related("organization", "incident", "generated_by").order_by(
        "-created_at"
    )
    return render(
        request,
        "reports/list.html",
        {
            "page_title": "Reports",
            "page_description": "Manager-ready workflow reports created from uploaded sample logs.",
            "reports": reports,
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
            "page_description": "Structured report output created by the deterministic MVP workflow.",
            "report": report,
        },
    )
