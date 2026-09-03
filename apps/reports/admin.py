from django.contrib import admin

from .models import GeneratedReport


@admin.register(GeneratedReport)
class GeneratedReportAdmin(admin.ModelAdmin):
    list_display = ("title", "organization", "incident", "report_type", "generated_by", "created_at")
    list_filter = ("report_type", "created_at")
    search_fields = ("title", "organization__name", "summary", "body", "export_path")
