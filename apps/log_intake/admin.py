from django.contrib import admin

from .models import ParsedAlert, UploadedLogFile


@admin.register(UploadedLogFile)
class UploadedLogFileAdmin(admin.ModelAdmin):
    list_display = ("file_name", "organization", "source_type", "status", "uploaded_by", "uploaded_at")
    list_filter = ("source_type", "status", "uploaded_at")
    search_fields = ("file_name", "organization__name", "storage_path", "notes")


@admin.register(ParsedAlert)
class ParsedAlertAdmin(admin.ModelAdmin):
    list_display = (
        "event_type",
        "organization",
        "source_tool",
        "severity_hint",
        "affected_system",
        "timestamp",
        "created_at",
    )
    list_filter = ("severity_hint", "source_tool", "created_at")
    search_fields = (
        "event_type",
        "organization__name",
        "affected_system",
        "account",
        "source_ip",
        "destination_ip",
        "raw_message",
        "normalized_summary",
    )
