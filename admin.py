from django.contrib import admin

from .models import AIRun, AuditLog


@admin.register(AIRun)
class AIRunAdmin(admin.ModelAdmin):
    list_display = (
        "ai_module",
        "organization",
        "input_type",
        "input_id",
        "output_type",
        "output_id",
        "status",
        "created_at",
    )
    list_filter = ("status", "ai_module", "created_at")
    search_fields = (
        "ai_module",
        "organization__name",
        "input_type",
        "input_id",
        "output_type",
        "output_id",
        "model_used",
        "prompt_version",
        "error_message",
    )


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("action", "organization", "user", "target_type", "target_id", "created_at")
    list_filter = ("action", "target_type", "created_at")
    search_fields = ("organization__name", "user__username", "action", "target_type", "target_id", "ip_address", "details")
