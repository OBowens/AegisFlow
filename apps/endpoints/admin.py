from django.contrib import admin

from .models import Endpoint, EndpointCorrelationCandidate, EndpointEvent


@admin.register(Endpoint)
class EndpointAdmin(admin.ModelAdmin):
    list_display = ("display_name", "organization", "last_seen", "created_at")
    list_filter = ("organization", "created_at", "last_seen")
    search_fields = ("display_name", "organization__name")
    # Only the token's hash is stored, and the raw token is issued by
    # `createendpoint`, never here. Shown read-only for support/debugging.
    readonly_fields = ("token_hash", "created_at", "last_seen")


@admin.register(EndpointEvent)
class EndpointEventAdmin(admin.ModelAdmin):
    list_display = (
        "event_type", "endpoint", "organization", "occurred_at",
        "received_at", "correlation_scanned_at", "candidate",
    )
    list_filter = ("event_type", "organization", "received_at", "correlation_scanned_at")
    search_fields = ("event_type", "endpoint__display_name")
    readonly_fields = (
        "endpoint", "organization", "event_type", "payload", "occurred_at",
        "received_at", "correlation_scanned_at", "candidate",
    )
    date_hierarchy = "received_at"


@admin.register(EndpointCorrelationCandidate)
class EndpointCorrelationCandidateAdmin(admin.ModelAdmin):
    list_display = (
        "id", "endpoint", "status", "ai_verdict", "ai_severity",
        "event_count", "attempt_count", "incident", "created_at", "triaged_at",
    )
    list_filter = ("status", "ai_verdict", "ai_severity", "organization")
    search_fields = ("endpoint__display_name", "trigger_summary", "ai_summary")
    readonly_fields = (
        "endpoint", "organization", "first_event_at", "last_event_at",
        "event_count", "trigger_summary", "attempt_count", "ai_verdict",
        "ai_severity", "ai_summary", "ai_reasoning", "ai_model", "ai_error",
        "incident", "created_at", "updated_at", "triaged_at",
    )
    date_hierarchy = "created_at"
