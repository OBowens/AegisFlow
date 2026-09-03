from django.contrib import admin

from .models import AnalystQuestion, AnalystResult, IncidentEvidence, IncidentGroup


@admin.register(IncidentGroup)
class IncidentGroupAdmin(admin.ModelAdmin):
    list_display = ("title", "organization", "incident_type", "severity", "status", "first_seen", "last_seen")
    list_filter = ("severity", "status", "incident_type", "created_at")
    search_fields = ("title", "organization__name", "incident_type", "affected_systems", "summary", "ai_reasoning")


@admin.register(IncidentEvidence)
class IncidentEvidenceAdmin(admin.ModelAdmin):
    list_display = ("incident", "alert", "created_at")
    list_filter = ("created_at",)
    search_fields = ("incident__title", "alert__event_type", "evidence_reason")


@admin.register(AnalystResult)
class AnalystResultAdmin(admin.ModelAdmin):
    list_display = ("incident", "model_used", "generated_at")
    list_filter = ("model_used", "generated_at")
    search_fields = ("incident__title", "analysis_text")


@admin.register(AnalystQuestion)
class AnalystQuestionAdmin(admin.ModelAdmin):
    list_display = ("incident", "model_used", "asked_at")
    list_filter = ("model_used", "asked_at")
    search_fields = ("incident__title", "question_text", "answer_text")
