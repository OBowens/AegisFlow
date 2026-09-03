from django.contrib import admin

from .models import GapFinding, RiskAssessment, RiskNarration, UserQuestion


@admin.register(GapFinding)
class GapFindingAdmin(admin.ModelAdmin):
    list_display = ("gap_name", "organization", "incident", "source", "priority", "affected_system", "created_at")
    list_filter = ("source", "priority", "created_at")
    search_fields = ("gap_name", "organization__name", "affected_system", "description", "evidence")


@admin.register(RiskAssessment)
class RiskAssessmentAdmin(admin.ModelAdmin):
    list_display = (
        "risk_title",
        "organization",
        "incident",
        "gap",
        "likelihood",
        "impact",
        "risk_level",
        "recommended_priority",
        "created_at",
    )
    list_filter = ("likelihood", "impact", "risk_level", "recommended_priority", "created_at")
    search_fields = ("risk_title", "organization__name", "reasoning")


@admin.register(RiskNarration)
class RiskNarrationAdmin(admin.ModelAdmin):
    list_display = ("gap", "model_used", "generated_at")
    list_filter = ("model_used", "generated_at")
    search_fields = ("gap__gap_name", "narration_text")


@admin.register(UserQuestion)
class UserQuestionAdmin(admin.ModelAdmin):
    list_display = ("organization", "asked_by", "category", "created_at")
    list_filter = ("category", "created_at")
    search_fields = ("organization__name", "asked_by__username", "question_text", "response_summary")
