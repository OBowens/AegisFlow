from django.contrib import admin

from .models import (
    DisasterReadinessFinding,
    ReadinessAnswer,
    ReadinessExplanation,
    ReadinessPlan,
    ReadinessQuestion,
)


@admin.register(DisasterReadinessFinding)
class DisasterReadinessFindingAdmin(admin.ModelAdmin):
    list_display = (
        "readiness_issue",
        "organization",
        "incident",
        "risk",
        "source",
        "priority",
        "created_at",
    )
    list_filter = ("source", "priority", "created_at")
    search_fields = ("readiness_issue", "organization__name", "disaster_impact", "recovery_concern")


@admin.register(ReadinessPlan)
class ReadinessPlanAdmin(admin.ModelAdmin):
    list_display = ("scenario", "organization", "created_at", "updated_at")
    search_fields = ("scenario", "organization__name", "checklist", "questions", "recommended_actions")


@admin.register(ReadinessAnswer)
class ReadinessAnswerAdmin(admin.ModelAdmin):
    list_display = ("question_text", "organization", "answered_by", "created_at")
    list_filter = ("created_at",)
    search_fields = ("question_text", "answer_text", "organization__name")


@admin.register(ReadinessQuestion)
class ReadinessQuestionAdmin(admin.ModelAdmin):
    list_display = ("organization", "model_used", "asked_at")
    list_filter = ("model_used", "asked_at")
    search_fields = ("organization__name", "question_text", "answer_text")


@admin.register(ReadinessExplanation)
class ReadinessExplanationAdmin(admin.ModelAdmin):
    list_display = ("organization", "model_used", "generated_at")
    list_filter = ("model_used", "generated_at")
    search_fields = ("organization__name", "explanation_text")
