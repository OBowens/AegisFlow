from django.contrib import admin

from .models import ChecklistItemState, PlaybookStep, ResponsePlaybook, SOPChecklist


@admin.register(SOPChecklist)
class SOPChecklistAdmin(admin.ModelAdmin):
    list_display = ("name", "incident_type", "version", "is_active", "created_at")
    list_filter = ("is_active", "incident_type", "created_at")
    search_fields = ("name", "incident_type", "version", "checklist_items")


@admin.register(ResponsePlaybook)
class ResponsePlaybookAdmin(admin.ModelAdmin):
    list_display = ("title", "organization", "incident", "priority", "status", "created_at", "updated_at")
    list_filter = ("priority", "status", "created_at", "updated_at")
    search_fields = ("title", "organization__name", "summary", "immediate_steps", "next_steps", "escalation_steps")


@admin.register(PlaybookStep)
class PlaybookStepAdmin(admin.ModelAdmin):
    list_display = ("playbook", "step_number", "owner", "urgency", "status", "updated_at")
    list_filter = ("urgency", "status", "created_at", "updated_at")
    search_fields = ("playbook__title", "action", "owner")


@admin.register(ChecklistItemState)
class ChecklistItemStateAdmin(admin.ModelAdmin):
    list_display = ("incident", "checklist", "item_key", "is_completed", "updated_at")
    list_filter = ("is_completed", "created_at", "updated_at")
    search_fields = ("incident__title", "checklist__name", "item_key")
