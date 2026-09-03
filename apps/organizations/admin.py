from django.contrib import admin

from .models import CriticalSystem, Organization


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "organization_type", "country", "sector", "risk_profile", "created_at")
    search_fields = ("name", "organization_type", "country", "sector", "risk_profile")


@admin.register(CriticalSystem)
class CriticalSystemAdmin(admin.ModelAdmin):
    list_display = (
        "system_name",
        "organization",
        "system_type",
        "criticality",
        "recovery_priority",
        "backup_required",
        "owner_name",
    )
    list_filter = ("criticality", "recovery_priority", "backup_required", "system_type")
    search_fields = ("system_name", "organization__name", "owner_name", "notes")
