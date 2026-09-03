from django.urls import path

from . import views


app_name = "playbooks"

urlpatterns = [
    path("", views.index, name="index"),
    path("generate-custom/", views.playbook_generate_custom, name="generate_custom"),
    path("sops/", views.sop_checklists, name="sops"),
    path(
        "incidents/<int:incident_id>/checklists/<int:checklist_id>/toggle-item/",
        views.playbook_toggle_checklist_item,
        name="toggle_checklist_item",
    ),
    path(
        "steps/<int:step_id>/status/",
        views.playbook_update_step_status,
        name="update_step_status",
    ),
]
