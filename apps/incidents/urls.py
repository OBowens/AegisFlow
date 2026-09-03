from django.urls import path

from . import views


app_name = "incidents"

urlpatterns = [
    path("", views.incident_list, name="index"),
    path("<int:incident_id>/", views.incident_detail, name="detail"),
    path("<int:incident_id>/investigate/", views.incident_workflow, {"stage": "understand"}, name="investigate"),
    path("<int:incident_id>/investigate/<str:stage>/", views.incident_workflow, name="workflow"),
    path("<int:incident_id>/investigate/<str:stage>/ask/", views.incident_workflow_ask, name="workflow_ask"),
    path("<int:incident_id>/evidence/", views.incident_evidence, name="evidence"),
    path("<int:incident_id>/gaps/", views.incident_gaps, name="gaps"),
    path("<int:incident_id>/analyze/", views.incident_analyze, name="analyze"),
    path("<int:incident_id>/ask/", views.incident_ask, name="ask"),
    path("<int:incident_id>/compare/", views.incident_compare, name="compare"),
    path(
        "<int:incident_id>/explain/plain-language/",
        views.incident_explain,
        {"audience": "plain_language"},
        name="explain_plain_language",
    ),
    path(
        "<int:incident_id>/explain/management/",
        views.incident_explain,
        {"audience": "management"},
        name="explain_management",
    ),
    path("<int:incident_id>/status/", views.incident_update_status, name="update_status"),
    path("<int:incident_id>/assign/", views.incident_assign_to_me, name="assign_to_me"),
    path("<int:incident_id>/generate-playbook/", views.incident_generate_playbook, name="generate_playbook"),
    path(
        "<int:incident_id>/report/technical/",
        views.incident_generate_report,
        {"report_type": "technical"},
        name="generate_technical_report",
    ),
    path(
        "<int:incident_id>/report/incident/",
        views.incident_generate_report,
        {"report_type": "incident"},
        name="generate_incident_report",
    ),
]
