from django.urls import path

from . import views


app_name = "risk"

urlpatterns = [
    path("", views.index, name="index"),
    path("<int:gap_id>/explain/", views.explain_risk, name="explain"),
    path("<int:gap_id>/ask/", views.ask_risk_question, name="ask"),
]
