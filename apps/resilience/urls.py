from django.urls import path

from . import views


app_name = "resilience"

urlpatterns = [
    path("", views.index, name="index"),
    path("explain/", views.explain_readiness, name="explain"),
    path("ask/", views.ask_readiness_question, name="ask_question"),
]
