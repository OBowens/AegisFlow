from django.urls import path

from . import views


app_name = "core"

urlpatterns = [
    path("", views.dashboard, name="index"),
    path("prioritize/", views.explain_priorities, name="explain_priorities"),
]
