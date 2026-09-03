from django.urls import path

from . import views


app_name = "endpoints"

urlpatterns = [
    path("api/enroll/", views.enroll, name="enroll"),
    path("api/ingest/", views.ingest, name="ingest"),
]
