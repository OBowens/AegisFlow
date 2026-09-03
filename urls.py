from django.urls import path

from . import views


app_name = "reports"

urlpatterns = [
    path("", views.report_list, name="index"),
    path("<int:report_id>/", views.report_detail, name="detail"),
]
