from django.urls import path

from . import views


app_name = "reports"

urlpatterns = [
    path("", views.report_list, name="index"),
    path("generate/<str:report_type>/", views.report_generate, name="generate"),
    path("<int:report_id>/", views.report_detail, name="detail"),
]
