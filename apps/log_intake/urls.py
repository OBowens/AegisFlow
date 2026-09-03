from django.urls import path

from . import views


app_name = "log_intake"

urlpatterns = [
    path("", views.log_file_list, name="index"),
    path("upload/", views.log_upload, name="upload"),
    path("files/", views.log_file_list, name="file_list"),
    path("alerts/", views.alert_list, name="alerts"),
    path("files/<int:uploaded_file_id>/results/", views.log_analysis_results, name="results"),
    path(
        "files/<int:uploaded_file_id>/export-alerts/",
        views.export_parsed_alerts_csv,
        name="export_alerts_csv",
    ),
    path(
        "files/<int:uploaded_file_id>/delete/",
        views.delete_uploaded_log_file,
        name="delete_upload",
    ),
]
