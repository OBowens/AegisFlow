from django.conf import settings
from django.db import models


class GeneratedReport(models.Model):
    class ReportType(models.TextChoices):
        EXECUTIVE = "executive", "Executive"
        TECHNICAL = "technical", "Technical"
        INCIDENT = "incident", "Incident"
        RISK = "risk", "Risk"
        READINESS = "readiness", "Readiness"
        UPLOAD_SUMMARY = "upload_summary", "Upload Summary"
        ACTION_PLAN = "action_plan", "Action Plan"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="generated_reports",
    )
    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reports",
    )
    report_type = models.CharField(
        max_length=20,
        choices=ReportType.choices,
        default=ReportType.EXECUTIVE,
    )
    title = models.CharField(max_length=255)
    summary = models.TextField(blank=True)
    body = models.TextField()
    export_path = models.CharField(max_length=500, blank=True)
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="generated_reports",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.title
