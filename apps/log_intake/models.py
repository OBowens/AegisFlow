from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


class UploadedLogFile(models.Model):
    class SourceType(models.TextChoices):
        WAZUH = "wazuh", "Wazuh"
        GRAYLOG = "graylog", "Graylog"
        PRTG = "prtg", "PRTG"
        PROXMOX = "proxmox", "Proxmox"
        FIREWALL = "firewall", "Firewall"
        BACKUP = "backup", "Backup"
        SSL_CERTIFICATE = "ssl_certificate", "SSL Certificate"
        WINDOWS = "windows", "Windows"
        LINUX = "linux", "Linux"
        OTHER = "other", "Other"

    class Status(models.TextChoices):
        UPLOADED = "uploaded", "Uploaded"
        PARSING = "parsing", "Parsing"
        PARSED = "parsed", "Parsed"
        FAILED = "failed", "Failed"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="uploaded_logs",
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="uploaded_log_files",
    )
    file_name = models.CharField(max_length=255)
    source_type = models.CharField(
        max_length=30,
        choices=SourceType.choices,
        default=SourceType.OTHER,
    )
    storage_path = models.CharField(max_length=500)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.UPLOADED,
    )
    notes = models.TextField(blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.file_name


class ParsedAlert(models.Model):
    class SeverityHint(models.TextChoices):
        UNKNOWN = "unknown", "Unknown"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    uploaded_file = models.ForeignKey(
        "log_intake.UploadedLogFile",
        on_delete=models.CASCADE,
        related_name="parsed_alerts",
    )
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="parsed_alerts",
    )
    source_tool = models.CharField(max_length=100)
    timestamp = models.DateTimeField(null=True, blank=True)
    affected_system = models.CharField(max_length=255, blank=True)
    account = models.CharField(max_length=255, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    event_type = models.CharField(max_length=255)
    severity_hint = models.CharField(
        max_length=20,
        choices=SeverityHint.choices,
        default=SeverityHint.UNKNOWN,
    )
    raw_message = models.TextField(blank=True)
    normalized_summary = models.TextField(blank=True)
    confidence_score = models.FloatField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)],
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.event_type} [{self.severity_hint}]"
