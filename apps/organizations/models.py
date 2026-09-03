from django.db import models


class Organization(models.Model):
    name = models.CharField(max_length=255)
    organization_type = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    sector = models.CharField(max_length=100)
    risk_profile = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name


class CriticalSystem(models.Model):
    class Criticality(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class RecoveryPriority(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        URGENT = "urgent", "Urgent"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="critical_systems",
    )
    system_name = models.CharField(max_length=255)
    system_type = models.CharField(max_length=100)
    criticality = models.CharField(
        max_length=20,
        choices=Criticality.choices,
        default=Criticality.MEDIUM,
    )
    owner_name = models.CharField(max_length=255)
    recovery_priority = models.CharField(
        max_length=20,
        choices=RecoveryPriority.choices,
        default=RecoveryPriority.MEDIUM,
    )
    backup_required = models.BooleanField(default=False)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.system_name} ({self.organization.name})"


class AppAssistantQuestion(models.Model):
    """One on-demand question+answer pair asked of the general App
    Assistant about how to use AegisFlow AI itself -- navigation, the
    guided workflow, terminology -- as opposed to
    incidents.AnalystQuestion / incidents.WorkflowStepQuestion /
    risk.RiskQuestion / resilience.ReadinessQuestion, which are all
    scoped to one specific incident/gap/organization's live data.
    Mirrors ReadinessQuestion's thread pattern exactly: scoped to
    Organization (this assistant is app-wide, not tied to one object),
    every question kept, not "latest wins".
    """

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="app_assistant_questions",
    )
    question_text = models.TextField()
    answer_text = models.TextField()
    model_used = models.CharField(max_length=100, blank=True)
    asked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["asked_at"]

    def __str__(self) -> str:
        return f"App assistant question for {self.organization_id} ({self.asked_at})"
