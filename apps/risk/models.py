from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


class GapFinding(models.Model):
    class Source(models.TextChoices):
        LOG_BASED = "log_based", "Log Based"
        USER_BASED = "user_based", "User Based"
        MANUAL = "manual", "Manual"

    class Priority(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="gap_findings",
    )
    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="gap_findings",
    )
    gap_name = models.CharField(max_length=255)
    description = models.TextField()
    affected_system = models.CharField(max_length=255, blank=True)
    source = models.CharField(
        max_length=20,
        choices=Source.choices,
        default=Source.LOG_BASED,
    )
    evidence = models.TextField(blank=True)
    priority = models.CharField(
        max_length=20,
        choices=Priority.choices,
        default=Priority.MEDIUM,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.gap_name


class RiskAssessment(models.Model):
    class Level(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class RecommendedPriority(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        URGENT = "urgent", "Urgent"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="risk_assessments",
    )
    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="risk_assessments",
    )
    gap = models.ForeignKey(
        "risk.GapFinding",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="risk_assessments",
    )
    SCALE_VALIDATORS = [MinValueValidator(1), MaxValueValidator(5)]

    risk_title = models.CharField(max_length=255)
    likelihood = models.PositiveSmallIntegerField(validators=SCALE_VALIDATORS, default=3)
    impact = models.PositiveSmallIntegerField(validators=SCALE_VALIDATORS, default=3)
    risk_level = models.CharField(
        max_length=20,
        choices=Level.choices,
        default=Level.MEDIUM,
    )
    reasoning = models.TextField()
    recommended_priority = models.CharField(
        max_length=20,
        choices=RecommendedPriority.choices,
        default=RecommendedPriority.MEDIUM,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def risk_score(self) -> int:
        return self.likelihood * self.impact

    def __str__(self) -> str:
        return self.risk_title


class RiskNarration(models.Model):
    """A saved Risk Advisor run for a specific gap/risk pair, so the
    result survives navigating away and a fresh page load doesn't
    require re-running (and re-paying for) the AI call.

    Mirrors incidents.AnalystResult's "latest wins" pattern, scoped to
    GapFinding since that's the individually-listed unit on the Detected
    Gaps page (each incident has exactly one gap + one risk, created
    together by apps.risk.services.assessment).
    """

    gap = models.ForeignKey(
        "risk.GapFinding",
        on_delete=models.CASCADE,
        related_name="risk_narrations",
    )
    narration_text = models.TextField()
    model_used = models.CharField(max_length=100, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self) -> str:
        return f"Risk narration for gap {self.gap_id} ({self.generated_at})"


class RiskQuestion(models.Model):
    """One on-demand question+answer pair asked of the Risk Advisor agent
    about a specific gap/risk pair. Mirrors incidents.AnalystQuestion's
    thread pattern exactly (every question kept, not "latest wins" like
    RiskNarration) and is scoped to GapFinding for the same reason
    RiskNarration is: each incident has exactly one gap + one risk, and
    GapFinding is the individually-listed unit on the Detected Gaps page.
    """

    gap = models.ForeignKey(
        "risk.GapFinding",
        on_delete=models.CASCADE,
        related_name="risk_questions",
    )
    question_text = models.TextField()
    answer_text = models.TextField()
    model_used = models.CharField(max_length=100, blank=True)
    asked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["asked_at"]

    def __str__(self) -> str:
        return f"Question on gap {self.gap_id} ({self.asked_at})"


class UserQuestion(models.Model):
    class Category(models.TextChoices):
        GAP_RISK = "gap_risk", "Gap / Risk"
        RESILIENCE = "resilience", "Resilience"
        PLAYBOOK = "playbook", "Playbook"
        REPORT = "report", "Report"
        GENERAL = "general", "General"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="user_questions",
    )
    asked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="caribsecure_questions",
    )
    category = models.CharField(
        max_length=20,
        choices=Category.choices,
        default=Category.GENERAL,
    )
    question_text = models.TextField()
    response_summary = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.category}: {self.question_text[:40]}"
