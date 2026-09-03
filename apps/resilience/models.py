from django.conf import settings
from django.db import models


class DisasterReadinessFinding(models.Model):
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
        related_name="readiness_findings",
    )
    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="readiness_findings",
    )
    risk = models.ForeignKey(
        "risk.RiskAssessment",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="readiness_findings",
    )
    readiness_issue = models.CharField(max_length=255)
    disaster_impact = models.TextField()
    recovery_concern = models.TextField()
    source = models.CharField(
        max_length=20,
        choices=Source.choices,
        default=Source.LOG_BASED,
    )
    priority = models.CharField(
        max_length=20,
        choices=Priority.choices,
        default=Priority.MEDIUM,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.readiness_issue


class ReadinessPlan(models.Model):
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="readiness_plans",
    )
    scenario = models.CharField(max_length=255)
    checklist = models.TextField(blank=True)
    questions = models.TextField(blank=True)
    recommended_actions = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.scenario


class ReadinessAnswer(models.Model):
    """A user-submitted answer to a readiness question, e.g. from the
    'Ask a Readiness Question' panel or a manual readiness review.
    """

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="readiness_answers",
    )
    question_text = models.CharField(max_length=255)
    answer_text = models.TextField()
    answered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="readiness_answers",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.question_text


class ReadinessQuestion(models.Model):
    """One on-demand question+answer pair asked of the Readiness Advisor
    agent about an organization's overall disaster readiness. Mirrors
    risk.RiskQuestion's thread pattern exactly (every question kept, not
    "latest wins" like ReadinessExplanation), scoped to Organization
    instead of GapFinding since the Disaster Readiness page is
    organization-wide, not tied to one gap/risk pair.

    Not to be confused with ReadinessAnswer above -- that's a
    user-submitted answer to a fixed readiness questionnaire, used to
    detect contradictions against real findings
    (apps.resilience.services.contradictions). This is a free-typed
    question to the AI advisor and its generated answer.
    """

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="readiness_questions",
    )
    question_text = models.TextField()
    answer_text = models.TextField()
    model_used = models.CharField(max_length=100, blank=True)
    asked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["asked_at"]

    def __str__(self) -> str:
        return f"Question on {self.organization_id} readiness ({self.asked_at})"


class ReadinessExplanation(models.Model):
    """A saved Readiness Advisor run for an organization, so the result
    survives navigating away and a fresh page load doesn't require
    re-running (and re-paying for) the AI call.

    Mirrors incidents.AnalystResult's "latest wins" pattern, but scoped
    to Organization instead of IncidentGroup -- the Disaster Readiness
    page is organization-wide, not tied to one incident.
    """

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="readiness_explanations",
    )
    explanation_text = models.TextField()
    model_used = models.CharField(max_length=100, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self) -> str:
        return f"Readiness explanation for {self.organization_id} ({self.generated_at})"


class ReadinessScoreSnapshot(models.Model):
    """One point-in-time reading of an organization's disaster-readiness
    score, recorded each time apps.resilience.views.index computes it --
    the dedicated Disaster Readiness page, not the sidebar nav badge or
    dashboard/Work Queue cards that also call compute_readiness_score.
    Those render on nearly every page view across the whole app; snapshotting
    there would produce a row on almost every request and drown any real
    trend in noise. This page is the deliberate "check readiness" moment.

    Never backfilled with fabricated historical points -- only real
    computations create a row, so a young organization's trend chart
    honestly shows few points until more real checks accumulate.
    """

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="readiness_score_snapshots",
    )
    score = models.PositiveSmallIntegerField()
    computed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["computed_at"]

    def __str__(self) -> str:
        return f"Readiness score {self.score}% for {self.organization_id} ({self.computed_at})"
