from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


class IncidentGroup(models.Model):
    class Severity(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        INVESTIGATING = "investigating", "Investigating"
        CONTAINED = "contained", "Contained"
        RESOLVED = "resolved", "Resolved"
        CLOSED = "closed", "Closed"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="incidents",
    )
    title = models.CharField(max_length=255)
    incident_type = models.CharField(max_length=100)
    severity = models.CharField(
        max_length=20,
        choices=Severity.choices,
        default=Severity.MEDIUM,
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.OPEN,
    )
    affected_systems = models.TextField(blank=True)
    summary = models.TextField(blank=True)
    ai_reasoning = models.TextField(blank=True)
    confidence = models.FloatField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0.0), MaxValueValidator(1.0)],
    )
    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    workflow_state = models.JSONField(default=dict, blank=True)
    # Real ownership, replacing the old workflow_state["assigned_to"]
    # display-name string: a proper FK (same pattern as AuditLog.user)
    # so "my investigations" is a real indexed query, not JSON-content
    # string matching, and survives a user renaming their account.
    # Set two ways -- see apps.incidents.views._auto_assign_investigator
    # (automatic, only when unassigned, on starting the guided workflow)
    # and incident_assign_to_me (explicit, always overwrites -- the
    # deliberate takeover/reassignment action).
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_incidents",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.title


class IncidentEvidence(models.Model):
    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.CASCADE,
        related_name="evidence_items",
    )
    alert = models.ForeignKey(
        "log_intake.ParsedAlert",
        on_delete=models.CASCADE,
        related_name="incident_links",
    )
    evidence_reason = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"Evidence for {self.incident.title}"


class IncidentSourceIPLink(models.Model):
    """Records that this incident shares a source IP with alerts from a
    different, prior upload/incident, so the connection is surfaced
    explicitly instead of the two incidents staying disconnected duplicates.
    """

    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.CASCADE,
        related_name="source_ip_links",
    )
    related_incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.CASCADE,
        related_name="source_ip_linked_from",
    )
    source_ip = models.GenericIPAddressField()
    matched_alert = models.ForeignKey(
        "log_intake.ParsedAlert",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["incident", "related_incident", "source_ip"],
                name="unique_incident_source_ip_link",
            )
        ]

    def __str__(self) -> str:
        return f"{self.incident_id} <- {self.source_ip} -> {self.related_incident_id}"


class AnalystResult(models.Model):
    """A saved Analyst-agent run for an incident, so the result survives
    navigating away and a fresh page load doesn't require re-running (and
    re-paying for) the AI call.
    """

    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.CASCADE,
        related_name="analyst_results",
    )
    analysis_text = models.TextField()
    model_used = models.CharField(max_length=100, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self) -> str:
        return f"Analyst result for incident {self.incident_id} ({self.generated_at})"


class AnalystQuestion(models.Model):
    """One on-demand question+answer pair asked of the Analyst agent about a
    specific incident. Unlike AnalystResult (one "latest wins" analysis),
    every question is kept -- this is a growing thread, not a single slot.
    """

    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.CASCADE,
        related_name="analyst_questions",
    )
    question_text = models.TextField()
    answer_text = models.TextField()
    model_used = models.CharField(max_length=100, blank=True)
    asked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["asked_at"]

    def __str__(self) -> str:
        return f"Question on incident {self.incident_id} ({self.asked_at})"


class IncidentComparison(models.Model):
    """One on-demand "compare this incident with another" run, triggered
    from `incident`'s detail page against `compared_incident`. Like
    AnalystQuestion (and unlike AnalystResult's "latest wins" single
    slot), every comparison is kept -- a security team may compare the
    same incident against several different candidates over time, and
    each is its own distinct result worth keeping, not an overwrite.
    """

    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.CASCADE,
        related_name="comparisons_started_here",
    )
    compared_incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.CASCADE,
        related_name="comparisons_targeting_here",
    )
    comparison_text = models.TextField()
    model_used = models.CharField(max_length=100, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["generated_at"]

    def __str__(self) -> str:
        return (
            f"Comparison of incident {self.incident_id} vs "
            f"{self.compared_incident_id} ({self.generated_at})"
        )


class IncidentExplanation(models.Model):
    """A saved Incident Explainer run for a specific audience, reusing
    the same underlying incident context as AnalystResult but reframed
    for someone other than a technical analyst.

    One flexible model with an `audience` field rather than two
    near-identical models -- both audiences share the exact same
    gather/persist/display shape and differ only in system preamble, so
    a second model would just be this one copy-pasted. "Latest wins" per
    (incident, audience) pair, same pattern as AnalystResult's single
    slot, just partitioned by audience.
    """

    class Audience(models.TextChoices):
        PLAIN_LANGUAGE = "plain_language", "Plain Language"
        MANAGEMENT = "management", "What To Tell Management"

    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.CASCADE,
        related_name="explanations",
    )
    audience = models.CharField(max_length=20, choices=Audience.choices)
    explanation_text = models.TextField()
    model_used = models.CharField(max_length=100, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self) -> str:
        return f"{self.get_audience_display()} explanation for incident {self.incident_id} ({self.generated_at})"


class WorkflowStepGuidance(models.Model):
    """AI-recommended "do this next" guidance for one stage of the guided
    Understand/Verify/Respond/Resolve workflow. "Latest wins" per
    (incident, stage) -- same overwrite pattern as AnalystResult -- since
    a stage's recommendation is regenerated as the underlying facts for
    that stage change (e.g. verification answers submitted), and only the
    newest one is ever shown. Unlike AnalystResult, more than one stage can
    have its own current guidance at once, so this is scoped by `stage`.
    """

    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.CASCADE,
        related_name="workflow_step_guidance",
    )
    stage = models.CharField(max_length=20)
    next_step_text = models.TextField()
    model_used = models.CharField(max_length=100, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self) -> str:
        return f"{self.stage} guidance for incident {self.incident_id} ({self.generated_at})"


class WorkflowStepQuestion(models.Model):
    """One on-demand "how do I do this" question+answer pair, scoped to a
    specific stage of the guided workflow (not the whole incident, unlike
    AnalystQuestion). A growing thread per (incident, stage) -- same
    append-only pattern as AnalystQuestion/RiskQuestion/ReadinessQuestion.
    """

    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.CASCADE,
        related_name="workflow_step_questions",
    )
    stage = models.CharField(max_length=20)
    question_text = models.TextField()
    answer_text = models.TextField()
    model_used = models.CharField(max_length=100, blank=True)
    asked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["asked_at"]

    def __str__(self) -> str:
        return f"{self.stage} question on incident {self.incident_id} ({self.asked_at})"


class VerificationItemEvidenceState(models.Model):
    """Per-incident record of which evidence tier backs one Verify-stage
    question in apps.incidents.views._workflow_verification_items --
    EVIDENCE_AVAILABLE (a real, on-hand data source materially informs
    the answer) or MANUAL_CHECK_REQUIRED (nothing in the app's data
    model can speak to it, a human has to check something outside the
    app). Recomputed and updated in place every time the Verify stage
    renders -- same per-(incident, item) mutable-state shape as
    playbooks.ChecklistItemState, not an accumulating thread.
    """

    class Tier(models.TextChoices):
        EVIDENCE_AVAILABLE = "evidence_available", "Evidence Available"
        MANUAL_CHECK_REQUIRED = "manual_check_required", "Manual Check Required"

    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.CASCADE,
        related_name="verification_evidence_states",
    )
    item_key = models.CharField(max_length=50)
    tier = models.CharField(max_length=30, choices=Tier.choices)
    evidence_summary = models.TextField(blank=True)
    computed_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["incident", "item_key"],
                name="unique_incident_verification_item_state",
            )
        ]

    def __str__(self) -> str:
        return f"{self.item_key} evidence state for incident {self.incident_id} ({self.tier})"
