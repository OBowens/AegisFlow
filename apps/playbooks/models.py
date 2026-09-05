from django.db import models


class SOPChecklist(models.Model):
    name = models.CharField(max_length=255)
    incident_type = models.CharField(max_length=100)
    checklist_items = models.TextField()
    version = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.name} v{self.version}"


class ResponsePlaybook(models.Model):
    class Priority(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        URGENT = "urgent", "Urgent"

    class Status(models.TextChoices):
        DRAFT = "draft", "Draft"
        ACTIVE = "active", "Active"
        COMPLETED = "completed", "Completed"
        ARCHIVED = "archived", "Archived"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="response_playbooks",
    )
    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="response_playbooks",
    )
    risk = models.ForeignKey(
        "risk.RiskAssessment",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="response_playbooks",
    )
    readiness_finding = models.ForeignKey(
        "resilience.DisasterReadinessFinding",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="response_playbooks",
    )
    title = models.CharField(max_length=255)
    summary = models.TextField(blank=True)
    immediate_steps = models.TextField(blank=True)
    next_steps = models.TextField(blank=True)
    escalation_steps = models.TextField(blank=True)
    priority = models.CharField(
        max_length=20,
        choices=Priority.choices,
        default=Priority.MEDIUM,
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.DRAFT,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.title


class ChecklistItemState(models.Model):
    """Per-incident completion state for one line of a SOPChecklist.

    Scoped to (incident, checklist) rather than just checklist, since the same
    SOP template applies to many incidents and each incident's progress must
    be tracked independently. Items have no stable ID in the source text blob,
    so they're identified by item_key -- see
    apps.playbooks.services.text_parsing.checklist_item_key for why that's a
    digest of the normalized line text rather than a line index.
    """

    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.CASCADE,
        related_name="checklist_item_states",
    )
    checklist = models.ForeignKey(
        "playbooks.SOPChecklist",
        on_delete=models.CASCADE,
        related_name="item_states",
    )
    item_key = models.CharField(max_length=300)
    is_completed = models.BooleanField(default=False)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["incident", "checklist", "item_key"],
                name="unique_checklist_item_state_per_incident",
            )
        ]

    def __str__(self) -> str:
        state = "completed" if self.is_completed else "pending"
        return f"Incident #{self.incident_id} / {self.checklist_id}: {self.item_key} ({state})"


class PlaybookStep(models.Model):
    class Urgency(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        URGENT = "urgent", "Urgent"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        IN_PROGRESS = "in_progress", "In Progress"
        COMPLETED = "completed", "Completed"
        SKIPPED = "skipped", "Skipped"

    class Source(models.TextChoices):
        GENERIC = "generic", "Generic"
        AI_GENERATED = "ai_generated", "AI Generated"

    playbook = models.ForeignKey(
        "playbooks.ResponsePlaybook",
        on_delete=models.CASCADE,
        related_name="steps",
    )
    step_number = models.PositiveIntegerField()
    action = models.TextField()
    owner = models.CharField(max_length=255, blank=True)
    urgency = models.CharField(
        max_length=20,
        choices=Urgency.choices,
        default=Urgency.MEDIUM,
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
    )
    source = models.CharField(
        max_length=20,
        choices=Source.choices,
        default=Source.GENERIC,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["step_number", "id"]

    def __str__(self) -> str:
        return f"{self.playbook.title} - Step {self.step_number}"
