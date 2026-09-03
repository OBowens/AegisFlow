from django.db import models


class PriorityBriefing(models.Model):
    """A saved "what should I fix first" AI run for an organization, so
    the result survives navigating away and a fresh page load doesn't
    require re-running (and re-paying for) the AI call.

    Mirrors resilience.ReadinessExplanation's "latest wins" pattern,
    scoped to Organization since this reasons across the org's open
    incidents/risks as a whole rather than one incident or gap.
    """

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="priority_briefings",
    )
    briefing_text = models.TextField()
    model_used = models.CharField(max_length=100, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self) -> str:
        return f"Priority briefing for {self.organization_id} ({self.generated_at})"
