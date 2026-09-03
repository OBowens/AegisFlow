"""Data layer for the Windows Endpoint Analyzer.

* ``Endpoint`` -- a Windows machine enrolled into the platform (Part 1).
* ``EndpointEvent`` -- one security-relevant record it has reported,
  stored verbatim (Part 1). Part 3 adds two nullable columns tracking
  whether the correlation scan has looked at the row yet.
* ``EndpointCorrelationCandidate`` -- a cluster of events that the
  deterministic correlation rules flagged as worth AI triage (Part 3).
  Its ``ai_*`` fields are populated *only* by a real completed triage
  call; a failed / rate-limited / abandoned triage leaves them null so
  the state reads honestly as "not yet triaged".

Provisioning is out-of-band: an operator runs ``manage.py createendpoint``
to mint the row and its token (mirrors ``manage.py createuser``), then
hands the token + a name to whoever installs the agent. The agent's
enrollment call only ever *looks up* an existing row by token and
confirms/rebinds its display name -- it never creates one.
"""

from __future__ import annotations

import hashlib
import secrets

from django.db import models


def generate_raw_token() -> str:
    """A URL-safe per-endpoint secret. ~43 chars from 32 random bytes
    (256 bits of entropy). This value is shown to an operator exactly
    once, by ``createendpoint``; only its hash is ever stored.
    """
    return secrets.token_urlsafe(32)


def hash_token(raw: str) -> str:
    """SHA-256 hex digest of a bearer token.

    A plain fast hash on purpose -- not a password KDF. The token already
    carries 256 bits of entropy, so there is nothing to brute-force; the
    hash exists only so a leak of the database alone does not hand an
    attacker working fleet credentials. Keeping it fast keeps every
    ingest call's auth check cheap.
    """
    return hashlib.sha256((raw or "").strip().encode("utf-8")).hexdigest()


def _default_token_hash() -> str:
    """Fallback for an ``Endpoint`` row created without going through
    :meth:`Endpoint.issue` (e.g. the Django admin's "add" form, or a
    test building a collision sibling it will never authenticate as).
    Hashes a fresh random token so the unique constraint still holds; the
    raw token is discarded, so such a row simply has no usable
    credential. Real provisioning uses ``createendpoint`` -> ``issue``.
    """
    return hash_token(generate_raw_token())


class Endpoint(models.Model):
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="endpoints",
    )
    # Unique per organization. A case-insensitive clash at enrollment is
    # resolved by auto-suffixing (see services.enroll_endpoint), so this
    # plain constraint is only the last-resort integrity guard -- the same
    # split of responsibilities ParsedAlert/SOPChecklist matching uses.
    display_name = models.CharField(max_length=255)
    # SHA-256 hex digest of the endpoint's bearer token. The raw token is
    # never stored -- see hash_token() and Endpoint.issue().
    token_hash = models.CharField(
        max_length=64,
        unique=True,
        editable=False,
        default=_default_token_hash,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    # Null until the endpoint's first successful ingest call. Set to the
    # server's receipt time, not the agent-reported event time -- agent
    # clock skew would otherwise make "last seen" untrustworthy.
    last_seen = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["display_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "display_name"],
                name="unique_endpoint_name_per_org",
            )
        ]

    def __str__(self) -> str:
        return self.display_name

    @classmethod
    def issue(cls, *, organization, display_name):
        """Create an endpoint and return ``(endpoint, raw_token)``. The
        raw token is the caller's only chance to see it -- only its hash
        is persisted.
        """
        raw_token = generate_raw_token()
        endpoint = cls.objects.create(
            organization=organization,
            display_name=display_name,
            token_hash=hash_token(raw_token),
        )
        return endpoint, raw_token


class EndpointEvent(models.Model):
    endpoint = models.ForeignKey(
        "endpoints.Endpoint",
        on_delete=models.CASCADE,
        related_name="events",
    )
    # Denormalized from endpoint.organization, same pattern as
    # ParsedAlert.organization: later parts (the work queue) scope large
    # event queries by organization directly.
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="endpoint_events",
    )
    # Free text on purpose at this stage -- the Windows channel / Event ID
    # label the agent chooses to send (e.g. "Security/4625"). No
    # vocabulary is enforced until the correlation part needs one.
    event_type = models.CharField(max_length=100, db_index=True)
    payload = models.JSONField(default=dict, blank=True)
    # When the event happened on the endpoint, as reported by the agent.
    occurred_at = models.DateTimeField(db_index=True)
    # When the platform stored it.
    received_at = models.DateTimeField(auto_now_add=True)

    # --- Part 3: correlation-scan bookkeeping ---
    # Set on every event a correlation scan has considered, so the next
    # scan does not re-process it. Null = not yet scanned.
    correlation_scanned_at = models.DateTimeField(null=True, blank=True, db_index=True)
    # Set only on events that were folded into a flagged cluster.
    candidate = models.ForeignKey(
        "endpoints.EndpointCorrelationCandidate",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="events",
    )

    class Meta:
        ordering = ["-received_at"]

    def __str__(self) -> str:
        return f"{self.event_type} @ {self.endpoint_id}"


class EndpointCorrelationCandidate(models.Model):
    """A cluster of an endpoint's events that the deterministic
    correlation rules flagged as worth AI triage.

    ``trigger_summary`` is mechanical -- exactly which rules fired and
    why. The ``ai_*`` fields are filled in only by a real, completed
    triage call: ``TRIAGE_FAILED`` / ``RATE_LIMITED`` / ``ABANDONED``
    leave them blank so nothing ever displays a verdict or severity that
    did not come from the model.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending triage"
        ESCALATED = "escalated", "Escalated to incident"
        BENIGN = "benign", "Triaged - not worth attention"
        TRIAGE_FAILED = "triage_failed", "Triage call failed"
        RATE_LIMITED = "rate_limited", "Triage rate-limited"
        ABANDONED = "abandoned", "Triage abandoned - manual check required"

    class Verdict(models.TextChoices):
        ESCALATE = "escalate", "Escalate"
        BENIGN = "benign", "Benign"

    class Severity(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    # Retries of a failed / rate-limited triage before we stop and leave
    # the candidate visible as "manual check required".
    MAX_TRIAGE_ATTEMPTS = 5

    endpoint = models.ForeignKey(
        "endpoints.Endpoint",
        on_delete=models.CASCADE,
        related_name="correlation_candidates",
    )
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="endpoint_correlation_candidates",
    )

    # The event window this cluster covers (deterministic).
    first_event_at = models.DateTimeField()
    last_event_at = models.DateTimeField()
    event_count = models.PositiveIntegerField(default=0)
    # Which correlation rule(s) fired and why -- never AI-derived.
    trigger_summary = models.TextField()

    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.PENDING, db_index=True
    )
    attempt_count = models.PositiveIntegerField(default=0)

    # Populated only by a real completed triage call.
    ai_verdict = models.CharField(max_length=10, choices=Verdict.choices, blank=True)
    ai_severity = models.CharField(max_length=10, choices=Severity.choices, blank=True)
    ai_summary = models.TextField(blank=True)
    ai_reasoning = models.TextField(blank=True)
    ai_model = models.CharField(max_length=100, blank=True)
    ai_error = models.TextField(blank=True)

    incident = models.ForeignKey(
        "incidents.IncidentGroup",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="endpoint_correlation_candidates",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    triaged_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Candidate for {self.endpoint_id} ({self.get_status_display()})"

    @property
    def is_retryable(self) -> bool:
        return (
            self.status in {self.Status.TRIAGE_FAILED, self.Status.RATE_LIMITED}
            and self.attempt_count < self.MAX_TRIAGE_ATTEMPTS
        )
