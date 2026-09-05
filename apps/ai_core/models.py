"""Persistent identifier aliasing.

``AliasMapping`` is the durable, org-wide, stable counterpart to the
sensitive-identifier detection that ``apps/ai_core/services/alias_engine.py``
performs. A real value (an IP, a hostname, a username, ...) gets exactly one
row per ``(organization, identifier_type)`` the first time it's ever seen for
that org, and keeps that row -- and therefore its alias -- forever. This is
what lets the same IP render as the same alias across every incident, log
view, and AI prompt for an organization, instead of a fresh, call-scoped
numbering each time (see ``alias_engine.EphemeralAliasStore``, which is kept
unchanged for the ``organization=None`` case).

Org-wide (not investigation-scoped) is a deliberate choice: both
``apps.incidents.services.correlation`` and
``apps.endpoints.services.correlation`` already link records across cases by
real identifier identity, so an alias scoped to one investigation would make
the same IP look like two different entities in a correlated pair.
"""

from django.db import models


class AliasMapping(models.Model):
    class IdentifierType(models.TextChoices):
        IP = "IP", "IP address"
        HOST = "HOST", "Hostname"
        DOMAIN = "DOMAIN", "Domain"
        EMAIL = "EMAIL", "Email address"
        USER = "USER", "Username/account"
        ORG = "ORG", "Organization name"
        PERSON = "PERSON", "Person name"
        PATH = "PATH", "File path"

    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="alias_mappings",
    )
    identifier_type = models.CharField(max_length=20, choices=IdentifierType.choices)
    # Dedup/lookup key: case-folded for every type except IP (kept
    # case-sensitive, matching apps/ai_core/services/alias_engine.py's
    # existing normalization rule so e.g. "j.browne" and "J.Browne" collapse
    # to one row).
    normalized_value = models.CharField(max_length=512)
    # Canonical form actually shown once revealed -- whichever casing/form
    # was seen first for this normalized_value.
    real_value = models.CharField(max_length=512)
    # Per (organization, identifier_type) counter. Assigned once,
    # monotonically increasing, never reused -- this is the "_n" in the
    # alias and it never resets, unlike the old per-call numbering.
    sequence = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "identifier_type", "normalized_value"],
                name="uniq_alias_per_org_type_value",
            ),
            models.UniqueConstraint(
                fields=["organization", "identifier_type", "sequence"],
                name="uniq_alias_sequence_per_org_type",
            ),
        ]
        indexes = [
            models.Index(
                fields=["organization", "identifier_type", "normalized_value"],
                name="aliasmapping_lookup_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.alias_label} -> {self.real_value} ({self.organization_id})"

    @property
    def alias_label(self) -> str:
        return f"{self.identifier_type}_{self.sequence}"

    @property
    def display_alias(self) -> str:
        """On-screen form of the alias, zero-padded for stable column width,
        e.g. ``[IP_007]``. Presentation only -- the stored ``sequence`` and
        the ``ai_token`` form are unchanged, so an existing ``IP_1`` row just
        renders as ``[IP_001]`` without any renumbering."""
        return f"[{self.identifier_type}_{self.sequence:03d}]"

    @property
    def ai_token(self) -> str:
        """Exact format the AI-boundary sanitizer has always emitted, e.g.
        ``"[[IP_1]]"`` -- unpadded, double-bracketed. Kept as-is so
        existing prompts/tests are unaffected by the switch to a
        persistent, org-wide sequence."""
        return f"[[{self.alias_label}]]"
