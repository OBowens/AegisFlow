"""This app is single-tenant in practice: there is exactly one real
organization a deployment cares about (plus, occasionally, stray/test
rows). Every page that needs "the" organization for an ambient,
whole-app summary -- not a specific record it's already looking at --
should resolve it the same way.

Before this existed, half a dozen places each guessed "the current
organization" independently: some used the oldest Organization row
directly, others sniffed whichever upload/incident/finding/report/
playbook happened to be most recently touched. The sniffing approach is
the fragile one -- a single stray or test row belonging to a different
organization (see the "T"/"A" contamination incident) could silently
hijack an entire page's organization-scoped data, which is exactly what
happened to the Work Queue Overview panel. This is the one,
deliberately simple, canonical resolution every such page now shares.

This is NOT for pages that are already looking at a specific, known
record (e.g. a page scoped to one particular uploaded file) -- those
should keep using that record's own `.organization` directly, since
that's a real, request-driven scope, not a guess.
"""

from apps.organizations.models import Organization

DEFAULT_ORGANIZATION_DEFAULTS = {
    "name": "AegisFlow AI Demo Organization",
    "organization_type": "Demo Organization",
    "country": "St. Vincent and the Grenadines",
    "sector": "Demo",
    "risk_profile": "medium",
}


def get_current_organization() -> Organization:
    existing = Organization.objects.order_by("created_at").first()
    if existing:
        return existing
    return Organization.objects.create(**DEFAULT_ORGANIZATION_DEFAULTS)
