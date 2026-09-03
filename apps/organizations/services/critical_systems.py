"""Lookup for matching a free-text affected-system name against the
CriticalSystem registry.

Mirrors the exact-match-then-token-fallback pattern already proven in
apps/playbooks/views.py::_resolve_checklist for SOPChecklist matching:
try an exact (case-insensitive) name match first, and only fall back to
a tokenized `icontains` match if nothing matched exactly. Never invents a
result -- returns None when nothing matches, and the caller is
responsible for representing that honestly (never falling back to a
guessed criticality).
"""

from __future__ import annotations

import re

from django.db.models import Q

from apps.organizations.models import CriticalSystem


def resolve_affected_system(text: str, *, organization=None) -> CriticalSystem | None:
    """Resolve a free-text affected-system name to a CriticalSystem row.

    `organization`, when given, scopes the match to that organization's
    own registry (CriticalSystem has a real organization FK, unlike
    SOPChecklist). Pass None to search across all organizations.
    """

    text = (text or "").strip()
    if not text:
        return None

    queryset = CriticalSystem.objects.select_related("organization")
    if organization is not None:
        queryset = queryset.filter(organization=organization)

    exact_match = queryset.filter(system_name__iexact=text).order_by("-updated_at").first()
    if exact_match:
        return exact_match

    # A minimum length keeps this useful against a short structured value
    # like "WEB-01" (its callers' original use case) while not spuriously
    # matching on filler words when given a whole typed sentence instead
    # (apps.ai_core.services.custom_playbook_context passes one) -- a
    # bare 1-2 character token like "a" or "me" is an icontains substring
    # of nearly every system name and produces false matches.
    tokens = [token for token in re.split(r"[^a-z0-9]+", text.lower()) if len(token) >= 3]
    if not tokens:
        return None

    token_query = Q()
    for token in tokens:
        token_query |= Q(system_name__icontains=token)

    return queryset.filter(token_query).order_by("-updated_at").first()
