"""The App Assistant's "what should I fix first?" shortcut.

The general App Assistant (apps/ai_core/modules/app_assistant.py) answers
only from a fixed app-reference corpus and is told to deflect anything
org-specific to a scoped assistant. That makes it answer "what should I
work on next?" by pointing elsewhere instead of just saying.

This module sits in front of that AI path. It does two things, neither of
which calls an AI provider:

1. ``looks_like_prioritization_question`` -- a curated phrase match that
   recognises a "of the work in front of me, what comes first" question.
   Deliberately not exhaustive: a missed question simply falls through to
   the normal assistant (unchanged behaviour), whereas a false positive
   hijacks an unrelated question, so the patterns favour precision. A
   slightly-too-broad match stays honest because the answer names its own
   source ("your security priority briefing, from Home").

2. ``build_priority_shortcut_answer`` -- fills that question from the most
   recent apps.core.models.PriorityBriefing (a plain DB read, no live
   incident context). It never generates a briefing: if none is fresh it
   says so plainly and points at the Home-page button that does, keeping
   every AI-generating action in this app an explicit user button click.
"""

from __future__ import annotations

import re
from datetime import timedelta

from django.utils import timezone

from apps.core.models import PriorityBriefing

# A briefing older than this is treated as "no current briefing" -- by
# then the org's open incidents have moved on. Tunable default.
PRIORITY_BRIEFING_FRESH_DAYS = 7

# Each pattern is a phrasing that unambiguously asks what to work on
# first, matched against the whitespace-collapsed, lower-cased question.
_PRIORITY_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"\bwhat (should|do|does|can|would) i .*(first|next)\b",
        r"\bwhat should i (focus on|start with|work on|tackle|prioriti[sz]e)\b",
        r"\bprioriti[sz]e\b",
        r"\bwhat('?s| is| are)\b.*\bmost (urgent|important|pressing|critical)\b",
        r"\bwhat('?s| is| are)\b.*\bpriorit(y|ies)\b",
        r"\bwhat (needs|requires|deserves|should get) .*attention\b",
        r"\bwhere (do|should) i (start|begin)\b",
        r"\bwhat('?s| is) next\b",
        r"\bwhat matters most\b",
        r"\bfix first\b",
        r"\btriage\b.*\bincident",
    )
)


def looks_like_prioritization_question(question: str) -> bool:
    """True when `question` is asking what to prioritise / fix first /
    focus on / do next, by curated phrase match -- no AI call."""
    if not question:
        return False
    normalized = re.sub(r"\s+", " ", question).strip().lower()
    return any(pattern.search(normalized) for pattern in _PRIORITY_PATTERNS)


def build_priority_shortcut_answer(organization) -> str:
    """Answer text for a prioritization question, taken from the latest
    PriorityBriefing for `organization`. Never triggers generation."""
    latest = (
        PriorityBriefing.objects.filter(organization=organization)
        .order_by("-generated_at")
        .first()
    )

    if latest and latest.generated_at >= timezone.now() - timedelta(
        days=PRIORITY_BRIEFING_FRESH_DAYS
    ):
        generated = timezone.localtime(latest.generated_at).strftime("%b %d, %Y %H:%M")
        return (
            "Here is your current security priority briefing, from the Home page "
            f"(generated {generated}):\n\n"
            f"{latest.briefing_text.strip()}\n\n"
            "You can see this next to your ranked incidents, or regenerate it, "
            'with the "Refresh priorities" button on the Home page.'
        )

    if latest:
        generated = timezone.localtime(latest.generated_at).strftime("%b %d, %Y")
        return (
            f"Your most recent priority briefing was generated on {generated}, which "
            "is likely out of date now. AegisFlow does not refresh it automatically "
            '-- open the Home page and use the "Refresh priorities" button in the '
            '"What Should I Fix First?" panel to generate a current ranked list.'
        )

    return (
        "No priority briefing has been generated for your organization yet. "
        "AegisFlow does not create one automatically -- open the Home page and use "
        'the "Explain priorities" button in the "What Should I Fix First?" panel to '
        "generate a ranked list of what to fix first."
    )
