"""Shared free-text -> discrete-step parsing.

Used both by playbooks/views.py (parsing SOPChecklist.checklist_items and
ResponsePlaybook's immediate_steps/next_steps/escalation_steps text
blobs for display) and by the Writer agent (apps/ai_core/modules/writer.py,
parsing Claude's numbered-list response into individual PlaybookStep
rows) -- one parser, so both stay in the same format.
"""

import hashlib
import re


def parse_action_text(text):
    if not text:
        return []

    normalized = re.sub(r"[;|]+", "\n", text)
    parts = []
    for line in normalized.splitlines():
        cleaned = re.sub(r"^\s*(?:[-*]|[0-9]+[.)])\s*", "", line).strip()
        if cleaned:
            parts.append(normalize_sentence(cleaned))
    return parts


def unique_items(items):
    seen = set()
    ordered = []

    for item in items:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(item)

    return ordered


def normalize_sentence(text):
    cleaned = " ".join((text or "").strip().split())
    return cleaned.rstrip(".") + "." if cleaned and not cleaned.endswith(".") else cleaned


def checklist_item_key(text):
    """Stable identity for a parsed checklist line, used by ChecklistItemState.

    Derived from the normalized/lowercased text rather than list position so
    that reordering the source SOPChecklist.checklist_items text doesn't
    silently reassign one incident's completion state to a different item.

    Returned as a SHA-256 digest of the full normalized text, not the text
    itself. Two reasons: it's a fixed-width opaque token, so it drops the old
    ``[:300]`` truncation (two lines identical in their first 300 chars would
    otherwise collide onto one completion state); and it keeps the SOP line
    text out of the ``ChecklistItemState`` row, the hidden form field it's
    rendered into, and anywhere that field might later be logged or stored.
    (The line text is still shown in the clear as the checkbox's own label --
    this is not trying to hide it there.)
    """
    normalized = normalize_sentence(text).strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
