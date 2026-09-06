"""Display-time alias substitution.

``{% load alias_display %}`` then:

* ``{% alias_field value "HOST" organization %}`` -- a single *structured*
  identifier column (Part 4). Renders ``value``'s stable ``AliasMapping``
  label (e.g. ``[HOST_003]``) in place of the real value. Minting happens
  in the view via ``warm_display_aliases``; this tag is a cache read (it
  still get-or-creates on a miss for correctness).

* ``{% alias_prose value organization %}`` -- a block of *free text* (Part
  5): an AI analysis/answer/report, a composed incident title or summary,
  or raw log text. Runs the shared detection pipeline over the whole block
  so every real identifier in it becomes its ``[TYPE_00n]`` alias while
  ordinary words are untouched; newlines become ``<br>``. Fail-closed --
  see ``apps.ai_core.services.alias_engine.sanitize_prose_for_display``.

Both use the same org-scoped ``AliasMapping`` the AI-boundary sanitizer
uses, so a value reads identically everywhere. Neither has a click-to-reveal
affordance yet -- that's Part 6.

``organization`` is always passed explicitly by the caller (the record's own
``.organization``, or whatever the view resolved for the page); these tags
never guess one.
"""

from __future__ import annotations

from django import template
from django.utils.html import format_html

from apps.ai_core.services.alias_engine import (
    get_request_alias_store,
    identifier_type_for_system,
    is_non_identity_sentinel,
    sanitize_prose_for_display,
)

register = template.Library()


@register.simple_tag(takes_context=True)
def alias_field(context, value, identifier_type, organization):
    if value is None or value == "" or organization is None:
        return ""
    text = str(value)
    # A missing-value placeholder ("Unknown system", "Unassigned", the
    # "AegisFlow AI" system actor, ...) is not an identifier -- render it
    # plainly, never as an alias, and never mint a row for it.
    if is_non_identity_sentinel(text):
        return text
    if identifier_type == "HOST":
        identifier_type = identifier_type_for_system(text)
    store = get_request_alias_store(context.get("request"), organization)
    return format_html(
        '<span class="af-alias">{}</span>',
        store.display_alias_for(text, identifier_type),
    )


@register.simple_tag(takes_context=True)
def alias_prose(context, value, organization):
    """Sanitize a block of stored free text / AI prose for display: every
    real identifier becomes its stable ``[TYPE_00n]`` alias, ordinary words
    are left untouched, newlines become ``<br>``. Fail-closed."""
    return sanitize_prose_for_display(
        value, organization, request=context.get("request")
    )
