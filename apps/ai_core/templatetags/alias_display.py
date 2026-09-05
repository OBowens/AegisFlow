"""Display-time alias substitution for structured identifier fields.

``{% load alias_display %}`` then ``{% alias_field value "HOST" organization %}``
renders ``value``'s stable ``AliasMapping`` label (e.g. ``[HOST_003]``) in
place of the real value. The mapping is the same org-scoped one the
AI-boundary sanitizer uses, so a value reads identically in both places.

Minting happens in the view: each list/detail view pre-warms its whole page's
identifier set in one call (``apps.ai_core.services.alias_engine.warm_display_aliases``),
so this tag is a cache read. It still get-or-creates on a miss for
correctness.

Only structured fields (a known column -> a known identifier type) go through
here. Free-text/prose sanitization and the click-to-reveal control are a
later part of the sensitive-identifier overhaul and are not wired up yet --
a rendered alias here has no reveal affordance.

``organization`` is always passed explicitly by the caller (the record's own
``.organization``, or whatever the view resolved for the page); this tag
never guesses one.
"""

from __future__ import annotations

from django import template
from django.utils.html import format_html

from apps.ai_core.services.alias_engine import (
    get_request_alias_store,
    identifier_type_for_system,
    is_non_identity_sentinel,
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
