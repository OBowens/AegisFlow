"""Authorization gate for revealing a real value behind an alias.

Part of the sensitive-identifier overhaul: sanitized values are meant to
become the display default everywhere (see ``apps/ai_core/models.py``'s
``AliasMapping`` and ``apps/ai_core/services/alias_engine.py``), with a real
value shown only through an explicit reveal action. ``can_reveal`` is the
single choke point that reveal action is required to call before it hands
back a real value.

Today's check is deliberately trivial: authentication only, via
``user.is_authenticated`` -- the exact same access level
``LoginRequiredMiddleware`` (see ``config/settings.py``) already grants
every view in the app. This is not a security downgrade from the status
quo; every authenticated user can already see every real identifier on
every page today (per the investigation this overhaul is based on), so
gating reveal on "is logged in" doesn't grant anything new.

This is an intentional seam, not an oversight. There is exactly one real
user account in this codebase today -- inventing roles or a permission
table now would mean guessing at a shape with no second real user and no
distinct need to validate it against. ``can_reveal`` exists so that when a
second real user with an actual distinct need shows up, real
per-user/per-role authorization logic replaces the body of this one
function -- the reveal API and UI built on top of it (Part 3 onward) call
``can_reveal(user)`` and never need to change.

The signature is deliberately minimal -- just ``user`` -- because nothing
today needs more than that. Part 3's reveal API may find it needs to pass
the organization (e.g. "can this user reveal for this org") or the
specific ``AliasMapping`` being revealed (e.g. per-identifier-type rules);
extend the signature then, against that real need, rather than here.
"""

from __future__ import annotations


def can_reveal(user) -> bool:
    return bool(getattr(user, "is_authenticated", False))
