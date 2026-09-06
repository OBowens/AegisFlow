"""Pseudonymization layer for text sent to the Anthropic API.

Every prompt built by ``apps/ai_core/modules/*`` passes through
``sanitize_for_ai()`` inside ``AnthropicProvider.send_message()`` before the
HTTP request is made, and the model's reply passes back through
``SanitizedPrompt.restore()`` before ``send_message()`` returns. Real
identifiers -- IP addresses, host and domain names, usernames, email
addresses, file paths, and the organization's own name and its
critical-system owner names -- are replaced with placeholder tokens
(``[[IP_1]]``, ``[[HOST_2]]``, ...) before anything leaves the process.
``restore()`` puts the real values back, so nothing downstream (the stored
AI output, the on-page evidence display) ever sees a token.

Detection itself (the regexes, the dictionary-first passes, the fixed pass
order) lives in ``apps/ai_core/services/alias_engine.py``. The pass order
and semantics are the original design (approved 2026-08-31); a 2026-09-05
amendment relaxed the IPv4 / IPv6 / bare-host trailing lookaheads so a
sentence-final identifier ("...from 203.0.113.9.") is no longer missed --
strictly more values pseudonymized, never fewer (see that module's
docstring and the before/after matrix in tests_sanitizer.py). What
changed here:

* With an ``organization``, token assignment is no longer ephemeral --
  it's backed by ``apps.ai_core.models.AliasMapping``, so the same real
  value always gets the same alias for that org, forever, not just within
  one prompt. This is required groundwork for a later display-layer reveal
  system that needs the same alias to render identically across every page,
  not just within one AI call; it changes nothing observable here, since
  ``restore()`` still converts every token back to its real value before
  this function returns.
* With ``organization=None`` there's no org to scope a durable alias to,
  so behaviour is byte-for-byte the original: a fresh, in-process,
  per-call numbering that is never persisted (``EphemeralAliasStore``).

This module still does no AI calls; the DB access for the ``organization``
case is confined to ``alias_engine.collect_org_identifiers`` (dictionary
seeding, same as before) and ``PersistentAliasStore`` (new).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from apps.ai_core.services.alias_engine import (
    EphemeralAliasStore,
    PersistentAliasStore,
    collect_org_identifiers,
    run_passes,
)

_PLACEHOLDER_NOTE = (
    "Note: some identifiers in the context below (IP addresses, host and "
    "domain names, usernames, email addresses, file paths, and the "
    "organization's own name) have been replaced with placeholder tokens "
    "of the form [[IP_n]], [[HOST_n]], [[USER_n]] and so on. The same real "
    "value always maps to the same token. Refer to them naturally in your "
    "response (\"the affected host\", \"the external IP address\") rather "
    "than repeating the placeholder text verbatim.\n\n"
)


@dataclass(frozen=True)
class SanitizedPrompt:
    """Result of :func:`sanitize_for_ai`.

    ``text`` is the scrubbed prompt to send to the API. ``restore(response)``
    turns the model's placeholder-bearing reply back into real values.
    """

    text: str
    mapping: dict = field(default_factory=dict)  # token -> real value (first seen)

    def restore(self, response: str) -> str:
        if not response or not self.mapping:
            return response
        result = response
        # Longest token first so "[[IP_10]]" is handled before "[[IP_1]]".
        for token in sorted(self.mapping, key=len, reverse=True):
            real = self.mapping[token]
            core = re.escape(token[2:-2])  # "IP_1"
            # Lenient: tolerate the model dropping one bracket on each side
            # ("[[IP_1]", "[IP_1]"), but still require at least one bracket
            # pair so "IP_1" inside "IP_10" or ordinary prose is left alone.
            pattern = re.compile(r"\[\[?" + core + r"\]\]?")
            result = pattern.sub(lambda _m, r=real: r, result)
        return result


def sanitize_for_ai(text: str, *, organization=None) -> SanitizedPrompt:
    """Replace real identifiers in ``text`` with placeholder tokens.

    ``organization`` (an ``apps.organizations.models.Organization`` or
    ``None``) seeds the dictionary of known real values -- its name, its
    ``CriticalSystem`` names/owners, its incidents' affected systems, and
    its parsed-alert accounts -- and, when given, makes token assignment
    durable and org-wide via ``AliasMapping`` instead of ephemeral.
    With ``organization=None`` only the regex passes run, and numbering is
    ephemeral exactly as before.
    """
    if not text or not _sanitizer_enabled():
        return SanitizedPrompt(text=text or "", mapping={})

    store = PersistentAliasStore(organization) if organization is not None else EphemeralAliasStore()
    known = collect_org_identifiers(organization) if organization is not None else {}

    out = run_passes(text, known, store)

    mapping = store.mapping
    if mapping:
        out = _PLACEHOLDER_NOTE + out
    return SanitizedPrompt(text=out, mapping=mapping)


def _sanitizer_enabled() -> bool:
    try:
        from django.conf import settings

        return bool(getattr(settings, "AI_SANITIZER_ENABLED", True))
    except Exception:  # pragma: no cover - Django not configured
        return True
