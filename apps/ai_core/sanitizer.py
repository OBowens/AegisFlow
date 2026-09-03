"""Pseudonymization layer for text sent to the Anthropic API.

Every prompt built by ``apps/ai_core/modules/*`` passes through
``sanitize_for_ai()`` inside ``AnthropicProvider.send_message()`` before the
HTTP request is made, and the model's reply passes back through
``SanitizedPrompt.restore()`` before ``send_message()`` returns. Real
identifiers -- IP addresses, host and domain names, usernames, email
addresses, file paths, and the organization's own name and its
critical-system owner names -- are replaced with stable per-prompt
placeholder tokens (``[[IP_1]]``, ``[[HOST_2]]``, ...). The same real value
always maps to the same token *within one prompt*, so the model can still
reason about "this same IP appeared twice". ``restore()`` puts the real
values back, so nothing downstream (the stored AI output, the on-page
evidence display) ever sees a token.

Design / scope (approved 2026-08-31):

* Detection is **dictionary-first** (the organization's real
  ``CriticalSystem`` / affected-system / account values) then **bounded
  regex**, applied in this order:
  org name -> person names -> internal domains -> emails -> FQDN hosts ->
  bare hosts -> IPs -> file paths -> usernames.
* General name / username NER over free prose is **explicitly out of
  scope**: a person name or a username that appears only in prose --
  matching no structured DB value and no tight regex -- can still reach
  the API. Accepted residual risk; revisit only on evidence of a real
  leak.
* The token -> real map lives only for the duration of one
  ``send_message()`` call. It is never persisted and never shared across
  prompts.
* ``settings.AI_SANITIZER_ENABLED`` (default ``True``) disables the whole
  pass. It exists only so the handful of tests that assert on raw prompt
  text can opt out.

This module does no AI calls and imports Django models lazily, so the
regex passes are unit-testable without a configured database.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Any already-inserted token. Every pass transforms only the text
# *between* these spans, so a value is never tokenized twice and a regex
# can never chew into a token another pass produced.
_TOKEN_RE = re.compile(r"\[\[[A-Z]+_\d+\]\]")

_PLACEHOLDER_NOTE = (
    "Note: some identifiers in the context below (IP addresses, host and "
    "domain names, usernames, email addresses, file paths, and the "
    "organization's own name) have been replaced with placeholder tokens "
    "of the form [[IP_n]], [[HOST_n]], [[USER_n]] and so on. The same real "
    "value always maps to the same token. Refer to them naturally in your "
    "response (\"the affected host\", \"the external IP address\") rather "
    "than repeating the placeholder text verbatim.\n\n"
)

# Account values that are generic roles, not a person -- left in the clear
# because "the admin account" is a meaningful signal and these leak nothing.
_GENERIC_ACCOUNTS = {
    "root", "admin", "administrator", "system", "guest", "nobody",
    "service", "svc", "daemon", "operator", "user", "sysadmin",
}

# Hostname-shaped strings that are really well-known standards / product
# names -- the bare-host regex would otherwise tokenize them.
_HOST_REGEX_STOPWORDS = {
    "sha1", "sha224", "sha256", "sha384", "sha512", "md5",
    "aes128", "aes192", "aes256", "rc4", "des3",
    "base64", "utf8", "utf16", "iso27001", "iso27002", "iso22301",
    "soc2", "pci4", "tls12", "tls13", "http2", "ipv4", "ipv6",
    "win7", "win8", "win10", "win11", "log4j",
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "sept", "oct", "nov", "dec",
    "q1", "q2", "q3", "q4",
}

_INTERNAL_TLDS = ("local", "internal", "corp", "lan", "intranet", "localdomain", "home")
_INTERNAL_TLD_GROUP = r"(?:%s)" % "|".join(_INTERNAL_TLDS)

# A DNS label: alphanumeric ends, internal hyphens allowed.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"

# label.internaltld standing on its own (not preceded by another label or
# an "@", so it does not fire on the domain half of an FQDN or an email --
# those are handled by later passes).
_INTERNAL_DOMAIN_RE = re.compile(
    r"(?<![\w.@-])" + _LABEL + r"\." + _INTERNAL_TLD_GROUP + r"(?![\w-])",
    re.IGNORECASE,
)

# host.(sub.)*internaltld -- a whole internal FQDN, tokenized as one HOST.
_FQDN_HOST_RE = re.compile(
    r"(?<![\w.@-])(?:" + _LABEL + r"\.)+" + _INTERNAL_TLD_GROUP + r"(?![\w-])",
    re.IGNORECASE,
)

_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])"
)

# Uppercase-led host tag: APP01, WEB-01, DB2, FILE01. Deliberately narrow
# (uppercase initial run) to keep it off ordinary lower-case prose; a
# lower-case bare hostname that appears only in prose is the documented
# residual risk.
_BARE_HOST_RE = re.compile(r"(?<![\w.-])[A-Z]{2,}[A-Z0-9]*[-_]?\d{1,4}(?![\w.-])")

_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")

# IPv6 only when it is unambiguous: a "::" compression or the full
# eight-group form. This keeps it off "12:34:56" timestamps and MAC
# addresses; a fully-expanded IPv6 written without "::" is residual risk.
_IPV6_RE = re.compile(
    r"(?<![\w:.])"
    r"(?=[A-Fa-f0-9:]*::|(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}(?![:\w]))"
    r"[A-Fa-f0-9]{0,4}(?::[A-Fa-f0-9]{0,4}){2,7}"
    r"(?![\w:.])"
)

_WINDOWS_PATH_RE = re.compile(r"(?<![\w])[A-Za-z]:\\(?:[^\s\\/:*?\"<>|,;]+\\?)+")
_UNC_PATH_RE = re.compile(r"(?<![\w])\\\\[A-Za-z0-9._-]+\\[^\s\"<>|,;]+")
# POSIX path: at least two "/segment"s, so "/etc/passwd" matches but
# "and/or", "n/a", "24/7" (no leading slash) do not.
_POSIX_PATH_RE = re.compile(r"(?<![\w~])(?:/[A-Za-z0-9._-]+){2,}/?(?![\w/])")


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
    """Replace real identifiers in ``text`` with stable placeholder tokens.

    ``organization`` (an ``apps.organizations.models.Organization`` or
    ``None``) seeds the dictionary of known real values -- its name, its
    ``CriticalSystem`` names/owners, its incidents' affected systems, and
    its parsed-alert accounts. With ``organization=None`` only the regex
    passes run.
    """
    if not text or not _sanitizer_enabled():
        return SanitizedPrompt(text=text or "", mapping={})

    tok = _Tokenizer()
    known = _collect_org_identifiers(organization) if organization is not None else {}
    out = text

    # --- order fixed by the approved design ---------------------------
    out = _dict_pass(out, known.get("ORG", ()), "ORG", tok)
    out = _dict_pass(out, known.get("PERSON", ()), "PERSON", tok)

    out = _dict_pass(out, known.get("DOMAIN", ()), "DOMAIN", tok)
    out = _regex_pass(out, _INTERNAL_DOMAIN_RE, "DOMAIN", tok)

    out = _regex_pass(out, _EMAIL_RE, "EMAIL", tok)

    out = _dict_pass(out, known.get("HOST_FQDN", ()), "HOST", tok)
    out = _regex_pass(out, _FQDN_HOST_RE, "HOST", tok)

    out = _dict_pass(out, known.get("HOST", ()), "HOST", tok)
    out = _regex_pass(out, _BARE_HOST_RE, "HOST", tok, validator=_looks_like_host)

    out = _regex_pass(out, _IPV6_RE, "IP", tok)
    out = _regex_pass(out, _IPV4_RE, "IP", tok, validator=_valid_ipv4)

    out = _regex_pass(out, _WINDOWS_PATH_RE, "PATH", tok)
    out = _regex_pass(out, _UNC_PATH_RE, "PATH", tok)
    out = _regex_pass(out, _POSIX_PATH_RE, "PATH", tok)

    out = _dict_pass(out, known.get("USER", ()), "USER", tok)

    mapping = tok.mapping
    if mapping:
        out = _PLACEHOLDER_NOTE + out
    return SanitizedPrompt(text=out, mapping=mapping)


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------


class _Tokenizer:
    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], str] = {}  # (label, norm real) -> token
        self._by_token: dict[str, str] = {}            # token -> real (first seen)
        self._counts: dict[str, int] = {}

    def token_for(self, real: str, label: str, *, key: str | None = None) -> str:
        norm = (key if key is not None else real).lower()
        cache_key = (label, norm)
        existing = self._by_key.get(cache_key)
        if existing:
            return existing
        n = self._counts.get(label, 0) + 1
        self._counts[label] = n
        token = f"[[{label}_{n}]]"
        self._by_key[cache_key] = token
        self._by_token[token] = real
        return token

    @property
    def mapping(self) -> dict:
        return dict(self._by_token)


def _sanitizer_enabled() -> bool:
    try:
        from django.conf import settings

        return bool(getattr(settings, "AI_SANITIZER_ENABLED", True))
    except Exception:  # pragma: no cover - Django not configured
        return True


def _sub_outside_tokens(text: str, pattern: re.Pattern, repl) -> str:
    """``pattern.sub(repl, ...)`` applied only to the stretches of ``text``
    that are not already an inserted ``[[TYPE_n]]`` token."""
    pieces: list[str] = []
    last = 0
    for m in _TOKEN_RE.finditer(text):
        pieces.append(pattern.sub(repl, text[last:m.start()]))
        pieces.append(m.group(0))
        last = m.end()
    pieces.append(pattern.sub(repl, text[last:]))
    return "".join(pieces)


def _regex_pass(text, pattern, label, tok, *, validator=None) -> str:
    def repl(m):
        value = m.group(0)
        # Keep trailing sentence punctuation out of the token so a period
        # or comma right after an identifier isn't swallowed.
        trailer = ""
        while value and value[-1] in ".,;:":
            trailer = value[-1] + trailer
            value = value[:-1]
        if not value:
            return m.group(0)
        if validator is not None and not validator(value):
            return m.group(0)
        # IPs are case-sensitive as keys; everything else folds case.
        key = value if label == "IP" else value.lower()
        return tok.token_for(value, label, key=key) + trailer

    return _sub_outside_tokens(text, pattern, repl)


def _dict_pass(text, terms, label, tok) -> str:
    cleaned = sorted(
        {t.strip() for t in terms if t and t.strip()}, key=len, reverse=True
    )
    if not cleaned:
        return text
    lower_to_canonical = {t.lower(): t for t in cleaned}
    pattern = re.compile(
        r"(?<![\w-])(?:" + "|".join(re.escape(t) for t in cleaned) + r")(?![\w-])",
        re.IGNORECASE,
    )

    def repl(m):
        matched = m.group(0)
        canonical = lower_to_canonical.get(matched.lower(), matched)
        return tok.token_for(canonical, label, key=canonical.lower())

    return _sub_outside_tokens(text, pattern, repl)


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _looks_like_host(value: str) -> bool:
    return value.lower().replace("-", "").replace("_", "") not in _HOST_REGEX_STOPWORDS


_SYSTEM_SPLIT_RE = re.compile(r"[,;/\n|]+")
_HOSTNAME_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$")


def _split_systems(raw):
    if not raw:
        return []
    return [seg.strip() for seg in _SYSTEM_SPLIT_RE.split(raw) if seg.strip()]


def _classify_host(value, fqdn_hosts: set, bare_hosts: set) -> None:
    if not value:
        return
    value = value.strip()
    if not _HOSTNAME_TOKEN_RE.match(value):  # has spaces / prose / too long
        return
    if "." in value and not _valid_ipv4(value):
        fqdn_hosts.add(value)
    elif not value.isdigit():
        bare_hosts.add(value)


def _collect_org_identifiers(organization) -> dict:
    """Real values to scrub for ``organization``, grouped by pass label.

    Runs once per ``send_message`` call (which is a network round-trip
    anyway); each query is capped so a pathological org can't blow the
    prompt-build time up.
    """
    from apps.incidents.models import IncidentGroup
    from apps.organizations.models import CriticalSystem
    from apps.risk.models import GapFinding

    try:
        from apps.log_intake.models import ParsedAlert
    except Exception:  # pragma: no cover - defensive
        ParsedAlert = None

    try:
        from apps.endpoints.models import Endpoint, EndpointEvent
    except Exception:  # pragma: no cover - defensive
        Endpoint = EndpointEvent = None

    org_names: set[str] = set()
    person_names: set[str] = set()
    fqdn_hosts: set[str] = set()
    bare_hosts: set[str] = set()
    accounts: set[str] = set()

    name = getattr(organization, "name", "") or ""
    if name.strip():
        org_names.add(name.strip())

    for system_name, owner_name in CriticalSystem.objects.filter(
        organization=organization
    ).values_list("system_name", "owner_name")[:1000]:
        _classify_host(system_name, fqdn_hosts, bare_hosts)
        if owner_name and owner_name.strip():
            person_names.add(owner_name.strip())

    for (affected,) in IncidentGroup.objects.filter(
        organization=organization
    ).values_list("affected_systems")[:2000]:
        for piece in _split_systems(affected):
            _classify_host(piece, fqdn_hosts, bare_hosts)

    for (affected,) in GapFinding.objects.filter(
        organization=organization
    ).values_list("affected_system")[:2000]:
        _classify_host(affected, fqdn_hosts, bare_hosts)

    if ParsedAlert is not None:
        for affected_system, account in ParsedAlert.objects.filter(
            organization=organization
        ).values_list("affected_system", "account")[:5000]:
            _classify_host(affected_system, fqdn_hosts, bare_hosts)
            if account and account.strip():
                account = account.strip()
                accounts.add(account)
                local_part = re.split(r"[\\/@]", account)[-1]
                if local_part and local_part != account:
                    accounts.add(local_part)

    # Windows Endpoint Analyzer (apps/endpoints): the endpoint's own name
    # and the usernames its 4688 events carry are exactly the identifiers
    # this feature's payloads are full of. Same dictionary-first handling
    # as CriticalSystem / ParsedAlert above -- the multi-segment hostnames
    # ("WIN-PILOT-01", "DESKTOP-A1B2C3") and bare usernames the regex
    # passes miss are caught here by exact match instead.
    if Endpoint is not None:
        for (display_name,) in Endpoint.objects.filter(
            organization=organization
        ).values_list("display_name")[:1000]:
            _classify_host(display_name, fqdn_hosts, bare_hosts)

    if EndpointEvent is not None:
        for username in (
            EndpointEvent.objects.filter(organization=organization)
            .values_list("payload__data__subject_user_name", flat=True)
            .distinct()[:2000]
        ):
            if username and str(username).strip():
                username = str(username).strip()
                accounts.add(username)
                local_part = re.split(r"[\\/@]", username)[-1]
                if local_part and local_part != username:
                    accounts.add(local_part)

    domains: set[str] = set()
    for fqdn in fqdn_hosts:
        _, _, rest = fqdn.partition(".")
        if rest:
            domains.add(rest)

    accounts = {a for a in accounts if a.lower() not in _GENERIC_ACCOUNTS}

    return {
        "ORG": org_names,
        "PERSON": person_names,
        "DOMAIN": domains,
        "HOST_FQDN": fqdn_hosts,
        "HOST": bare_hosts,
        "USER": accounts,
    }
