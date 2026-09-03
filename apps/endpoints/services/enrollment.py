"""Enrollment logic for the endpoint agent.

Kept out of views.py so the name-collision handling is unit-testable
without going through HTTP.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.db import IntegrityError, transaction

from ..models import Endpoint, hash_token

# A hard ceiling on the auto-suffix search so a pathological org can't
# turn one enrollment into an unbounded scan. 200 same-named endpoints in
# one org is already far past this feature's 5-10 pilot machines.
_MAX_SUFFIX_ATTEMPTS = 200


@dataclass(frozen=True)
class EnrollmentResult:
    endpoint: Endpoint
    #: True when the requested name was already taken (by a *different*
    #: endpoint in the org) and a "-N" suffix was appended. The caller
    #: must surface `endpoint.display_name` back to the installer so the
    #: effective name is visible immediately, not discovered later.
    name_was_suffixed: bool


def _normalize(name: str) -> str:
    return " ".join(name.split()).strip()


def resolve_available_name(organization, requested_name: str, *, exclude_pk=None) -> str:
    """Return `requested_name`, or `requested_name-2`, `-3`, ... -- the
    first that no *other* endpoint in `organization` is using
    (case-insensitively).
    """
    base = _normalize(requested_name)
    siblings = Endpoint.objects.filter(organization=organization)
    if exclude_pk is not None:
        siblings = siblings.exclude(pk=exclude_pk)
    taken = {name.casefold() for name in siblings.values_list("display_name", flat=True)}

    if base.casefold() not in taken:
        return base
    for suffix in range(2, _MAX_SUFFIX_ATTEMPTS + 1):
        candidate = f"{base}-{suffix}"
        if candidate.casefold() not in taken:
            return candidate
    raise ValueError(
        f"Could not find a free variant of {base!r} for organization "
        f"{organization.pk} after {_MAX_SUFFIX_ATTEMPTS} attempts."
    )


def enroll_endpoint(token: str, requested_name: str) -> EnrollmentResult | None:
    """Look up the endpoint owning `token` and bind `requested_name` to it.

    Returns None when the token matches no endpoint. Otherwise:

    * If the endpoint's name already equals `requested_name`
      (case-insensitively), it is left untouched -- re-running the
      installer with the same answers is a no-op.
    * If `requested_name` is free in the org, it is adopted as-is.
    * If a *different* endpoint in the org holds that name, a numeric
      suffix is appended and `name_was_suffixed` is set.

    An empty / whitespace-only `requested_name` keeps the provisioning
    name the operator set with `createendpoint`.
    """
    token = (token or "").strip()
    if not token:
        return None

    try:
        endpoint = Endpoint.objects.select_related("organization").get(
            token_hash=hash_token(token)
        )
    except Endpoint.DoesNotExist:
        return None

    wanted = _normalize(requested_name or "")
    if not wanted or wanted.casefold() == endpoint.display_name.casefold():
        return EnrollmentResult(endpoint=endpoint, name_was_suffixed=False)

    for _ in range(3):  # retry on the race where a sibling name lands mid-resolve
        effective = resolve_available_name(
            endpoint.organization, wanted, exclude_pk=endpoint.pk
        )
        try:
            with transaction.atomic():
                endpoint.display_name = effective
                endpoint.save(update_fields=["display_name"])
            return EnrollmentResult(
                endpoint=endpoint,
                name_was_suffixed=effective.casefold() != wanted.casefold(),
            )
        except IntegrityError:
            endpoint.refresh_from_db(fields=["display_name"])
            continue

    return EnrollmentResult(endpoint=endpoint, name_was_suffixed=False)
