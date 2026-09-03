"""Per-endpoint token authentication for the agent-facing API.

These two endpoints are the only views in the project reached by an
unauthenticated (no Django session) caller -- the Windows agent. They
carry `@login_not_required` so `LoginRequiredMiddleware` lets them
through, and this module is their actual gate: a valid
`Endpoint.enrollment_token` presented as an HTTP Bearer token.
"""

from __future__ import annotations

from .models import Endpoint, hash_token


def extract_bearer_token(request) -> str | None:
    """Pull the token out of `Authorization: Bearer <token>`.

    Also accepts a bare `Authorization: <token>` (no scheme), which is an
    easy mistake to make when hand-testing with curl.
    """
    header = request.META.get("HTTP_AUTHORIZATION", "").strip()
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip() or None
    if len(parts) == 1:
        return parts[0].strip() or None
    return None


def authenticate_endpoint(request) -> Endpoint | None:
    """Return the `Endpoint` whose token authenticates this request, or
    None. The lookup is a single indexed, unique-column query.
    """
    token = extract_bearer_token(request)
    if not token:
        return None
    try:
        return Endpoint.objects.select_related("organization").get(
            token_hash=hash_token(token)
        )
    except Endpoint.DoesNotExist:
        return None
