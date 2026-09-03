"""Agent-facing JSON API for the Windows Endpoint Analyzer (Part 1).

Two endpoints, both POST-only, both authenticated by a per-endpoint
token rather than a Django session:

* ``/endpoints/api/enroll/``  -- confirm a token and bind a display name
* ``/endpoints/api/ingest/``  -- store a batch of reported events

They are ``@csrf_exempt`` (an external agent has no CSRF token; the
Bearer token is the credential) and ``@login_not_required`` (so
``LoginRequiredMiddleware`` does not bounce them to the login page).
No AI, correlation, or severity logic here -- this is storage only.
"""

from __future__ import annotations

import json

from django.contrib.auth.decorators import login_not_required
from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt

from .auth import authenticate_endpoint
from .models import EndpointEvent
from .services import enroll_endpoint

# A single agent batch. The agent (Part 2) filters and batches locally;
# this is a generous ceiling for 5-10 pilot machines, and a guard against
# a misbehaving client trying to push its whole Event Log in one call.
MAX_EVENTS_PER_BATCH = 500


def _json_body(request):
    """Return the parsed JSON object, or a JsonResponse describing why it
    could not be read. Callers check ``isinstance(result, JsonResponse)``.
    """
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return JsonResponse({"error": "Request body must be valid UTF-8 JSON."}, status=400)
    if not isinstance(payload, dict):
        return JsonResponse({"error": "Request body must be a JSON object."}, status=400)
    return payload


@csrf_exempt
@login_not_required
def enroll(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST required."}, status=405)

    body = _json_body(request)
    if isinstance(body, JsonResponse):
        return body

    token = body.get("token")
    if not isinstance(token, str) or not token.strip():
        return JsonResponse({"error": "A 'token' string is required."}, status=400)

    display_name = body.get("display_name", "")
    if not isinstance(display_name, str):
        return JsonResponse({"error": "'display_name' must be a string."}, status=400)

    result = enroll_endpoint(token, display_name)
    if result is None:
        return JsonResponse({"error": "Unknown or invalid enrollment token."}, status=401)

    endpoint = result.endpoint
    return JsonResponse(
        {
            "endpoint": {
                "id": endpoint.id,
                "display_name": endpoint.display_name,
                "organization": endpoint.organization.name,
            },
            # True when the requested name collided and was auto-suffixed.
            # The installer's connectivity-check step must show
            # `endpoint.display_name` to the operator when this is set.
            "name_was_adjusted": result.name_was_suffixed,
        }
    )


@csrf_exempt
@login_not_required
def ingest(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST required."}, status=405)

    endpoint = authenticate_endpoint(request)
    if endpoint is None:
        return JsonResponse({"error": "Missing or invalid endpoint token."}, status=401)

    body = _json_body(request)
    if isinstance(body, JsonResponse):
        return body

    raw_events = body.get("events")
    if not isinstance(raw_events, list):
        return JsonResponse({"error": "'events' must be a list."}, status=400)
    if len(raw_events) > MAX_EVENTS_PER_BATCH:
        return JsonResponse(
            {
                "error": (
                    f"Batch of {len(raw_events)} events exceeds the "
                    f"{MAX_EVENTS_PER_BATCH}-event limit."
                )
            },
            status=400,
        )

    parsed, error = _parse_events(raw_events)
    if error is not None:
        return JsonResponse({"error": error}, status=400)

    now = timezone.now()
    rows = [
        EndpointEvent(
            endpoint=endpoint,
            organization=endpoint.organization,
            event_type=item["event_type"],
            payload=item["payload"],
            occurred_at=item["occurred_at"],
        )
        for item in parsed
    ]
    with transaction.atomic():
        EndpointEvent.objects.bulk_create(rows)
        endpoint.last_seen = now
        endpoint.save(update_fields=["last_seen"])

    return JsonResponse({"accepted": len(rows)})


def _parse_events(raw_events):
    """Validate every event up front and reject the whole batch on the
    first bad one -- a partial write would leave the agent unsure which
    events it still owes.
    """
    parsed = []
    for index, item in enumerate(raw_events):
        if not isinstance(item, dict):
            return None, f"events[{index}] must be a JSON object."

        event_type = item.get("event_type")
        if not isinstance(event_type, str) or not event_type.strip():
            return None, f"events[{index}] is missing a non-empty 'event_type'."
        if len(event_type) > 100:
            return None, f"events[{index}] 'event_type' exceeds 100 characters."

        occurred_raw = item.get("occurred_at")
        if not isinstance(occurred_raw, str) or not occurred_raw.strip():
            return None, f"events[{index}] is missing 'occurred_at'."
        occurred_at = parse_datetime(occurred_raw)
        if occurred_at is None:
            return None, f"events[{index}] 'occurred_at' is not an ISO-8601 datetime."
        if timezone.is_naive(occurred_at):
            occurred_at = timezone.make_aware(occurred_at, timezone.get_default_timezone())

        payload = item.get("payload", {})
        if not isinstance(payload, dict):
            return None, f"events[{index}] 'payload' must be a JSON object."

        parsed.append(
            {
                "event_type": event_type.strip(),
                "occurred_at": occurred_at,
                "payload": payload,
            }
        )
    return parsed, None
