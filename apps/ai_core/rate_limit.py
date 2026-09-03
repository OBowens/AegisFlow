"""Rate limiting for the AI endpoints -- Part G, item 3.

There is no real auth and exactly one tenant (see
apps/organizations/services/current_organization.py), so the limits are
keyed on time alone -- not per-user or per-session. The counter is the
``AIRun`` table that ``apps/audit`` already writes one row to for every AI
call, right before the provider call. "AI calls in the last hour" is
therefore just a ``COUNT`` over ``created_at`` -- no cache backend (the
default ``LocMemCache`` would be per-gunicorn-worker and wrong), no new
dependency.

Two rolling windows, both env-overridable via settings:

* **global**          -- ``settings.AI_RATE_LIMIT_GLOBAL_PER_HOUR``   (default 40 / 60 min)
* **per-endpoint**    -- ``settings.AI_RATE_LIMIT_ENDPOINT_PER_MINUTE`` (default 8 / 60 s)

``settings.AI_RATE_LIMIT_ENABLED`` (default ``True``) turns the whole
thing off.

Rows for ``ai_module="demo_log_workflow"`` are excluded: that pipeline
writes an ``AIRun`` row on every upload but makes no Claude call
(deterministic parsing/grouping only).

Usage in a view, right before its ``AIRun.objects.create(STARTED)`` row::

    denied = deny_ai_call(incident.organization, "analyst")
    if denied:
        return _render_incident_action_result(request, incident, analysis_error=denied)

``deny_ai_call`` returns ``None`` when the call is allowed. When it is
denied it writes the ``AIRun`` FAILED row itself (so every rejection is
audited exactly like a real failure) and returns the friendly message
string for the view to drop into its existing error-context key or
``messages.error()``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from apps.audit.models import AIRun

# ai_module values that write an AIRun row but never call the provider.
_NON_BILLABLE_MODULES = ("demo_log_workflow",)

_GLOBAL_WINDOW_SECONDS = 3600
_ENDPOINT_WINDOW_SECONDS = 60

_BURST_MESSAGE = "You're generating these a bit fast — wait a moment and try again."


@dataclass(frozen=True)
class RateLimitVerdict:
    message: str  # shown to the user, via the view's existing error path
    reason: str   # stored on the AIRun FAILED row's error_message


def _default(name: str, fallback):
    return getattr(settings, name, fallback)


def _count_ai_runs(within_seconds: int, ai_module: str | None = None) -> int:
    since = timezone.now() - timedelta(seconds=within_seconds)
    queryset = AIRun.objects.filter(created_at__gte=since).exclude(
        ai_module__in=_NON_BILLABLE_MODULES
    )
    if ai_module is not None:
        queryset = queryset.filter(ai_module=ai_module)
    return queryset.count()


def _minutes_until_global_slot_frees(per_hour: int) -> int:
    """Rough "try again in about N minutes" for the hourly cap: when the
    oldest call still inside the 60-minute window ages out, a slot frees.
    Deliberately an over-estimate (tells the user to wait a touch longer)
    rather than under.
    """
    since = timezone.now() - timedelta(seconds=_GLOBAL_WINDOW_SECONDS)
    oldest = (
        AIRun.objects.filter(created_at__gte=since)
        .exclude(ai_module__in=_NON_BILLABLE_MODULES)
        .order_by("created_at")
        .values_list("created_at", flat=True)
        .first()
    )
    if oldest is None:
        return 1
    frees_at = oldest + timedelta(seconds=_GLOBAL_WINDOW_SECONDS)
    seconds_left = (frees_at - timezone.now()).total_seconds()
    return max(1, math.ceil(seconds_left / 60))


def check_ai_rate_limit(ai_module: str) -> RateLimitVerdict | None:
    """Return a :class:`RateLimitVerdict` if an AI call for ``ai_module``
    is over budget right now, else ``None``. Reads only -- writes nothing.
    """
    if not _default("AI_RATE_LIMIT_ENABLED", True):
        return None

    per_minute = _default("AI_RATE_LIMIT_ENDPOINT_PER_MINUTE", 8)
    per_hour = _default("AI_RATE_LIMIT_GLOBAL_PER_HOUR", 40)

    # Per-endpoint burst first: it's the more local, "you specifically are
    # hammering this one button" signal, and its message is the gentler one.
    if per_minute and _count_ai_runs(_ENDPOINT_WINDOW_SECONDS, ai_module) >= per_minute:
        return RateLimitVerdict(
            message=_BURST_MESSAGE,
            reason=(
                f"rate limited: per-endpoint burst — {ai_module} reached "
                f"{per_minute}/{_ENDPOINT_WINDOW_SECONDS}s"
            ),
        )

    if per_hour and _count_ai_runs(_GLOBAL_WINDOW_SECONDS) >= per_hour:
        minutes = _minutes_until_global_slot_frees(per_hour)
        return RateLimitVerdict(
            message=(
                f"The demo's hourly AI limit ({per_hour} requests) has been reached. "
                f"Try again in about {minutes} minute{'s' if minutes != 1 else ''}."
            ),
            reason=f"rate limited: global hourly — reached {per_hour}/60min",
        )

    return None


def deny_ai_call(organization, ai_module: str) -> str | None:
    """Rate-limit gate for an AI view. Returns ``None`` if the call may
    proceed. If it may not, writes an ``AIRun`` FAILED row describing the
    rejection (so it's audited like any other failed call) and returns the
    friendly message for the caller to surface.
    """
    verdict = check_ai_rate_limit(ai_module)
    if verdict is None:
        return None

    AIRun.objects.create(
        organization=organization,
        ai_module=ai_module,
        input_type="RateLimit",
        input_id="",
        output_type="",
        output_id="",
        status=AIRun.Status.FAILED,
        error_message=verdict.reason,
    )
    return verdict.message
