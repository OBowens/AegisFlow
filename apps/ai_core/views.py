"""The reveal endpoint: the one HTTP entry point that hands back a real
value behind an ``AliasMapping`` alias, per ``apps/ai_core/reveal_policy.py``.

Every attempt that reaches this view -- allowed, denied, or the alias
not existing (for this org) at all -- is written to ``AuditLog``. A
not-found lookup is logged deliberately, not skipped: a pattern of
not-found attempts (e.g. sequential id probing) is itself audit-worthy,
arguably more so than a straightforward permission denial.

What this guarantee does *not* cover: an unauthenticated request never
reaches this view at all. ``LoginRequiredMiddleware`` (config/settings.py)
redirects it before ``process_view`` gets here, and -- independently --
``CsrfViewMiddleware`` rejects any POST without a valid CSRF token before
that, since it runs earlier in ``MIDDLEWARE``. Neither of those upstream
rejections goes through this view, so neither is (or can be) recorded in
``AuditLog`` here. This is proven, not assumed: see
``tests_reveal_view.py``'s ``test_raw_anonymous_request_without_csrf_token_never_reaches_the_view``.
The logging guarantee this module actually provides is: every reveal
attempt by a request that reaches the view -- i.e. authenticated, with a
valid CSRF token -- is logged, whether it is allowed, denied, or not found.
"""

from __future__ import annotations

from django.http import JsonResponse
from django.views.decorators.http import require_POST

from apps.audit.models import AuditLog
from apps.organizations.services.current_organization import get_current_organization

from .models import AliasMapping
from .reveal_policy import can_reveal


def _log(*, organization, request, action, target_id, details=""):
    AuditLog.objects.create(
        organization=organization,
        user=request.user if request.user.is_authenticated else None,
        action=action,
        target_type="AliasMapping",
        target_id=str(target_id),
        ip_address=request.META.get("REMOTE_ADDR", "") or "",
        details=details,
    )


@require_POST
def reveal_alias(request, pk):
    organization = get_current_organization()

    try:
        alias = AliasMapping.objects.get(pk=pk, organization=organization)
    except AliasMapping.DoesNotExist:
        _log(organization=organization, request=request, action="reveal_alias_not_found", target_id=pk)
        return JsonResponse({"detail": "Not found."}, status=404)

    if not can_reveal(request.user):
        _log(organization=organization, request=request, action="reveal_alias_denied", target_id=alias.pk)
        return JsonResponse({"detail": "Not allowed."}, status=403)

    _log(
        organization=organization,
        request=request,
        action="reveal_alias",
        target_id=alias.pk,
        details=alias.alias_label,
    )
    return JsonResponse({"alias": alias.alias_label, "real_value": alias.real_value})
