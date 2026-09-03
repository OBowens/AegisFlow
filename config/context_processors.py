from django.conf import settings
from django.db.utils import OperationalError, ProgrammingError


def _user_display(user):
    """Real identity only. Falls back through the fields Django's User
    actually has -- never a hardcoded name or an invented role."""
    if not user or not getattr(user, "is_authenticated", False):
        return "", ""

    name = (user.get_full_name() or "").strip() or user.get_username()
    parts = [part for part in name.split() if part]
    if len(parts) >= 2:
        initials = (parts[0][0] + parts[1][0]).upper()
    elif parts:
        initials = parts[0][:2].upper()
    else:
        initials = ""
    return name, initials


def branding(request):
    display_name, initials = _user_display(getattr(request, "user", None))
    context = {
        "BRAND_NAME": settings.BRAND_NAME,
        "BRAND_TAGLINE": settings.BRAND_TAGLINE,
        "user_display_name": display_name,
        "user_initials": initials,
    }

    # Keep the navigation score aligned with the Readiness page's canonical
    # calculation. Imports stay local so startup and migrations remain safe.
    try:
        from apps.organizations.services.current_organization import get_current_organization
        from apps.resilience.models import DisasterReadinessFinding
        from apps.resilience.services.scoring import compute_readiness_score

        # Scoped to the same canonical organization every other page now
        # resolves -- previously this aggregated findings across every
        # organization in the database with no filter at all, which
        # happened to still be correct only because no stray/test
        # organization had accumulated its own findings yet.
        organization = get_current_organization()
        counts = {
            row["priority"]: row["total"]
            for row in DisasterReadinessFinding.objects.filter(organization=organization)
            .values("priority")
            .annotate(total=__import__("django.db.models", fromlist=["Count"]).Count("id"))
        }
        score = compute_readiness_score(
            critical_count=counts.get(DisasterReadinessFinding.Priority.CRITICAL, 0),
            high_count=counts.get(DisasterReadinessFinding.Priority.HIGH, 0),
            medium_count=counts.get(DisasterReadinessFinding.Priority.MEDIUM, 0),
        )
    except (OperationalError, ProgrammingError):
        score = None

    context["sidebar_readiness_score"] = score
    return context
