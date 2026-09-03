from django.conf import settings
from django.contrib import admin
from django.urls import include, path


admin.site.site_header = f"{settings.BRAND_NAME} Administration"
admin.site.site_title = f"{settings.BRAND_NAME} Admin"
admin.site.index_title = f"{settings.BRAND_NAME} administration"


urlpatterns = [
    path("", include("apps.core.urls")),
    path("accounts/", include("apps.accounts.urls")),
    path("organizations/", include("apps.organizations.urls")),
    path("logs/", include("apps.log_intake.urls")),
    path("incidents/", include("apps.incidents.urls")),
    path("risk/", include("apps.risk.urls")),
    path("resilience/", include("apps.resilience.urls")),
    path("playbooks/", include("apps.playbooks.urls")),
    path("reports/", include("apps.reports.urls")),
    path("audit/", include("apps.audit.urls")),
    path("endpoints/", include("apps.endpoints.urls")),
    path("admin/", admin.site.urls),
]
