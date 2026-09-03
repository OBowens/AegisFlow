from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_not_required
from django.urls import path
from django.views.generic import RedirectView


app_name = "accounts"

urlpatterns = [
    # The login page is the one view LoginRequiredMiddleware must let an
    # anonymous user reach. It renders Codex's template (accounts/login.html),
    # which is already written against Django's stock AuthenticationForm
    # (fields "username" / "password").
    path(
        "login/",
        login_not_required(
            auth_views.LoginView.as_view(template_name="accounts/login.html")
        ),
        name="login",
    ),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    # /accounts/ was a dead placeholder page; keep the name resolvable but
    # send it somewhere real. Anonymous hits bounce through the login gate.
    path(
        "",
        RedirectView.as_view(pattern_name="core:index", permanent=False),
        name="index",
    ),
]
