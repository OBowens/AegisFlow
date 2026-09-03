import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def load_env_file(env_path: Path) -> None:
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        if key and key not in os.environ:
            os.environ[key] = value


load_env_file(BASE_DIR / ".env")


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: str = "") -> list[str]:
    value = os.environ.get(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "django-insecure-caribsecure-ai-dev-only",
)

# Structurally prevents any test from ever making a real, billed call to
# the Anthropic API -- see config/test_runner.py for why this exists.
TEST_RUNNER = "config.test_runner.NoLiveProviderCallsTestRunner"

# Pseudonymize real identifiers (IPs, hostnames, usernames, emails, file
# paths, the org's own name) out of every prompt before it reaches the
# Anthropic API, rehydrating them in the response -- see
# apps/ai_core/sanitizer.py. On by default; the escape hatch is only for
# the handful of tests that need to assert on raw prompt text.
AI_SANITIZER_ENABLED = env_bool("AI_SANITIZER_ENABLED", True)

# Rate limiting for the AI endpoints -- see apps/ai_core/rate_limit.py.
# Counted against the AIRun table (one row per AI call already exists),
# keyed on time only (single-tenant, no auth). Two rolling windows.
AI_RATE_LIMIT_ENABLED = env_bool("AI_RATE_LIMIT_ENABLED", True)
AI_RATE_LIMIT_GLOBAL_PER_HOUR = int(os.environ.get("AI_RATE_LIMIT_GLOBAL_PER_HOUR", "40"))
AI_RATE_LIMIT_ENDPOINT_PER_MINUTE = int(
    os.environ.get("AI_RATE_LIMIT_ENDPOINT_PER_MINUTE", "8")
)
# Calls in the shared hourly budget above that the background endpoint-
# triage scan (apps/endpoints/services/triage_run.py) keeps free for
# interactive, human-in-the-loop AI features (analyst, App Assistant).
# When the hour's usage is within this many calls of the global cap the
# scan triages nothing new that run and retries the next one. 0 disables.
AI_TRIAGE_INTERACTIVE_RESERVE = int(os.environ.get("AI_TRIAGE_INTERACTIVE_RESERVE", "15"))

BRAND_NAME = os.environ.get("BRAND_NAME", "AegisFlow AI")
BRAND_TAGLINE = os.environ.get(
    "BRAND_TAGLINE",
    "AI-powered cyber resilience workflow for alerts, risks, playbooks, and reports.",
)

DEBUG = env_bool("DJANGO_DEBUG", True)

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "apps.core.apps.CoreConfig",
    "apps.accounts.apps.AccountsConfig",
    "apps.organizations.apps.OrganizationsConfig",
    "apps.log_intake.apps.LogIntakeConfig",
    "apps.incidents.apps.IncidentsConfig",
    "apps.risk.apps.RiskConfig",
    "apps.resilience.apps.ResilienceConfig",
    "apps.playbooks.apps.PlaybooksConfig",
    "apps.reports.apps.ReportsConfig",
    "apps.audit.apps.AuditConfig",
    "apps.ai_core.apps.AICoreConfig",
    "apps.endpoints.apps.EndpointsConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # Every view requires an authenticated user. The only opt-out is an
    # explicit @login_not_required on a view (the login view itself); the
    # admin login view already carries that decorator upstream. There is
    # deliberately no per-view @login_required anywhere -- a new view is
    # protected by default, not by remembering to guard it.
    "django.contrib.auth.middleware.LoginRequiredMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "config.context_processors.branding",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

if all(
    os.environ.get(name)
    for name in [
        "DATABASE_NAME",
        "DATABASE_USER",
        "DATABASE_PASSWORD",
        "DATABASE_HOST",
        "DATABASE_PORT",
    ]
):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ["DATABASE_NAME"],
            "USER": os.environ["DATABASE_USER"],
            "PASSWORD": os.environ["DATABASE_PASSWORD"],
            "HOST": os.environ["DATABASE_HOST"],
            "PORT": os.environ["DATABASE_PORT"],
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

PRIVATE_UPLOAD_ROOT = BASE_DIR / os.environ.get("PRIVATE_UPLOAD_ROOT", "private_uploads")
PRIVATE_EXPORT_ROOT = BASE_DIR / os.environ.get("PRIVATE_EXPORT_ROOT", "private_exports")

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "core:index"
LOGOUT_REDIRECT_URL = "accounts:login"
