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

# Full scheme://host[:port] origins trusted for unsafe (POST) cross-origin
# requests -- Django's CSRF layer requires this once the app is served from a
# real domain over HTTPS behind Nginx. Without it, every form POST and AI
# action button on the deployed site fails CSRF verification. Empty by
# default so local `runserver` (same-origin http://127.0.0.1:8000) is
# unaffected. Example prod value:
#   DJANGO_CSRF_TRUSTED_ORIGINS=https://aegisflow.vincypros.com
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS", "")

# --- HTTPS / reverse-proxy hardening --------------------------------------
# Production runs behind Nginx, which terminates TLS and proxies to gunicorn
# over a local plain-HTTP unix socket. Every switch below is env-gated and
# defaults to the dev-safe value, so a plain `runserver` box is unchanged.
#
# Trust Nginx's X-Forwarded-Proto so request.is_secure(), secure-cookie and
# redirect logic see the original HTTPS scheme. Only safe because gunicorn
# is not directly reachable (unix socket) and Nginx always sets this header.
# Kept as an `if`-gate rather than a plain assignment: an unconditional
# SECURE_PROXY_SSL_HEADER lets anyone who can reach gunicorn directly spoof
# the scheme, so the setting simply does not exist unless explicitly enabled.
if env_bool("DJANGO_SECURE_PROXY_SSL_HEADER", False):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Send session / CSRF cookies only over HTTPS.
SESSION_COOKIE_SECURE = env_bool("DJANGO_SESSION_COOKIE_SECURE", False)
CSRF_COOKIE_SECURE = env_bool("DJANGO_CSRF_COOKIE_SECURE", False)

# Redirect any plain-HTTP request to HTTPS. Nginx does this too once certbot
# runs; this is the Django-side backstop.
SECURE_SSL_REDIRECT = env_bool("DJANGO_SECURE_SSL_REDIRECT", False)

# HTTP Strict Transport Security. 0 = off, and that is the default here for
# BOTH dev and this initial deployment -- do not enable a long max-age until
# the site has been verified stable over HTTPS. When ready, start small
# (e.g. 3600) and only later raise toward 31536000 (1 year); enable
# subdomains/preload last, after the long max-age is proven in the field.
SECURE_HSTS_SECONDS = int(os.environ.get("DJANGO_SECURE_HSTS_SECONDS", "0"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS", False)
SECURE_HSTS_PRELOAD = env_bool("DJANGO_SECURE_HSTS_PRELOAD", False)

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
# `python manage.py collectstatic` writes here. In production Nginx serves
# this directory directly at STATIC_URL (see deploy/nginx-aegisflow.conf) --
# there is deliberately NO WhiteNoise (or any other static-serving
# middleware/dependency): Nginx already sits in front of gunicorn and serves
# files faster with zero Python in the path. In DEBUG, `runserver` still
# serves static itself, so local dev needs nothing here.
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

PRIVATE_UPLOAD_ROOT = BASE_DIR / os.environ.get("PRIVATE_UPLOAD_ROOT", "private_uploads")
PRIVATE_EXPORT_ROOT = BASE_DIR / os.environ.get("PRIVATE_EXPORT_ROOT", "private_exports")

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "core:index"
LOGOUT_REDIRECT_URL = "accounts:login"

# --- Logging -------------------------------------------------------------
# With DEBUG=False Django no longer echoes tracebacks in the response, and
# without an explicit config an unhandled 500 would surface only as a bare
# gunicorn stderr line. WARNING+ always goes to the console (captured by
# journald under systemd -- `journalctl -u aegisflow`).
#
# The durable ERROR-and-above file log (logs/django-errors.log, rotating) is
# a PRODUCTION-ONLY facility: the log directory and file are created, and the
# file handler attached, ONLY when DEBUG is False. Under DEBUG -- local
# `runserver` and the test suite -- nothing touches logs/, so running the
# tests never spawns a production log file as a side effect. `logs/` is
# git-ignored.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "{asctime} {levelname} {name}: {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "WARNING",
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "django.request": {
            "handlers": ["console"],
            "level": "ERROR",
            "propagate": False,
        },
    },
}

if not DEBUG:
    LOG_DIR = BASE_DIR / "logs"
    LOG_DIR.mkdir(exist_ok=True)
    LOGGING["handlers"]["error_file"] = {
        "class": "logging.handlers.RotatingFileHandler",
        "filename": str(LOG_DIR / "django-errors.log"),
        "maxBytes": 5 * 1024 * 1024,
        "backupCount": 5,
        "level": "ERROR",
        "formatter": "standard",
    }
    for _log_name in ("django", "django.request"):
        LOGGING["loggers"][_log_name]["handlers"].append("error_file")
