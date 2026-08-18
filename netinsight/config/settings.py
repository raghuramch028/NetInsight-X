import logging
import os
import sys
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

def load_dotenv():
    env_path = BASE_DIR.parent / ".env"
    if env_path.exists():
        with open(env_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    # Strip quotes if present
                    value = value.strip('"').strip("'")
                    os.environ.setdefault(key.strip(), value.strip())

load_dotenv()

# ==========================================
# Django Specific Configurations
# ==========================================
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "django-insecure-netinsightx-academic-project-secret",
)

DEBUG = os.environ.get("DEBUG", "True").lower() in ("true", "1", "yes")

if not DEBUG and (not SECRET_KEY or SECRET_KEY == "django-insecure-netinsightx-academic-project-secret"):
    logging.getLogger(__name__).warning(
        "DJANGO_SECRET_KEY is not set. Using a hardcoded fallback key. "
        "Set DJANGO_SECRET_KEY in production."
    )

_allowed_hosts = os.environ.get("ALLOWED_HOSTS", "*")
ALLOWED_HOSTS = [h.strip() for h in _allowed_hosts.split(",") if h.strip()]

# Optional secret API token for agent endpoint authentication
NETINSIGHT_AGENT_TOKEN = os.environ.get("NETINSIGHT_AGENT_TOKEN", None)
NETINSIGHT_ENFORCE_AGENT_TOKEN = os.environ.get("NETINSIGHT_ENFORCE_AGENT_TOKEN", "False").lower() in ("true", "1", "yes")

if not DEBUG and "*" in ALLOWED_HOSTS:
    logging.getLogger(__name__).warning(
        "ALLOWED_HOSTS contains '*' while DEBUG is False. This is insecure for production."
    )

if not DEBUG and not NETINSIGHT_AGENT_TOKEN:
    logging.getLogger(__name__).warning(
        "NETINSIGHT_AGENT_TOKEN is not set. Agent telemetry endpoints are open to any client. "
        "Set NETINSIGHT_AGENT_TOKEN in .env for production deployments."
    )

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",        # Django REST Framework
    "netinsight.dashboard",  # Dashboard App
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "netinsight.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "dashboard" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "netinsight.dashboard.context_processors.global_settings",
            ],
        },
    },
]

WSGI_APPLICATION = "netinsight.wsgi.application"

# ==========================================
# Database Configuration (SQLite 3)
# ==========================================

DB_PATH = os.environ.get("NETINSIGHT_DB_PATH", str(BASE_DIR / "database" / "netinsight.db"))

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": DB_PATH,
        "OPTIONS": {
            "timeout": 30.0,
            "init_command": "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=30000; PRAGMA synchronous=NORMAL;",
        },
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Static files (CSS, JavaScript, Images)
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

# ==========================================
# Custom NetInsight-X Specific Settings
# ==========================================
# Set CAPTURE_INTERFACE to None to bind to the default interface
CAPTURE_INTERFACE = os.environ.get("NETINSIGHT_INTERFACE", None)

# Link Capacity in bps (default: 100 Mbps)
LINK_CAPACITY = float(os.environ.get("NETINSIGHT_LINK_CAPACITY", 100_000_000.0))  # 100 Mbps in bits/sec

# Dashboard UI Configurations
DASHBOARD_REFRESH_INTERVAL = int(os.environ.get("NETINSIGHT_REFRESH_INTERVAL", 1000)) # 1.0s sub-second refresh (in ms)

# Demonstration / Replay Mode
DEMO_MODE = os.environ.get("NETINSIGHT_DEMO_MODE", "True").lower() in ("true", "1", "yes")

# Hotspot AP SSID for edge agent connection tracking
HOTSPOT_SSID = os.environ.get("HOTSPOT_SSID", "SEM3_PROJECT")

# Dashboard access control setting (default: False for lab demos, set True to enforce authentication)
NETINSIGHT_REQUIRE_AUTH = os.environ.get("NETINSIGHT_REQUIRE_AUTH", "False").lower() in ("true", "1", "yes")

# Bandwidth Optimization QoS Thresholds (for 4 classes)
QOS_PRIORITIES = [1.0, 2.0, 0.5, 3.0]
QOS_MIN_BANDWIDTH = [5_000_000.0, 15_000_000.0, 2_000_000.0, 10_000_000.0]
QOS_MAX_BANDWIDTH = [40_000_000.0, 60_000_000.0, 30_000_000.0, 50_000_000.0]

# ==========================================
# Logging
# ==========================================
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": os.environ.get("NETINSIGHT_LOG_LEVEL", "INFO"),
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "netinsight": {
            "handlers": ["console"],
            "level": os.environ.get("NETINSIGHT_LOG_LEVEL", "INFO"),
            "propagate": False,
        },
        "matplotlib": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}

# ==========================================
# Django REST Framework Configuration
# ==========================================
REST_FRAMEWORK = {
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "120/minute",
        "agent": "600/minute",
    },
}

# ==========================================
# Transport Security (opt-in)
# ==========================================
# Off by default: local/LAN demo deployments (this project's documented default use case) run
# over plain HTTP, and forcing HTTPS/secure cookies there would just lock users out. Set
# NETINSIGHT_FORCE_HTTPS=True when this server sits behind TLS termination (a reverse proxy,
# load balancer, or platform-level HTTPS) to enable standard Django transport-security hardening.
NETINSIGHT_FORCE_HTTPS = os.environ.get("NETINSIGHT_FORCE_HTTPS", "False").lower() in ("true", "1", "yes")

if NETINSIGHT_FORCE_HTTPS:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = os.environ.get("NETINSIGHT_SSL_REDIRECT", "True").lower() in ("true", "1", "yes")
    SECURE_HSTS_SECONDS = int(os.environ.get("NETINSIGHT_HSTS_SECONDS", "31536000"))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    # When behind a reverse proxy that terminates TLS, trust its forwarded-proto header so
    # Django knows the original request was HTTPS (avoids a redirect loop behind the proxy).
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# In production mode (DEBUG=False), enforce strict secret key and agent token requirements
if not DEBUG and 'test' not in sys.argv:
    if SECRET_KEY == "django-insecure-netinsightx-academic-project-secret" or len(SECRET_KEY) < 32:
        raise ImproperlyConfigured("Insecure DJANGO_SECRET_KEY detected in production mode (DEBUG=False). Set DJANGO_SECRET_KEY in environment variables.")
    if not NETINSIGHT_AGENT_TOKEN:
        raise ImproperlyConfigured("NETINSIGHT_AGENT_TOKEN is required in production mode (DEBUG=False) to secure telemetry endpoints. Set NETINSIGHT_AGENT_TOKEN in environment variables.")

