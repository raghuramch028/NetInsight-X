import logging
import os
from pathlib import Path

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

if not SECRET_KEY or SECRET_KEY == "django-insecure-netinsightx-academic-project-secret":
    logging.getLogger(__name__).warning(
        "DJANGO_SECRET_KEY is not set. Using a hardcoded fallback key. "
        "Set DJANGO_SECRET_KEY in production."
    )

DEBUG = os.environ.get("DEBUG", "True").lower() in ("true", "1", "yes")

_allowed_hosts = os.environ.get("ALLOWED_HOSTS", "*")
ALLOWED_HOSTS = [h.strip() for h in _allowed_hosts.split(",") if h.strip()]

if not DEBUG and "*" in ALLOWED_HOSTS:
    logging.getLogger(__name__).warning(
        "ALLOWED_HOSTS contains '*' while DEBUG is False. This is insecure for production."
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
# Database Configuration
# ==========================================
import dj_database_url

DB_PATH = os.environ.get("NETINSIGHT_DB_PATH", str(BASE_DIR / "database" / "netinsight.db"))
_DATABASE_URL = os.environ.get("DATABASE_URL", "")

if _DATABASE_URL:
    try:
        import psycopg2
        # Parse connection params to check reachability
        db_config = dj_database_url.parse(_DATABASE_URL)
        # Test connection with a short 3-second timeout
        conn = psycopg2.connect(
            database=db_config['NAME'],
            user=db_config['USER'],
            password=db_config['PASSWORD'],
            host=db_config['HOST'],
            port=db_config.get('PORT', 5432),
            connect_timeout=3
        )
        conn.close()
        DATABASES = {
            "default": dj_database_url.config(
                default=_DATABASE_URL,
                conn_max_age=600,
                ssl_require=True
            )
        }
        logging.getLogger("netinsight").info("Successfully connected to Neon PostgreSQL database.")
    except Exception as e:
        logging.getLogger("netinsight").warning(
            f"Could not connect to Neon PostgreSQL ({e}). "
            "Falling back to local SQLite database for development."
        )
        DATABASES = {
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": DB_PATH,
            }
        }
else:
    # Fallback to local SQLite if DATABASE_URL is not set
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": DB_PATH,
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
DASHBOARD_REFRESH_INTERVAL = int(os.environ.get("NETINSIGHT_REFRESH_INTERVAL", 2000)) # in milliseconds

# Demonstration / Replay Mode
DEMO_MODE = os.environ.get("NETINSIGHT_DEMO_MODE", "True").lower() in ("true", "1", "yes")

# Configurable thresholds for network states (based on bandwidth utilization and packet loss)
STATE_THRESHOLDS = {
    "NORMAL": {
        "util_max": 0.40,      # < 40%
        "loss_max": 0.02       # < 2%
    },
    "BUSY": {
        "util_min": 0.40,
        "util_max": 0.75,      # 40% to 75%
        "loss_max": 0.05       # < 5%
    },
    "CONGESTED": {
        "util_min": 0.75,
        "util_max": 0.95,      # 75% to 95%
        "loss_max": 0.10       # < 10%
    },
    "FAILURE": {
        "util_min": 0.95,      # >= 95%
        "loss_min": 0.10       # or Loss >= 10%
    }
}

# MDP Configurable Parameters
MDP_DISCOUNT_FACTOR = float(os.environ.get("NETINSIGHT_MDP_GAMMA", 0.90))

# Reward matrices for each (state, action) pair
MDP_REWARDS = {
    0: {0: 10.0, 1: 5.0, 2: 8.0},    # Normal
    1: {0: 8.0,  1: 4.0, 2: 7.0},    # Busy
    2: {0: 5.0,  1: 8.0, 2: 6.0},    # Congested
    3: {0: -2.0, 1: -5.0, 2: 2.0}     # Failure
}

# SVM Classification Configuration
SVM_MODEL_PATH = os.environ.get("NETINSIGHT_SVM_PATH", str(BASE_DIR / "classification" / "svm_model.joblib"))

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
