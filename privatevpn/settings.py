"""Django settings for PrivateVPN.

Everything deployment-specific comes from PRIVATEVPN_* environment variables
(see deploy/install.sh, which writes them to /etc/privatevpn.env). With no
variables set, it runs as a local development copy.
"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("PRIVATEVPN_DATA_DIR", BASE_DIR))


def _env_list(name, default=""):
    return [v.strip() for v in os.environ.get(name, default).split(",") if v.strip()]


def _load_secret_key():
    env_key = os.environ.get("PRIVATEVPN_SECRET_KEY")
    if env_key:
        return env_key
    key_file = DATA_DIR / ".secret_key"
    if not key_file.exists():
        key_file.write_text(secrets.token_urlsafe(50))
    return key_file.read_text().strip()


SECRET_KEY = _load_secret_key()
DEBUG = os.environ.get("PRIVATEVPN_DEBUG", "1") == "1"
ALLOWED_HOSTS = _env_list("PRIVATEVPN_ALLOWED_HOSTS", "127.0.0.1,localhost")
CSRF_TRUSTED_ORIGINS = _env_list("PRIVATEVPN_CSRF_ORIGINS")

# Behind nginx with TLS (production install).
BEHIND_PROXY = os.environ.get("PRIVATEVPN_HTTPS", "0") == "1"
if BEHIND_PROXY:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_REFERRER_POLICY = "same-origin"

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "vpn",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # Serves STATIC_ROOT straight from gunicorn, so the panel works with or
    # without nginx in front of it.
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "vpn.middleware.ForcePasswordChangeMiddleware",
]

ROOT_URLCONF = "privatevpn.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "privatevpn.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": DATA_DIR / "db.sqlite3",
    }
}

# File cache is shared between gunicorn workers (used for login rate limiting).
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.filebased.FileBasedCache",
        "LOCATION": DATA_DIR / "cache",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = os.environ.get("PRIVATEVPN_TIME_ZONE", "Asia/Manila")
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = Path(os.environ.get("PRIVATEVPN_STATIC_ROOT", BASE_DIR / "staticfiles"))
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"},
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = 60 * 60 * 12

# --- PrivateVPN ---
PRIVATEVPN_HELPER = os.environ.get("PRIVATEVPN_HELPER", "/usr/local/sbin/privatevpn-helper")
# The bootstrap password. Anyone logging in with it is forced to change it.
PRIVATEVPN_DEFAULT_ADMIN_PASSWORD = "admin2027"
# Lock a username+IP out for LOGIN_LOCK_SECONDS after this many failures.
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_SECONDS = 15 * 60
# Seconds between samples on the dashboard traffic graph. 1 is as live as
# WireGuard gets: its counters are read with `wg show`, there is nothing to
# subscribe to. Raise it if the server is managed over a slow SSH link.
PRIVATEVPN_TRAFFIC_SECONDS = int(os.environ.get("PRIVATEVPN_TRAFFIC_SECONDS", "1"))
