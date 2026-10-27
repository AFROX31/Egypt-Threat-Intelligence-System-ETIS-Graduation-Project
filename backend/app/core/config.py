"""
config.py

Single place where the backend reads its settings from the environment
(added 2026-10-26; before this, CORS origins, the rate limit and the API key
were hard-coded or read ad hoc in main.py, rate_limit.py and security.py).

The .env file at the project root is loaded here, once, so every setting
below can come either from the real environment or from .env (the real
environment wins). See .env.example at the project root for every variable.

Deliberately a plain frozen dataclass rather than pydantic-settings: it
avoids a new dependency, and the handful of settings does not need more.

    DATABASE_URL                  PostgreSQL connection string
    ETIS_AUTH_REQUIRED            true/false; false (local dev) lets every request through
    ETIS_SESSION_SECRET           HMAC key that signs dashboard session cookies (32+ chars)
    ETIS_SESSION_TTL_SECONDS      how long a dashboard session lasts
    ETIS_COOKIE_SECURE            true/false; Secure flag on the session cookie
    ETIS_COOKIE_SAMESITE          lax / strict / none
    ETIS_TURNSTILE_SITE_KEY       Cloudflare Turnstile site key (public, sent to the page)
    ETIS_TURNSTILE_SECRET_KEY     Cloudflare Turnstile secret; both set = bot check on
    ETIS_CORS_ORIGINS             comma-separated list of allowed browser origins
    ETIS_CORS_ALLOW_CREDENTIALS   true/false; must be true for the session cookie
    ETIS_ANALYZE_RATE_LIMIT       slowapi limit for POST /analyze, per caller (session or client)
    ETIS_ANALYZE_IP_RATE_LIMIT    slowapi limit for POST /analyze, per client IP
    ETIS_SESSION_RATE_LIMIT       slowapi limit for POST /session, per client IP
    ETIS_FRONTEND_DIST            built dashboard folder to serve from the API's own origin
    ETIS_MAX_TEXT_CHARS           longest accepted message text, in characters
    ETIS_MAX_URL_CHARS            longest accepted URL, in characters
    ETIS_MAX_REQUEST_BYTES        largest accepted request body, in bytes
    ETIS_MAX_EMBEDDED_LINKS       how many links found inside the text are scanned

Authentication (2026-10-26) replaces the single ETIS_API_KEY that used to be
built into the public dashboard: the dashboard gets a short-lived signed
session cookie (after a Turnstile bot check), and programs use their own
per-client API keys stored hashed in the database (see app/core/security.py).
ETIS_API_KEY is refused at startup so an old .env cannot silently leave a
deployment open.

Defaults for the length limits were checked against data/processed/dataset.csv
(2026-10-26): the longest message text is 14,640 characters (limit 20,000);
2 of 90,923 URLs are longer than 4,096 characters (limit 4,096).
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[3]  # core -> app -> backend -> root
load_dotenv(dotenv_path=PROJECT_ROOT / ".env")

DEFAULT_DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/etis"
DEFAULT_CORS_ORIGINS = ("http://localhost:5173",)
MIN_SESSION_SECRET_CHARS = 32
SAMESITE_VALUES = ("lax", "strict", "none")

_TRUE_VALUES = ("1", "true", "yes", "on")
_FALSE_VALUES = ("0", "false", "no", "off", "")


@dataclass(frozen=True)
class Settings:
    database_url: str
    auth_required: bool
    session_secret: str | None
    session_ttl_seconds: int
    cookie_secure: bool
    cookie_samesite: str
    turnstile_site_key: str | None
    turnstile_secret_key: str | None
    cors_origins: tuple[str, ...]
    cors_allow_credentials: bool
    analyze_rate_limit: str
    analyze_ip_rate_limit: str
    session_rate_limit: str
    frontend_dist: str | None
    max_text_chars: int
    max_url_chars: int
    max_request_bytes: int
    max_embedded_links: int


def _get_bool(environ: Mapping[str, str], name: str, default: bool) -> bool:
    raw = environ.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ValueError(f"{name} must be true or false, got {raw!r}.")


def _get_positive_int(environ: Mapping[str, str], name: str, default: int) -> int:
    raw = environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        raise ValueError(f"{name} must be a whole number, got {raw!r}.") from None
    if value <= 0:
        raise ValueError(f"{name} must be greater than 0, got {value}.")
    return value


def _get_optional(environ: Mapping[str, str], name: str) -> str | None:
    """An unset variable and an empty `NAME=` line in .env both mean "not set"."""
    raw = environ.get(name)
    if raw is None or raw.strip() == "":
        return None
    return raw.strip()


def _get_origins(environ: Mapping[str, str]) -> tuple[str, ...]:
    raw = environ.get("ETIS_CORS_ORIGINS")
    if raw is None or raw.strip() == "":
        return DEFAULT_CORS_ORIGINS
    # Browsers send the Origin header without a trailing slash, so
    # "http://localhost:5173/" would otherwise never match.
    return tuple(origin.strip().rstrip("/") for origin in raw.split(",") if origin.strip())


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    """Build Settings from `environ` (default: os.environ). Raises ValueError
    with the variable's name when a value is malformed, so a typo stops the
    server at startup instead of silently falling back to a default."""
    env = os.environ if environ is None else environ
    if env.get("ETIS_API_KEY"):
        raise ValueError(
            "ETIS_API_KEY is no longer used. Set ETIS_AUTH_REQUIRED=true and "
            "ETIS_SESSION_SECRET, and create per-client keys with "
            "manage_api_keys.py (see SETUP.md)."
        )

    auth_required = _get_bool(env, "ETIS_AUTH_REQUIRED", False)
    session_secret = _get_optional(env, "ETIS_SESSION_SECRET")
    if session_secret is not None and len(session_secret) < MIN_SESSION_SECRET_CHARS:
        raise ValueError(f"ETIS_SESSION_SECRET must be at least {MIN_SESSION_SECRET_CHARS} characters.")
    if auth_required and session_secret is None:
        raise ValueError("ETIS_AUTH_REQUIRED=true needs ETIS_SESSION_SECRET to sign session cookies.")

    turnstile_site_key = _get_optional(env, "ETIS_TURNSTILE_SITE_KEY")
    turnstile_secret_key = _get_optional(env, "ETIS_TURNSTILE_SECRET_KEY")
    if (turnstile_site_key is None) != (turnstile_secret_key is None):
        raise ValueError("Set both ETIS_TURNSTILE_SITE_KEY and ETIS_TURNSTILE_SECRET_KEY, or neither.")

    cookie_secure = _get_bool(env, "ETIS_COOKIE_SECURE", True)
    cookie_samesite = (env.get("ETIS_COOKIE_SAMESITE") or "lax").strip().lower()
    if cookie_samesite not in SAMESITE_VALUES:
        raise ValueError(f"ETIS_COOKIE_SAMESITE must be one of {', '.join(SAMESITE_VALUES)}, got {cookie_samesite!r}.")
    if cookie_samesite == "none" and not cookie_secure:
        # Browsers drop a SameSite=None cookie that is not Secure.
        raise ValueError("ETIS_COOKIE_SAMESITE=none needs ETIS_COOKIE_SECURE=true.")

    return Settings(
        database_url=env.get("DATABASE_URL") or DEFAULT_DATABASE_URL,
        auth_required=auth_required,
        session_secret=session_secret,
        session_ttl_seconds=_get_positive_int(env, "ETIS_SESSION_TTL_SECONDS", 3_600),
        cookie_secure=cookie_secure,
        cookie_samesite=cookie_samesite,
        turnstile_site_key=turnstile_site_key,
        turnstile_secret_key=turnstile_secret_key,
        cors_origins=_get_origins(env),
        # The dashboard's session cookie only travels when this is true. Safe
        # because the origins are an explicit list (a '*' with credentials is
        # refused in main.py).
        cors_allow_credentials=_get_bool(env, "ETIS_CORS_ALLOW_CREDENTIALS", True),
        analyze_rate_limit=(env.get("ETIS_ANALYZE_RATE_LIMIT") or "20/minute").strip(),
        analyze_ip_rate_limit=(env.get("ETIS_ANALYZE_IP_RATE_LIMIT") or "60/minute").strip(),
        session_rate_limit=(env.get("ETIS_SESSION_RATE_LIMIT") or "10/minute").strip(),
        frontend_dist=_get_optional(env, "ETIS_FRONTEND_DIST"),
        max_text_chars=_get_positive_int(env, "ETIS_MAX_TEXT_CHARS", 20_000),
        max_url_chars=_get_positive_int(env, "ETIS_MAX_URL_CHARS", 4_096),
        max_request_bytes=_get_positive_int(env, "ETIS_MAX_REQUEST_BYTES", 256_000),
        max_embedded_links=_get_positive_int(env, "ETIS_MAX_EMBEDDED_LINKS", 5),
    )


settings = load_settings()
