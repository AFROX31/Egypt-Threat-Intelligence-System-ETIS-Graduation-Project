"""
security.py

Who is calling, and are they allowed to. Replaces the single shared
ETIS_API_KEY (2026-10-26), which the dashboard had to carry inside its
public JavaScript, where anyone could read it.

Two kinds of caller, each with its own credential:

    dashboard (browser)  signed session cookie (app/core/sessions.py), issued
                         by POST /session after a Cloudflare Turnstile bot
                         check; HttpOnly, short-lived, nothing secret in the page
    programs             per-client API key in the X-API-Key header
                         (app/core/api_keys.py), hashed in the database,
                         revocable one client at a time

With ETIS_AUTH_REQUIRED=false (the default, local development) every request
is let through as an anonymous caller, keyed by IP for the rate limit, and
API keys are not looked up at all.

The Caller is stored on request.state so the rate limiter can key the
per-caller limit on it (app/core/rate_limit.py).

Errors: a wrong or revoked API key -> AuthenticationError (401); no
credentials -> SessionRequiredError (401, "start a session and retry"). Both
are mapped in main.py.
"""

from dataclasses import dataclass

from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session

from app.core.api_keys import find_active_client
from app.core.config import settings
from app.core.database import get_db_session
from app.core.exceptions import AuthenticationError, SessionRequiredError
from app.core.sessions import SESSION_COOKIE_NAME, verify_session_token

# Module-level copies (not read from settings on every call) so tests can
# monkeypatch them; see tests/test_security.py.
AUTH_REQUIRED = settings.auth_required
SESSION_SECRET = settings.session_secret


@dataclass(frozen=True)
class Caller:
    kind: str  # "client", "session" or "anonymous"
    identifier: str  # client name, session id, or IP address

    @property
    def rate_limit_key(self) -> str:
        return f"{self.kind}:{self.identifier}"


def client_ip(request: Request) -> str:
    # request.client is the direct peer. Behind a reverse proxy, run uvicorn
    # with --proxy-headers --forwarded-allow-ips=<proxy IP> so this is the
    # real client and not the proxy (see SETUP.md, deployment).
    return request.client.host if request.client else "unknown"


def require_caller(
    request: Request,
    x_api_key: str | None = Header(default=None),
    db: Session = Depends(get_db_session),
) -> Caller:
    """FastAPI dependency for every data endpoint (/analyze, /threats, /stats)."""
    if not AUTH_REQUIRED:
        caller = Caller("anonymous", client_ip(request))
    elif x_api_key is not None:
        # A key that is sent must be valid: falling back to the cookie would
        # hide a revoked or mistyped key from the program that uses it.
        client = find_active_client(db, x_api_key)
        if client is None:
            raise AuthenticationError("Invalid or revoked API key.")
        caller = Caller("client", client.name)
    else:
        session = verify_session_token(SESSION_SECRET, request.cookies.get(SESSION_COOKIE_NAME))
        if session is None:
            raise SessionRequiredError("No valid session. Start one with POST /session.")
        caller = Caller("session", session.session_id)

    request.state.caller = caller
    return caller
