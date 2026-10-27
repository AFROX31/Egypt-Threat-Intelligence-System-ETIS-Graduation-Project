"""
session.py

GET  /session  -> what the dashboard needs to know before it can call the API:
                  is a session required, the Turnstile site key (public), and
                  whether the browser already holds a valid session.
POST /session  -> checks the Turnstile token (when the bot check is on) and
                  sets the signed, HttpOnly session cookie.

The cookie value never appears in a response body, so page scripts cannot
read or leak it. Programs do not use this; they send their own API key.
"""

from typing import Optional

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from app.core import security
from app.core.config import settings
from app.core.rate_limit import SESSION_RATE_LIMIT, limiter
from app.core.security import client_ip
from app.core.sessions import SESSION_COOKIE_NAME, issue_session_token, verify_session_token
from app.core.turnstile import MAX_TOKEN_CHARS, verify_turnstile_token

router = APIRouter(prefix="/session", tags=["session"])

# Module-level so tests can switch the bot check on and off.
TURNSTILE_SITE_KEY = settings.turnstile_site_key
TURNSTILE_SECRET_KEY = settings.turnstile_secret_key


class SessionStatus(BaseModel):
    auth_required: bool
    turnstile_site_key: Optional[str] = Field(
        default=None, description="Public site key for the Turnstile widget; null when the bot check is off."
    )
    active: bool = Field(description="True when the request carried a valid session cookie.")
    expires_at: Optional[int] = Field(default=None, description="Unix time the current session ends.")


class StartSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    turnstile_token: Optional[str] = Field(default=None, max_length=MAX_TOKEN_CHARS)


def _status(request: Request, token_override: Optional[str] = None) -> SessionStatus:
    session = None
    if security.AUTH_REQUIRED:
        token = token_override if token_override is not None else request.cookies.get(SESSION_COOKIE_NAME)
        session = verify_session_token(security.SESSION_SECRET, token)
    return SessionStatus(
        auth_required=security.AUTH_REQUIRED,
        turnstile_site_key=TURNSTILE_SITE_KEY if security.AUTH_REQUIRED else None,
        active=session is not None,
        expires_at=session.expires_at if session else None,
    )


@router.get("", response_model=SessionStatus)
def get_session(request: Request) -> SessionStatus:
    return _status(request)


@router.post("", response_model=SessionStatus)
@limiter.limit(SESSION_RATE_LIMIT)
def start_session(request: Request, response: Response, payload: StartSessionRequest) -> SessionStatus:
    """Plain `def`: the Turnstile check is a blocking network call, so it
    runs in FastAPI's thread pool rather than on the event loop."""
    if not security.AUTH_REQUIRED:
        return _status(request)

    if TURNSTILE_SECRET_KEY is not None:
        verify_turnstile_token(TURNSTILE_SECRET_KEY, payload.turnstile_token, client_ip(request))

    token, session = issue_session_token(security.SESSION_SECRET, settings.session_ttl_seconds)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )
    return _status(request, token_override=token)
