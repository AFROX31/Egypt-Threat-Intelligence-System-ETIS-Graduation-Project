"""
sessions.py

Signed, stateless session tokens for the dashboard. The browser keeps the
token in an HttpOnly cookie, so page scripts (and anything injected into
the page) cannot read it, and no long-lived secret is ever built into the
public JavaScript.

Token format: "v1.<session id>.<expiry unix time>.<signature>", where the
signature is HMAC-SHA256 over "v1.<session id>.<expiry>" with
ETIS_SESSION_SECRET. Nothing is stored server-side: a token is valid while
its signature matches and it has not expired. Changing ETIS_SESSION_SECRET
ends every session at once. The session id has no meaning beyond being a
stable key for the per-session rate limit.
"""

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass

SESSION_COOKIE_NAME = "etis_session"
_VERSION = "v1"


@dataclass(frozen=True)
class SessionToken:
    session_id: str
    expires_at: int


def _signature(secret: str, payload: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def issue_session_token(secret: str, ttl_seconds: int, now: float | None = None) -> tuple[str, SessionToken]:
    issued_at = int(time.time() if now is None else now)
    session = SessionToken(session_id=secrets.token_urlsafe(16), expires_at=issued_at + ttl_seconds)
    payload = f"{_VERSION}.{session.session_id}.{session.expires_at}"
    return f"{payload}.{_signature(secret, payload)}", session


def verify_session_token(secret: str, token: str | None, now: float | None = None) -> SessionToken | None:
    """The session, or None for a missing, malformed, forged or expired token."""
    if not token:
        return None
    parts = token.split(".")
    if len(parts) != 4 or parts[0] != _VERSION:
        return None
    version, session_id, expires_raw, signature = parts
    expected = _signature(secret, f"{version}.{session_id}.{expires_raw}")
    if not hmac.compare_digest(signature.encode("ascii", "replace"), expected.encode("ascii")):
        return None
    try:
        expires_at = int(expires_raw)
    except ValueError:
        return None
    if expires_at <= (time.time() if now is None else now):
        return None
    return SessionToken(session_id=session_id, expires_at=expires_at)
