"""
turnstile.py

Server-side check of a Cloudflare Turnstile token, done before a dashboard
session is issued, so scripts cannot mint sessions in bulk. The browser
widget only produces a token; the decision is made here by asking
Cloudflare's siteverify endpoint with the secret key.

Docs: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
Cloudflare publishes test keys that always pass or always fail, for local
development without an account (listed in SETUP.md).

Standard library only (urllib), so no new dependency. Called from a plain
`def` route, which FastAPI runs in its thread pool, so the network call does
not block the event loop.
"""

import json
import logging
import urllib.error
import urllib.parse
import urllib.request

from app.core.exceptions import BotCheckFailedError, BotCheckUnavailableError

SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
# Must match the `action` the dashboard passes to turnstile.render().
EXPECTED_ACTION = "etis_session"
TIMEOUT_SECONDS = 5
MAX_TOKEN_CHARS = 2048  # Cloudflare's documented maximum token length

logger = logging.getLogger("uvicorn.error")


def _post_siteverify(form: dict[str, str]) -> dict:
    data = urllib.parse.urlencode(form).encode("ascii")
    request = urllib.request.Request(SITEVERIFY_URL, data=data, method="POST")
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def verify_turnstile_token(secret_key: str, token: str | None, remote_ip: str | None) -> None:
    """Returns when Cloudflare confirms the token; raises BotCheckFailedError
    (403) when it does not, BotCheckUnavailableError (503) when Cloudflare
    cannot be reached."""
    if not token or len(token) > MAX_TOKEN_CHARS:
        raise BotCheckFailedError("Bot check token missing or invalid.")
    form = {"secret": secret_key, "response": token}
    if remote_ip:
        form["remoteip"] = remote_ip
    try:
        result = _post_siteverify(form)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        logger.warning("Turnstile siteverify failed: %s", exc)
        raise BotCheckUnavailableError("The bot check service could not be reached.") from exc

    if not result.get("success"):
        logger.info("Turnstile refused a token: %s", result.get("error-codes"))
        raise BotCheckFailedError("Bot check failed.")
    # A real site key echoes the action the widget was rendered with; only a
    # different, non-empty action is refused, so Cloudflare's test keys
    # (which may report no action, or "test") still work in development.
    action = result.get("action")
    if action and action not in (EXPECTED_ACTION, "test"):
        raise BotCheckFailedError("Bot check token was issued for a different action.")
