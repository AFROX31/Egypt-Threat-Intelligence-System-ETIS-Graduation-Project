"""Unit tests for the pieces behind authentication: session tokens, API key
hashing and lookup, the Turnstile check, and the require_caller dependency.
Endpoint-level behaviour is in test_session.py and test_api_endpoints.py."""

import urllib.error

import pytest
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.core import api_keys, security, turnstile
from app.core.database import engine
from app.core.exceptions import (
    AuthenticationError,
    BotCheckFailedError,
    BotCheckUnavailableError,
    SessionRequiredError,
)
from app.core.sessions import SESSION_COOKIE_NAME, issue_session_token, verify_session_token

SECRET = "s" * 32


@pytest.fixture
def db_session():
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


def _request(cookie: str | None = None) -> Request:
    headers = [(b"cookie", f"{SESSION_COOKIE_NAME}={cookie}".encode())] if cookie else []
    return Request({"type": "http", "headers": headers, "client": ("203.0.113.7", 1234)})


# --- session tokens -------------------------------------------------------------

def test_session_token_round_trip():
    token, session = issue_session_token(SECRET, 60, now=1_000)
    assert verify_session_token(SECRET, token, now=1_030) == session
    assert session.expires_at == 1_060


def test_expired_session_token_is_refused():
    token, _ = issue_session_token(SECRET, 60, now=1_000)
    assert verify_session_token(SECRET, token, now=1_060) is None


def test_session_token_signed_with_another_secret_is_refused():
    token, _ = issue_session_token("o" * 32, 60)
    assert verify_session_token(SECRET, token) is None


@pytest.mark.parametrize("tamper", [
    lambda t: t.replace(t.split(".")[2], str(int(t.split(".")[2]) + 9999)),  # extend expiry
    lambda t: t.replace(t.split(".")[1], "someoneelse"),  # change session id
    lambda t: t[:-2] + ("AA" if not t.endswith("AA") else "BB"),  # change signature
    lambda t: "v2" + t[2:],
    lambda t: "garbage",
    lambda t: "",
    lambda t: "v1.a.b.مفتاح",
])
def test_tampered_session_token_is_refused(tamper):
    token, _ = issue_session_token(SECRET, 60)
    assert verify_session_token(SECRET, tamper(token)) is None


# --- API keys -------------------------------------------------------------------

def test_api_key_is_stored_only_as_a_hash(db_session):
    client, key = api_keys.create_api_client(db_session, "unit-test-client")
    assert key.startswith("etis_") and len(key) > 40
    assert client.key_hash == api_keys.hash_api_key(key) != key
    assert key.startswith(client.key_prefix) and len(client.key_prefix) < 16


def test_api_key_lookup_and_revoke(db_session):
    _, key = api_keys.create_api_client(db_session, "unit-test-client")
    found = api_keys.find_active_client(db_session, key)
    assert found is not None and found.last_used_at is not None
    assert api_keys.find_active_client(db_session, key + "x") is None
    assert api_keys.find_active_client(db_session, "not-an-etis-key") is None
    api_keys.revoke_api_client(db_session, "unit-test-client")
    assert api_keys.find_active_client(db_session, key) is None


def test_duplicate_client_name_is_refused(db_session):
    api_keys.create_api_client(db_session, "unit-test-client")
    with pytest.raises(ValueError, match="already exists"):
        api_keys.create_api_client(db_session, "unit-test-client")


# --- require_caller -------------------------------------------------------------

def test_auth_off_lets_everyone_through_as_anonymous(monkeypatch):
    monkeypatch.setattr(security, "AUTH_REQUIRED", False)
    caller = security.require_caller(_request(), x_api_key="anything", db=None)
    assert caller.kind == "anonymous" and caller.identifier == "203.0.113.7"


def test_valid_session_cookie_is_accepted(monkeypatch):
    monkeypatch.setattr(security, "AUTH_REQUIRED", True)
    monkeypatch.setattr(security, "SESSION_SECRET", SECRET)
    token, session = issue_session_token(SECRET, 60)
    request = _request(token)
    caller = security.require_caller(request, x_api_key=None, db=None)
    assert caller.kind == "session" and caller.identifier == session.session_id
    assert request.state.caller == caller


def test_no_credentials_asks_for_a_session(monkeypatch):
    monkeypatch.setattr(security, "AUTH_REQUIRED", True)
    monkeypatch.setattr(security, "SESSION_SECRET", SECRET)
    with pytest.raises(SessionRequiredError):
        security.require_caller(_request(), x_api_key=None, db=None)


def test_wrong_api_key_is_refused_even_with_a_valid_cookie(monkeypatch, db_session):
    monkeypatch.setattr(security, "AUTH_REQUIRED", True)
    monkeypatch.setattr(security, "SESSION_SECRET", SECRET)
    token, _ = issue_session_token(SECRET, 60)
    with pytest.raises(AuthenticationError) as raised:
        security.require_caller(_request(token), x_api_key="etis_wrong", db=db_session)
    assert not isinstance(raised.value, SessionRequiredError)


def test_valid_api_key_identifies_the_client(monkeypatch, db_session):
    monkeypatch.setattr(security, "AUTH_REQUIRED", True)
    monkeypatch.setattr(security, "SESSION_SECRET", SECRET)
    _, key = api_keys.create_api_client(db_session, "unit-test-client")
    caller = security.require_caller(_request(), x_api_key=key, db=db_session)
    assert caller.kind == "client" and caller.identifier == "unit-test-client"


# --- Turnstile --------------------------------------------------------------------

def test_turnstile_success(monkeypatch):
    sent = {}
    monkeypatch.setattr(turnstile, "_post_siteverify", lambda form: sent.update(form) or {"success": True, "action": "etis_session"})
    turnstile.verify_turnstile_token("secret", "token", "203.0.113.7")
    assert sent == {"secret": "secret", "response": "token", "remoteip": "203.0.113.7"}


@pytest.mark.parametrize("result", [
    {"success": False, "error-codes": ["invalid-input-response"]},
    {"success": True, "action": "some_other_form"},
])
def test_turnstile_refusal(monkeypatch, result):
    monkeypatch.setattr(turnstile, "_post_siteverify", lambda form: result)
    with pytest.raises(BotCheckFailedError):
        turnstile.verify_turnstile_token("secret", "token", None)


def test_turnstile_missing_token_is_refused_without_calling_cloudflare(monkeypatch):
    monkeypatch.setattr(turnstile, "_post_siteverify", lambda form: pytest.fail("should not be called"))
    with pytest.raises(BotCheckFailedError):
        turnstile.verify_turnstile_token("secret", None, None)


def test_turnstile_unreachable(monkeypatch):
    def fail(form):
        raise urllib.error.URLError("no route")
    monkeypatch.setattr(turnstile, "_post_siteverify", fail)
    with pytest.raises(BotCheckUnavailableError):
        turnstile.verify_turnstile_token("secret", "token", None)


def test_error_status_codes():
    from app.main import _STATUS_BY_EXCEPTION

    assert _STATUS_BY_EXCEPTION[AuthenticationError] == 401
    assert _STATUS_BY_EXCEPTION[SessionRequiredError] == 401
    assert _STATUS_BY_EXCEPTION[BotCheckFailedError] == 403
    assert _STATUS_BY_EXCEPTION[BotCheckUnavailableError] == 503
