"""GET/POST /session: the dashboard's way in when authentication is on."""

import pytest
from fastapi.testclient import TestClient

from app.core.exceptions import BotCheckFailedError
from app.core.rate_limit import limiter
from app.core.sessions import SESSION_COOKIE_NAME
from app.main import app

SECRET = "k" * 32


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr("app.core.security.AUTH_REQUIRED", True)
    monkeypatch.setattr("app.core.security.SESSION_SECRET", SECRET)
    monkeypatch.setattr("app.routers.session.TURNSTILE_SITE_KEY", "site-key")
    monkeypatch.setattr("app.routers.session.TURNSTILE_SECRET_KEY", "secret-key")
    monkeypatch.setattr(limiter, "enabled", False)
    # https so the Secure cookie is stored and sent back by the test client.
    return TestClient(app, base_url="https://testserver")


def _accept_turnstile(monkeypatch, seen=None):
    def verify(secret, token, remote_ip):
        if seen is not None:
            seen.append((secret, token))
        if token != "good-token":
            raise BotCheckFailedError("Bot check failed.")
    monkeypatch.setattr("app.routers.session.verify_turnstile_token", verify)


def test_status_before_a_session(client):
    body = client.get("/session").json()
    assert body == {"auth_required": True, "turnstile_site_key": "site-key", "active": False, "expires_at": None}


def test_session_with_passing_bot_check_sets_an_httponly_cookie(client, monkeypatch):
    seen = []
    _accept_turnstile(monkeypatch, seen)
    response = client.post("/session", json={"turnstile_token": "good-token"})
    assert response.status_code == 200
    assert response.json()["active"] is True
    assert seen == [("secret-key", "good-token")]

    set_cookie = response.headers["set-cookie"]
    assert set_cookie.startswith(f"{SESSION_COOKIE_NAME}=")
    for attribute in ("HttpOnly", "Secure", "SameSite=lax", "Max-Age=3600", "Path=/"):
        assert attribute.lower() in set_cookie.lower()
    # The token itself is never in the body, where page scripts could read it.
    assert response.cookies[SESSION_COOKIE_NAME] not in response.text

    assert client.get("/session").json()["active"] is True
    assert client.get("/stats").status_code == 200


def test_failed_bot_check_gets_403_and_no_cookie(client, monkeypatch):
    _accept_turnstile(monkeypatch)
    response = client.post("/session", json={"turnstile_token": "bad-token"})
    assert response.status_code == 403
    assert response.json()["error"] == "BotCheckFailedError"
    assert "set-cookie" not in response.headers
    assert client.get("/stats").status_code == 401


def test_missing_bot_check_token_gets_403(client, monkeypatch):
    _accept_turnstile(monkeypatch)
    assert client.post("/session", json={}).status_code == 403


def test_without_turnstile_configured_a_session_is_issued_directly(client, monkeypatch):
    monkeypatch.setattr("app.routers.session.TURNSTILE_SITE_KEY", None)
    monkeypatch.setattr("app.routers.session.TURNSTILE_SECRET_KEY", None)
    assert client.get("/session").json()["turnstile_site_key"] is None
    assert client.post("/session", json={}).status_code == 200
    assert client.get("/stats").status_code == 200


def test_auth_off_reports_not_required_and_sets_no_cookie(client, monkeypatch):
    monkeypatch.setattr("app.core.security.AUTH_REQUIRED", False)
    response = client.post("/session", json={})
    assert response.json()["auth_required"] is False
    assert "set-cookie" not in response.headers


def test_session_endpoint_is_rate_limited_per_ip(client, monkeypatch):
    from limits import parse as parse_rate_limit

    from app.core.rate_limit import SESSION_RATE_LIMIT

    _accept_turnstile(monkeypatch)
    allowed = parse_rate_limit(SESSION_RATE_LIMIT).amount
    if allowed > 50:
        pytest.skip("ETIS_SESSION_RATE_LIMIT too high to exhaust in a test.")
    monkeypatch.setattr(limiter, "enabled", True)
    limiter.reset()
    try:
        for _ in range(allowed):
            assert client.post("/session", json={"turnstile_token": "good-token"}).status_code == 200
        assert client.post("/session", json={"turnstile_token": "good-token"}).status_code == 429
    finally:
        limiter.reset()


def test_unknown_fields_are_refused(client):
    assert client.post("/session", json={"turnstile_token": "x", "admin": True}).status_code == 400
