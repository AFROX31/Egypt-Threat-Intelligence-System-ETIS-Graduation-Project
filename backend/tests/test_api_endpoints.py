"""
Endpoint tests for the FastAPI app (POST /analyze, GET /threats, GET /stats).

Database: every test runs inside a transaction that is rolled back
afterwards, so scans saved by /analyze never stay in the database (the
route's own commit becomes a SAVEPOINT release). The blacklist must be
seeded for the /threats tests that need rows; they skip otherwise.

Rate limiting is switched off except in the test that checks it, and
authentication is off except in the tests that check it (tests/test_session.py
covers sessions and API keys in depth), so the results do not depend on
ETIS_AUTH_REQUIRED or earlier requests in the same run.
"""

import asyncio
import importlib
import inspect
import time

import httpx
import pytest
from fastapi.testclient import TestClient
from limits import parse as parse_rate_limit
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import engine, get_db_session
from app.core.rate_limit import ANALYZE_RATE_LIMIT, limiter
from app.main import app
from app.models.scan import ScanRequest

PHISHING_TEXT_WITH_LINK = "عميلنا العزيز تم ايقاف بطاقتك اضغط https://nbe-update.com/login لتفعيلها"
BENIGN_TEXT = "تم إيداع راتبكم الشهري بنجاح"


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


@pytest.fixture
def client(db_session, monkeypatch):
    monkeypatch.setattr("app.core.security.AUTH_REQUIRED", False)
    monkeypatch.setattr(limiter, "enabled", False)

    def override_db():
        yield db_session

    app.dependency_overrides[get_db_session] = override_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_db_session, None)


# --- POST /analyze: successful scans -----------------------------------------

def test_root_health_check(client):
    assert client.get("/").json() == {"status": "ok", "service": "ETIS"}


def test_analyze_text_only(client, db_session):
    response = client.post("/analyze", json={"text": BENIGN_TEXT})
    assert response.status_code == 200
    body = response.json()
    assert body["engines_applied"] == ["rule_based", "text_model"]
    assert body["scanned_url"] is None
    assert body["url_source"] is None
    assert body["additional_links"] == []
    assert body["saved"] is True
    assert db_session.query(ScanRequest).filter_by(text_value=BENIGN_TEXT).count() == 1


def test_analyze_url_only(client):
    response = client.post("/analyze", json={"url": "http://192.168.1.50/login"})
    assert response.status_code == 200
    body = response.json()
    assert body["engines_applied"] == ["rule_based", "blacklist", "url_model"]
    assert body["url_source"] == "submitted"
    assert body["verdict"] in ("MEDIUM", "HIGH")


def test_analyze_extracts_link_from_text_and_records_it(client, db_session):
    response = client.post("/analyze", json={"text": PHISHING_TEXT_WITH_LINK})
    assert response.status_code == 200
    body = response.json()
    assert body["scanned_url"] == "https://nbe-update.com/login"
    assert body["url_source"] == "extracted_from_text"
    assert set(body["engines_applied"]) == {"rule_based", "blacklist", "url_model", "text_model"}
    assert body["verdict"] == "HIGH"
    saved = db_session.query(ScanRequest).filter_by(text_value=PHISHING_TEXT_WITH_LINK).one()
    assert saved.url_value == "https://nbe-update.com/login"


def test_analyze_scans_other_links_and_lets_them_raise_the_verdict(client):
    # The submitted URL is a verified brand domain (allowlisted -> LOW); the
    # IP-address link in the text is scored HIGH on its own.
    response = client.post(
        "/analyze",
        json={"url": "https://www.cibeg.com/", "text": "Meeting notes. Also http://192.168.1.50/login"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["allowlisted"] is True
    assert [link["url"] for link in body["additional_links"]] == ["http://192.168.1.50/login"]
    link = body["additional_links"][0]
    assert body["verdict"] == link["verdict"] == "HIGH"
    assert body["final_score"] == link["final_score"]
    assert body["decided_by"] == "additional_link"


# --- POST /analyze: validation returns 400 -----------------------------------

def _assert_400(response, error="RequestValidationError", detail_contains=None):
    assert response.status_code == 400, response.text
    body = response.json()
    assert body["error"] == error
    assert isinstance(body["detail"], str) and body["detail"]
    if detail_contains:
        assert detail_contains in body["detail"]
    return body


def test_empty_body_is_400(client):
    _assert_400(client.post("/analyze", json={}), error="InvalidScanInputError")


def test_whitespace_only_text_is_400(client):
    _assert_400(client.post("/analyze", json={"text": "   \n "}), error="InvalidScanInputError")


def test_hostless_url_is_400(client):
    _assert_400(client.post("/analyze", json={"url": "https://"}), error="InvalidScanInputError")


def test_text_over_the_limit_is_400(client):
    too_long = "ا" * (settings.max_text_chars + 1)
    body = _assert_400(client.post("/analyze", json={"text": too_long}), detail_contains="text")
    # The submitted value is not echoed back.
    assert too_long not in str(body)


def test_text_at_the_limit_is_accepted(client):
    response = client.post("/analyze", json={"text": "ا" * settings.max_text_chars})
    assert response.status_code == 200


def test_url_over_the_limit_is_400(client):
    url = "https://example.com/" + "a" * settings.max_url_chars
    _assert_400(client.post("/analyze", json={"url": url}), detail_contains="url")


@pytest.mark.parametrize("payload", [{"text": 123}, {"url": ["https://a.com"]}, {"text": True}])
def test_wrong_types_are_400(client, payload):
    _assert_400(client.post("/analyze", json=payload))


def test_nul_character_is_400(client):
    _assert_400(client.post("/analyze", json={"text": "hello\x00world"}), detail_contains="NUL")


def test_malformed_json_is_400(client):
    response = client.post("/analyze", content=b'{"text": ', headers={"Content-Type": "application/json"})
    _assert_400(response)


def test_json_that_is_not_an_object_is_400(client):
    _assert_400(client.post("/analyze", json=["not", "an", "object"]))


def test_oversized_body_is_413_before_parsing(client):
    response = client.post(
        "/analyze",
        content=b"x" * (settings.max_request_bytes + 1),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"] == "RequestTooLarge"


# --- GET /threats and GET /stats ----------------------------------------------

def test_threats_returns_page_shape(client):
    response = client.get("/threats", params={"limit": 2})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"total_matching", "limit", "offset", "results"}
    assert body["limit"] == 2
    assert len(body["results"]) <= 2
    if not body["results"]:
        pytest.skip("Database not seeded -- run data/scripts/seed_database.py first.")
    entry = body["results"][0]
    assert "url" not in entry and "url_hash" not in entry  # domain-level only


def test_threats_filter_by_source(client):
    body = client.get("/threats", params={"source": "manual-does-not-exist"}).json()
    assert body["total_matching"] == 0
    assert body["results"] == []


@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 501}, {"offset": -1}, {"is_active": "maybe"}])
def test_threats_bad_query_parameters_are_400(client, params):
    _assert_400(client.get("/threats", params=params))


def test_stats_shape(client):
    response = client.get("/stats")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"blacklist", "scans"}
    assert set(body["scans"]["by_verdict"]) >= {"LOW", "MEDIUM", "HIGH"}


def test_stats_counts_a_new_scan(client):
    before = client.get("/stats").json()["scans"]["total_scans"]
    assert client.post("/analyze", json={"text": BENIGN_TEXT}).status_code == 200
    assert client.get("/stats").json()["scans"]["total_scans"] == before + 1


# --- authentication -----------------------------------------------------------

@pytest.mark.parametrize("method,path,kwargs", [
    ("post", "/analyze", {"json": {"text": BENIGN_TEXT}}),
    ("get", "/threats", {}),
    ("get", "/stats", {}),
])
def test_authentication_is_enforced_on_every_endpoint(client, db_session, monkeypatch, method, path, kwargs):
    from app.core.api_keys import create_api_client
    from app.core.sessions import SESSION_COOKIE_NAME, issue_session_token

    secret = "x" * 32
    monkeypatch.setattr("app.core.security.AUTH_REQUIRED", True)
    monkeypatch.setattr("app.core.security.SESSION_SECRET", secret)
    _, key = create_api_client(db_session, "endpoint-test-client")
    cookie, _ = issue_session_token(secret, 60)
    call = getattr(client, method)

    no_credentials = call(path, **kwargs)
    assert no_credentials.status_code == 401
    assert no_credentials.json()["error"] == "SessionRequiredError"
    assert call(path, headers={"X-API-Key": "etis_wrong"}, **kwargs).status_code == 401
    assert call(path, headers={"X-API-Key": key}, **kwargs).status_code == 200
    client.cookies.set(SESSION_COOKIE_NAME, cookie)
    try:
        assert call(path, **kwargs).status_code == 200
    finally:
        client.cookies.clear()


# --- rate limit and CORS ------------------------------------------------------

def test_analyze_rate_limit_returns_429(client, monkeypatch):
    allowed = parse_rate_limit(ANALYZE_RATE_LIMIT).amount
    if allowed > 50:
        pytest.skip(f"ETIS_ANALYZE_RATE_LIMIT={ANALYZE_RATE_LIMIT} is too high to exhaust in a test.")
    monkeypatch.setattr(limiter, "enabled", True)
    limiter.reset()
    try:
        for _ in range(allowed):
            assert client.post("/analyze", json={"text": BENIGN_TEXT}).status_code == 200
        assert client.post("/analyze", json={"text": BENIGN_TEXT}).status_code == 429
        # Cheap read endpoints are not limited.
        assert client.get("/stats").status_code == 200
    finally:
        limiter.reset()


def test_cors_allows_configured_origin_only(client):
    allowed_origin = settings.cors_origins[0]
    preflight = {
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,x-api-key",
    }
    ok = client.options("/analyze", headers={"Origin": allowed_origin, **preflight})
    assert ok.status_code == 200
    assert ok.headers["access-control-allow-origin"] == allowed_origin

    if "*" not in settings.cors_origins:
        refused = client.options("/analyze", headers={"Origin": "https://evil.example", **preflight})
        assert "access-control-allow-origin" not in refused.headers


# --- blocking code does not run on the event loop -----------------------------

@pytest.mark.parametrize("endpoint", [
    "app.routers.analyze:analyze",
    "app.routers.threats:list_threats",
    "app.routers.stats:get_stats",
])
def test_routes_that_block_are_plain_functions(endpoint):
    module_name, function_name = endpoint.split(":")
    function = getattr(importlib.import_module(module_name), function_name)
    assert not inspect.iscoroutinefunction(function), (
        f"{endpoint} must be a plain `def`: its scorer/database calls block the event loop."
    )


def test_slow_requests_run_concurrently(monkeypatch):
    """Two /stats requests whose database work takes 0.4 s each finish in
    well under 0.8 s, which is only possible if they do not share the event
    loop thread. With the old `async def` routes this took ~0.8 s."""
    delay = 0.4

    def slow_section(db):
        time.sleep(delay)
        return {}

    monkeypatch.setattr("app.core.security.AUTH_REQUIRED", False)
    monkeypatch.setattr("app.routers.stats._blacklist_stats", slow_section)
    monkeypatch.setattr("app.routers.stats._scan_stats", lambda db: {})

    def no_db():
        yield None

    app.dependency_overrides[get_db_session] = no_db

    async def two_requests():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            start = time.perf_counter()
            responses = await asyncio.gather(http.get("/stats"), http.get("/stats"))
            return time.perf_counter() - start, responses

    try:
        elapsed, responses = asyncio.run(two_requests())
    finally:
        app.dependency_overrides.pop(get_db_session, None)

    assert all(r.status_code == 200 for r in responses)
    assert elapsed < delay * 1.75, f"requests ran one after another ({elapsed:.2f} s)"
