import pytest

from app.core.config import DEFAULT_CORS_ORIGINS, DEFAULT_DATABASE_URL, load_settings


def test_defaults_when_nothing_is_set():
    settings = load_settings({})
    assert settings.database_url == DEFAULT_DATABASE_URL
    assert settings.auth_required is False
    assert settings.session_secret is None
    assert settings.turnstile_site_key is None and settings.turnstile_secret_key is None
    assert settings.cookie_secure is True and settings.cookie_samesite == "lax"
    assert settings.cors_origins == DEFAULT_CORS_ORIGINS
    assert settings.cors_allow_credentials is True
    assert settings.analyze_rate_limit == "20/minute"
    assert settings.analyze_ip_rate_limit == "60/minute"
    assert settings.frontend_dist is None
    assert settings.max_text_chars == 20_000
    assert settings.max_url_chars == 4_096
    assert settings.max_embedded_links == 5


def test_cors_origins_are_split_trimmed_and_lose_trailing_slash():
    settings = load_settings({"ETIS_CORS_ORIGINS": " http://localhost:5173/ , https://etis.example.org ,"})
    assert settings.cors_origins == ("http://localhost:5173", "https://etis.example.org")


def test_old_shared_api_key_is_refused_loudly():
    assert load_settings({"ETIS_API_KEY": ""}).auth_required is False  # empty line in an old .env is fine
    with pytest.raises(ValueError, match="ETIS_API_KEY is no longer used"):
        load_settings({"ETIS_API_KEY": "s3cret"})


def test_auth_required_needs_a_long_session_secret():
    with pytest.raises(ValueError, match="ETIS_SESSION_SECRET"):
        load_settings({"ETIS_AUTH_REQUIRED": "true"})
    with pytest.raises(ValueError, match="at least 32"):
        load_settings({"ETIS_AUTH_REQUIRED": "true", "ETIS_SESSION_SECRET": "short"})
    settings = load_settings({"ETIS_AUTH_REQUIRED": "true", "ETIS_SESSION_SECRET": "x" * 32})
    assert settings.auth_required is True


def test_turnstile_keys_come_in_pairs():
    with pytest.raises(ValueError, match="both"):
        load_settings({"ETIS_TURNSTILE_SITE_KEY": "site"})
    settings = load_settings({"ETIS_TURNSTILE_SITE_KEY": "site", "ETIS_TURNSTILE_SECRET_KEY": "secret"})
    assert settings.turnstile_secret_key == "secret"


def test_samesite_none_needs_secure():
    with pytest.raises(ValueError, match="SAMESITE"):
        load_settings({"ETIS_COOKIE_SAMESITE": "none", "ETIS_COOKIE_SECURE": "false"})
    with pytest.raises(ValueError, match="SAMESITE"):
        load_settings({"ETIS_COOKIE_SAMESITE": "sometimes"})


def test_values_are_read_from_the_environment():
    settings = load_settings({
        "DATABASE_URL": "postgresql://u:p@db:5432/etis_eval",
        "ETIS_CORS_ALLOW_CREDENTIALS": "TRUE",
        "ETIS_ANALYZE_RATE_LIMIT": "5/second",
        "ETIS_MAX_TEXT_CHARS": "100",
        "ETIS_MAX_EMBEDDED_LINKS": "2",
    })
    assert settings.database_url.endswith("/etis_eval")
    assert settings.cors_allow_credentials is True
    assert settings.analyze_rate_limit == "5/second"
    assert settings.max_text_chars == 100
    assert settings.max_embedded_links == 2


@pytest.mark.parametrize("value", ["abc", "0", "-5", "1.5"])
def test_bad_number_names_the_variable(value):
    with pytest.raises(ValueError, match="ETIS_MAX_TEXT_CHARS"):
        load_settings({"ETIS_MAX_TEXT_CHARS": value})


def test_bad_boolean_names_the_variable():
    with pytest.raises(ValueError, match="ETIS_CORS_ALLOW_CREDENTIALS"):
        load_settings({"ETIS_CORS_ALLOW_CREDENTIALS": "maybe"})
