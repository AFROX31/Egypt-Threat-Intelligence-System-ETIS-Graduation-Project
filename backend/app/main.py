"""
main.py

FastAPI application entrypoint (Phase 6). Schema creation runs
automatically on startup via the lifespan handler rather than the manual
Base.metadata.create_all() one-liner used in Phases 0-5 — safe because
create_all() is idempotent, and this removes a manual step that would
otherwise need to be repeated on every fresh clone or hosted deployment
(Railway/Render).

The lifespan handler also warms up the learned models so the first scan is
not slow (see app/core/warmup.py; skip with ETIS_SKIP_WARMUP=1).

Settings (CORS origins, rate limits, input limits, authentication, database URL)
come from the environment or .env via app/core/config.py, not from values
hard-coded here (2026-10-26). Request validation errors are returned as 400
in the same {"error", "detail"} shape as the ETIS exceptions, and request
bodies over ETIS_MAX_REQUEST_BYTES are refused with 413 before parsing.

Authentication (app/core/security.py): the dashboard uses a session cookie
from POST /session, programs use per-client API keys. With ETIS_FRONTEND_DIST
set, the built dashboard is served from this same origin, which is what lets
the SameSite session cookie work on hosts whose subdomains count as separate
sites (e.g. *.onrender.com).
"""
import logging
from contextlib import asynccontextmanager

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.config import settings
from app.core.database import engine, Base
from app.core.rate_limit import limiter
import app.models  # noqa: F401 — registers all models on Base.metadata
from app.core.exceptions import (
    ETISException,
    InvalidScanInputError,
    EngineFailureError,
    BlacklistLookupError,
    AuthenticationError,
    SessionRequiredError,
    BotCheckFailedError,
    BotCheckUnavailableError,
)
from app.core.warmup import warm_up_engines

logger = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    logger.info(
        "ETIS settings: CORS origins %s, /analyze limits %s per caller and %s per IP, authentication %s, bot check %s.",
        ", ".join(settings.cors_origins),
        settings.analyze_rate_limit,
        settings.analyze_ip_rate_limit,
        "required" if settings.auth_required else "OFF (ETIS_AUTH_REQUIRED=false, local development only)",
        "on" if settings.turnstile_secret_key else "off",
    )
    if settings.auth_required and not settings.turnstile_secret_key:
        logger.warning("Authentication is on but the Turnstile bot check is off: anyone can script POST /session.")
    if settings.auth_required and not settings.cookie_secure:
        logger.warning("ETIS_COOKIE_SECURE=false: the session cookie can travel over plain HTTP. Local testing only.")
    warm_up_engines()
    yield


app = FastAPI(
    title="ETIS — Egypt-Specific Threat Intelligence System",
    description="Hybrid phishing detection API for Egyptian SMEs.",
    version="0.1.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

if "*" in settings.cors_origins and settings.cors_allow_credentials:
    # Browsers refuse credentials with a wildcard origin; fail loudly instead
    # of starting a server the dashboard cannot talk to.
    raise ValueError("ETIS_CORS_ORIGINS='*' cannot be combined with ETIS_CORS_ALLOW_CREDENTIALS=true.")

# Only what the dashboard and the extension use: GET/POST, a JSON body and
# the X-API-Key header. Credentials are on by default so the dashboard's
# session cookie travels on cross-origin calls (localhost:5173 -> :8000).
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)


@app.middleware("http")
async def limit_request_body_size(request: Request, call_next):
    """Refuse oversized bodies from their Content-Length header, before
    FastAPI reads and parses them. Field-level limits (text/url length) are
    enforced by the AnalyzeRequest model; this guards the parser itself.
    A chunked request without Content-Length is not covered here; uvicorn
    and the field limits still apply to it."""
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            too_large = int(content_length) > settings.max_request_bytes
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"error": "InvalidRequest", "detail": "Invalid Content-Length header."},
            )
        if too_large:
            return JSONResponse(
                status_code=413,
                content={
                    "error": "RequestTooLarge",
                    "detail": f"Request body is larger than {settings.max_request_bytes} bytes.",
                },
            )
    return await call_next(request)

from app.routers import analyze, threats, stats, session

app.include_router(analyze.router)
app.include_router(threats.router)
app.include_router(stats.router)
app.include_router(session.router)

# --- Global exception handling ------------------------------------------
# Maps the ETISException hierarchy to HTTP responses in one place, per
# CLAUDE.md's error-handling convention. Routes and engine code raise the
# custom exceptions directly; they never construct HTTPException inline.

_STATUS_BY_EXCEPTION = {
    InvalidScanInputError: 400,
    BlacklistLookupError: 502,
    EngineFailureError: 500,
    AuthenticationError: 401,
    SessionRequiredError: 401,
    BotCheckFailedError: 403,
    BotCheckUnavailableError: 503,
}


@app.exception_handler(ETISException)
async def etis_exception_handler(request: Request, exc: ETISException) -> JSONResponse:
    status_code = _STATUS_BY_EXCEPTION.get(type(exc), 500)
    return JSONResponse(
        status_code=status_code,
        content={"error": type(exc).__name__, "detail": str(exc)},
    )


def _describe_validation_errors(errors: list[dict]) -> str:
    """One readable line per problem, e.g. "text: String should have at most
    20000 characters". The submitted values are deliberately NOT echoed back:
    they can be a 20,000-character message that may contain personal data."""
    parts = []
    for error in errors:
        location = ".".join(str(item) for item in error.get("loc", ()) if item != "body")
        message = error.get("msg", "Invalid value")
        parts.append(f"{location}: {message}" if location else message)
    return "; ".join(parts) or "Invalid request."


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """400 (not FastAPI's default 422) for a malformed request: wrong type,
    too long, not JSON, query parameter out of range. Same body shape as
    the ETIS exceptions, plus a machine-readable `fields` list."""
    errors = exc.errors()
    return JSONResponse(
        status_code=400,
        content={
            "error": "RequestValidationError",
            "detail": _describe_validation_errors(errors),
            "fields": [
                {
                    "loc": [str(item) for item in error.get("loc", ())],
                    "type": error.get("type"),
                    "msg": error.get("msg"),
                }
                for error in errors
            ],
        },
    )


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "ETIS"}


if settings.frontend_dist:
    # Serve the built dashboard (npm run build -> etis-frontend/dist) from
    # this origin. Mounted last, so every API route above takes precedence.
    frontend_dir = Path(settings.frontend_dist)
    if not (frontend_dir / "index.html").is_file():
        raise ValueError(f"ETIS_FRONTEND_DIST={settings.frontend_dist!r} has no index.html (run npm run build).")
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="dashboard")
else:
    @app.get("/")
    async def root() -> dict:
        return {"status": "ok", "service": "ETIS"}
