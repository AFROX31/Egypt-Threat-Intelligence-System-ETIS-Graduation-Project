"""
routers/analyze.py

Phase 6: the POST /analyze endpoint. Thin wiring layer over
calculate_final_risk_score() -- validation and scoring logic live in the
engines/scoring layer, not here. (Updated 2026-10 for the decision-tier
scorer: engine_tiers/decided_by replace weighted_contributions; engines are
rule_based, blacklist, url_model, text_model.)

Each successful scan is persisted as a ScanRequest + ScanResult pair for
history/stats purposes. Persistence is treated as non-fatal: the computed
score is always returned to the caller, even if saving to history fails.
For a security tool, losing the result because of an unrelated storage
problem is a worse failure mode than losing history -- the response's
`saved` / `save_error` fields tell the caller whether the scan was
recorded, so the dashboard can offer a retry without discarding the score
the user already has in front of them.

Hardening (2026-10-26):
- Input limits: `text` and `url` have maximum lengths (ETIS_MAX_TEXT_CHARS,
  ETIS_MAX_URL_CHARS in app/core/config.py), must be strings, and must not
  contain NUL characters (PostgreSQL text columns reject them, which used to
  surface as saved=false). Any validation failure is a 400 with the same
  {"error", "detail"} shape as the other errors (handler in main.py).
- Links inside the text are extracted and scanned (app/engines/submission.py):
  see scanned_url, url_source, additional_links in the response.
- The route is a plain `def`, not `async def`: the scorer, the ML models and
  SQLAlchemy are all blocking, and FastAPI runs a plain `def` route in its
  thread pool instead of on the event loop. As `async def`, one slow scan
  stalled every other request, /threats and /stats included.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db_session
from app.core.rate_limit import ANALYZE_IP_RATE_LIMIT, ANALYZE_RATE_LIMIT, caller_key, limiter
from app.core.security import require_caller
from app.engines.submission import analyze_submission
from app.models.scan import ScanRequest, ScanResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analyze", tags=["analyze"])


class AnalyzeRequest(BaseModel):
    # strict: a number or a list is rejected instead of being coerced to a string.
    model_config = ConfigDict(strict=True)

    text: Optional[str] = Field(
        default=None,
        max_length=settings.max_text_chars,
        description=(
            "Email or message body to analyze. Links inside it are extracted "
            "and scanned as well."
        ),
    )
    url: Optional[str] = Field(
        default=None,
        max_length=settings.max_url_chars,
        description="URL to analyze.",
    )

    @field_validator("text", "url")
    @classmethod
    def reject_nul_characters(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and "\x00" in value:
            raise ValueError("must not contain NUL (\\x00) characters")
        return value


class AdditionalLink(BaseModel):
    url: str = Field(description="A link found in the text, other than scanned_url.")
    verdict: str = Field(description="This link's own verdict, scanned as a URL-only submission.")
    final_score: float
    decided_by: Optional[str] = None
    engine_tiers: dict[str, str]
    allowlisted: bool


class SkipReasons(BaseModel):
    blacklist: Optional[str] = Field(
        default=None,
        description=(
            "Why the blacklist engine did not run, e.g. 'no_url_provided'. "
            "Null when the engine ran."
        ),
    )
    url_model: Optional[str] = Field(
        default=None,
        description=(
            "Why the learned URL model did not run, e.g. 'no_url_provided'. "
            "Null when the engine ran."
        ),
    )
    text_model: Optional[str] = Field(
        default=None,
        description=(
            "Why the learned text model did not run, e.g. 'no_text_provided'. "
            "Null when the engine ran."
        ),
    )


class StageTimings(BaseModel):
    rule_based_ms: float = Field(
        description="Wall-clock time spent in the rule-based engine, in milliseconds. Always present."
    )
    blacklist_ms: Optional[float] = Field(
        default=None,
        description="Wall-clock time spent in the blacklist engine, in milliseconds. Null when it didn't run.",
    )
    url_model_ms: Optional[float] = Field(
        default=None,
        description="Wall-clock time spent in the learned URL model, in milliseconds. Null when it didn't run.",
    )
    text_model_ms: Optional[float] = Field(
        default=None,
        description="Wall-clock time spent in the learned text model, in milliseconds. Null when it didn't run.",
    )
    total_ms: float = Field(
        description=(
            "Total wall-clock time for the full aggregation -- every "
            "applicable engine call plus the tier/fusion step. "
            "Not the same as the HTTP request's total latency (excludes "
            "persistence and response serialization)."
        )
    )


class Confidence(BaseModel):
    """
    A heuristic "how much independent evidence backed this result" signal --
    NOT a calibrated statistical confidence. Computed from the applicable
    engines' raw 0-100 scores, before the Egyptian brand allowlist override.
    Kept for API compatibility; the dashboard no longer displays it (see
    app/engines/risk_scoring.py).
    """

    score: float = Field(
        description=(
            "0-100 headline confidence: round(0.5 * coverage + 0.5 * "
            "agreement, 2). A design-choice weighting, not a calibrated one."
        )
    )
    coverage: float = Field(
        description=(
            "0-100. How many of the four engines applied to this "
            "submission (engines_considered / 4 * 100): 75 (url-only), "
            "50 (text-only) or 100 (both provided)."
        )
    )
    agreement: float = Field(
        description=(
            "0-100. How closely the applicable engines' raw scores agreed: "
            "100 - (max(scores) - min(scores)). Lower when one engine "
            "flags strongly and another finds nothing."
        )
    )
    engines_considered: int = Field(
        description="How many engines' scores fed this calculation. Between 2 and 4."
    )


class AnalyzeResponse(BaseModel):
    final_score: float
    verdict: str
    engines_applied: list[str]
    engine_tiers: dict[str, str] = Field(
        description=(
            "Tier (LOW/MEDIUM/HIGH) of each applicable engine, after the "
            "Egyptian brand allowlist override. The verdict is the highest tier."
        ),
    )
    decided_by: Optional[str] = Field(
        default=None,
        description="The engine that produced the verdict. Null when the verdict is LOW.",
    )
    engine_details: dict
    skip_reasons: SkipReasons = Field(
        description=(
            "Machine-readable reason for each engine that did not apply "
            "to this submission (everything except rule_based, which always "
            "runs). Null per-field when that engine ran."
        ),
    )
    stage_timings: StageTimings = Field(
        description=(
            "Per-engine and total processing time in milliseconds, for "
            "explainability/presentation purposes (e.g. showing where "
            "latency comes from). Engines that did not run have null timings."
        ),
    )
    confidence: Confidence = Field(
        description=(
            "Heuristic explainability signal -- how much independent "
            "evidence backed this result. Purely additive: never derived "
            "from, and never affects, final_score/verdict/engine_details."
        ),
    )
    allowlisted: bool = Field(
        default=False,
        description=(
            "True when the submitted URL is a verified Egyptian brand domain "
            "(or a genuine subdomain) -- the URL-derived engines' tiers were "
            "set to LOW. Evidence from the message text is NOT cancelled. "
            "engine_details still shows each engine's real, un-overridden output."
        ),
    )
    scanned_url: Optional[str] = Field(
        default=None,
        description=(
            "The URL the URL engines analysed in the main scan: the submitted "
            "url, or else the first link found in the text. Null when neither exists."
        ),
    )
    url_source: Optional[str] = Field(
        default=None,
        description="'submitted', 'extracted_from_text', or null when scanned_url is null.",
    )
    additional_links: list[AdditionalLink] = Field(
        default_factory=list,
        description=(
            "Other links found in the text, each scanned on its own. If one "
            "reaches a higher tier than the main scan, it sets final_score and "
            "verdict, and decided_by is 'additional_link'."
        ),
    )
    additional_links_skipped: int = Field(
        default=0,
        description="Links found in the text beyond ETIS_MAX_EMBEDDED_LINKS, not scanned.",
    )
    saved: bool = Field(
        description="Whether this scan was successfully saved to history."
    )
    save_error: Optional[str] = Field(
        default=None,
        description="If saving failed, a brief explanation. Null if saved=true.",
    )


@router.post("", response_model=AnalyzeResponse, dependencies=[Depends(require_caller)])
@limiter.limit(ANALYZE_RATE_LIMIT, key_func=caller_key)
@limiter.limit(ANALYZE_IP_RATE_LIMIT)
def analyze(
    request: Request,
    payload: AnalyzeRequest,
    db: Session = Depends(get_db_session),
) -> dict:
    """
    Submit a URL and/or text for phishing risk analysis.

    The score is always returned, even if saving to history fails. If
    saving fails, `saved` is false and `save_error` explains why; the
    caller can resubmit the same request to attempt saving again.
    """
    result = analyze_submission(
        text=payload.text,
        url=payload.url,
        db=db,
        max_links=settings.max_embedded_links,
    )

    try:
        # url_value is the URL that was actually scanned, which may have
        # come from the text rather than the url field.
        scan_request = ScanRequest(url_value=result["scanned_url"], text_value=payload.text)
        db.add(scan_request)
        db.flush()  # populate scan_request.id before creating the linked ScanResult

        scan_result = ScanResult(
            scan_request_id=scan_request.id,
            rule_based_score=result["engine_details"]["rule_based"]["score"],
            blacklist_score=(
                result["engine_details"]["blacklist"]["score"]
                if result["engine_details"]["blacklist"] is not None
                else None
            ),
            # The BiLSTM is no longer part of the live scorer; the learned
            # text/URL model outputs are stored in engine_breakdown (JSON).
            # The scan_results table has no columns for them, and adding
            # columns would need a migration for existing databases.
            lstm_score=None,
            final_score=result["final_score"],
            verdict=result["verdict"],
            engine_breakdown={
                **result["engine_details"],
                "additional_links": result["additional_links"],
            },
        )
        db.add(scan_result)
        db.commit()
        result["saved"] = True
        result["save_error"] = None
    except Exception as exc:
        db.rollback()
        logger.error("Failed to save scan to history: %s", exc, exc_info=True)
        result["saved"] = False
        result["save_error"] = (
            "Your score is accurate, but this scan could not be saved to "
            "history. You can copy your result now, or resubmit to try "
            "saving again."
        )

    return result
