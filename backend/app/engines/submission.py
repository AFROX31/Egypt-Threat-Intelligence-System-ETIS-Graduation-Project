"""
submission.py

What POST /analyze runs: calculate_final_risk_score() plus the links found
inside the message text (added 2026-10-26). calculate_final_risk_score()
itself is unchanged, so every evaluation that calls it directly still
measures the same scorer.

1. Links are extracted from the text (app/core/link_extraction.py).
2. The URL the main scan uses ("scanned_url"):
       - the submitted `url` when there is one   (url_source = "submitted")
       - otherwise the FIRST link in the text      (url_source = "extracted_from_text")
       - otherwise none                            (url_source = None)
   The main scan is calculate_final_risk_score(text, scanned_url), i.e. the
   full four-engine scan of a URL+text submission.
3. Every OTHER link in the text, up to max_links in total, is scored on its
   own as a URL-only submission and listed in "additional_links". Links past
   the cap are counted in "additional_links_skipped", not scanned.
4. Verdict: still the highest tier. When an additional link reaches a higher
   tier than the main scan, final_score/verdict take that link's values and
   decided_by becomes "additional_link". engine_tiers and engine_details keep
   describing the main scan only, so they show where the main verdict came
   from; the link's own tiers are in its additional_links entry.

As with any submitted URL, an extracted link that is a verified Egyptian
brand domain is allowlisted (its URL-derived engines are set to LOW).
"""

from sqlalchemy.orm import Session

from app.core.link_extraction import extract_links, link_identity
from app.engines.risk_scoring import calculate_final_risk_score

URL_SOURCE_SUBMITTED = "submitted"
URL_SOURCE_EXTRACTED = "extracted_from_text"
DECIDED_BY_ADDITIONAL_LINK = "additional_link"

_TIER_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def _link_summary(link: str, result: dict) -> dict:
    return {
        "url": link,
        "verdict": result["verdict"],
        "final_score": result["final_score"],
        "decided_by": result["decided_by"],
        "engine_tiers": result["engine_tiers"],
        "allowlisted": result["allowlisted"],
    }


def analyze_submission(
    text: str | None,
    url: str | None,
    db: Session,
    max_links: int,
) -> dict:
    """Run the main scan plus the additional-link scans. Returns the
    calculate_final_risk_score() dict with scanned_url, url_source,
    additional_links and additional_links_skipped added (and final_score /
    verdict / decided_by raised when an additional link scores higher).
    Raises InvalidScanInputError for the same inputs the scorer rejects."""
    url_provided = isinstance(url, str) and url.strip() != ""
    links = extract_links(text)

    if url_provided:
        scanned_url, url_source = url, URL_SOURCE_SUBMITTED
        budget = max_links
    elif links:
        scanned_url, url_source = links[0], URL_SOURCE_EXTRACTED
        budget = max_links - 1  # the promoted link counts towards the cap
    else:
        scanned_url, url_source = None, None
        budget = max_links

    result = calculate_final_risk_score(text=text, url=scanned_url, db=db)

    scanned_key = link_identity(scanned_url) if scanned_url else None
    others = [link for link in links if link_identity(link) != scanned_key]
    to_scan, skipped = others[:max(budget, 0)], others[max(budget, 0):]

    additional = []
    for link in to_scan:
        link_result = calculate_final_risk_score(url=link, db=db)
        additional.append(_link_summary(link, link_result))

    worst = max(additional, key=lambda item: (_TIER_RANK[item["verdict"]], item["final_score"]), default=None)
    if worst is not None and _TIER_RANK[worst["verdict"]] > _TIER_RANK[result["verdict"]]:
        result["final_score"] = worst["final_score"]
        result["verdict"] = worst["verdict"]
        result["decided_by"] = DECIDED_BY_ADDITIONAL_LINK

    result["scanned_url"] = scanned_url
    result["url_source"] = url_source
    result["additional_links"] = additional
    result["additional_links_skipped"] = len(skipped)
    return result
