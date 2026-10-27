"""
Unit tests for app/engines/submission.py with a fake scorer, so the link
handling (which URL is scanned, the cap, the verdict escalation) is tested
independently of the real models' scores.
"""

import pytest

from app.engines import submission
from app.engines.submission import analyze_submission

HIGH_HOST = "evil.top"


def fake_score(text=None, url=None, db=None):
    """HIGH for any URL on HIGH_HOST, LOW for everything else."""
    verdict = "HIGH" if url and HIGH_HOST in url else "LOW"
    return {
        "final_score": 90.0 if verdict == "HIGH" else 5.0,
        "verdict": verdict,
        "decided_by": "url_model" if verdict == "HIGH" else None,
        "engine_tiers": {"rule_based": "LOW"},
        "allowlisted": False,
        "engine_details": {},
    }


@pytest.fixture(autouse=True)
def use_fake_scorer(monkeypatch):
    calls = []

    def recording(text=None, url=None, db=None):
        calls.append({"text": text, "url": url})
        return fake_score(text=text, url=url, db=db)

    monkeypatch.setattr(submission, "calculate_final_risk_score", recording)
    return calls


def test_text_without_links_scans_text_only(use_fake_scorer):
    result = analyze_submission("hello there", None, db=None, max_links=5)
    assert result["scanned_url"] is None
    assert result["url_source"] is None
    assert result["additional_links"] == []
    assert use_fake_scorer == [{"text": "hello there", "url": None}]


def test_first_link_is_promoted_when_no_url_is_submitted(use_fake_scorer):
    text = "click https://a.com/x then https://b.com/y"
    result = analyze_submission(text, None, db=None, max_links=5)
    assert result["scanned_url"] == "https://a.com/x"
    assert result["url_source"] == "extracted_from_text"
    assert [link["url"] for link in result["additional_links"]] == ["https://b.com/y"]
    assert use_fake_scorer[0] == {"text": text, "url": "https://a.com/x"}
    assert use_fake_scorer[1] == {"text": None, "url": "https://b.com/y"}  # URL-only scan


def test_submitted_url_is_not_scanned_twice(use_fake_scorer):
    result = analyze_submission("see A.com/ and c.com", "https://a.com", db=None, max_links=5)
    assert result["url_source"] == "submitted"
    assert [link["url"] for link in result["additional_links"]] == ["c.com"]


def test_additional_link_raises_the_verdict(use_fake_scorer):
    result = analyze_submission(f"ok https://{HIGH_HOST}/login", "https://a.com", db=None, max_links=5)
    assert result["verdict"] == "HIGH"
    assert result["final_score"] == 90.0
    assert result["decided_by"] == "additional_link"
    # engine_tiers still describe the main scan only.
    assert result["engine_tiers"] == {"rule_based": "LOW"}


def test_main_verdict_is_kept_when_links_are_not_worse(use_fake_scorer):
    result = analyze_submission("see https://b.com", f"https://{HIGH_HOST}/", db=None, max_links=5)
    assert result["verdict"] == "HIGH"
    assert result["decided_by"] == "url_model"


def test_link_cap_counts_the_promoted_link_and_reports_the_rest(use_fake_scorer):
    text = " ".join(f"https://site{i}.com" for i in range(6))
    result = analyze_submission(text, None, db=None, max_links=3)
    assert result["scanned_url"] == "https://site0.com"
    assert [link["url"] for link in result["additional_links"]] == ["https://site1.com", "https://site2.com"]
    assert result["additional_links_skipped"] == 3
    assert len(use_fake_scorer) == 3  # 1 main + 2 additional, never more than max_links
