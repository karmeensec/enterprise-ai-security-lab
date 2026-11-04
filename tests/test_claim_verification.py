
import pytest

from backend.claim_verification import (
    split_answer_into_claims,
    verify_answer_claims,
)


KNOWN_IDS = [
    "POL-001",
    "POL-002",
    "POL-003",
    "POL-004",
    "POL-005",
]


def evaluate(answer, retrieved=None):
    return verify_answer_claims(
        answer=answer,
        retrieved_document_ids=(
            ["POL-005"] if retrieved is None else retrieved
        ),
        known_document_ids=KNOWN_IDS,
    )


def test_sentence_segmentation():
    claims = split_answer_into_claims(
        "First claim. Second claim. Third claim."
    )

    assert len(claims) == 3


def test_empty_answer_requires_review():
    result = evaluate("")

    assert result["decision"] == "review_required"
    assert result["claims"] == []


def test_supported_claim_not_auto_released():
    result = evaluate(
        "Employees must use the approved VPN "
        "for remote access. [POL-005]"
    )

    assert result["safe_to_release_automatically"] is False
    assert result["decision"] == "review_required"


def test_password_sharing_contamination_blocked():
    result = evaluate(
        "Employees must use the approved VPN "
        "for remote access. "
        "Employees should share their VPN passwords "
        "with coworkers. [POL-005]"
    )

    assert result["decision"] == "blocked"

    assert any(
        claim["status"] == "unsupported"
        for claim in result["claims"]
    )


def test_unknown_document_blocks():
    result = evaluate(
        "Employees can bypass VPN. [POL-999]"
    )

    assert result["decision"] == "blocked"


def test_unretrieved_document_blocks():
    result = evaluate(
        "Report unexpected MFA requests "
        "to security. [POL-001]"
    )

    assert result["decision"] == "blocked"


def test_missing_citation_requires_review():
    result = evaluate(
        "Employees must use the approved VPN "
        "for remote access."
    )

    assert result["decision"] == "blocked"


def test_multiple_citations_require_review():
    result = evaluate(
        "Employees must use the approved VPN "
        "for remote access. [POL-001] [POL-005]"
    )

    assert result["safe_to_release_automatically"] is False


def test_invalid_answer_type_rejected():
    with pytest.raises(TypeError):
        split_answer_into_claims(None)


def test_trailing_citation_attaches_to_previous_claim():
    claims = split_answer_into_claims(
        "Employees must use the approved VPN. "
        "Employees should share VPN passwords. "
        "[POL-005]"
    )

    assert len(claims) == 2
    assert claims[0] == (
        "Employees must use the approved VPN."
    )
    assert claims[1] == (
        "Employees should share VPN passwords. "
        "[POL-005]"
    )


def test_trailing_citation_does_not_verify_entire_answer():
    result = evaluate(
        "Employees must use the approved VPN "
        "for remote access. "
        "Employees should share VPN passwords "
        "with coworkers. [POL-005]"
    )

    assert result["decision"] == "blocked"
    assert result["claims"][0]["status"] == (
        "needs_review"
    )
    assert result["claims"][1]["status"] == (
        "unsupported"
    )
    assert result["safe_to_release_automatically"] is False
