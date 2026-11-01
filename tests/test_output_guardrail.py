
from backend.output_guardrail import (
    SAFE_FALLBACK,
    validate_chat_output,
)


def test_allows_normal_cybersecurity_answer():
    result = validate_chat_output(
        "MFA uses multiple authentication factors."
    )

    assert result["allowed"] is True
    assert result["response"].startswith("MFA uses")


def test_blocks_citation_without_retrieval():
    result = validate_chat_output(
        "MFA is required. [POL-001]"
    )

    assert result["allowed"] is False
    assert result["response"] == SAFE_FALLBACK
    assert result["reason"] == (
        "policy_citation_without_evidence"
    )


def test_blocks_fabricated_policy():
    result = validate_chat_output(
        "POL-999 is a verified company policy."
    )

    assert result["allowed"] is False
    assert "POL-999" in result["original_citations"]


def test_blocks_unknown_citation_with_retrieval():
    result = validate_chat_output(
        "Follow policy [POL-999].",
        retrieved_document_ids=["POL-001"],
        known_document_ids=["POL-001"],
    )

    assert result["allowed"] is False
    assert result["reason"] == "invalid_policy_citation"


def test_blocks_known_but_not_retrieved_policy():
    result = validate_chat_output(
        "Follow policy [POL-002].",
        retrieved_document_ids=["POL-001"],
        known_document_ids=["POL-001", "POL-002"],
    )

    assert result["allowed"] is False


def test_accepts_retrieved_known_citation():
    result = validate_chat_output(
        "The policy states this. [POL-001]",
        retrieved_document_ids=["POL-001"],
        known_document_ids=["POL-001"],
    )

    assert result["allowed"] is True
    assert result["reason"] == (
        "citation_ids_verified_only"
    )


def test_no_citation_does_not_prove_grounding():
    result = validate_chat_output(
        "A company policy requires an action."
    )

    assert result["allowed"] is True
    assert result["reason"] == (
        "no_policy_citations_detected"
    )


def test_preserves_original_safe_response():
    answer = "Encryption protects information."

    result = validate_chat_output(answer)

    assert result["response"] == answer
