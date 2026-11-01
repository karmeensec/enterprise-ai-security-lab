
from typing import Any

from backend.citation_validator import (
    extract_citations,
    validate_citations,
)


SAFE_FALLBACK = (
    "The generated response could not be verified "
    "against the available company policy evidence. "
    "Please consult the authorized policy documents."
)


def validate_chat_output(
    response: str,
    retrieved_document_ids: list[str] | None = None,
    known_document_ids: list[str] | None = None,
) -> dict[str, Any]:
    """
    Validate policy references in an LLM response.

    This checks citation integrity only.
    It does not establish factual or semantic support.
    """
    retrieved_ids = retrieved_document_ids or []
    known_ids = known_document_ids or []

    citations = extract_citations(response)

    # The ordinary /chat endpoint has no retrieved
    # policy evidence. Policy IDs cannot be verified.
    if not retrieved_ids and citations:
        return {
            "allowed": False,
            "reason": "policy_citation_without_evidence",
            "response": SAFE_FALLBACK,
            "original_citations": citations,
        }

    # No policy citation was detected.
    if not citations:
        return {
            "allowed": True,
            "reason": "no_policy_citations_detected",
            "response": response,
            "original_citations": [],
        }

    validation = validate_citations(
        answer=response,
        retrieved_document_ids=retrieved_ids,
        known_document_ids=known_ids,
    )

    if not validation["all_references_verified"]:
        return {
            "allowed": False,
            "reason": "invalid_policy_citation",
            "response": SAFE_FALLBACK,
            "original_citations": citations,
        }

    return {
        "allowed": True,
        "reason": "citation_ids_verified_only",
        "response": response,
        "original_citations": citations,
    }
