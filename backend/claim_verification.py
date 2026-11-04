
import re
from typing import Any

from backend.citation_validator import (
    extract_citations,
    validate_citations,
)
from backend.grounding_validator import verify_grounding



def split_answer_into_claims(answer: str) -> list[str]:
    """
    Split sentences while attaching standalone
    trailing citations to the preceding sentence.

    A citation is not inherited by earlier sentences.
    """
    if not isinstance(answer, str):
        raise TypeError("Answer must be a string")

    segments = [
        segment.strip()
        for segment in re.split(
            r"(?<=[.!?])\s+",
            answer.strip(),
        )
        if segment.strip()
    ]

    claims = []

    standalone_citations = re.compile(
        r"^(?:\s*\[POL-\d{3}\]\s*)+$",
        flags=re.IGNORECASE,
    )

    for segment in segments:
        if (
            standalone_citations.fullmatch(segment)
            and claims
        ):
            claims[-1] += " " + segment
        else:
            claims.append(segment)

    return claims



def verify_answer_claims(
    answer: str,
    retrieved_document_ids: list[str],
    known_document_ids: list[str],
) -> dict[str, Any]:
    """
    Verify individual sentences of a generated answer.

    Uses rule-based grounding only in this initial
    implementation. No automatic-release decision.
    """
    claims = split_answer_into_claims(answer)

    citations = extract_citations(answer)

    citation_result = validate_citations(
        answer=answer,
        retrieved_document_ids=retrieved_document_ids,
        known_document_ids=known_document_ids,
    )

    results = []

    for claim in claims:
        claim_citations = extract_citations(claim)

        # A sentence's citation is explicit evidence
        # attribution. We do not automatically assign
        # another sentence's citation to it.
        if len(claim_citations) != 1:
            results.append({
                "claim": claim,
                "citation": None,
                "status": "needs_review",
                "reason": (
                    "Claim has missing or ambiguous "
                    "citation attribution."
                ),
            })
            continue

        document_id = claim_citations[0]

        if document_id not in (
            set(retrieved_document_ids)
            & set(known_document_ids)
        ):
            results.append({
                "claim": claim,
                "citation": document_id,
                "status": "unsupported",
                "reason": (
                    "Cited document was not verified "
                    "as known and retrieved."
                ),
            })
            continue

        grounding = verify_grounding(
            claim=claim,
            cited_document=document_id,
        )

        results.append({
            "claim": claim,
            "citation": document_id,
            "status": grounding["status"],
            "reason": grounding["reason"],
        })

    if not results:
        decision = "review_required"
        reason = "empty_answer"

    elif any(
        item["status"] in ("unsupported", "unknown_source")
        for item in results
    ):
        decision = "blocked"
        reason = "unsupported_claim_detected"

    elif not citation_result["all_references_verified"]:
        decision = "blocked"
        reason = "citation_validation_failed"

    else:
        decision = "review_required"
        reason = "full_answer_support_not_established"

    return {
        "decision": decision,
        "reason": reason,
        "claims": results,
        "citation_validation": citation_result,
        "safe_to_release_automatically": False,
    }
