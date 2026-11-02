
import re
from typing import Any

from backend.citation_validator import validate_citations
from backend.grounding_validator import verify_grounding


INJECTION_PATTERNS = {
    "instruction_override": re.compile(
        r"\bignore (?:your |all |previous )*"
        r"(?:system )?instructions\b",
        re.IGNORECASE,
    ),
    "fake_system_update": re.compile(
        r"\[(?:SYSTEM UPDATE|SYSTEM MESSAGE)\]",
        re.IGNORECASE,
    ),
    "assistant_directive": re.compile(
        r"\b(?:important ai assistant instruction|"
        r"editorial note for ai assistants)\s*:",
        re.IGNORECASE,
    ),
}

SAFE_RESPONSE = (
    "The retrieved information or generated answer "
    "requires security review. Please consult the "
    "authorized company policy documents."
)


def inspect_retrieved_context(context: str) -> list[str]:
    """Find known instruction-in-document indicators."""
    return [
        name
        for name, pattern in INJECTION_PATTERNS.items()
        if pattern.search(context)
    ]


def split_claims(answer: str) -> list[str]:
    """Split simple sentences for exploratory evaluation."""
    return [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+", answer.strip())
        if part.strip()
    ]


def evaluate_rag_answer(
    answer: str,
    retrieved_context: str,
    retrieved_document_ids: list[str],
    known_document_ids: list[str],
) -> dict[str, Any]:
    """
    Conservative RAG security assessment.

    Uses the trusted local policy rules, not the
    potentially poisoned context, for grounding.

    This is an experimental fail-closed gate:
    uncertain results require review.
    """
    if not isinstance(answer, str):
        raise TypeError("Answer must be a string")

    if not isinstance(retrieved_context, str):
        raise TypeError("Context must be a string")

    injection_findings = inspect_retrieved_context(
        retrieved_context
    )

    citation_result = validate_citations(
        answer=answer,
        retrieved_document_ids=retrieved_document_ids,
        known_document_ids=known_document_ids,
    )

    citations = citation_result["citations"]
    claims = split_claims(answer)
    claim_assessments = []

    for claim in claims:
        # A single citation may be repeated across
        # several claims. Its presence alone does
        # not demonstrate that every claim is supported.
        #
        # Multiple citations make attribution ambiguous,
        # so they require review.
        if len(citations) != 1:
            claim_assessments.append({
                "claim": claim,
                "status": "needs_review",
                "reason": "Ambiguous or missing citation attribution",
            })
            continue

        result = verify_grounding(
            claim=claim,
            cited_document=citations[0],
        )

        claim_assessments.append({
            "claim": claim,
            "status": result["status"],
            "reason": result["reason"],
        })

    unsupported = any(
        item["status"] in ("unsupported", "unknown_source")
        for item in claim_assessments
    )

    uncertain = any(
        item["status"] != "supported"
        for item in claim_assessments
    )

    citation_invalid = (
        not citation_result["all_references_verified"]
    )

    if injection_findings or unsupported or citation_invalid:
        decision = "blocked"
        reason = "rag_security_check_failed"
    elif uncertain or not claims:
        decision = "review_required"
        reason = "claim_support_not_established"
    else:
        # The existing grounding rules are limited.
        # Even their "supported" verdict is not
        # proof of complete semantic correctness.
        decision = "review_required"
        reason = "additional_review_required"

    return {
        "decision": decision,
        "reason": reason,
        "review_required": True,
        "safe_to_release_automatically": False,
        "display_response": SAFE_RESPONSE,
        "injection_findings": injection_findings,
        "citation_validation": citation_result,
        "claim_assessments": claim_assessments,
    }
