
import re


POLICY_ID_PATTERN = re.compile(
    r"\bPOL-\d{3}\b",
    flags=re.IGNORECASE,
)


def extract_citations(answer: str) -> list[str]:
    """Extract policy IDs, with or without square brackets."""
    return list(dict.fromkeys(
        match.group(0).upper()
        for match in POLICY_ID_PATTERN.finditer(answer)
    ))


def validate_citations(
    answer: str,
    retrieved_document_ids: list[str],
    known_document_ids: list[str],
) -> dict:
    """
    Check whether cited document IDs exist and were retrieved.

    This does not prove that a cited document supports
    the claims in the generated answer.
    """
    citations = extract_citations(answer)

    retrieved = {
        document_id.upper()
        for document_id in retrieved_document_ids
    }

    known = {
        document_id.upper()
        for document_id in known_document_ids
    }

    unknown_citations = [
        citation
        for citation in citations
        if citation not in known
    ]

    not_retrieved = [
        citation
        for citation in citations
        if citation in known and citation not in retrieved
    ]

    valid_citations = [
        citation
        for citation in citations
        if citation in known and citation in retrieved
    ]

    if unknown_citations or not_retrieved:
        status = "invalid"
    elif not citations:
        status = "missing"
    else:
        status = "references_verified"

    return {
        "status": status,
        "citations": citations,
        "valid_citations": valid_citations,
        "unknown_citations": unknown_citations,
        "not_retrieved": not_retrieved,
        "citation_count": len(citations),
        "all_references_verified": (
            status == "references_verified"
        ),
        "claim_support_verified": False,
    }
