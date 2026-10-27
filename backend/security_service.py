
from dataclasses import dataclass
from typing import Any, Callable

from backend.citation_validator import validate_citations
from backend.hybrid_grounding import verify_hybrid_grounding


@dataclass
class SecurityAssessment:
    citation_validation: dict[str, Any]
    grounding_validation: dict[str, Any]
    decision: str
    review_required: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "citation_validation": self.citation_validation,
            "grounding_validation": self.grounding_validation,
            "decision": self.decision,
            "review_required": self.review_required,
        }


class AISecurityService:
    """
    Reusable AI security evaluation component.

    This is an experimental assessment service.
    It does not enforce access authorization or
    guarantee the factual correctness of an answer.
    """

    def __init__(
        self,
        grounding_checker: Callable = verify_hybrid_grounding,
    ):
        self.grounding_checker = grounding_checker

    def assess_claim(
        self,
        claim: str,
        cited_document: str,
        retrieved_document_ids: list[str],
        known_document_ids: list[str],
    ) -> SecurityAssessment:

        citation_result = validate_citations(
            answer=f"[{cited_document}]",
            retrieved_document_ids=retrieved_document_ids,
            known_document_ids=known_document_ids,
        )

        # Do not evaluate source grounding if the
        # referenced document was not retrieved.
        if not citation_result["all_references_verified"]:
            return SecurityAssessment(
                citation_validation=citation_result,
                grounding_validation={
                    "status": "not_evaluated",
                    "reason": (
                        "Cited document is unknown "
                        "or was not retrieved."
                    ),
                },
                decision="review_required",
                review_required=True,
            )

        grounding_result = self.grounding_checker(
            claim=claim,
            cited_document=cited_document,
        )

        # Experimental support assessment only.
        # No security-sensitive action is authorized here.
        if grounding_result["status"] == "supported":
            decision = "supported_by_checks"
            review_required = False
        elif grounding_result["status"] == "unsupported":
            decision = "unsupported_by_checks"
            review_required = True
        else:
            decision = "review_required"
            review_required = True

        return SecurityAssessment(
            citation_validation=citation_result,
            grounding_validation=grounding_result,
            decision=decision,
            review_required=review_required,
        )
