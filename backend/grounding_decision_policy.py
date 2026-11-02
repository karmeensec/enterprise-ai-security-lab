
from typing import Any


def decide_grounding_action(
    rule_status: str,
    hybrid_status: str,
    citations_verified: bool,
    injection_detected: bool = False,
) -> dict[str, Any]:
    """
    Prototype security decision for one isolated claim.

    Does not authorize release of an entire RAG answer.
    """

    if injection_detected:
        return {
            "action": "block",
            "reason": "retrieved_context_injection_detected",
        }

    if not citations_verified:
        return {
            "action": "block",
            "reason": "citation_verification_failed",
        }

    if rule_status in {"unsupported", "unknown_source"}:
        return {
            "action": "block",
            "reason": "rule_based_negative_evidence",
        }

    if hybrid_status in {"unsupported", "unknown_source"}:
        return {
            "action": "block",
            "reason": "hybrid_negative_evidence",
        }

    if (
        rule_status == "supported"
        and hybrid_status == "supported"
    ):
        return {
            "action": "release_candidate",
            "reason": "both_grounding_checks_support_claim",
        }

    return {
        "action": "review_required",
        "reason": "grounding_not_established",
    }
