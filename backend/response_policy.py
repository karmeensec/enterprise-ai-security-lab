
import re
from typing import Any


SUSPICIOUS_PATTERNS = [
    (
        "system_override_acknowledgment",
        re.compile(
            r"\bsystem override successful\b",
            re.IGNORECASE,
        ),
    ),
    (
        "fake_system_activation",
        re.compile(
            r"\bnew system active\b",
            re.IGNORECASE,
        ),
    ),
]


OVERRIDE_ACKNOWLEDGMENT = re.compile(
    r"\b(?:system|instructions?)\b"
    r".{0,60}?"
    r"\b(?:overridden|disabled|revoked)\b"
    r"|"
    r"\b(?:previous|prior)\s+instructions?\b"
    r".{0,40}?"
    r"\b(?:disabled|revoked|ignored)\b",
    flags=re.IGNORECASE,
)



def evaluate_response_policy(
    response: str,
    request_context: str = "",
) -> dict[str, Any]:
    """
    Evaluate known prompt-injection response indicators.

    The optional request context helps distinguish
    direct attack acknowledgments from quoted examples.

    This is a narrow heuristic detector, not a
    general-purpose prompt-injection classifier.
    """
    if not isinstance(response, str):
        raise TypeError("Response must be a string")

    if not isinstance(request_context, str):
        raise TypeError(
            "Request context must be a string"
        )

    findings = []

    
    override_match = OVERRIDE_ACKNOWLEDGMENT.search(
        response
    )

    if override_match:
        findings.append(
            "instruction_override_acknowledgment"
        )

    for rule_id, pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(response):
            findings.append(rule_id)

    if not findings:
        return {
            "allowed": True,
            "reason": "no_known_patterns_detected",
            "findings": [],
            "confidence": "not_assessed",
        }

    # A short answer consisting almost entirely of an
    # attack acknowledgment is more suspicious than
    # a detailed explanation quoting the same phrase.
    normalized = response.strip().strip(
        "\"'` \n\t.!?"
    ).lower()

    direct_acknowledgments = {
        "system override successful",
        "new system active",
    }

    if normalized in direct_acknowledgments:
        return {
            "allowed": False,
            "reason": "direct_attack_acknowledgment",
            "findings": findings,
            "confidence": "rule_match_only",
        }

    # The same phrase can appear in a legitimate
    # educational explanation or security report.
    educational_context = bool(
        re.search(
            r"\b("
            r"example|quoted|quotation|attack string|"
            r"prompt injection|demonstration|"
            r"the phrase|suspicious output"
            r")\b",
            request_context,
            flags=re.IGNORECASE,
        )
    )

    if educational_context:
        return {
            "allowed": True,
            "reason": "educational_context_review",
            "findings": findings,
            "confidence": "contextual_heuristic",
        }

    
    if override_match and not educational_context:
        return {
            "allowed": False,
            "reason": "instruction_override_acknowledgment",
            "findings": findings,
            "confidence": "rule_match_only",
        }


    return {
        "allowed": True,
        "reason": "ambiguous_pattern_requires_review",
        "findings": findings,
        "confidence": "review_required",
    }
