
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

POLICY_FILE = (
    ROOT / "data" / "knowledge_base"
    / "security_policies.json"
)


def normalize(text: str) -> str:
    """Normalize text for simple matching."""
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return " ".join(text.split())


def load_policies() -> dict:
    with POLICY_FILE.open(
        "r", encoding="utf-8"
    ) as file:
        documents = json.load(file)

    return {
        document["id"]: document
        for document in documents
    }


def verify_grounding(
    claim: str,
    cited_document: str,
) -> dict:
    """
    Verify a small set of known company-policy claims.

    This is a deterministic baseline, not general-purpose
    natural-language entailment verification.
    """
    policies = load_policies()

    if cited_document not in policies:
        return {
            "status": "unknown_source",
            "cited_document": cited_document,
            "reason": "Document does not exist.",
        }

    policy = policies[cited_document]
    policy_text = normalize(
        policy["title"] + " " + policy["content"]
    )

    normalized_claim = normalize(claim)

    # Detect unsupported exact timing requirements.
    if re.search(
        r"\bwithin exactly \d+ minutes?\b",
        normalized_claim
    ):
        return {
            "status": "unsupported",
            "cited_document": cited_document,
            "reason": (
                "Exact time requirements require "
                "explicit verification."
            ),
        }

    # Password length verification
    if "password" in normalized_claim:
        if cited_document != "POL-002":
            return {
                "status": "unsupported",
                "cited_document": cited_document,
                "reason": "Incorrect source for password policy.",
            }

        numbers = re.findall(
            r"\b\d+\b", normalized_claim
        )

        if "14" in numbers and "14" in policy_text:
            return {
                "status": "supported",
                "cited_document": cited_document,
                "reason": (
                    "Claim matches the configured "
                    "password-length requirement."
                ),
            }

        return {
            "status": "unsupported",
            "cited_document": cited_document,
            "reason": "Password-length claim not established.",
        }

    # Remote access verification
    if (
        "vpn" in normalized_claim
        or "remote access" in normalized_claim
    ):
        if cited_document != "POL-005":
            return {
                "status": "unsupported",
                "cited_document": cited_document,
                "reason": "Incorrect source for remote access.",
            }

        if "vpn" in policy_text and "vpn" in normalized_claim:
            return {
                "status": "supported",
                "cited_document": cited_document,
                "reason": "VPN requirement appears in policy.",
            }

    # Unexpected MFA approval reporting
    if (
        "mfa" in normalized_claim
        and "report" in normalized_claim
    ):
        if cited_document != "POL-001":
            return {
                "status": "unsupported",
                "cited_document": cited_document,
                "reason": "Incorrect source for MFA policy.",
            }

        if (
            "report" in policy_text
            and "security" in policy_text
        ):
            return {
                "status": "supported",
                "cited_document": cited_document,
                "reason": (
                    "Reporting instruction matches "
                    "the MFA policy."
                ),
            }

    return {
        "status": "needs_review",
        "cited_document": cited_document,
        "reason": (
            "No deterministic rule established "
            "whether this claim is supported."
        ),
    }
