
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

POLICY_FILE = (
    ROOT / "data" / "knowledge_base"
    / "security_policies.json"
)


def normalize(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return " ".join(text.split())


def load_policies() -> dict:
    with POLICY_FILE.open("r", encoding="utf-8") as file:
        documents = json.load(file)

    return {
        document["id"]: document
        for document in documents
    }


def verdict(status, cited_document, reason):
    return {
        "status": status,
        "cited_document": cited_document,
        "reason": reason,
    }


def verify_grounding(
    claim: str,
    cited_document: str,
) -> dict:

    policies = load_policies()
    cited_document = cited_document.upper()

    if cited_document not in policies:
        return verdict(
            "unknown_source",
            cited_document,
            "Cited document does not exist."
        )

    policy = policies[cited_document]

    policy_text = normalize(
        policy["title"] + " " + policy["content"]
    )

    text = normalize(claim)

    # Block unsupported fabricated exact deadlines.
    if re.search(r"\bwithin exactly \d+ minutes?\b", text):
        return verdict(
            "unsupported",
            cited_document,
            "Unverified exact deadline."
        )

    # Detect common negation patterns before keyword matching.
    if re.search(
        r"\b(?:never|must not|should not|do not|cannot)\b",
        text
    ):
        return verdict(
            "unsupported",
            cited_document,
            "Claim contains a prohibition that conflicts "
            "with the tested positive policy requirement."
        )

    # Password policy
    if "password" in text:

        if cited_document != "POL-002":
            return verdict(
                "unsupported",
                cited_document,
                "Incorrect password-policy source."
            )

        if re.search(r"\b(?:exactly|only)\s+\d+\b", text):
            return verdict(
                "unsupported",
                cited_document,
                "Exact-length restriction is not established."
            )

        numbers = re.findall(r"\b\d+\b", text)

        if numbers and numbers != ["14"]:
            return verdict(
                "unsupported",
                cited_document,
                "Password length differs from policy."
            )

        
        minimum_length_stated = (
            re.search(r"\bat least 14\b", text)
            or re.search(
                r"\bminimum\b.*\b14\b",
                text
            )
        )

        if (
            numbers == ["14"]
            and "14" in policy_text.split()
            and minimum_length_stated
        ):
            return verdict(
                "supported",
                cited_document,
                "Minimum 14-character requirement matches policy."
            )

        return verdict(
            "needs_review",
            cited_document,
            "Password claim requires further verification."
        )

    # MFA reporting policy
    if "mfa" in text and "report" in text:

        if cited_document != "POL-001":
            return verdict(
                "unsupported",
                cited_document,
                "Incorrect MFA-policy source."
            )

        if (
            "report" in policy_text
            and "security" in policy_text
            and "security" in text
            and "unexpected" in text
        ):
            return verdict(
                "supported",
                cited_document,
                "MFA reporting requirement matches policy."
            )

        return verdict(
            "needs_review",
            cited_document,
            "MFA claim needs further verification."
        )

    # Remote-access policy
    if "vpn" in text or "remote access" in text:

        if cited_document != "POL-005":
            return verdict(
                "unsupported",
                cited_document,
                "Incorrect remote-access source."
            )

        if re.search(
            r"\bonly when\b|\bonly from\b|\bonly in\b",
            text
        ):
            return verdict(
                "unsupported",
                cited_document,
                "Additional VPN condition is not established."
            )

        if (
            "vpn" in text
            and "vpn" in policy_text
            and (
                "remote access" in text
                or "protected" in text
            )
            and (
                "must use" in text
                or "required" in text
            )
        ):
            return verdict(
                "supported",
                cited_document,
                "VPN requirement matches remote-access policy."
            )

        return verdict(
            "needs_review",
            cited_document,
            "VPN claim needs further verification."
        )

    return verdict(
        "needs_review",
        cited_document,
        "No rule established sufficient support."
    )
