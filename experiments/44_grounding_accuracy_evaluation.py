
import json
from datetime import datetime, timezone
from pathlib import Path

from backend.grounding_validator import verify_grounding


ROOT = Path(__file__).resolve().parent.parent

OUTPUT = (
    ROOT / "results" / "44_grounding_accuracy_evaluation.json"
)


TEST_CASES = [
    {
        "id": "GR-001",
        "claim": (
            "Employees must use the approved VPN "
            "for remote access."
        ),
        "cited_document": "POL-005",
        "expected": "supported",
    },
    {
        "id": "GR-002",
        "claim": (
            "Employees must use the approved VPN "
            "for remote access only from home."
        ),
        "cited_document": "POL-005",
        "expected": "unsupported",
    },
    {
        "id": "GR-003",
        "claim": (
            "Employees should share their VPN "
            "passwords with coworkers."
        ),
        "cited_document": "POL-005",
        "expected": "unsupported",
    },
    {
        "id": "GR-004",
        "claim": (
            "Employees must use the approved VPN "
            "for remote access."
        ),
        "cited_document": "POL-999",
        "expected": "unknown_source",
    },
    {
        "id": "GR-005",
        "claim": (
            "Employees must report unexpected MFA "
            "requests to the security team."
        ),
        "cited_document": "POL-001",
        "expected": "supported",
    },
    {
        "id": "GR-006",
        "claim": (
            "Employees must never report unexpected "
            "MFA requests to the security team."
        ),
        "cited_document": "POL-001",
        "expected": "needs_review",
    },
    {
        "id": "GR-007",
        "claim": (
            "Passwords must have at least 14 characters."
        ),
        "cited_document": "POL-002",
        "expected": "supported",
    },
    {
        "id": "GR-008",
        "claim": (
            "Passwords must contain exactly 8 characters."
        ),
        "cited_document": "POL-002",
        "expected": "unsupported",
    },
    {
        "id": "GR-009",
        "claim": (
            "All employees receive unlimited "
            "administrative access."
        ),
        "cited_document": "POL-005",
        "expected": "needs_review",
    },
    {
        "id": "GR-010",
        "claim": (
            "Employees must use the approved VPN "
            "for remote access and share their "
            "passwords with coworkers."
        ),
        "cited_document": "POL-005",
        "expected": "unsupported",
    },
]


def main():
    results = []

    for case in TEST_CASES:
        assessment = verify_grounding(
            claim=case["claim"],
            cited_document=case["cited_document"],
        )

        predicted = assessment["status"]

        results.append({
            **case,
            "predicted": predicted,
            "reason": assessment["reason"],
            "correct": predicted == case["expected"],
        })

    total = len(results)
    correct = sum(
        item["correct"]
        for item in results
    )

    false_supports = [
        item["id"]
        for item in results
        if item["predicted"] == "supported"
        and item["expected"] != "supported"
    ]

    report = {
        "experiment": "44_grounding_accuracy_evaluation",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "summary": {
            "total_cases": total,
            "correct": correct,
            "accuracy": round(correct / total, 4),
            "false_supports": false_supports,
        },
        "results": results,
        "limitations": [
            "Small manually labeled synthetic dataset.",
            "Only the rule-based grounding validator "
            "is evaluated.",
            "Hybrid NLI verification is not yet assessed.",
            "Rule correctness does not prove that an "
            "entire generated answer is safe.",
            "No live RAG endpoint behavior is changed.",
        ],
    }

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("=" * 62)
    print("EXPERIMENT 44 - GROUNDING ACCURACY EVALUATION")
    print("=" * 62)

    for item in results:
        status = (
            "PASS"
            if item["correct"]
            else "MISMATCH"
        )

        print(
            f"{item['id']}: "
            f"expected={item['expected']} "
            f"predicted={item['predicted']} "
            f"[{status}]"
        )

    print()
    print("Cases:", total)
    print("Exact matches:", correct)
    print("Accuracy:", f"{correct / total:.1%}")
    print("False supports:", false_supports)
    print("Report:", OUTPUT)


if __name__ == "__main__":
    main()
