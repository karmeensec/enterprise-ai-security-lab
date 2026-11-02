
import json
from datetime import datetime, timezone
from pathlib import Path

from backend.hybrid_grounding import (
    MODEL_NAME,
    verify_hybrid_grounding,
)


ROOT = Path(__file__).resolve().parent.parent

BASELINE = (
    ROOT / "results" / "44_grounding_accuracy_evaluation.json"
)

OUTPUT = (
    ROOT / "results" / "44_hybrid_grounding_evaluation.json"
)


def main():
    baseline = json.loads(
        BASELINE.read_text(encoding="utf-8")
    )

    cases = baseline["results"]
    results = []

    print("=" * 65)
    print("EXPERIMENT 44 - HYBRID GROUNDING EVALUATION")
    print("=" * 65)
    print("NLI model:", MODEL_NAME)
    print("Cases:", len(cases))

    for case in cases:
        print()
        print("Evaluating:", case["id"], flush=True)

        assessment = verify_hybrid_grounding(
            claim=case["claim"],
            cited_document=case["cited_document"],
        )

        expected = case["expected"]
        predicted = assessment["status"]

        # A review decision is an abstention rather
        # than an incorrect automatic approval.
        false_support = (
            predicted == "supported"
            and expected != "supported"
        )

        record = {
            "id": case["id"],
            "claim": case["claim"],
            "cited_document": case["cited_document"],
            "expected": expected,
            "rule_prediction": case["predicted"],
            "hybrid_prediction": predicted,
            "exact_match": predicted == expected,
            "false_support": false_support,
            "abstained": predicted == "needs_review",
            "nli": assessment.get("nli"),
            "reason": assessment["reason"],
        }

        results.append(record)

        print("Expected:", expected)
        print("Rule result:", case["predicted"])
        print("Hybrid result:", predicted)

        nli = assessment.get("nli")
        if nli:
            print("NLI label:", nli["label"])
            print("NLI confidence:", nli["confidence"])

        if false_support:
            print("WARNING: FALSE SUPPORT")

    total = len(results)

    exact_matches = sum(
        item["exact_match"] for item in results
    )

    false_supports = [
        item["id"]
        for item in results
        if item["false_support"]
    ]

    abstentions = [
        item["id"]
        for item in results
        if item["abstained"]
    ]

    supported_expected = [
        item for item in results
        if item["expected"] == "supported"
    ]

    supported_released = sum(
        item["hybrid_prediction"] == "supported"
        for item in supported_expected
    )

    report = {
        "experiment": "44_hybrid_grounding_evaluation",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "model": MODEL_NAME,
        "summary": {
            "total_cases": total,
            "exact_matches": exact_matches,
            "exact_match_accuracy": round(
                exact_matches / total, 4
            ),
            "false_support_ids": false_supports,
            "abstention_ids": abstentions,
            "abstention_count": len(abstentions),
            "supported_cases_expected": len(
                supported_expected
            ),
            "supported_cases_approved": supported_released,
        },
        "results": results,
        "limitations": [
            "Small manually labeled synthetic dataset.",
            "NLI confidence values are not calibrated "
            "safety probabilities.",
            "Review-required classifications are "
            "abstentions, not verified rejections.",
            "Whole-answer citation attribution and "
            "mixed-claim verification remain incomplete.",
            "No production automatic-release policy "
            "is established by this evaluation.",
        ],
    }

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 65)
    print("HYBRID EVALUATION SUMMARY")
    print("=" * 65)
    print("Cases evaluated:", total)
    print("Exact matches:", exact_matches)
    print("Accuracy:", f"{exact_matches / total:.1%}")
    print("False supports:", false_supports)
    print("Abstentions:", len(abstentions))
    print(
        "Supported claims approved:",
        supported_released,
        "/",
        len(supported_expected),
    )
    print("Report saved:", OUTPUT)


if __name__ == "__main__":
    main()
