
import json
from collections import Counter
from pathlib import Path

from backend.grounding_validator import verify_grounding


ROOT = Path(__file__).resolve().parent.parent

DATASET_FILE = (
    ROOT / "data" / "evaluations"
    / "unseen_adversarial_cases.json"
)

OUTPUT_FILE = (
    ROOT / "results"
    / "21_unseen_adversarial_results.json"
)


def main():
    with DATASET_FILE.open(
        "r", encoding="utf-8"
    ) as file:
        cases = json.load(file)

    results = []

    print("=== Experiment 21: Unseen Adversarial Tests ===")

    for case in cases:
        evaluation = verify_grounding(
            claim=case["claim"],
            cited_document=case["cited_document"],
        )

        expected = case["expected_result"]
        predicted = evaluation["status"]

        passed = predicted == expected

        results.append({
            "test_id": case["test_id"],
            "attack_type": case["attack_type"],
            "claim": case["claim"],
            "cited_document": case["cited_document"],
            "expected": expected,
            "predicted": predicted,
            "passed": passed,
            "reason": evaluation["reason"],
        })

        print(f"\n{case['test_id']} — {case['attack_type']}")
        print(f"Expected: {expected}")
        print(f"Predicted: {predicted}")
        print(f"Result: {'PASS' if passed else 'FAIL'}")
        print(f"Reason: {evaluation['reason']}")

    passed_count = sum(
        item["passed"]
        for item in results
    )

    false_positives = [
        item for item in results
        if item["expected"] == "unsupported"
        and item["predicted"] == "supported"
    ]

    false_negatives = [
        item for item in results
        if item["expected"] == "supported"
        and item["predicted"] != "supported"
    ]

    needs_review = [
        item for item in results
        if item["predicted"] == "needs_review"
    ]

    report = {
        "experiment": "21_unseen_adversarial_grounding",
        "method": "Held-out adversarial evaluation",
        "summary": {
            "total": len(results),
            "passed": passed_count,
            "failed": len(results) - passed_count,
            "false_positive_count": len(false_positives),
            "false_negative_count": len(false_negatives),
            "needs_review_count": len(needs_review),
            "prediction_counts": dict(
                Counter(
                    item["predicted"]
                    for item in results
                )
            ),
        },
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "needs_review": needs_review,
        "results": results,
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w", encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False
        )

    print("\n=== Experiment 21 Summary ===")
    print(f"Passed: {passed_count}/{len(results)}")
    print(f"Failed: {len(results) - passed_count}")
    print(f"False positives: {len(false_positives)}")
    print(f"False negatives: {len(false_negatives)}")
    print(f"Needs review: {len(needs_review)}")
    print(f"Report saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
