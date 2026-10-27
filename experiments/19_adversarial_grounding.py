
import json
from collections import Counter
from pathlib import Path

from backend.grounding_validator import verify_grounding


ROOT = Path(__file__).resolve().parent.parent

DATASET_FILE = (
    ROOT / "data" / "evaluations"
    / "adversarial_grounding_cases.json"
)

OUTPUT_FILE = (
    ROOT / "results" / "19_adversarial_grounding.json"
)


def main():
    with DATASET_FILE.open(
        "r", encoding="utf-8"
    ) as file:
        cases = json.load(file)

    results = []

    print("=== Experiment 19: Adversarial Grounding ===")

    for case in cases:
        evaluation = verify_grounding(
            claim=case["claim"],
            cited_document=case["cited_document"],
        )

        predicted = evaluation["status"]
        expected = case["expected_result"]

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
        result["passed"] for result in results
    )

    false_positives = [
        result for result in results
        if result["expected"] == "unsupported"
        and result["predicted"] == "supported"
    ]

    counts = Counter(
        result["predicted"] for result in results
    )

    report = {
        "experiment": "19_adversarial_grounding",
        "method": "Adversarial evaluation of deterministic verifier",
        "summary": {
            "total_cases": len(results),
            "passed": passed_count,
            "failed": len(results) - passed_count,
            "false_positive_count": len(false_positives),
            "predicted_status_counts": dict(counts),
        },
        "false_positives": false_positives,
        "results": results,
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True, exist_ok=True
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

    print("\n=== Adversarial Evaluation Summary ===")
    print(f"Passed: {passed_count}/{len(results)}")
    print(f"Failed: {len(results) - passed_count}")
    print(f"False positives: {len(false_positives)}")
    print(f"Report saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
