
import json
from collections import Counter
from pathlib import Path

from backend.grounding_validator import verify_grounding


ROOT = Path(__file__).resolve().parent.parent

DATASET_FILE = (
    ROOT / "data" / "evaluations"
    / "grounding_test_cases.json"
)

OUTPUT_FILE = ROOT / "results" / "18_grounding_results.json"


def main():
    with DATASET_FILE.open(
        "r", encoding="utf-8"
    ) as file:
        test_cases = json.load(file)

    results = []

    print("=== Experiment 18: Grounding Verification ===")

    for test in test_cases:
        evaluation = verify_grounding(
            claim=test["claim"],
            cited_document=test["cited_document"],
        )

        expected = test["expected_result"]
        predicted = evaluation["status"]

        passed = predicted == expected

        results.append({
            "test_id": test["test_id"],
            "claim": test["claim"],
            "cited_document": test["cited_document"],
            "expected": expected,
            "predicted": predicted,
            "passed": passed,
            "reason": evaluation["reason"],
        })

        print(f"\n{test['test_id']}")
        print(f"Expected: {expected}")
        print(f"Predicted: {predicted}")
        print(f"Result: {'PASS' if passed else 'FAIL'}")
        print(f"Reason: {evaluation['reason']}")

    counts = Counter(
        result["predicted"]
        for result in results
    )

    passed_count = sum(
        result["passed"]
        for result in results
    )

    report = {
        "experiment": "18_grounding_verification",
        "method": "Deterministic policy-specific baseline",
        "total": len(results),
        "passed": passed_count,
        "status_counts": dict(counts),
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

    print("\n=== Final Summary ===")
    print(
        f"Passed: {passed_count}/{len(results)}"
    )
    print(f"Report saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
