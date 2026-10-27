
import json
from collections import Counter
from pathlib import Path

from backend.hybrid_grounding import verify_hybrid_grounding


ROOT = Path(__file__).resolve().parent.parent

DATASETS = [
    ROOT / "data/evaluations/grounding_test_cases.json",
    ROOT / "data/evaluations/adversarial_grounding_cases.json",
    ROOT / "data/evaluations/unseen_adversarial_cases.json",
]

OUTPUT_FILE = (
    ROOT / "results/26_hybrid_grounding_results.json"
)


def main():
    print("=== Experiment 26: Hybrid Grounding Evaluation ===")

    results = []

    for dataset_path in DATASETS:
        with dataset_path.open("r", encoding="utf-8") as file:
            cases = json.load(file)

        print(f"\nDataset: {dataset_path.name}")

        for case in cases:
            evaluation = verify_hybrid_grounding(
                claim=case["claim"],
                cited_document=case["cited_document"],
            )

            expected = case["expected_result"]
            predicted = evaluation["status"]

            exact_match = expected == predicted

            unsafe_approval = (
                expected == "unsupported"
                and predicted == "supported"
            )

            false_rejection = (
                expected == "supported"
                and predicted == "unsupported"
            )

            record = {
                "dataset": dataset_path.name,
                "test_id": case["test_id"],
                "claim": case["claim"],
                "expected": expected,
                "predicted": predicted,
                "exact_match": exact_match,
                "unsafe_approval": unsafe_approval,
                "false_rejection": false_rejection,
                "rule_status": evaluation["rule_status"],
                "nli": evaluation["nli"],
                "reason": evaluation["reason"],
            }

            results.append(record)

            print(
                f"{case['test_id']}: "
                f"expected={expected}, "
                f"predicted={predicted}, "
                f"NLI={evaluation['nli']['label']}"
            )

    total = len(results)

    exact_matches = sum(
        result["exact_match"] for result in results
    )

    unsafe_approvals = sum(
        result["unsafe_approval"] for result in results
    )

    false_rejections = sum(
        result["false_rejection"] for result in results
    )

    abstentions = sum(
        result["predicted"] == "needs_review"
        for result in results
    )

    supported_cases = sum(
        result["expected"] == "supported"
        for result in results
    )

    unsupported_cases = sum(
        result["expected"] == "unsupported"
        for result in results
    )

    summary = {
        "total_cases": total,
        "exact_matches": exact_matches,
        "exact_match_rate": round(
            exact_matches / total, 4
        ) if total else None,
        "supported_cases": supported_cases,
        "unsupported_cases": unsupported_cases,
        "unsafe_approvals": unsafe_approvals,
        "false_rejections": false_rejections,
        "abstentions": abstentions,
        "abstention_rate": round(
            abstentions / total, 4
        ) if total else None,
        "prediction_counts": dict(
            Counter(
                result["predicted"]
                for result in results
            )
        ),
    }

    report = {
        "experiment": "26_hybrid_grounding_evaluation",
        "method": "Conservative rule-based plus NLI verification",
        "limitations": (
            "These are small, development-influenced test "
            "datasets. NLI probabilities are not calibrated "
            "security guarantees. Abstention does not prove "
            "that a claim is false."
        ),
        "summary": summary,
        "results": results,
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
        )

    print("\n=== Hybrid Evaluation Summary ===")

    for key, value in summary.items():
        print(f"{key}: {value}")

    print(f"\nReport saved: {OUTPUT_FILE}")
    print("Experiment 26 completed!")


if __name__ == "__main__":
    main()
